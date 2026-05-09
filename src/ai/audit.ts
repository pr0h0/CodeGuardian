import path from "node:path";
import { z } from "zod";
import type { IndexedFile } from "../repo/repoIndexer.js";
import type { Finding, ScannerResult } from "../scanners/types.js";
import { redactSecrets } from "../utils/redact.js";
import { safeJsonParse } from "../utils/safeJson.js";
import { extractImports } from "../repo/importGraph.js";
import { detectRoutes } from "../repo/routeDetector.js";
import { extractSymbols } from "../repo/symbolExtractor.js";
import type { AiMessage, AiProvider } from "./types.js";

const auditFindingSchema = z.object({
  title: z.string(),
  category: z.string(),
  severity: z.enum(["critical", "high", "medium", "low", "info"]),
  confidence: z.enum(["confirmed", "high", "medium", "low"]),
  status: z.enum(["confirmed", "suspected", "needs_dynamic_test", "false_positive"]).default("suspected"),
  path: z.string(),
  startLine: z.number().int().positive().optional(),
  endLine: z.number().int().positive().optional(),
  source: z.string().default("AI exploratory audit"),
  sink: z.string().default("source code"),
  evidence: z.array(z.object({ path: z.string(), line: z.number().int().positive(), note: z.string() })).default([]),
  reasoning: z.string(),
  remediation: z.string()
});

const auditResponseSchema = z.object({
  summary: z.string().default(""),
  requestedFiles: z.array(z.string()).default([]),
  complete: z.boolean().default(false),
  findings: z.array(auditFindingSchema).default([])
});

export interface AiExploratoryAuditOptions {
  maxFiles: number;
  maxRounds: number;
  maxChars: number;
}

interface ManifestEntry {
  path: string;
  language: string;
  lines: number;
  imports: string[];
  routes: Array<{ method: string; path: string; line: number; framework: string }>;
  symbols: Array<{ name: string; kind: string; line: number }>;
  hasScannerResult: boolean;
  priorityHints: string[];
}

export async function runExploratoryAudit(
  provider: AiProvider,
  files: IndexedFile[],
  scannerResults: ScannerResult[],
  options: AiExploratoryAuditOptions,
  log: (message: string) => void = () => undefined
): Promise<Finding[]> {
  const candidates = files.filter(isAuditableFile);
  const manifest = buildManifest(candidates, scannerResults);
  const allowed = new Map(candidates.map((file) => [file.path, file]));
  const inspected = new Set<string>();
  const findings: Finding[] = [];
  let remainingChars = options.maxChars;
  let requested = await requestInitialFiles(provider, manifest, log);
  if (!requested.length) requested = heuristicEntryFiles(candidates, scannerResults);
  const messages: AiMessage[] = [{ role: "user", content: buildInitialPrompt(manifest, options) }];

  for (let round = 1; round <= options.maxRounds; round++) {
    const paths = normalizeRequestedPaths(requested, allowed, inspected).slice(0, Math.max(0, options.maxFiles - inspected.size));
    if (!paths.length) {
      log(`ai-audit: round ${round}/${options.maxRounds} no new files requested`);
      break;
    }
    const pack = buildFilePack(paths.map((filePath) => allowed.get(filePath)!), remainingChars);
    if (!pack.files.length) {
      log(`ai-audit: round ${round}/${options.maxRounds} source char budget exhausted`);
      break;
    }
    for (const file of pack.files) inspected.add(file.path);
    remainingChars -= pack.charCount;
    log(`ai-audit: round ${round}/${options.maxRounds} sending files=${pack.files.length} inspected=${inspected.size}/${options.maxFiles} chars=${pack.charCount} remaining=${remainingChars}`);
    messages.push({ role: "user", content: buildAuditRoundPrompt(pack, [...inspected]) });
    const parsed = await requestAuditRound(provider, messages, log, round);
    messages.push({ role: "assistant", content: JSON.stringify(parsed) });
    findings.push(...parsed.findings.map((finding) => toFinding(finding)));
    requested = parsed.requestedFiles;
    log(`ai-audit: round ${round}/${options.maxRounds} findings=${parsed.findings.length} requested=${requested.length} complete=${parsed.complete}`);
    if (parsed.complete || inspected.size >= options.maxFiles || remainingChars <= 0) break;
    if (!requested.length) requested = nextUnseenHeuristicFiles(candidates, scannerResults, inspected);
  }

  log(`ai-audit: complete inspected=${inspected.size} findings=${findings.length}`);
  return dedupeFindings(findings);
}

async function requestInitialFiles(provider: AiProvider, manifest: unknown, log: (message: string) => void): Promise<string[]> {
  log("ai-audit: asking AI to choose initial files from manifest");
  const output = await provider.complete({
    system: buildAuditSystemPrompt(),
    messages: [{ role: "user", content: buildInitialPrompt(manifest, { maxFiles: 10, maxRounds: 1, maxChars: 30000 }) }],
    temperature: 0,
    maxTokens: 1800
  });
  const parsed = normalizeAuditResponse(safeJsonParse(output.text));
  const checked = auditResponseSchema.safeParse(parsed);
  if (!checked.success) {
    log("ai-audit: initial file selection invalid, using heuristic entries");
    return [];
  }
  log(`ai-audit: initial AI requested ${checked.data.requestedFiles.length} files`);
  return checked.data.requestedFiles;
}

async function requestAuditRound(provider: AiProvider, messages: AiMessage[], log: (message: string) => void, round: number): Promise<z.infer<typeof auditResponseSchema>> {
  const output = await provider.complete({
    system: buildAuditSystemPrompt(),
    messages,
    temperature: 0,
    maxTokens: 3500
  });
  const parsed = normalizeAuditResponse(safeJsonParse(output.text));
  const checked = auditResponseSchema.safeParse(parsed);
  if (!checked.success) {
    log(`ai-audit: round ${round} invalid JSON/schema, continuing with no findings`);
    return { summary: "Invalid AI audit response", requestedFiles: [], complete: false, findings: [] };
  }
  return checked.data;
}

function buildAuditSystemPrompt(): string {
  return [
    "Role: senior application security auditor.",
    "Goal: find source-code vulnerabilities missed by deterministic SAST scanners.",
    "You first receive a repository manifest, then selected source files.",
    "Request more files by exact path when needed. Do not ask for generated, lockfile, binary, or dependency code.",
    "Only report vulnerabilities supported by supplied source code. Do not invent files or line numbers.",
    "Focus on auth/authz, tenant isolation, injection, XSS, SSRF, path traversal, file upload, crypto misuse, webhooks, CORS/CSRF/session bugs, secrets, unsafe redirects, unsafe dynamic execution.",
    "Return one JSON object only: {summary, requestedFiles, complete, findings}. findings must include title, category, severity, confidence, status, path, startLine, endLine, source, sink, evidence, reasoning, remediation."
  ].join("\n");
}

function buildInitialPrompt(manifest: unknown, options: AiExploratoryAuditOptions): string {
  return `Repository manifest follows. Select entry points or security-critical files to inspect first.

Caps:
- max files you may inspect this audit: ${options.maxFiles}
- max request rounds: ${options.maxRounds}
- max source chars: ${options.maxChars}

Return JSON only with requestedFiles. Do not include findings until source file contents are supplied.

Manifest:
${JSON.stringify(manifest, null, 2)}`;
}

function buildAuditRoundPrompt(pack: unknown, inspected: string[]): string {
  return `Audit these source files for vulnerabilities not necessarily reported by scanners.

Already inspected:
${inspected.map((file) => `- ${file}`).join("\n")}

Source pack:
${JSON.stringify(pack, null, 2)}

Return JSON only:
{
  "summary": "short summary",
  "requestedFiles": ["exact/path.ts"],
  "complete": false,
  "findings": [
    {
      "title": "finding title",
      "category": "auth | ssrf | xss | injection | secrets | weak-crypto | ...",
      "severity": "critical | high | medium | low | info",
      "confidence": "confirmed | high | medium | low",
      "status": "confirmed | suspected | needs_dynamic_test | false_positive",
      "path": "exact/path.ts",
      "startLine": 1,
      "endLine": 1,
      "source": "source of tainted input",
      "sink": "dangerous operation",
      "evidence": [{"path":"exact/path.ts","line":1,"note":"evidence"}],
      "reasoning": "why exploitable from supplied code",
      "remediation": "specific fix"
    }
  ]
}`;
}

function buildManifest(files: IndexedFile[], scannerResults: ScannerResult[]): ManifestEntry[] {
  const scannerPaths = new Set(scannerResults.map((result) => result.path).filter(Boolean));
  return files.map((file) => {
    const routes = detectRoutes(file.path, file.content).slice(0, 12);
    const symbols = extractSymbols(file.content).slice(0, 25);
    return {
      path: file.path,
      language: file.language,
      lines: file.lineCount,
      imports: extractImports(file.content).slice(0, 30),
      routes: routes.map((route) => ({ method: route.method, path: route.routePath, line: route.startLine, framework: route.frameworkGuess })),
      symbols: symbols.map((symbol) => ({ name: symbol.name, kind: symbol.kind, line: symbol.startLine })),
      hasScannerResult: scannerPaths.has(file.path),
      priorityHints: priorityHints(file)
    };
  }).sort((a, b) => scoreManifestFile(b) - scoreManifestFile(a));
}

function buildFilePack(files: IndexedFile[], charBudget: number) {
  const output: Array<{ path: string; language: string; lines: number; content: string }> = [];
  let charCount = 0;
  for (const file of files) {
    const content = safeFileContent(file);
    const remaining = charBudget - charCount;
    if (remaining <= 0) break;
    const clipped = content.length > remaining ? `${content.slice(0, remaining)}\n[TRUNCATED BY AUDIT BUDGET]` : content;
    output.push({ path: file.path, language: file.language, lines: file.lineCount, content: clipped });
    charCount += clipped.length;
  }
  return { files: output, charCount };
}

function safeFileContent(file: IndexedFile): string {
  if (/(^|\/)\.env($|\.|\/)/.test(file.path)) return "[REDACTED ENV FILE CONTENT]";
  if (/(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|Gemfile\.lock|poetry\.lock|go\.sum|Cargo\.lock)$/i.test(file.path)) return "[DEPENDENCY LOCKFILE CONTENT OMITTED]";
  return redactSecrets(withLineNumbers(file.content));
}

function withLineNumbers(content: string): string {
  return content.split(/\r?\n/).map((line, index) => `${index + 1}: ${line}`).join("\n");
}

function normalizeRequestedPaths(paths: string[], allowed: Map<string, IndexedFile>, inspected: Set<string>): string[] {
  const normalized = paths.map((filePath) => filePath.replaceAll("\\", "/").replace(/^\/+/, ""));
  return [...new Set(normalized)].filter((filePath) => allowed.has(filePath) && !inspected.has(filePath));
}

function heuristicEntryFiles(files: IndexedFile[], scannerResults: ScannerResult[]): string[] {
  return nextUnseenHeuristicFiles(files, scannerResults, new Set());
}

function nextUnseenHeuristicFiles(files: IndexedFile[], scannerResults: ScannerResult[], inspected: Set<string>): string[] {
  const scannerPaths = new Set(scannerResults.map((result) => result.path).filter(Boolean) as string[]);
  return files
    .filter((file) => !inspected.has(file.path))
    .sort((a, b) => scoreFile(b, scannerPaths) - scoreFile(a, scannerPaths))
    .slice(0, 8)
    .map((file) => file.path);
}

function scoreManifestFile(file: ManifestEntry): number {
  return file.priorityHints.length * 10 + file.routes.length * 5 + (file.hasScannerResult ? 8 : 0);
}

function scoreFile(file: IndexedFile, scannerPaths: Set<string>): number {
  return priorityHints(file).length * 10 + detectRoutes(file.path, file.content).length * 5 + (scannerPaths.has(file.path) ? 8 : 0) - Math.min(file.lineCount / 500, 5);
}

function priorityHints(file: IndexedFile): string[] {
  const hints: string[] = [];
  if (/(route|routes|controller|api|server|auth|session|login|webhook|admin|security|crypto|upload|email|billing|tenant|shopify)/i.test(file.path)) hints.push("security-critical-path");
  if (detectRoutes(file.path, file.content).length) hints.push("route-entrypoint");
  if (/(getSession|requireAuth|admin|jwt|csrf|cors|crypto|encrypt|decrypt|webhook|fetch|axios|redirect|sendFile|readFile|createTransport)/i.test(file.content)) hints.push("security-sensitive-symbols");
  return hints;
}

function isAuditableFile(file: IndexedFile): boolean {
  if (file.lineCount === 0) return false;
  if (file.language === "binary" || file.language === "unknown") return false;
  if (/(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|dist\/|build\/|coverage\/)/i.test(file.path)) return false;
  return file.content.length <= 250_000;
}

function normalizeAuditResponse(parsed: unknown): unknown {
  if (parsed && typeof parsed === "object") {
    const object = parsed as Record<string, unknown>;
    if (object.audit && typeof object.audit === "object") return object.audit;
    if (object.result && typeof object.result === "object") return object.result;
  }
  return parsed;
}

function toFinding(input: z.infer<typeof auditFindingSchema>): Finding {
  return {
    title: input.title,
    category: input.category,
    severity: input.severity,
    confidence: input.confidence,
    status: input.status,
    path: input.path,
    startLine: input.startLine,
    endLine: input.endLine ?? input.startLine,
    source: input.source,
    sink: input.sink,
    evidence: input.evidence,
    reasoning: input.reasoning,
    remediation: input.remediation,
    scannerSource: "ai-exploratory-audit",
    raw: input
  };
}

function dedupeFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter((finding) => {
    const key = `${finding.path}:${finding.startLine}:${finding.title}`.toLowerCase();
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
