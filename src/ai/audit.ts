import path from "node:path";
import { z } from "zod";
import type { IndexedFile } from "../repo/repoIndexer.js";
import type { Finding, ScannerResult } from "../scanners/types.js";
import { redactSecrets } from "../utils/redact.js";
import { safeJsonParse } from "../utils/safeJson.js";
import { extractImports } from "../repo/importGraph.js";
import { detectRoutes } from "../repo/routeDetector.js";
import { extractSymbols } from "../repo/symbolExtractor.js";
import { lineSlice } from "../utils/lineMap.js";
import type { AiMessage, AiProvider } from "./types.js";

const auditFindingSchema = z.object({
  title: z.string(),
  category: z.string(),
  severity: z.enum(["critical", "high", "medium", "low", "info"]),
  confidence: z.enum(["confirmed", "high", "medium", "low"]),
  status: z.enum(["confirmed", "confirmed_true_positive", "likely_true_positive", "security_hotspot", "needs_context", "suspected", "needs_dynamic_test", "false_positive"]).default("suspected"),
  path: z.string(),
  startLine: z.number().int().positive().optional(),
  endLine: z.number().int().positive().optional(),
  source: z.string().default("AI exploratory audit"),
  sourceLine: z.number().int().positive().nullable().default(null),
  sink: z.string().default("source code"),
  sinkLine: z.number().int().positive().nullable().default(null),
  dataFlow: z.array(z.object({ path: z.string(), line: z.number().int().positive(), step: z.string() })).default([]),
  missingControl: z.string().default(""),
  exploitPreconditions: z.array(z.string()).default([]),
  safeRepro: z.array(z.string()).default([]),
  evidence: z.array(z.object({ path: z.string(), line: z.number().int().positive(), note: z.string() })).default([]),
  reasoning: z.string(),
  remediation: z.string()
});

const auditToolCallSchema = z.object({
  type: z.enum(["read_file", "search_text", "search_symbol", "find_category"]),
  path: z.string().optional(),
  query: z.string().optional(),
  symbol: z.string().optional(),
  category: z.string().optional(),
  reason: z.string().optional()
});

const auditResponseSchema = z.object({
  summary: z.string().default(""),
  requestedFiles: z.array(z.string()).default([]),
  toolCalls: z.array(auditToolCallSchema).default([]),
  complete: z.boolean().default(false),
  findings: z.array(auditFindingSchema).default([])
});

export interface AiExploratoryAuditOptions {
  maxFiles: number;
  maxRounds: number;
  maxChars: number;
  aiInstructions?: string;
}

interface ManifestEntry {
  path: string;
  language: string;
  lines: number;
  imports: string[];
  localImports: string[];
  routes: Array<{ method: string; path: string; line: number; framework: string }>;
  symbols: Array<{ name: string; kind: string; line: number }>;
  hasScannerResult: boolean;
  priorityHints: string[];
  frameworkHints: string[];
  securityInventory: SecurityInventory;
}

interface AuditTarget {
  path: string;
  startLine: number;
  endLine: number;
  chunkIndex: number;
  chunkCount: number;
}

interface AuditMemory {
  inspectedFiles: Set<string>;
  inspectedRanges: Map<string, Array<{ startLine: number; endLine: number }>>;
  notes: Array<{ path: string; note: string }>;
}

interface SecurityInventory {
  entrypoints: Array<{ kind: string; line: number; detail: string }>;
  trustBoundaries: Array<{ line: number; detail: string }>;
  sinks: Array<{ category: string; line: number; detail: string }>;
  guards: Array<{ line: number; detail: string }>;
}

export async function runExploratoryAudit(
  provider: AiProvider,
  files: IndexedFile[],
  scannerResults: ScannerResult[],
  options: AiExploratoryAuditOptions,
  log: (message: string) => void = () => undefined
): Promise<Finding[]> {
  const candidates = files.filter(isAuditableFile);
  const manifest = buildManifest(candidates, scannerResults, files);
  const allowed = new Map(candidates.map((file) => [file.path, file]));
  const importGraph = buildImportGraph(candidates, files);
  const chunks = buildAuditChunks(candidates);
  const traversal = createAuditTraversal(candidates, scannerResults, importGraph, chunks);
  const memory: AuditMemory = { inspectedFiles: new Set(), inspectedRanges: new Map(), notes: [] };
  const findings: Finding[] = [];
  let remainingChars = options.maxChars;
  let requested = traversal.next(memory, 6, options.maxFiles);
  const messages: AiMessage[] = [{ role: "user", content: buildInitialPrompt(manifest, options) }];
  log(`ai-audit: breadth-first initial targets=${requested.length}`);

  for (let round = 1; round <= options.maxRounds; round++) {
    const targets = normalizeRequestedTargets(requested, allowed, memory, options.maxFiles);
    if (!targets.length) {
      log(`ai-audit: round ${round}/${options.maxRounds} no new files requested`);
      break;
    }
    const pack = buildFilePack(targets, allowed, remainingChars, importGraph, memory);
    if (!pack.files.length) {
      log(`ai-audit: round ${round}/${options.maxRounds} source char budget exhausted`);
      break;
    }
    for (const file of pack.files) {
      rememberRange(memory, file.path, file.startLine, file.endLine);
      memory.inspectedFiles.add(file.path);
      memory.notes.push({ path: file.path, note: summarizeInventory(file.securityInventory) });
    }
    traversal.enqueueImports(pack.files.map((file) => file.path));
    remainingChars -= pack.charCount;
    log(`ai-audit: round ${round}/${options.maxRounds} sending chunks=${pack.files.length} inspectedFiles=${memory.inspectedFiles.size}/${options.maxFiles} chars=${pack.charCount} remaining=${remainingChars}`);
    messages.push({ role: "user", content: buildAuditRoundPrompt(pack, memory) });
    const parsed = await requestAuditRound(provider, messages, log, round);
    messages.push({ role: "assistant", content: JSON.stringify(parsed) });
    const validFindings = parsed.findings.filter((finding) => isSupportedAuditFinding(finding, allowed, memory));
    const dropped = parsed.findings.length - validFindings.length;
    if (dropped) log(`ai-audit: round ${round}/${options.maxRounds} dropped unsupported findings=${dropped}`);
    findings.push(...validFindings.map((finding) => toFinding(finding)));
    traversal.enqueueRequested(parsed.requestedFiles);
    const toolTargets = resolveToolCalls(parsed.toolCalls, allowed, memory);
    if (toolTargets.length) log(`ai-audit: round ${round}/${options.maxRounds} tool targets=${toolTargets.length}`);
    traversal.enqueueTargets(toolTargets);
    requested = traversal.next(memory, 6, options.maxFiles);
    log(`ai-audit: round ${round}/${options.maxRounds} findings=${parsed.findings.length} requested=${requested.length} toolCalls=${parsed.toolCalls.length} complete=${parsed.complete}`);
    if (memory.inspectedFiles.size >= options.maxFiles || remainingChars <= 0) break;
  }

  log(`ai-audit: complete inspected=${memory.inspectedFiles.size} findings=${findings.length}`);
  return dedupeFindings(findings);
}

async function requestAuditRound(provider: AiProvider, messages: AiMessage[], log: (message: string) => void, round: number): Promise<z.infer<typeof auditResponseSchema>> {
  const output = await provider.complete({
    system: buildAuditSystemPrompt(),
    messages,
    temperature: 0,
    maxTokens: 3500
  });
  const parsed = normalizeAuditResponse(safeJsonParse(output.text));
  let checked = auditResponseSchema.safeParse(parsed);
  if (!checked.success) {
    log(`ai-audit: round ${round} invalid JSON/schema, repairing`);
    const repair = await provider.complete({
      system: "Repair invalid JSON to match this schema exactly: {summary:string, requestedFiles:string[], complete:boolean, findings:array}. Output JSON only.",
      messages: [{ role: "user", content: output.text }],
      temperature: 0,
      maxTokens: 2500
    });
    checked = auditResponseSchema.safeParse(normalizeAuditResponse(safeJsonParse(repair.text)));
    if (!checked.success) {
      log(`ai-audit: round ${round} repair failed, continuing with no findings`);
      return { summary: "Invalid AI audit response", requestedFiles: [], toolCalls: [], complete: false, findings: [] };
    }
  }
  return checked.data;
}

function buildAuditSystemPrompt(): string {
  return [
    "Role: senior application security auditor.",
    "Goal: validate concrete source-code vulnerabilities missed by deterministic SAST scanners.",
    "You receive a repository manifest, then breadth-first source chunks: entrypoints first, local imports next, then remaining files.",
    "Honor repository AI instructions as local security context and use them to reject known false positives unless supplied source contradicts them.",
    "For each batch, audit every supplied chunk top to bottom. Use memoryNotes for earlier chunks and localImports for cross-file flows.",
    "Use a two-phase strategy: broad sweep first to identify all sources, sinks, auth boundaries, framework guards, and suspicious cross-file flows; deep confirmation next for only promising signals.",
    "You may request toolCalls instead of guessing: read_file for exact paths, search_text for literal terms/patterns, search_symbol for functions/classes, find_category for source/sink categories such as ssrf, command-injection, path-traversal, xss, auth, secrets, crypto.",
    "Tool calls are fulfilled by the scanner in later rounds. Never pretend tool results exist until supplied in source packs.",
    "First produce internal hypotheses. Then try to disprove each one by checking guards, framework invariants, sanitizers, reachability, and test/dev-only context. Return only findings that survive this critic pass.",
    "Use this pass order: identify entrypoints, identify trust boundaries, identify dangerous sinks, trace source-to-sink, then check sanitizers/guards.",
    "Request more files by exact path when needed. Do not ask for generated, lockfile, binary, or dependency code.",
    "Only report vulnerabilities supported by supplied source code. Do not invent files or line numbers.",
    "Do not report runtime environment references such as process.env.API_KEY, import.meta.env.KEY, os.environ['KEY'], getenv('KEY'), or ENV['KEY'] as hardcoded secrets.",
    "If source, sink, missing control, and exploit preconditions are not all visible in supplied code, request more files or report nothing.",
    "Prefer no finding over a weak finding.",
    "Use category rubrics: auth requires missing authorization on reachable sensitive action; SSRF requires user-controlled URL reaching outbound request without allowlist; path traversal requires user path reaching filesystem without normalization/base check; command injection requires user input reaching shell command; XSS requires untrusted HTML/script reaching render sink without escaping; template/RCE chains require a plausible pollution/input vector plus vulnerable render/eval behavior; secrets require literal committed secret value, not runtime env reference; crypto requires weak primitive or unsafe key/IV usage; CSRF/CORS requires browser-reachable state change or credential exposure.",
    "Focus on auth/authz, tenant isolation, injection, XSS, SSRF, path traversal, file upload, crypto misuse, webhooks, CORS/CSRF/session bugs, secrets, unsafe redirects, unsafe dynamic execution.",
    "Return one JSON object only: {summary, requestedFiles, toolCalls, complete, findings}. findings must include title, category, severity, confidence, status, path, startLine, endLine, source, sourceLine, sink, sinkLine, dataFlow, missingControl, exploitPreconditions, safeRepro, evidence, reasoning, remediation."
  ].join("\n");
}

function buildInitialPrompt(manifest: unknown, options: AiExploratoryAuditOptions): string {
  return `Repository manifest follows. The scanner will choose deterministic breadth-first entry points first, then local imports, then remaining files. Use this manifest only to understand repository shape and request exact follow-up files when needed.

Caps:
- max files you may inspect this audit: ${options.maxFiles}
- max request rounds: ${options.maxRounds}
- max source chars: ${options.maxChars}

Do not return findings until source file contents are supplied.

Repository AI instructions:
${options.aiInstructions || "None supplied."}

Manifest:
${JSON.stringify(manifest, null, 2)}`;
}

function buildAuditRoundPrompt(pack: unknown, memory: AuditMemory): string {
  return `Audit these source files for vulnerabilities not necessarily reported by scanners.

Already inspected files:
${[...memory.inspectedFiles].map((file) => `- ${file}`).join("\n")}

Memory notes:
${memory.notes.slice(-40).map((item) => `- ${item.path}: ${item.note}`).join("\n") || "- none"}

Source pack:
${JSON.stringify(pack, null, 2)}

Return JSON only:
{
  "summary": "short summary",
  "requestedFiles": ["exact/path.ts"],
  "toolCalls": [
    {"type":"read_file","path":"exact/path.ts","reason":"need callee"},
    {"type":"search_text","query":"dangerousFunction","reason":"find callers"},
    {"type":"search_symbol","symbol":"handlerName","reason":"find definition"},
    {"type":"find_category","category":"ssrf","reason":"find outbound sinks"}
  ],
  "complete": false,
  "findings": [
    {
      "title": "finding title",
      "category": "auth | ssrf | xss | injection | secrets | weak-crypto | ...",
      "severity": "critical | high | medium | low | info",
      "confidence": "confirmed | high | medium | low",
      "status": "confirmed | confirmed_true_positive | likely_true_positive | security_hotspot | needs_context | suspected | needs_dynamic_test | false_positive",
      "path": "exact/path.ts",
      "startLine": 1,
      "endLine": 1,
      "source": "source of tainted input",
      "sourceLine": 1,
      "sink": "dangerous operation",
      "sinkLine": 1,
      "dataFlow": [{"path":"exact/path.ts","line":1,"step":"source -> variable -> sink"}],
      "missingControl": "missing sanitizer/auth/allowlist/validation",
      "exploitPreconditions": ["condition required for exploit"],
      "safeRepro": ["safe verification step"],
      "evidence": [{"path":"exact/path.ts","line":1,"note":"evidence"}],
      "reasoning": "why exploitable from supplied code",
      "remediation": "specific fix"
    }
  ]
}`;
}

function buildManifest(files: IndexedFile[], scannerResults: ScannerResult[], allFiles = files): ManifestEntry[] {
  const scannerPaths = new Set(scannerResults.map((result) => result.path).filter(Boolean));
  const importGraph = buildImportGraph(files, allFiles);
  return files.map((file) => {
    const routes = detectRoutes(file.path, file.content).slice(0, 12);
    const symbols = extractSymbols(file.content).slice(0, 25);
    return {
      path: file.path,
      language: file.language,
      lines: file.lineCount,
      imports: extractImports(file.content).slice(0, 30),
      localImports: (importGraph.get(file.path) ?? []).slice(0, 30),
      routes: routes.map((route) => ({ method: route.method, path: route.routePath, line: route.startLine, framework: route.frameworkGuess })),
      symbols: symbols.map((symbol) => ({ name: symbol.name, kind: symbol.kind, line: symbol.startLine })),
      hasScannerResult: scannerPaths.has(file.path),
      priorityHints: priorityHints(file),
      frameworkHints: frameworkHints(file),
      securityInventory: buildSecurityInventory(file)
    };
  }).sort((a, b) => scoreManifestFile(b) - scoreManifestFile(a));
}

function buildFilePack(targets: AuditTarget[], allowed: Map<string, IndexedFile>, charBudget: number, importGraph: Map<string, string[]>, memory: AuditMemory) {
  const output: Array<{ path: string; language: string; lines: number; startLine: number; endLine: number; chunkIndex: number; chunkCount: number; localImports: string[]; frameworkHints: string[]; securityInventory: SecurityInventory; previousNotes: string[]; content: string }> = [];
  let charCount = 0;
  for (const target of targets) {
    const file = allowed.get(target.path);
    if (!file) continue;
    const content = safeFileContent(file, target.startLine, target.endLine);
    const remaining = charBudget - charCount;
    if (remaining <= 0) break;
    const clipped = content.length > remaining ? `${content.slice(0, remaining)}\n[TRUNCATED BY AUDIT BUDGET]` : content;
    output.push({
      path: file.path,
      language: file.language,
      lines: file.lineCount,
      startLine: target.startLine,
      endLine: target.endLine,
      chunkIndex: target.chunkIndex,
      chunkCount: target.chunkCount,
      localImports: importGraph.get(file.path) ?? [],
      frameworkHints: frameworkHints(file),
      securityInventory: offsetInventory(buildSecurityInventory({ ...file, content: lineSlice(file.content, target.startLine, target.endLine), lineCount: target.endLine - target.startLine + 1 }), target.startLine - 1),
      previousNotes: memory.notes.filter((item) => item.path === file.path).map((item) => item.note).slice(-5),
      content: clipped
    });
    charCount += clipped.length;
  }
  return { files: output, charCount };
}

function safeFileContent(file: IndexedFile, startLine = 1, endLine = file.lineCount): string {
  if (/(^|\/)\.env($|\.|\/)/.test(file.path)) return "[REDACTED ENV FILE CONTENT]";
  if (/(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|Gemfile\.lock|poetry\.lock|go\.sum|Cargo\.lock)$/i.test(file.path)) return "[DEPENDENCY LOCKFILE CONTENT OMITTED]";
  return redactSecrets(withLineNumbers(lineSlice(file.content, startLine, endLine), startLine));
}

function withLineNumbers(content: string, startLine = 1): string {
  return content.split(/\r?\n/).map((line, index) => `${startLine + index}: ${line}`).join("\n");
}

function normalizeRequestedTargets(targets: AuditTarget[], allowed: Map<string, IndexedFile>, memory: AuditMemory, maxFiles: number): AuditTarget[] {
  const next: AuditTarget[] = [];
  const nextFiles = new Set<string>();
  for (const target of targets) {
    if (!allowed.has(target.path) || hasInspectedRange(memory, target.path, target.startLine, target.endLine)) continue;
    if (!memory.inspectedFiles.has(target.path) && !nextFiles.has(target.path) && memory.inspectedFiles.size + nextFiles.size >= maxFiles) continue;
    next.push(target);
    nextFiles.add(target.path);
  }
  return next;
}

function heuristicEntryFiles(files: IndexedFile[], scannerResults: ScannerResult[]): string[] {
  const scannerPaths = new Set(scannerResults.map((result) => result.path).filter(Boolean) as string[]);
  return files
    .slice()
    .sort((a, b) => scoreFile(b, scannerPaths) - scoreFile(a, scannerPaths))
    .map((file) => file.path);
}

function buildAuditChunks(files: IndexedFile[], windowLines = 180): Map<string, AuditTarget[]> {
  const chunks = new Map<string, AuditTarget[]>();
  for (const file of files) {
    const targets: AuditTarget[] = [];
    for (let startLine = 1; startLine <= file.lineCount; startLine += windowLines) {
      const endLine = Math.min(file.lineCount, startLine + windowLines - 1);
      targets.push({ path: file.path, startLine, endLine, chunkIndex: targets.length + 1, chunkCount: 0 });
      if (endLine === file.lineCount) break;
    }
    chunks.set(file.path, targets.map((target) => ({ ...target, chunkCount: targets.length })));
  }
  return chunks;
}

function createAuditTraversal(files: IndexedFile[], scannerResults: ScannerResult[], importGraph: Map<string, string[]>, chunks: Map<string, AuditTarget[]>) {
  const fallback = heuristicEntryFiles(files, scannerResults);
  const byPath = new Map(files.map((file) => [file.path, file]));
  const allowed = new Set(files.map((file) => file.path));
  const queued = new Set<string>();
  const queue: AuditTarget[] = [];
  const keyOf = (target: AuditTarget) => `${target.path}:${target.startLine}:${target.endLine}`;
  const pushTargets = (targets: AuditTarget[]) => {
    for (const target of targets) {
      if (!allowed.has(target.path)) continue;
      const key = keyOf(target);
      if (queued.has(key)) continue;
      queued.add(key);
      queue.push(target);
    }
  };
  const pushFirstChunks = (paths: string[]) => {
    for (const filePath of paths) {
      if (!allowed.has(filePath)) continue;
      const first = chunks.get(filePath)?.[0];
      if (first) pushTargets([first]);
    }
  };
  pushFirstChunks(fallback.filter((filePath) => isEntryPointFile(byPath.get(filePath)!)));
  if (!queue.length) pushFirstChunks(fallback.slice(0, 6));

  return {
    enqueueImports(paths: string[]) {
      pushFirstChunks(paths.flatMap((filePath) => importGraph.get(filePath) ?? []));
    },
    enqueueRequested(paths: string[]) {
      pushFirstChunks(paths.map((filePath) => filePath.replaceAll("\\", "/").replace(/^\/+/, "")));
    },
    enqueueTargets(targets: AuditTarget[]) {
      pushTargets(targets);
    },
    next(memory: AuditMemory, limit: number, maxFiles: number): AuditTarget[] {
      while (queue.length && hasInspectedRange(memory, queue[0].path, queue[0].startLine, queue[0].endLine)) queue.shift();
      if (!queue.length) pushFirstChunks(fallback.filter((filePath) => !memory.inspectedFiles.has(filePath)));
      const nextTargets: AuditTarget[] = [];
      const newFiles = new Set<string>();
      while (queue.length && nextTargets.length < limit) {
        const target = queue.shift()!;
        if (hasInspectedRange(memory, target.path, target.startLine, target.endLine)) continue;
        if (!memory.inspectedFiles.has(target.path) && !newFiles.has(target.path) && memory.inspectedFiles.size + newFiles.size >= maxFiles) continue;
        nextTargets.push(target);
        newFiles.add(target.path);
        const fileChunks = chunks.get(target.path) ?? [];
        const nextChunk = fileChunks[target.chunkIndex];
        if (nextChunk) pushTargets([nextChunk]);
      }
      return nextTargets;
    }
  };
}

function isEntryPointFile(file: IndexedFile): boolean {
  if (detectRoutes(file.path, file.content).length) return true;
  return /(server|entry|main|index|route|routes|controller|api|webhook|bin\/|cli|command|worker|job)/i.test(file.path);
}

function buildImportGraph(files: IndexedFile[], allFiles = files): Map<string, string[]> {
  const byPath = new Map(files.map((file) => [file.path, file]));
  const aliases = buildPathAliases(allFiles);
  const graph = new Map<string, string[]>();
  for (const file of files) {
    const localImports = extractImports(file.content)
      .flatMap((specifier) => resolveLocalImport(file.path, specifier, byPath, aliases))
      .filter((filePath) => filePath !== file.path);
    graph.set(file.path, [...new Set(localImports)]);
  }
  return graph;
}

function buildPathAliases(files: IndexedFile[]): Array<{ prefix: string; targets: string[] }> {
  const configs = files.filter((file) => /(^|\/)(tsconfig|jsconfig)\.json$/.test(file.path));
  const aliases: Array<{ prefix: string; targets: string[] }> = [];
  for (const file of configs) {
    const parsed = safeJsonParse(stripJsonComments(file.content));
    if (!parsed || typeof parsed !== "object") continue;
    const paths = (parsed as any).compilerOptions?.paths;
    if (!paths || typeof paths !== "object") continue;
    for (const [key, values] of Object.entries(paths)) {
      if (!Array.isArray(values)) continue;
      aliases.push({
        prefix: key.replace(/\*.*$/, ""),
        targets: values.map((value) => String(value).replace(/\*.*$/, "").replace(/^\.?\//, ""))
      });
    }
  }
  if (!aliases.some((alias) => alias.prefix === "@/")) aliases.push({ prefix: "@/", targets: ["src/"] });
  return aliases;
}

function stripJsonComments(input: string): string {
  return input.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
}

function resolveLocalImport(fromPath: string, specifier: string, byPath: Map<string, IndexedFile>, aliases: Array<{ prefix: string; targets: string[] }>): string[] {
  const normalized = specifier.replaceAll("\\", "/").trim();
  const candidates = new Set<string>();
  const fromDir = path.posix.dirname(fromPath.replaceAll("\\", "/"));
  if (normalized.startsWith(".")) {
    addPathCandidates(candidates, path.posix.normalize(path.posix.join(fromDir, normalized)));
  } else if (normalized.startsWith("/")) {
    addPathCandidates(candidates, normalized.replace(/^\/+/, ""));
  } else {
    for (const alias of aliases) {
      if (!normalized.startsWith(alias.prefix)) continue;
      const remainder = normalized.slice(alias.prefix.length);
      for (const target of alias.targets) addPathCandidates(candidates, path.posix.join(target, remainder));
    }
    const modulePath = normalized.replace(/\./g, "/");
    addPathCandidates(candidates, modulePath);
    addPathCandidates(candidates, path.posix.join(fromDir, modulePath));
  }
  return [...candidates].filter((candidate) => byPath.has(candidate));
}

function addPathCandidates(candidates: Set<string>, basePath: string): void {
  const clean = basePath.replace(/^\/+/, "");
  candidates.add(clean);
  for (const ext of [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".rb", ".php", ".go", ".java", ".cs"]) {
    candidates.add(`${clean}${ext}`);
    candidates.add(path.posix.join(clean, `index${ext}`));
    candidates.add(path.posix.join(clean, `__init__${ext}`));
  }
}

function resolveToolCalls(calls: Array<z.infer<typeof auditToolCallSchema>>, allowed: Map<string, IndexedFile>, memory: AuditMemory): AuditTarget[] {
  const targets: AuditTarget[] = [];
  for (const call of calls.slice(0, 20)) {
    if (call.type === "read_file" && call.path) {
      const file = allowed.get(normalizePath(call.path));
      if (file) targets.push(targetWindow(file.path, 1, file.lineCount, 1, 1));
      continue;
    }
    if (call.type === "search_text" && call.query) {
      targets.push(...searchFiles(allowed, call.query, memory, "text"));
      continue;
    }
    if (call.type === "search_symbol" && call.symbol) {
      targets.push(...searchFiles(allowed, call.symbol, memory, "symbol"));
      continue;
    }
    if (call.type === "find_category" && call.category) {
      targets.push(...findCategoryTargets(allowed, call.category, memory));
    }
  }
  return dedupeTargets(targets).slice(0, 30);
}

function normalizePath(filePath: string): string {
  return filePath.replaceAll("\\", "/").replace(/^\/+/, "");
}

function searchFiles(allowed: Map<string, IndexedFile>, query: string, memory: AuditMemory, mode: "text" | "symbol"): AuditTarget[] {
  const needle = query.trim();
  if (!needle || needle.length < 2) return [];
  const targets: AuditTarget[] = [];
  const symbolRegex = mode === "symbol" ? new RegExp(`\\b${escapeRegExp(needle)}\\b`) : undefined;
  for (const file of allowed.values()) {
    const lines = file.content.split(/\r?\n/);
    for (const [index, line] of lines.entries()) {
      const matched = symbolRegex ? symbolRegex.test(line) : line.toLowerCase().includes(needle.toLowerCase());
      if (!matched) continue;
      const lineNo = index + 1;
      if (hasInspectedLine(memory, file.path, lineNo)) continue;
      targets.push(targetWindow(file.path, Math.max(1, lineNo - 60), Math.min(file.lineCount, lineNo + 90), 1, 1));
      if (targets.length >= 20) return targets;
    }
  }
  return targets;
}

function findCategoryTargets(allowed: Map<string, IndexedFile>, category: string, memory: AuditMemory): AuditTarget[] {
  const normalized = category.toLowerCase();
  const targets: AuditTarget[] = [];
  for (const file of allowed.values()) {
    const inventory = buildSecurityInventory(file);
    const lines = [
      ...inventory.sinks.filter((sink) => sink.category.includes(normalized) || normalized.includes(sink.category)).map((sink) => sink.line),
      ...(/auth|tenant|csrf|cors/.test(normalized) ? inventory.guards.map((guard) => guard.line) : []),
      ...(/source|entry|route/.test(normalized) ? inventory.entrypoints.map((entry) => entry.line) : []),
      ...(/trust|input|source/.test(normalized) ? inventory.trustBoundaries.map((boundary) => boundary.line) : [])
    ];
    for (const line of lines) {
      if (hasInspectedLine(memory, file.path, line)) continue;
      targets.push(targetWindow(file.path, Math.max(1, line - 60), Math.min(file.lineCount, line + 90), 1, 1));
      if (targets.length >= 30) return targets;
    }
  }
  return targets;
}

function targetWindow(pathName: string, startLine: number, endLine: number, chunkIndex: number, chunkCount: number): AuditTarget {
  return { path: pathName, startLine, endLine, chunkIndex, chunkCount };
}

function dedupeTargets(targets: AuditTarget[]): AuditTarget[] {
  const seen = new Set<string>();
  return targets.filter((target) => {
    const key = `${target.path}:${target.startLine}:${target.endLine}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function rememberRange(memory: AuditMemory, filePath: string, startLine: number, endLine: number): void {
  const ranges = memory.inspectedRanges.get(filePath) ?? [];
  ranges.push({ startLine, endLine });
  memory.inspectedRanges.set(filePath, ranges);
}

function hasInspectedRange(memory: AuditMemory, filePath: string, startLine: number, endLine: number): boolean {
  return (memory.inspectedRanges.get(filePath) ?? []).some((range) => startLine >= range.startLine && endLine <= range.endLine);
}

function hasInspectedLine(memory: AuditMemory, filePath: string, line: number): boolean {
  return (memory.inspectedRanges.get(filePath) ?? []).some((range) => line >= range.startLine && line <= range.endLine);
}

function frameworkHints(file: IndexedFile): string[] {
  const hints = new Set<string>();
  for (const route of detectRoutes(file.path, file.content)) hints.add(route.frameworkGuess);
  const text = `${file.path}\n${file.content}`;
  if (/\bexpress\b|app\.(get|post|put|patch|delete)|router\./i.test(text)) hints.add("express");
  if (/\/app\/api\/|\/pages\/api\/|next\/server|NextRequest/i.test(text)) hints.add("nextjs");
  if (/FastAPI|@app\.(get|post|put|patch|delete)/.test(text)) hints.add("fastapi");
  if (/django|urlpatterns|models\.Model|DEBUG\s*=/i.test(text)) hints.add("django");
  if (/config\/routes\.rb|ApplicationController|before_action|params\[/i.test(text)) hints.add("rails");
  if (/Route::|app\/Http\/Controllers|Illuminate\\/i.test(text)) hints.add("laravel");
  return [...hints].slice(0, 8);
}

function buildSecurityInventory(file: IndexedFile): SecurityInventory {
  const entrypoints = detectRoutes(file.path, file.content).map((route) => ({ kind: `route:${route.frameworkGuess}`, line: route.startLine, detail: `${route.method} ${route.routePath}` })).slice(0, 30);
  const trustBoundaries: SecurityInventory["trustBoundaries"] = [];
  const sinks: SecurityInventory["sinks"] = [];
  const guards: SecurityInventory["guards"] = [];
  const lines = file.content.split(/\r?\n/);
  for (const [index, line] of lines.entries()) {
    const lineNo = index + 1;
    if (/(req\.(query|params|body|headers|cookies)|request\.(args|form|json|files)|params\[|\$_(GET|POST|REQUEST|COOKIE|FILES)|ARGV|process\.argv|sys\.argv)/i.test(line)) trustBoundaries.push({ line: lineNo, detail: line.trim().slice(0, 180) });
    if (/(fetch\(|axios\.|http\.get|https\.get|request\()/i.test(line)) sinks.push({ category: "ssrf", line: lineNo, detail: line.trim().slice(0, 180) });
    if (/(exec|execSync|spawn|spawnSync|system|shell_exec|subprocess\.(run|Popen)|Open3\.)\s*\(/i.test(line)) sinks.push({ category: "command-injection", line: lineNo, detail: line.trim().slice(0, 180) });
    if (/(sendFile|readFile|writeFile|createReadStream|open|file_get_contents|File\.read|Path\()/i.test(line)) sinks.push({ category: "path-traversal", line: lineNo, detail: line.trim().slice(0, 180) });
    if (/(innerHTML|dangerouslySetInnerHTML|v-html|render\s+inline)/i.test(line)) sinks.push({ category: "xss", line: lineNo, detail: line.trim().slice(0, 180) });
    if (/(redirect|location\.href|header\s*\(\s*['"]Location)/i.test(line)) sinks.push({ category: "open-redirect", line: lineNo, detail: line.trim().slice(0, 180) });
    if (/(requireAuth|isAuthenticated|authorize|policy|before_action|middleware|csrf|sanitize|escape|validate|schema|zod|joi|allowlist|whitelist|normalize|realpath)/i.test(line)) guards.push({ line: lineNo, detail: line.trim().slice(0, 180) });
  }
  return { entrypoints, trustBoundaries: trustBoundaries.slice(0, 30), sinks: sinks.slice(0, 40), guards: guards.slice(0, 40) };
}

function summarizeInventory(inventory: SecurityInventory): string {
  return [
    `entrypoints=${inventory.entrypoints.length}`,
    `trustBoundaries=${inventory.trustBoundaries.length}`,
    `sinks=${inventory.sinks.map((sink) => sink.category).slice(0, 8).join(",") || "none"}`,
    `guards=${inventory.guards.length}`
  ].join(" ");
}

function offsetInventory(inventory: SecurityInventory, offset: number): SecurityInventory {
  if (!offset) return inventory;
  return {
    entrypoints: inventory.entrypoints.map((item) => ({ ...item, line: item.line + offset })),
    trustBoundaries: inventory.trustBoundaries.map((item) => ({ ...item, line: item.line + offset })),
    sinks: inventory.sinks.map((item) => ({ ...item, line: item.line + offset })),
    guards: inventory.guards.map((item) => ({ ...item, line: item.line + offset }))
  };
}

function scoreManifestFile(file: ManifestEntry): number {
  return attackSurfaceWeight(file.path) + file.priorityHints.length * 10 + file.routes.length * 6 + (file.hasScannerResult ? 8 : 0);
}

function scoreFile(file: IndexedFile, scannerPaths: Set<string>): number {
  return attackSurfaceWeight(file.path) + priorityHints(file).length * 10 + detectRoutes(file.path, file.content).length * 6 + (scannerPaths.has(file.path) ? 8 : 0) - Math.min(file.lineCount / 500, 5);
}

function attackSurfaceWeight(filePath: string): number {
  if (/(routes?|controllers?|api|server|entry|webhook)/i.test(filePath)) return 60;
  if (/(auth|session|login|permission|policy|tenant|admin)/i.test(filePath)) return 55;
  if (/(upload|download|file|storage)/i.test(filePath)) return 45;
  if (/(bin\/|cli|command|task|rake|worker|job)/i.test(filePath)) return 35;
  if (/(crypto|secret|env|config)/i.test(filePath)) return 25;
  return 0;
}

function priorityHints(file: IndexedFile): string[] {
  const hints: string[] = [];
  if (/(route|routes|controller|command|cli|bin\/|exe\/|rake|task|worker|job|api|server|auth|session|login|webhook|admin|security|crypto|upload|email|billing|tenant|shopify)/i.test(file.path)) hints.push("security-critical-path");
  if (detectRoutes(file.path, file.content).length) hints.push("route-entrypoint");
  if (/(getSession|requireAuth|admin|jwt|csrf|cors|crypto|encrypt|decrypt|webhook|fetch|axios|redirect|sendFile|readFile|createTransport|params|ARGV|process\.argv|sys\.argv|\$_(GET|POST|REQUEST|COOKIE)|unserialize|Marshal\.load|YAML\.load|shell_exec|Open3|system\()/i.test(file.content)) hints.push("security-sensitive-symbols");
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

function isSupportedAuditFinding(input: z.infer<typeof auditFindingSchema>, allowed: Map<string, IndexedFile>, memory: AuditMemory): boolean {
  const target = allowed.get(input.path);
  if (!target || !memory.inspectedFiles.has(input.path)) return false;
  const lines = [input.startLine, input.endLine, input.sourceLine, input.sinkLine, ...input.evidence.map((item) => item.line), ...input.dataFlow.map((item) => item.line)].filter((line): line is number => typeof line === "number");
  if (!lines.length) return false;
  if (lines.some((line) => line < 1 || line > target.lineCount)) return false;
  if (input.evidence.some((item) => !memory.inspectedFiles.has(item.path) || !allowed.has(item.path) || !hasInspectedLine(memory, item.path, item.line))) return false;
  if (input.dataFlow.some((item) => !memory.inspectedFiles.has(item.path) || !allowed.has(item.path) || !hasInspectedLine(memory, item.path, item.line))) return false;
  for (const line of [input.startLine, input.endLine, input.sourceLine, input.sinkLine].filter((item): item is number => typeof item === "number")) {
    if (!hasInspectedLine(memory, input.path, line)) return false;
  }
  const text = JSON.stringify(input).toLowerCase();
  if (input.category.toLowerCase() === "secrets" && /(process\.env|import\.meta\.env|os\.environ|getenv\(|env\[)/i.test(text) && !/(hardcoded|literal|committed|checked in|\.env)/i.test(text)) return false;
  if (/(^|\/)(__tests__|test|tests|spec|fixtures|examples?)\//i.test(input.path) && !/prod|production|runtime|reachable/i.test(text)) return false;
  return lineEvidenceMatches(input, allowed);
}

function lineEvidenceMatches(input: z.infer<typeof auditFindingSchema>, allowed: Map<string, IndexedFile>): boolean {
  const category = input.category.toLowerCase();
  const citedLines = [
    ...input.evidence.map((item) => ({ path: item.path, line: item.line })),
    ...input.dataFlow.map((item) => ({ path: item.path, line: item.line })),
    ...(input.sourceLine ? [{ path: input.path, line: input.sourceLine }] : []),
    ...(input.sinkLine ? [{ path: input.path, line: input.sinkLine }] : [])
  ];
  const snippets = citedLines.map((item) => getLine(allowed.get(item.path)?.content ?? "", item.line)).join("\n").toLowerCase();
  if (!snippets.trim()) return false;
  if (/secret/.test(category)) return /(api[_-]?key|token|password|secret|passwd|pwd)\b/.test(snippets) && /['"][^'"]{8,}['"]|=\s*[A-Za-z0-9_./+=-]{12,}/.test(snippets);
  if (/ssrf/.test(category)) return /(fetch|axios|request|http\.|https\.|url)/.test(snippets);
  if (/path|file/.test(category)) return /(readfile|writefile|sendfile|createreadstream|open|path|file_get_contents|fopen|file\.read)/.test(snippets);
  if (/command|injection/.test(category)) return /(exec|spawn|system|shell|subprocess|open3|eval|query|sql)/.test(snippets);
  if (/xss/.test(category)) return /(innerhtml|dangerouslysetinnerhtml|v-html|render|html|template)/.test(snippets);
  if (/auth|tenant/.test(category)) return /(auth|admin|user|tenant|permission|role|policy|session|jwt|params|req\.|request)/.test(snippets);
  return true;
}

function getLine(content: string, line: number): string {
  return content.split(/\r?\n/)[line - 1] ?? "";
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
    source: `${input.source}${input.sourceLine ? `:${input.sourceLine}` : ""}`,
    sink: `${input.sink}${input.sinkLine ? `:${input.sinkLine}` : ""}`,
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
