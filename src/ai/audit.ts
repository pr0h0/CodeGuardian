import path from "node:path";
import { z } from "zod";
import type { IndexedFile } from "../repo/repoIndexer.js";
import type { Finding, ScannerResult } from "../scanners/types.js";
import { redactSecrets } from "../utils/redact.js";
import { safeJsonParse } from "../utils/safeJson.js";
import { extractImports } from "../repo/importGraph.js";
import { detectRoutes } from "../repo/routeDetector.js";
import { extractSymbols } from "../repo/symbolExtractor.js";
import { classifyFileRole, fileRoleScore, isReusableOrGeneratedRole } from "../repo/fileRole.js";
import { lineSlice } from "../utils/lineMap.js";
import type { AiProvider } from "./types.js";
import { auditCategoriesForClasses, auditResponseJsonSchemaForClasses, auditSourceMapJsonSchema, auditValidationJsonSchema, categoryValues, confidenceValues, severityValues, statusValues, type AiJsonSchema } from "./schemas.js";
import type { AiJobRecorder } from "./jobs.js";
import type { VulnerabilityClass } from "../config/projectConfig.js";
import { normalizeAuditResponseJson } from "./jsonNormalize.js";

const DEFAULT_AUDIT_REQUEST_CHAR_BUDGET = 60_000;
const AUDIT_PROMPT_OVERHEAD_CHARS = 12_000;
const AUDIT_CHUNK_LINES = 180;
const DEFAULT_AUDIT_CLASSES: VulnerabilityClass[] = [
  "auth",
  "authz",
  "ssrf",
  "injection",
  "xss",
  "exposure",
  "validation",
  "dependency",
  "crypto",
  "misconfig",
  "xxe",
  "business-logic"
];

const auditFindingSchema = z.object({
  title: z.string(),
  category: z.enum(categoryValues),
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
  path: z.string().default(""),
  query: z.string().default(""),
  symbol: z.string().default(""),
  category: z.string().default(""),
  startLine: z.number().int().positive().nullable().default(null),
  endLine: z.number().int().positive().nullable().default(null),
  reason: z.string().default("")
});

const auditHypothesisSchema = z.object({
  id: z.string(),
  vulnerabilityClass: z.string(),
  title: z.string(),
  path: z.string(),
  source: z.string(),
  sink: z.string(),
  evidence: z.array(z.object({ path: z.string(), line: z.number().int().positive(), note: z.string() })).default([]),
  status: z.enum(["candidate", "validated", "rejected"]),
  reason: z.string()
});

const rejectedHypothesisSchema = z.object({
  id: z.string(),
  title: z.string(),
  path: z.string(),
  reason: z.string()
});

const auditResponseSchema = z.object({
  summary: z.string().default(""),
  requestedFiles: z.array(z.string()).default([]),
  toolCalls: z.array(auditToolCallSchema).default([]),
  complete: z.boolean().default(false),
  hypotheses: z.array(auditHypothesisSchema).default([]),
  rejectedHypotheses: z.array(rejectedHypothesisSchema).default([]),
  findings: z.array(auditFindingSchema).default([])
});

const auditCatalogItemSchema = z.object({
  name: z.string(),
  path: z.string(),
  line: z.number().int().positive().nullable().default(null),
  category: z.string().default("security"),
  evidence: z.string().default("")
});

const auditSourceMapSchema = z.object({
  summary: z.string().default(""),
  globalPriorityFiles: z.array(z.string()).default([]),
  priorityFilesByClass: z.record(z.array(z.string())).default({}),
  notes: z.array(z.string()).default([]),
  catalog: z.object({
    sources: z.array(auditCatalogItemSchema).default([]),
    sinks: z.array(auditCatalogItemSchema).default([]),
    sanitizers: z.array(auditCatalogItemSchema).default([]),
    guards: z.array(auditCatalogItemSchema).default([])
  }).default({ sources: [], sinks: [], sanitizers: [], guards: [] })
});

const auditValidationResponseSchema = z.object({
  decisions: z.array(z.object({
    findingIndex: z.number().int().min(0),
    verdict: z.enum(["keep", "downgrade", "reject"]),
    revisedStatus: z.enum(statusValues),
    revisedConfidence: z.enum(confidenceValues),
    reasons: z.array(z.string()).default([])
  })).default([])
});

type AuditSourceMap = z.infer<typeof auditSourceMapSchema>;
type ValidationIssue = { path: Array<string | number>; message: string };
type ParseResult<T> = { ok: true; data: T } | { ok: false; issues: ValidationIssue[] };

const AI_JSON_RETRY_ATTEMPTS = 2;

export interface AiExploratoryAuditOptions {
  maxFiles: number;
  maxRounds: number;
  maxChars: number;
  maxRequestChars?: number;
  aiInstructions?: string;
  jobRecorder?: AiJobRecorder;
  vulnerabilityClasses?: VulnerabilityClass[];
  sourceMap?: AuditSourceMap;
  priorityFiles?: string[];
  negativeEvidence?: Array<{ title: string; path?: string | null; startLine?: number | null; reason: string; status: string; fingerprint?: string | null }>;
  artifactRecorder?: AiAuditArtifactRecorder;
  validationPass?: boolean;
  parallelClassAudits?: boolean;
}

export interface AiAuditArtifactRecorder {
  record(event: AiAuditArtifactEvent): void;
}

export type AiAuditArtifactEvent =
  | { kind: "source-map"; sourceMap: AuditSourceMap }
  | { kind: "class-start"; vulnerabilityClass: VulnerabilityClass; priorityFiles: string[] }
  | { kind: "class-complete"; vulnerabilityClass: VulnerabilityClass; findingCount: number }
  | {
    kind: "round";
    vulnerabilityClass?: VulnerabilityClass;
    round: number;
    hypothesisCount: number;
    rejectedHypothesisCount: number;
    findingCount: number;
    hypotheses: Array<z.infer<typeof auditHypothesisSchema>>;
    rejectedHypotheses: Array<z.infer<typeof rejectedHypothesisSchema>>;
  };

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
  const traversal = createAuditTraversal(candidates, scannerResults, importGraph, chunks, options.priorityFiles ?? []);
  const memory: AuditMemory = { inspectedFiles: new Set(), inspectedRanges: new Map(), notes: [] };
  const findings: Finding[] = [];
  const requestCharBudget = auditRequestCharBudget(options);
  const systemPrompt = buildAuditSystemPrompt();
  const responseSchema = auditResponseJsonSchemaForClasses(options.vulnerabilityClasses ?? []);
  const promptCategories = auditCategoriesForClasses(options.vulnerabilityClasses ?? []);
  const initialPrompt = buildInitialPrompt(manifest, options, Math.max(2_000, Math.floor((requestCharBudget - systemPrompt.length) * 0.32)));
  let remainingChars = options.maxChars;
  let requested = traversal.next(memory, 6, options.maxFiles);
  log(`ai-audit: breadth-first initial targets=${requested.length} requestCharBudget=${requestCharBudget}`);

  for (let round = 1; round <= options.maxRounds; round++) {
    const targets = normalizeRequestedTargets(requested, allowed, memory, options.maxFiles);
    if (!targets.length) {
      log(`ai-audit: round ${round}/${options.maxRounds} no new files requested`);
      break;
    }
    const pack = buildBoundedFilePack(targets, allowed, remainingChars, importGraph, memory, systemPrompt.length + initialPrompt.length, requestCharBudget);
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
    const parsed = await requestAuditRound(provider, systemPrompt, initialPrompt, buildAuditRoundPrompt(pack, memory, promptCategories), responseSchema, log, round, options.jobRecorder);
    options.artifactRecorder?.record({
      kind: "round",
      vulnerabilityClass: options.vulnerabilityClasses?.[0],
      round,
      hypothesisCount: parsed.hypotheses.length,
      rejectedHypothesisCount: parsed.rejectedHypotheses.length,
      findingCount: parsed.findings.length,
      hypotheses: parsed.hypotheses,
      rejectedHypotheses: parsed.rejectedHypotheses
    });
    let validFindings = parsed.findings.filter((finding) => isSupportedAuditFinding(finding, allowed, memory));
    if (options.validationPass && validFindings.length) {
      validFindings = await validateAuditFindingsWithAi(provider, validFindings, pack, memory, responseSchema, log, round, options.jobRecorder);
    }
    const dropped = parsed.findings.length - validFindings.length;
    if (dropped) log(`ai-audit: round ${round}/${options.maxRounds} dropped unsupported findings=${dropped}`);
    findings.push(...validFindings.map((finding) => toFinding(finding)));
    traversal.enqueueRequested(parsed.requestedFiles);
    const toolTargets = resolveToolCalls(parsed.toolCalls, allowed, memory);
    if (toolTargets.length) log(`ai-audit: round ${round}/${options.maxRounds} tool targets=${toolTargets.length}`);
    traversal.enqueueTargets(toolTargets);
    requested = traversal.next(memory, 6, options.maxFiles);
    log(`ai-audit: round ${round}/${options.maxRounds} findings=${parsed.findings.length} requested=${requested.length} toolCalls=${parsed.toolCalls.length} complete=${parsed.complete}`);
    if (remainingChars <= 0) break;
  }

  log(`ai-audit: complete inspected=${memory.inspectedFiles.size} findings=${findings.length}`);
  return dedupeFindings(findings);
}

export async function runTargetedExploratoryAudit(
  provider: AiProvider,
  files: IndexedFile[],
  scannerResults: ScannerResult[],
  options: AiExploratoryAuditOptions,
  log: (message: string) => void = () => undefined
): Promise<Finding[]> {
  const classes = options.vulnerabilityClasses?.length ? options.vulnerabilityClasses : DEFAULT_AUDIT_CLASSES;
  const scannerSeedMap = scannerSeedSourceMap(scannerResults, files, classes);
  const aiSourceMap = await runAuditSourceMap(provider, files, scannerResults, { ...options, vulnerabilityClasses: classes, sourceMap: scannerSeedMap }, log);
  const sourceMap = mergeSourceMaps(scannerSeedMap, aiSourceMap);
  options.artifactRecorder?.record({ kind: "source-map", sourceMap });
  const maxRoundsPerClass = Math.max(1, options.maxRounds);
  const maxFilesPerClass = Math.max(1, Math.ceil(options.maxFiles / Math.max(1, classes.length)));
  const maxCharsPerClass = Math.max(12_000, Math.ceil(options.maxChars / Math.max(1, classes.length)));
  const runClassAudit = async (vulnerabilityClass: VulnerabilityClass): Promise<Finding[]> => {
    const priorityFiles = sourceMapPriorityFiles(sourceMap, vulnerabilityClass);
    options.artifactRecorder?.record({ kind: "class-start", vulnerabilityClass, priorityFiles });
    log(`ai-audit: class=${vulnerabilityClass} start maxFiles=${maxFilesPerClass} maxRounds=${maxRoundsPerClass} maxChars=${maxCharsPerClass}`);
    const classFindings = await runExploratoryAudit(provider, files, scannerResults, {
      ...options,
      maxFiles: maxFilesPerClass,
      maxRounds: maxRoundsPerClass,
      maxChars: maxCharsPerClass,
      vulnerabilityClasses: [vulnerabilityClass],
      sourceMap,
      priorityFiles
    }, log);
    options.artifactRecorder?.record({ kind: "class-complete", vulnerabilityClass, findingCount: classFindings.length });
    return classFindings;
  };
  const findings = options.parallelClassAudits
    ? (await Promise.all(classes.map(runClassAudit))).flat()
    : (await sequence(classes, runClassAudit)).flat();
  return dedupeFindings(findings);
}

async function runAuditSourceMap(provider: AiProvider, files: IndexedFile[], scannerResults: ScannerResult[], options: AiExploratoryAuditOptions, log: (message: string) => void): Promise<AuditSourceMap> {
  const candidates = files.filter(isAuditableFile);
  const allowedPaths = new Set(candidates.map((file) => file.path));
  const manifest = buildManifest(candidates, scannerResults, files);
  const systemPrompt = buildSourceMapSystemPrompt();
  const userPrompt = buildSourceMapUserPrompt(manifest, options);
  const jobId = options.jobRecorder?.start("audit", "source-map", { provider: provider.name, classes: options.vulnerabilityClasses ?? [] });
  try {
    log(`ai-audit: source-map start files=${candidates.length}`);
    let lastOutput = "";
    let lastIssues: ValidationIssue[] = [{ path: [], message: "No source-map response was received" }];
    for (let attempt = 1; attempt <= AI_JSON_RETRY_ATTEMPTS; attempt++) {
      const prompt = attempt === 1 ? userPrompt : buildSourceMapRetryPrompt(userPrompt, lastOutput, lastIssues);
      const output = await provider.complete({
        system: systemPrompt,
        messages: [{ role: "user", content: prompt }],
        jsonSchema: auditSourceMapJsonSchema,
        temperature: 0,
        maxTokens: 2600
      });
      options.jobRecorder?.trace(jobId, { label: attempt === 1 ? "source-map" : `source-map-retry-${attempt}`, prompt: `${systemPrompt}\n\n${prompt}`, response: output.text });
      const parsed = parseSourceMapResponse(output.text);
      if (parsed.ok) {
        const sourceMap = sanitizeSourceMap(parsed.data, allowedPaths);
        log(`ai-audit: source-map priorityFiles=${sourceMap.globalPriorityFiles.length} notes=${sourceMap.notes.length}`);
        options.jobRecorder?.succeed(jobId, { valid: true, priorityFiles: sourceMap.globalPriorityFiles.length, notes: sourceMap.notes.length });
        return sourceMap;
      }
      lastOutput = output.text;
      lastIssues = parsed.issues;
      if (attempt < AI_JSON_RETRY_ATTEMPTS) {
        log(`ai-audit: source-map invalid, retrying attempt ${attempt + 1}/${AI_JSON_RETRY_ATTEMPTS}`);
      }
    }
    if (lastOutput.trim()) {
      log("ai-audit: source-map invalid, repairing");
      const repairPrompt = buildSourceMapRepairPrompt(lastOutput, lastIssues);
      const repair = await provider.complete({
        system: "Repair invalid source-map JSON to match the strict JSON schema exactly. Output raw JSON only. No prose, markdown, comments, code fences, or extra keys. Use exact paths present in the invalid JSON only.",
        messages: [{ role: "user", content: repairPrompt }],
        jsonSchema: auditSourceMapJsonSchema,
        temperature: 0,
        maxTokens: 2200
      });
      options.jobRecorder?.trace(jobId, { label: "source-map-repair", prompt: repairPrompt, response: repair.text });
      const repaired = parseSourceMapResponse(repair.text);
      if (repaired.ok) {
        const sourceMap = sanitizeSourceMap(repaired.data, allowedPaths);
        log(`ai-audit: source-map priorityFiles=${sourceMap.globalPriorityFiles.length} notes=${sourceMap.notes.length}`);
        options.jobRecorder?.succeed(jobId, { valid: true, repaired: true, priorityFiles: sourceMap.globalPriorityFiles.length, notes: sourceMap.notes.length });
        return sourceMap;
      }
    }
    log("ai-audit: source-map invalid, continuing without AI source map");
    options.jobRecorder?.succeed(jobId, { valid: false });
    return emptySourceMap();
  } catch (error) {
    log(`ai-audit: source-map failed: ${error instanceof Error ? error.message : String(error)}`);
    options.jobRecorder?.fail(jobId, error);
    return emptySourceMap();
  }
}

function buildSourceMapSystemPrompt(): string {
  return [
    "Role: senior security reconnaissance engineer.",
    "Goal: create a compact source map that will steer later class-specific audit passes.",
    "Choose files that are security-relevant because they contain entrypoints, auth/session logic, authorization checks, trust boundaries, dangerous sinks, data access, uploads, redirects, outbound requests, or template rendering.",
    "Keep output compact: at most 20 global priority files, 8 files per class, and 12 notes.",
    "If uncertain, choose the most obvious entrypoints, controllers, services, middleware, route handlers, and template files. Do not return an empty response.",
    "Return raw JSON only: {summary, globalPriorityFiles, priorityFilesByClass, notes}.",
    "No prose, markdown, comments, code fences, or extra keys."
  ].join("\n");
}

function buildSourceMapUserPrompt(manifest: ManifestEntry[], options: AiExploratoryAuditOptions): string {
  const classes = options.vulnerabilityClasses?.length ? options.vulnerabilityClasses : DEFAULT_AUDIT_CLASSES;
  return `Build a security source map from this repository manifest.

Vulnerability classes to support: ${classes.join(", ")}

Repository AI instructions:
${options.aiInstructions || "None supplied."}

Static scanner seed files:
${formatStaticSeedsForPrompt(options.sourceMap)}

Negative evidence memory:
${formatNegativeEvidenceForPrompt(options.negativeEvidence)}

Return exact paths from the manifest only.

JSON shape:
{
  "summary": "short architecture and risk summary",
  "globalPriorityFiles": ["exact/path.ts"],
  "priorityFilesByClass": {
    "auth": ["exact/auth/path.ts"],
    "authz": ["exact/authz/path.ts"],
    "ssrf": ["exact/http/client.ts"],
    "injection": ["exact/db/or/shell/path.ts"],
    "xss": ["exact/template/path.ts"],
    "exposure": ["exact/export/or/log/path.ts"],
    "validation": ["exact/upload/or/redirect/path.ts"],
    "dependency": ["exact/package/usage/path.ts"],
    "crypto": ["exact/crypto/path.ts"],
    "misconfig": ["exact/config/path.ts"],
    "xxe": ["exact/xml/upload/path.ts"],
    "business-logic": ["exact/order/basket/payment/path.ts"]
  },
  "notes": ["short note used by later audit passes"],
  "catalog": {
    "sources": [{"name":"custom source/helper", "path":"exact/path.ts", "line":1, "category":"request/session/file", "evidence":"why this is a source"}],
    "sinks": [{"name":"custom sink/helper", "path":"exact/path.ts", "line":1, "category":"ssrf/sql/xss/authz", "evidence":"why this is a sink"}],
    "sanitizers": [{"name":"custom sanitizer/helper", "path":"exact/path.ts", "line":1, "category":"html/sql/url/path/authz", "evidence":"what it guarantees"}],
    "guards": [{"name":"custom guard/helper", "path":"exact/path.ts", "line":1, "category":"auth/authz/tenant/csrf", "evidence":"what it enforces"}]
  }
}

Manifest:
${formatManifestForPrompt(manifest, 12_000)}`;
}

function sourceMapPriorityFiles(sourceMap: AuditSourceMap, vulnerabilityClass: VulnerabilityClass): string[] {
  return [...new Set([
    ...(sourceMap.priorityFilesByClass[vulnerabilityClass] ?? []),
    ...sourceMap.globalPriorityFiles
  ])];
}

function scannerSeedSourceMap(scannerResults: ScannerResult[], files: IndexedFile[], classes: VulnerabilityClass[]): AuditSourceMap {
  const allowedPaths = new Set(files.filter(isAuditableFile).map((file) => file.path));
  const classSet = new Set(classes);
  const ranked = scannerResults
    .filter((result) => result.path && allowedPaths.has(normalizePath(result.path)))
    .filter((result) => result.severity === "critical" || result.severity === "high" || result.scanner === "source-patterns")
    .sort((a, b) => scannerSeedScore(b) - scannerSeedScore(a))
    .slice(0, 80);
  const globalPriorityFiles = unique(ranked.map((result) => normalizePath(result.path!))).slice(0, 30);
  const priorityFilesByClass: Record<string, string[]> = {};
  for (const result of ranked) {
    const filePath = normalizePath(result.path!);
    for (const vulnerabilityClass of classesForScannerSeed(result)) {
      if (!classSet.has(vulnerabilityClass)) continue;
      priorityFilesByClass[vulnerabilityClass] = unique([...(priorityFilesByClass[vulnerabilityClass] ?? []), filePath]).slice(0, 12);
    }
  }
  return {
    summary: globalPriorityFiles.length ? "Deterministic scanner seed files available for class-focused audit." : "",
    globalPriorityFiles,
    priorityFilesByClass,
    notes: ranked.slice(0, 20).map((result) => `${result.scanner}/${result.ruleId} ${result.category ?? "security"} ${normalizePath(result.path ?? "")}:${result.startLine ?? "?"}`),
    catalog: { sources: [], sinks: [], sanitizers: [], guards: [] }
  };
}

function scannerSeedScore(result: ScannerResult): number {
  const severityScore: Record<string, number> = { critical: 100, high: 80, medium: 45, low: 10, info: 0 };
  let score = severityScore[result.severity] ?? 0;
  if (result.scanner === "source-patterns") score += 40;
  if (String(JSON.stringify(result.raw ?? {})).includes("sourceLine")) score += 10;
  score += fileRoleScore(classifyFileRole(result.path ?? ""));
  return score;
}

function classesForScannerSeed(result: ScannerResult): VulnerabilityClass[] {
  const text = `${result.scanner} ${result.ruleId} ${result.title} ${result.category ?? ""} ${result.message}`.toLowerCase();
  const classes = new Set<VulnerabilityClass>();
  if (/\bxxe|xml|entity|noent|parsexml\b/.test(text)) classes.add("xxe");
  if (/\bsql|nosql|\$where|command|cmd|exec|eval|template|ssti|deserial|prototype|injection|rce\b/.test(text)) classes.add("injection");
  if (/\bxss|html|script|template|innerhtml\b/.test(text)) classes.add("xss");
  if (/\bssrf|fetch|axios|metadata|webhook|url\b/.test(text)) classes.add("ssrf");
  if (/\bauthentication|login|session|csrf|jwt|password|credential\b/.test(text)) classes.add("auth");
  if (/\bauthorization|authz|access|tenant|idor|owner|permission|role|admin|object\b/.test(text)) classes.add("authz");
  if (/\bbusiness|basket|cart|order|checkout|payment|coupon|discount|review|feedback|price|quantity|workflow\b/.test(text)) classes.add("business-logic");
  if (/\bpath|traversal|redirect|upload|file|archive|zip|validation|mime|extension\b/.test(text)) classes.add("validation");
  if (/\bsecret|credential|token|api[_ -]?key|log|debug|exposure|disclosure\b/.test(text)) classes.add("exposure");
  if (/\bcrypto|md5|sha1|cipher|encrypt|decrypt|tls|ssl|signature|hmac\b/.test(text)) classes.add("crypto");
  if (/\bcors|config|misconfig|helmet|cookie|header|debug|default\b/.test(text)) classes.add("misconfig");
  if (/\bdependency|package|cve|ghsa|supply chain\b/.test(text)) classes.add("dependency");
  return classes.size ? [...classes] : ["validation"];
}

function mergeSourceMaps(primary: AuditSourceMap, secondary: AuditSourceMap): AuditSourceMap {
  const priorityFilesByClass: Record<string, string[]> = {};
  for (const key of unique([...Object.keys(primary.priorityFilesByClass), ...Object.keys(secondary.priorityFilesByClass)])) {
    priorityFilesByClass[key] = unique([...(primary.priorityFilesByClass[key] ?? []), ...(secondary.priorityFilesByClass[key] ?? [])]).slice(0, 40);
  }
  return {
    summary: [primary.summary, secondary.summary].filter(Boolean).join(" "),
    globalPriorityFiles: unique([...primary.globalPriorityFiles, ...secondary.globalPriorityFiles]).slice(0, 40),
    priorityFilesByClass,
    notes: unique([...primary.notes, ...secondary.notes]).slice(0, 30),
    catalog: {
      sources: mergeCatalogItems(primary.catalog.sources, secondary.catalog.sources),
      sinks: mergeCatalogItems(primary.catalog.sinks, secondary.catalog.sinks),
      sanitizers: mergeCatalogItems(primary.catalog.sanitizers, secondary.catalog.sanitizers),
      guards: mergeCatalogItems(primary.catalog.guards, secondary.catalog.guards)
    }
  };
}

function mergeCatalogItems<T extends { path: string; line: number | null; name: string }>(a: T[], b: T[]): T[] {
  const seen = new Set<string>();
  return [...a, ...b].filter((item) => {
    const key = `${item.path}:${item.line ?? ""}:${item.name}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).slice(0, 80);
}

function formatStaticSeedsForPrompt(sourceMap: AuditSourceMap | undefined): string {
  if (!sourceMap || (!sourceMap.globalPriorityFiles.length && !Object.keys(sourceMap.priorityFilesByClass).length && !sourceMap.notes.length)) return "None.";
  return JSON.stringify({
    globalPriorityFiles: sourceMap.globalPriorityFiles,
    priorityFilesByClass: sourceMap.priorityFilesByClass,
    notes: sourceMap.notes.slice(0, 20)
  }, null, 2);
}

function formatNegativeEvidenceForPrompt(negativeEvidence: AiExploratoryAuditOptions["negativeEvidence"]): string {
  if (!negativeEvidence?.length) return "None.";
  return JSON.stringify(negativeEvidence.slice(0, 40).map((item) => ({
    title: item.title,
    path: item.path ?? "",
    startLine: item.startLine ?? null,
    status: item.status,
    reason: item.reason.slice(0, 500)
  })), null, 2);
}

function sanitizeSourceMap(sourceMap: AuditSourceMap, allowedPaths: Set<string>): AuditSourceMap {
  const keepPaths = (paths: string[]) => [...new Set(paths.map(normalizePath).filter((filePath) => allowedPaths.has(filePath)))].slice(0, 40);
  const priorityFilesByClass = Object.fromEntries(
    Object.entries(sourceMap.priorityFilesByClass)
      .map(([key, paths]) => [key, keepPaths(paths)])
      .filter(([, paths]) => paths.length)
  );
  return {
    summary: sourceMap.summary.slice(0, 1200),
    globalPriorityFiles: keepPaths(sourceMap.globalPriorityFiles),
    priorityFilesByClass,
    notes: sourceMap.notes.map((note) => note.slice(0, 500)).slice(0, 30),
    catalog: sanitizeCatalog(sourceMap.catalog, allowedPaths)
  };
}

function emptySourceMap(): AuditSourceMap {
  return { summary: "", globalPriorityFiles: [], priorityFilesByClass: {}, notes: [], catalog: { sources: [], sinks: [], sanitizers: [], guards: [] } };
}

function sanitizeCatalog(catalog: AuditSourceMap["catalog"], allowedPaths: Set<string>): AuditSourceMap["catalog"] {
  const keep = (items: AuditSourceMap["catalog"]["sources"]) => items
    .map((item) => ({ ...item, path: normalizePath(item.path), evidence: item.evidence.slice(0, 500), name: item.name.slice(0, 160), category: item.category.slice(0, 80) }))
    .filter((item) => allowedPaths.has(item.path))
    .slice(0, 80);
  return {
    sources: keep(catalog.sources),
    sinks: keep(catalog.sinks),
    sanitizers: keep(catalog.sanitizers),
    guards: keep(catalog.guards)
  };
}

async function requestAuditRound(provider: AiProvider, systemPrompt: string, manifestPrompt: string, roundPrompt: string, jsonSchema: AiJsonSchema, log: (message: string) => void, round: number, jobRecorder?: AiJobRecorder): Promise<z.infer<typeof auditResponseSchema>> {
  const jobId = jobRecorder?.start("audit", `round ${round}`, { provider: provider.name });
  try {
    let lastOutput = "";
    let lastIssues: ValidationIssue[] = [{ path: [], message: "No audit response was received" }];
    for (let attempt = 1; attempt <= AI_JSON_RETRY_ATTEMPTS; attempt++) {
      const currentRoundPrompt = attempt === 1 ? roundPrompt : buildAuditRetryPrompt(roundPrompt, lastOutput, lastIssues);
      const output = await provider.complete({
        system: systemPrompt,
        messages: [
          { role: "user", content: manifestPrompt },
          { role: "user", content: currentRoundPrompt }
        ],
        jsonSchema,
        temperature: 0,
        maxTokens: 3500
      });
      jobRecorder?.trace(jobId, { label: attempt === 1 ? "audit" : `audit-retry-${attempt}`, prompt: [systemPrompt, manifestPrompt, currentRoundPrompt].join("\n\n"), response: output.text });
      const parsed = parseAuditResponse(output.text);
      if (parsed.ok) {
        jobRecorder?.succeed(jobId, { valid: true, findings: parsed.data.findings.length, requestedFiles: parsed.data.requestedFiles.length, toolCalls: parsed.data.toolCalls.length });
        return parsed.data;
      }
      lastOutput = output.text;
      lastIssues = parsed.issues;
      if (attempt < AI_JSON_RETRY_ATTEMPTS) {
        log(`ai-audit: round ${round} invalid JSON/schema, retrying attempt ${attempt + 1}/${AI_JSON_RETRY_ATTEMPTS}`);
      }
    }

    log(`ai-audit: round ${round} invalid JSON/schema, repairing`);
    const repairPrompt = buildAuditRepairPrompt(lastOutput, lastIssues);
    const repair = await provider.complete({
      system: "Repair invalid JSON to match the strict JSON schema exactly. Output raw JSON only. No prose, markdown, comments, code fences, or extra keys. Use only enum values allowed by schema. Enum fields must be single strings, never arrays.",
      messages: [{ role: "user", content: repairPrompt }],
      jsonSchema,
      temperature: 0,
      maxTokens: 2500
    });
    jobRecorder?.trace(jobId, { label: "repair", prompt: repairPrompt, response: repair.text });
    const repaired = parseAuditResponse(repair.text);
    if (!repaired.ok) {
      log(`ai-audit: round ${round} repair failed, continuing with no findings`);
      jobRecorder?.succeed(jobId, { valid: false, findings: 0 });
      return { summary: "Invalid AI audit response", requestedFiles: [], toolCalls: [], complete: false, hypotheses: [], rejectedHypotheses: [], findings: [] };
    }
    jobRecorder?.succeed(jobId, { valid: true, repaired: true, findings: repaired.data.findings.length, requestedFiles: repaired.data.requestedFiles.length, toolCalls: repaired.data.toolCalls.length });
    return repaired.data;
  } catch (error) {
    jobRecorder?.fail(jobId, error);
    throw error;
  }
}

async function validateAuditFindingsWithAi(
  provider: AiProvider,
  findings: Array<z.infer<typeof auditFindingSchema>>,
  sourcePack: unknown,
  memory: AuditMemory,
  _responseSchema: AiJsonSchema,
  log: (message: string) => void,
  round: number,
  jobRecorder?: AiJobRecorder
): Promise<Array<z.infer<typeof auditFindingSchema>>> {
  const jobId = jobRecorder?.start("audit", `validation round ${round}`, { provider: provider.name, findings: findings.length });
  const system = [
    "Role: security finding validation critic.",
    "Goal: reject or downgrade exploratory audit findings unless source, sink, missing control, reachability, and sanitizer/guard mismatch are supported by supplied evidence.",
    "Return raw JSON only. Do not add new findings."
  ].join("\n");
  const prompt = [
    "Validate these candidate findings against the supplied source-pack evidence and memory.",
    "Use findingIndex values from the candidates array.",
    "Reject findings with invented paths/lines, missing source-to-sink evidence, sufficient sanitizer/guard evidence, test-only context, or weak exploitability.",
    "Downgrade uncertain findings to security_hotspot or needs_context.",
    "",
    "Memory:",
    JSON.stringify({
      inspectedFiles: [...memory.inspectedFiles],
      memoryNotes: memory.notes.slice(-30)
    }, null, 2),
    "",
    "Source pack:",
    JSON.stringify(sourcePack, null, 2),
    "",
    "Candidates:",
    JSON.stringify(findings.map((finding, index) => ({ findingIndex: index, ...finding })), null, 2),
    "",
    "Return {\"decisions\":[{\"findingIndex\":0,\"verdict\":\"keep\",\"revisedStatus\":\"confirmed_true_positive\",\"revisedConfidence\":\"high\",\"reasons\":[\"why\"]}]}."
  ].join("\n");
  try {
    const output = await provider.complete({
      system,
      messages: [{ role: "user", content: prompt }],
      jsonSchema: auditValidationJsonSchema,
      temperature: 0,
      maxTokens: 1800
    });
    jobRecorder?.trace(jobId, { label: "validation", prompt: `${system}\n\n${prompt}`, response: output.text });
    const parsed = parseAuditValidationResponse(output.text, output.parsedJson);
    if (!parsed.ok) {
      log(`ai-audit: validation round ${round} invalid response, keeping pre-validation findings`);
      jobRecorder?.succeed(jobId, { valid: false, kept: findings.length });
      return findings;
    }
    const decisions = new Map(parsed.data.decisions.map((decision) => [decision.findingIndex, decision]));
    const filtered = findings.flatMap((finding, index) => {
      const decision = decisions.get(index);
      if (!decision) return [finding];
      if (decision.verdict === "reject") return [];
      return [{
        ...finding,
        status: decision.revisedStatus,
        confidence: decision.revisedConfidence,
        reasoning: `${finding.reasoning}\nAI validation: ${decision.reasons.join("; ")}`
      }];
    });
    log(`ai-audit: validation round ${round} kept=${filtered.length}/${findings.length}`);
    jobRecorder?.succeed(jobId, { valid: true, kept: filtered.length, rejected: findings.length - filtered.length });
    return filtered;
  } catch (error) {
    log(`ai-audit: validation round ${round} failed: ${error instanceof Error ? error.message : String(error)}`);
    jobRecorder?.fail(jobId, error);
    return findings;
  }
}

function parseSourceMapResponse(text: string): ParseResult<AuditSourceMap> {
  const raw = normalizeSourceMapJson(safeJsonParse(text));
  const checked = auditSourceMapSchema.safeParse(raw);
  if (checked.success && hasSourceMapResponseShape(raw)) return { ok: true, data: checked.data };
  const salvaged = salvageSourceMapResponse(raw);
  if (salvaged && hasSourceMapResponseShape(raw)) return { ok: true, data: salvaged };
  return { ok: false, issues: checked.success ? [{ path: [], message: "Response did not include source-map keys" }] : toValidationIssues(checked.error.issues) };
}

function parseAuditResponse(text: string): ParseResult<z.infer<typeof auditResponseSchema>> {
  const raw = safeJsonParse(text);
  const normalized = normalizeAuditResponseJson(raw);
  const checked = auditResponseSchema.safeParse(normalized);
  if (checked.success && hasAuditResponseShape(normalized)) return { ok: true, data: checked.data };
  const salvaged = salvageAuditResponse(normalized);
  if (salvaged && hasAuditResponseShape(normalized)) return { ok: true, data: salvaged };
  return { ok: false, issues: checked.success ? [{ path: [], message: "Response did not include audit response keys" }] : toValidationIssues(checked.error.issues) };
}

function parseAuditValidationResponse(text: string, parsedJson?: unknown): ParseResult<z.infer<typeof auditValidationResponseSchema>> {
  const raw = parsedJson ?? safeJsonParse(text);
  const checked = auditValidationResponseSchema.safeParse(raw);
  if (checked.success && isRecord(raw) && Object.prototype.hasOwnProperty.call(raw, "decisions")) return { ok: true, data: checked.data };
  return { ok: false, issues: checked.success ? [{ path: [], message: "Response did not include validation decisions" }] : toValidationIssues(checked.error.issues) };
}

function salvageAuditResponse(value: unknown): z.infer<typeof auditResponseSchema> | undefined {
  if (!isRecord(value)) return undefined;
  const rawFindings = Array.isArray(value.findings) ? value.findings : [];
  const findings = rawFindings
    .map((item) => auditFindingSchema.safeParse(item))
    .filter((item): item is z.SafeParseSuccess<z.infer<typeof auditFindingSchema>> => item.success)
    .map((item) => item.data);
  const requestedFiles = z.array(z.string()).safeParse(value.requestedFiles).success
    ? z.array(z.string()).parse(value.requestedFiles)
    : [];
  const toolCalls = Array.isArray(value.toolCalls)
    ? value.toolCalls.map((item) => auditToolCallSchema.safeParse(item)).filter((item): item is z.SafeParseSuccess<z.infer<typeof auditToolCallSchema>> => item.success).map((item) => item.data)
    : [];
  const hypotheses = Array.isArray(value.hypotheses)
    ? value.hypotheses.map((item) => auditHypothesisSchema.safeParse(item)).filter((item): item is z.SafeParseSuccess<z.infer<typeof auditHypothesisSchema>> => item.success).map((item) => item.data)
    : [];
  const rejectedHypotheses = Array.isArray(value.rejectedHypotheses)
    ? value.rejectedHypotheses.map((item) => rejectedHypothesisSchema.safeParse(item)).filter((item): item is z.SafeParseSuccess<z.infer<typeof rejectedHypothesisSchema>> => item.success).map((item) => item.data)
    : [];
  if (!findings.length && !requestedFiles.length && !toolCalls.length && !hypotheses.length && !rejectedHypotheses.length) return undefined;
  return {
    summary: typeof value.summary === "string" ? value.summary : "Partially salvaged malformed AI audit response",
    requestedFiles,
    toolCalls,
    complete: typeof value.complete === "boolean" ? value.complete : false,
    hypotheses,
    rejectedHypotheses,
    findings
  };
}

function salvageSourceMapResponse(value: unknown): AuditSourceMap | undefined {
  if (!isRecord(value)) return undefined;
  const priorityFilesByClass: Record<string, string[]> = {};
  if (isRecord(value.priorityFilesByClass)) {
    for (const [key, paths] of Object.entries(value.priorityFilesByClass)) {
      const strings = stringArrayFrom(paths);
      if (strings.length) priorityFilesByClass[key] = strings;
    }
  }
  const catalog = salvageSourceMapCatalog(value.catalog);
  const sourceMap: AuditSourceMap = {
    summary: typeof value.summary === "string" ? value.summary : "",
    globalPriorityFiles: stringArrayFrom(value.globalPriorityFiles),
    priorityFilesByClass,
    notes: stringArrayFrom(value.notes),
    catalog
  };
  const hasCatalog = catalog.sources.length || catalog.sinks.length || catalog.sanitizers.length || catalog.guards.length;
  if (!sourceMap.summary && !sourceMap.globalPriorityFiles.length && !Object.keys(priorityFilesByClass).length && !sourceMap.notes.length && !hasCatalog) return undefined;
  return sourceMap;
}

function salvageSourceMapCatalog(value: unknown): AuditSourceMap["catalog"] {
  const empty = { sources: [], sinks: [], sanitizers: [], guards: [] };
  if (!isRecord(value)) return empty;
  const keep = (items: unknown): AuditSourceMap["catalog"]["sources"] => Array.isArray(items)
    ? items
      .map((item) => auditCatalogItemSchema.safeParse(item))
      .filter((item): item is z.SafeParseSuccess<z.infer<typeof auditCatalogItemSchema>> => item.success)
      .map((item) => item.data)
    : [];
  return {
    sources: keep(value.sources),
    sinks: keep(value.sinks),
    sanitizers: keep(value.sanitizers),
    guards: keep(value.guards)
  };
}

function stringArrayFrom(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

function buildSourceMapRetryPrompt(originalPrompt: string, invalidJson: string, issues: ValidationIssue[]): string {
  return [
    "Previous source-map response was invalid. Retry from the original manifest and return a complete JSON object.",
    "Validation errors:",
    ...formatValidationIssues(issues),
    "",
    "Previous response:",
    truncateForPrompt(invalidJson || "<empty>", 4_000),
    "",
    "Requirements:",
    "- Return raw JSON only: {summary, globalPriorityFiles, priorityFilesByClass, notes}.",
    "- Use exact paths from the manifest only.",
    "- Keep output compact and close all JSON arrays/objects.",
    "",
    originalPrompt
  ].join("\n");
}

function buildSourceMapRepairPrompt(invalidJson: string, issues: ValidationIssue[]): string {
  return [
    "Validation errors:",
    ...formatValidationIssues(issues),
    "",
    "Invalid source-map JSON to repair:",
    truncateForPrompt(invalidJson, 8_000),
    "",
    "Return the corrected raw JSON object only with keys: summary, globalPriorityFiles, priorityFilesByClass, notes."
  ].join("\n");
}

function buildAuditRetryPrompt(roundPrompt: string, invalidJson: string, issues: ValidationIssue[]): string {
  return [
    "Previous audit response was invalid or empty. Retry the same audit round and return a complete JSON object.",
    "Validation errors:",
    ...formatValidationIssues(issues),
    "",
    "Previous response:",
    truncateForPrompt(invalidJson || "<empty>", 4_000),
    "",
    "Requirements:",
    "- Return raw JSON only: {summary, requestedFiles, toolCalls, complete, hypotheses, rejectedHypotheses, findings}.",
    "- Use enum fields as single strings, never arrays.",
    "- If there are no findings, still include all required keys with empty arrays.",
    "",
    roundPrompt
  ].join("\n");
}

function buildAuditRepairPrompt(invalidJson: string, issues: ValidationIssue[]): string {
  return [
    "Validation errors:",
    ...formatValidationIssues(issues),
    "",
    "Invalid JSON to repair:",
    invalidJson,
    "",
    "Return the corrected raw JSON object only. Enum fields must be single strings, never arrays."
  ].join("\n");
}

function formatValidationIssues(issues: readonly ValidationIssue[]): string[] {
  return issues.slice(0, 20).map((issue) => `- ${issue.path.join(".") || "<root>"}: ${issue.message}`);
}

function toValidationIssues(issues: readonly z.ZodIssue[]): ValidationIssue[] {
  return issues.map((issue) => ({ path: [...issue.path], message: issue.message }));
}

function normalizeSourceMapJson(value: unknown): unknown {
  if (isRecord(value)) {
    if (isRecord(value.sourceMap)) return value.sourceMap;
    if (isRecord(value.result)) return value.result;
  }
  return value;
}

function hasSourceMapResponseShape(value: unknown): boolean {
  return isRecord(value) && ["summary", "globalPriorityFiles", "priorityFilesByClass", "notes"].some((key) => Object.prototype.hasOwnProperty.call(value, key));
}

function hasAuditResponseShape(value: unknown): boolean {
  return isRecord(value) && ["summary", "requestedFiles", "toolCalls", "complete", "findings"].some((key) => Object.prototype.hasOwnProperty.call(value, key));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function truncateForPrompt(value: string, maxChars: number): string {
  if (value.length <= maxChars) return value;
  return `${value.slice(0, maxChars)}\n...[truncated]`;
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
    "Use category rubrics: auth requires missing authentication on a reachable sensitive action; authz/business-logic requires an actor to access or mutate another actor's object, privileged function, workflow, payment, coupon, order, review, basket, or admin state without server-side policy enforcement; SSRF requires user-controlled URL reaching outbound request without allowlist; path traversal requires user path reaching filesystem without normalization/base check; open redirect requires attacker-controlled redirect destination without a strict allowlist; file upload requires unsafe extension/content validation, archive extraction, or server-side write controls; XXE requires XML parsing with entity expansion or external entities enabled on user-controlled XML; command injection requires user input reaching shell command; XSS requires untrusted HTML/script reaching render sink without escaping; template/RCE chains require a plausible pollution/input vector plus vulnerable render/eval behavior; secrets require literal committed secret value, not runtime env reference; crypto requires weak primitive or unsafe key/IV usage; dependency requires vulnerable or integrity-sensitive package usage that is reachable or loaded by app code; CSRF/CORS/session requires browser-reachable state change, credential exposure, or cookie/session weakening.",
    "Focus on auth/authz, business logic, tenant isolation, injection, XSS, SSRF, path traversal, file upload, XXE, vulnerable dependency reachability, crypto misuse, webhooks, CORS/CSRF/session bugs, secrets, unsafe redirects, unsafe dynamic execution, debug/metrics/log exposure, and sensitive data exposure.",
    "Return raw JSON object only: {summary, requestedFiles, toolCalls, complete, findings}. No prose, markdown, code fences, comments, or extra keys.",
    "Use only enum values listed in the schema. Do not invent categories, severities, confidences, statuses, tool types, or field names.",
    "Enum fields are single strings, never arrays: category=\"security\", severity=\"high\", confidence=\"high\", status=\"suspected\".",
    "findings must include title, category, severity, confidence, status, path, startLine, endLine, source, sourceLine, sink, sinkLine, dataFlow, missingControl, exploitPreconditions, safeRepro, evidence, reasoning, remediation."
  ].join("\n");
}

function buildInitialPrompt(manifest: unknown, options: AiExploratoryAuditOptions, manifestCharBudget = 20_000): string {
  return `Repository manifest follows. The scanner will choose deterministic breadth-first entry points first, then local imports, then remaining files. Use this manifest only to understand repository shape and request exact follow-up files when needed.

Caps:
- max files you may inspect this audit: ${options.maxFiles}
- max request rounds: ${options.maxRounds}
- max source chars: ${options.maxChars}

Do not return findings until source file contents are supplied.

Repository AI instructions:
${options.aiInstructions || "None supplied."}

Negative evidence memory:
${formatNegativeEvidenceForPrompt(options.negativeEvidence)}

AI source map:
${formatSourceMapForPrompt(options.sourceMap)}

Manifest:
${formatManifestForPrompt(manifest, manifestCharBudget)}`;
}

function buildAuditRoundPrompt(pack: unknown, memory: AuditMemory, allowedCategories: readonly string[] = categoryValues): string {
  return `Audit these source files for vulnerabilities not necessarily reported by scanners.

Already inspected files:
${[...memory.inspectedFiles].map((file) => `- ${file}`).join("\n")}

Memory notes:
${memory.notes.slice(-40).map((item) => `- ${item.path}: ${item.note}`).join("\n") || "- none"}

Source pack:
${JSON.stringify(pack, null, 2)}

Return raw JSON only. No prose, markdown fences, comments, or extra keys. Use only predefined enum values:
{
  "summary": "short summary",
  "requestedFiles": ["exact/path.ts"],
	  "toolCalls": [
    {"type":"read_file","path":"exact/path.ts","query":"","symbol":"","category":"","startLine":1,"endLine":120,"reason":"need callee line range"},
    {"type":"search_text","path":"","query":"dangerousFunction","symbol":"","category":"","startLine":null,"endLine":null,"reason":"find callers"},
    {"type":"search_symbol","path":"","query":"","symbol":"handlerName","category":"","startLine":null,"endLine":null,"reason":"find definition"},
    {"type":"find_category","path":"","query":"","symbol":"","category":"ssrf","startLine":null,"endLine":null,"reason":"find outbound sinks"}
	  ],
	  "complete": false,
	  "hypotheses": [
	    {
	      "id": "authz-1",
	      "vulnerabilityClass": "authz",
	      "title": "candidate vulnerability title",
	      "path": "exact/path.ts",
	      "source": "input or actor",
	      "sink": "side effect or dangerous operation",
	      "evidence": [{"path":"exact/path.ts","line":1,"note":"candidate evidence"}],
	      "status": "candidate",
	      "reason": "why this needs validation before reporting"
	    }
	  ],
	  "rejectedHypotheses": [
	    {"id":"safe-1","title":"candidate rejected", "path":"exact/path.ts", "reason":"guard, sanitizer, unreachable, or test-only context disproves it"}
	  ],
	  "findings": [
    {
      "title": "finding title",
      "category": "security",
      "severity": "high",
      "confidence": "high",
      "status": "suspected",
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
}

Allowed enum values:
- category: ${JSON.stringify(allowedCategories)}
- severity: ${JSON.stringify(severityValues)}
- confidence: ${JSON.stringify(confidenceValues)}
- status: ${JSON.stringify(statusValues)}

Enum fields must be single strings, never arrays. Do not output category=["xss"] or severity=["high"].`;
}

function auditRequestCharBudget(options: AiExploratoryAuditOptions): number {
  const configured = options.maxRequestChars ?? DEFAULT_AUDIT_REQUEST_CHAR_BUDGET;
  return Math.max(12_000, Math.min(options.maxChars, configured));
}

function formatManifestForPrompt(manifest: unknown, charBudget: number): string {
  if (!Array.isArray(manifest)) return truncateString(JSON.stringify(manifest, null, 2), charBudget);
  const entries = manifest as ManifestEntry[];
  const files: Array<ReturnType<typeof compactManifestEntry>> = [];
  for (const entry of entries) {
    const next = [...files, compactManifestEntry(entry)];
    const candidate = JSON.stringify({ files: next, omittedFiles: entries.length - next.length }, null, 2);
    if (candidate.length > charBudget && files.length) break;
    if (candidate.length > charBudget) {
      files.push(compactManifestEntry(entry, true));
      break;
    }
    files.push(compactManifestEntry(entry));
  }
  return JSON.stringify({ files, omittedFiles: Math.max(0, entries.length - files.length) }, null, 2);
}

function formatSourceMapForPrompt(sourceMap: AuditSourceMap | undefined): string {
  if (!sourceMap || (!sourceMap.summary && !sourceMap.notes.length && !sourceMap.globalPriorityFiles.length && !Object.keys(sourceMap.priorityFilesByClass).length && !sourceMapCatalogCount(sourceMap))) {
    return "None supplied.";
  }
  return JSON.stringify({
    summary: sourceMap.summary,
    globalPriorityFiles: sourceMap.globalPriorityFiles,
    priorityFilesByClass: sourceMap.priorityFilesByClass,
    notes: sourceMap.notes,
    catalog: sourceMap.catalog
  }, null, 2);
}

function sourceMapCatalogCount(sourceMap: AuditSourceMap): number {
  return sourceMap.catalog.sources.length + sourceMap.catalog.sinks.length + sourceMap.catalog.sanitizers.length + sourceMap.catalog.guards.length;
}

function compactManifestEntry(entry: ManifestEntry, minimal = false) {
  if (minimal) return { path: entry.path, language: entry.language, lines: entry.lines, priorityHints: entry.priorityHints.slice(0, 3) };
  return {
    path: entry.path,
    language: entry.language,
    lines: entry.lines,
    localImports: entry.localImports.slice(0, 8),
    routes: entry.routes.slice(0, 6),
    symbols: entry.symbols.slice(0, 8),
    hasScannerResult: entry.hasScannerResult,
    priorityHints: entry.priorityHints.slice(0, 5),
    frameworkHints: entry.frameworkHints.slice(0, 5),
    securityInventory: {
      entrypoints: entry.securityInventory.entrypoints.slice(0, 8),
      trustBoundaryCount: entry.securityInventory.trustBoundaries.length,
      sinks: entry.securityInventory.sinks.slice(0, 12).map((sink) => ({ category: sink.category, line: sink.line })),
      guardCount: entry.securityInventory.guards.length
    }
  };
}

function truncateString(value: string, maxChars: number): string {
  if (value.length <= maxChars) return value;
  return `${value.slice(0, Math.max(0, maxChars - 36))}\n[TRUNCATED BY AUDIT CONTEXT BUDGET]`;
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

function buildBoundedFilePack(targets: AuditTarget[], allowed: Map<string, IndexedFile>, remainingChars: number, importGraph: Map<string, string[]>, memory: AuditMemory, fixedPromptChars: number, requestCharBudget: number) {
  const maxRoundPromptChars = Math.max(3_000, requestCharBudget - fixedPromptChars);
  let sourceBudget = Math.max(1_000, Math.min(remainingChars, maxRoundPromptChars - AUDIT_PROMPT_OVERHEAD_CHARS));
  let pack = buildFilePack(targets, allowed, sourceBudget, importGraph, memory);
  let prompt = buildAuditRoundPrompt(pack, memory);
  while (pack.files.length && fixedPromptChars + prompt.length > requestCharBudget && sourceBudget > 1_000) {
    sourceBudget = Math.max(1_000, Math.floor(sourceBudget * 0.7));
    pack = buildFilePack(targets, allowed, sourceBudget, importGraph, memory);
    prompt = buildAuditRoundPrompt(pack, memory);
  }
  return pack;
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
    const nextFile = {
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
    };
    const nextOutput = [...output, nextFile];
    if (JSON.stringify({ files: nextOutput, charCount: charCount + clipped.length }, null, 2).length > charBudget && output.length) break;
    output.push(nextFile);
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

function buildAuditChunks(files: IndexedFile[], windowLines = AUDIT_CHUNK_LINES): Map<string, AuditTarget[]> {
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

function createAuditTraversal(files: IndexedFile[], scannerResults: ScannerResult[], importGraph: Map<string, string[]>, chunks: Map<string, AuditTarget[]>, priorityFiles: string[] = []) {
  const fallback = heuristicEntryFiles(files, scannerResults);
  const byPath = new Map(files.map((file) => [file.path, file]));
  const allowed = new Set(files.map((file) => file.path));
  const queued = new Set<string>();
  const queue: AuditTarget[] = [];
  const keyOf = (target: AuditTarget) => `${target.path}:${target.startLine}:${target.endLine}`;
  const pushTargets = (targets: AuditTarget[], front = false) => {
    const additions: AuditTarget[] = [];
    for (const target of targets) {
      if (!allowed.has(target.path)) continue;
      const key = keyOf(target);
      if (queued.has(key)) continue;
      queued.add(key);
      additions.push(target);
    }
    if (front) queue.unshift(...additions);
    else queue.push(...additions);
  };
  const pushFirstChunks = (paths: string[]) => {
    for (const filePath of paths) {
      if (!allowed.has(filePath)) continue;
      const first = chunks.get(filePath)?.[0];
      if (first) pushTargets([first]);
    }
  };
  pushFirstChunks(priorityFiles.map(normalizePath));
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
      pushTargets(targets, true);
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
      if (file) {
        const startLine = Math.min(file.lineCount, Math.max(1, call.startLine ?? 1));
        const requestedEnd = call.endLine && call.endLine >= startLine ? call.endLine : startLine + AUDIT_CHUNK_LINES - 1;
        const endLine = Math.min(file.lineCount, requestedEnd);
        targets.push(targetWindow(file.path, startLine, endLine, 1, 1));
      }
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
  return attackSurfaceWeight(file.path) + fileRoleScore(classifyFileRole(file.path, file.language)) + file.priorityHints.length * 10 + file.routes.length * 6 + (file.hasScannerResult ? 8 : 0);
}

function scoreFile(file: IndexedFile, scannerPaths: Set<string>): number {
  return attackSurfaceWeight(file.path) + fileRoleScore(classifyFileRole(file.path, file.language)) + priorityHints(file).length * 10 + detectRoutes(file.path, file.content).length * 6 + (scannerPaths.has(file.path) ? 8 : 0) - Math.min(file.lineCount / 500, 5);
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
  if (isReusableOrGeneratedRole(classifyFileRole(file.path, file.language))) return false;
  if (/(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|dist\/|build\/|coverage\/)/i.test(file.path)) return false;
  return file.content.length <= 250_000;
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
  if (input.category.toLowerCase() === "xss" && isServerTemplatePath(input.path) && !hasTemplateRenderReachability(input, allowed)) return false;
  if (/(^|\/)(__tests__|test|tests|spec|fixtures|examples?)\//i.test(input.path) && !/prod|production|runtime|reachable/i.test(text)) return false;
  return lineEvidenceMatches(input, allowed);
}

function isServerTemplatePath(filePath: string): boolean {
  return /\.(ejs|pug|jade|hbs|handlebars|erb|twig|njk|liquid)$/i.test(filePath)
    || /(^|\/)(views|templates)\//i.test(filePath);
}

function hasTemplateRenderReachability(input: z.infer<typeof auditFindingSchema>, allowed: Map<string, IndexedFile>): boolean {
  const names = templateReferenceNames(input.path);
  for (const file of allowed.values()) {
    if (file.path === input.path) continue;
    if (!/\.(js|jsx|mjs|cjs|ts|tsx|py|php|rb|java|cs)$/i.test(file.path)) continue;
    if (!/(render|template|view)/i.test(file.content)) continue;
    const lines = file.content.split(/\r?\n/);
    for (const [index, line] of lines.entries()) {
      if (!/(render|template|view)/i.test(line)) continue;
      if (!names.some((name) => line.includes(name))) continue;
      const nearby = lines.slice(Math.max(0, index - 5), Math.min(lines.length, index + 6)).join("\n");
      if (detectRoutes(file.path, nearby).length || /(req|request|res\.render|reply\.view|render_template|erb\s*:|haml\s*:)/i.test(nearby)) return true;
    }
  }
  return false;
}

function templateReferenceNames(filePath: string): string[] {
  const normalized = filePath.replaceAll("\\", "/");
  const withoutExt = normalized.replace(/\.[^.]+$/, "");
  const basename = path.posix.basename(withoutExt);
  const viewsRelative = withoutExt.match(/(?:^|\/)(?:views|templates)\/(.+)$/i)?.[1];
  return [...new Set([basename, viewsRelative, withoutExt].filter((item): item is string => Boolean(item)))];
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

function unique<T>(values: T[]): T[] {
  return [...new Set(values)];
}

async function sequence<T, R>(items: T[], fn: (item: T) => Promise<R>): Promise<R[]> {
  const output: R[] = [];
  for (const item of items) output.push(await fn(item));
  return output;
}
