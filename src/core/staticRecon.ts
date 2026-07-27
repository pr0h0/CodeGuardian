import type { IndexedFile } from "../repo/repoIndexer.js";
import { detectRoutes } from "../repo/routeDetector.js";
import type { SecurityIntelligence } from "../repo/securityIntelligence.js";
import type { ScannerResult } from "../scanners/types.js";

export interface StaticReconEndpoint {
  method: string;
  routePath: string;
  path: string;
  line: number;
  framework: string;
  objectIdParameters: string[];
}

export interface StaticReconItem {
  kind: string;
  path: string;
  line?: number | null;
  detail: string;
}

export interface StaticReconArtifact {
  generatedAt: string;
  summary: string;
  endpoints: StaticReconEndpoint[];
  guards: StaticReconItem[];
  inputVectors: StaticReconItem[];
  sinks: StaticReconItem[];
  boundaries: Array<{ id: string; kind: string; name: string; fileCount: number; entrypointCount: number }>;
  invariants: Array<{ category: string; path: string; line: number; rule: string; confidence: string }>;
}

const guardPattern = /\b(requireAuth|isAuthenticated|authorize|isAuthorized|requireRole|requireAdmin|policy|permission|guard|can\?|csrf|jwt\.verify|passport\.authenticate|current_user|req\.user|session\.user)\b/i;
const requestInputPattern = /\b(req|request|ctx)\.(body|query|params|headers|cookies)\.([A-Za-z0-9_$-]+)|\b(searchParams|getParameter|getHeader)\s*\(/i;

export function buildStaticReconArtifact(input: {
  files: IndexedFile[];
  scannerResults: ScannerResult[];
  securityIntelligence?: SecurityIntelligence;
}): StaticReconArtifact {
  const endpoints = buildEndpoints(input.files);
  const guards = buildLineItems(input.files, "guard", guardPattern, 80);
  const inputVectors = buildLineItems(input.files, "request-input", requestInputPattern, 120);
  const scannerSinks = input.scannerResults
    .filter((result) => /sink|injection|xss|ssrf|command|path|file|deserialization|template|authz|business/i.test(`${result.ruleId} ${result.category ?? ""} ${result.title}`))
    .map((result) => ({
      kind: result.category ?? result.ruleId,
      path: result.path ?? "repository",
      line: result.startLine ?? null,
      detail: `${result.scanner}/${result.ruleId}: ${result.title}`.slice(0, 220)
    }));
  const catalogSinks = (input.securityIntelligence?.catalog ?? [])
    .filter((item) => item.kind === "sink")
    .map((item) => ({ kind: item.category, path: item.path, line: item.line, detail: item.evidence.slice(0, 220) }));
  const sinks = dedupeItems([...scannerSinks, ...catalogSinks]).slice(0, 120);
  const boundaries = (input.securityIntelligence?.boundaries ?? []).slice(0, 60).map((item) => ({
    id: item.id,
    kind: item.kind,
    name: item.name,
    fileCount: item.fileCount,
    entrypointCount: item.entrypointCount
  }));
  const invariants = (input.securityIntelligence?.invariants ?? []).slice(0, 80).map((item) => ({
    category: item.category,
    path: item.path,
    line: item.line,
    rule: item.rule,
    confidence: item.confidence
  }));
  return {
    generatedAt: new Date().toISOString(),
    summary: `${endpoints.length} endpoint(s), ${guards.length} guard hint(s), ${inputVectors.length} input vector(s), ${sinks.length} sink/control candidate(s), ${boundaries.length} boundary group(s), ${invariants.length} business invariant(s).`,
    endpoints,
    guards,
    inputVectors,
    sinks,
    boundaries,
    invariants
  };
}

function buildEndpoints(files: IndexedFile[]): StaticReconEndpoint[] {
  return files.flatMap((file) => detectRoutes(file.path, file.content).map((route) => ({
    method: route.method,
    routePath: route.routePath,
    path: file.path,
    line: route.startLine,
    framework: route.frameworkGuess,
    objectIdParameters: objectIdParameters(route.routePath)
  }))).slice(0, 300);
}

function buildLineItems(files: IndexedFile[], kind: string, pattern: RegExp, limit: number): StaticReconItem[] {
  const output: StaticReconItem[] = [];
  for (const file of files) {
    if (!isSourceFile(file.path)) continue;
    const lines = file.content.split(/\r?\n/);
    for (const [index, line] of lines.entries()) {
      if (!pattern.test(line)) continue;
      output.push({ kind, path: file.path, line: index + 1, detail: line.trim().slice(0, 220) });
      if (output.length >= limit) return output;
    }
  }
  return output;
}

function objectIdParameters(routePath: string): string[] {
  return [...routePath.matchAll(/[:{]([A-Za-z0-9_]*(?:id|Id|ID))[}?]?/g)].map((match) => match[1]);
}

function dedupeItems(items: StaticReconItem[]): StaticReconItem[] {
  const seen = new Set<string>();
  return items.filter((item) => {
    const key = `${item.kind}:${item.path}:${item.line ?? ""}:${item.detail}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function isSourceFile(filePath: string): boolean {
  return /\.(js|jsx|mjs|cjs|ts|tsx|py|php|rb|go|java|cs)$/i.test(filePath);
}
