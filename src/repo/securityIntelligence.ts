import type { ScannerResult } from "../scanners/types.js";
import { classifyFileRole, type FileRole } from "./fileRole.js";
import type { IndexedFile } from "./repoIndexer.js";
import { detectRoutes } from "./routeDetector.js";
import { buildSecurityGraph, sanitizerPattern } from "./securityGraph.js";
import { discoverBusinessInvariants, type BusinessInvariant } from "./businessInvariants.js";

export interface CatalogInputItem {
  name: string;
  path: string;
  line?: number | null;
  category?: string;
  evidence?: string;
}

export interface AiSourceMapForIntelligence {
  summary: string;
  globalPriorityFiles: string[];
  priorityFilesByClass: Record<string, string[]>;
  notes: string[];
  catalog?: {
    sources?: CatalogInputItem[];
    sinks?: CatalogInputItem[];
    sanitizers?: CatalogInputItem[];
    guards?: CatalogInputItem[];
  };
}

export interface SecurityCatalogItem {
  kind: "source" | "sink" | "sanitizer" | "guard";
  name: string;
  path: string;
  line: number | null;
  category: string;
  evidence: string;
  discoveredBy: "deterministic" | "ai";
}

export interface SecurityEntrypoint {
  method: string;
  routePath: string;
  path: string;
  line: number;
  framework: string;
  boundary: string;
}

export interface BoundaryInfo {
  id: string;
  kind: FileRole;
  name: string;
  paths: string[];
  fileCount: number;
  entrypointCount: number;
}

export interface NegativeEvidence {
  title: string;
  path?: string | null;
  startLine?: number | null;
  reason: string;
  status: string;
  fingerprint?: string | null;
}

export interface SecurityIntelligence {
  summary: string;
  generatedAt: string;
  entrypoints: SecurityEntrypoint[];
  catalog: SecurityCatalogItem[];
  invariants: BusinessInvariant[];
  boundaries: BoundaryInfo[];
  highRiskFiles: Array<{ path: string; score: number; reasons: string[] }>;
  negativeEvidence: NegativeEvidence[];
  aiNotes: string[];
  auditArtifacts: unknown[];
  coverage: {
    indexedFiles: number;
    entrypointFiles: number;
    scannerSeedFiles: number;
    boundaries: number;
    deterministicCatalogItems: number;
    aiCatalogItems: number;
  };
}

export function buildSecurityIntelligence(
  files: IndexedFile[],
  scannerResults: ScannerResult[],
  options: {
    aiSourceMap?: AiSourceMapForIntelligence;
    negativeEvidence?: NegativeEvidence[];
    auditArtifacts?: unknown[];
  } = {}
): SecurityIntelligence {
  const entrypoints = buildEntrypoints(files);
  const deterministicCatalog = buildDeterministicCatalog(files);
  const aiCatalog = buildAiCatalog(options.aiSourceMap, new Set(files.map((file) => normalizePath(file.path))));
  const catalog = dedupeCatalog([...deterministicCatalog, ...aiCatalog]).slice(0, 400);
  const boundaries = buildBoundaries(files, entrypoints);
  const highRiskFiles = rankHighRiskFiles(files, scannerResults, entrypoints, options.aiSourceMap).slice(0, 80);
  const aiNotes = [
    ...(options.aiSourceMap?.summary ? [options.aiSourceMap.summary] : []),
    ...(options.aiSourceMap?.notes ?? [])
  ].slice(0, 80);
  return {
    summary: summarize(entrypoints, catalog, boundaries, highRiskFiles, options.negativeEvidence ?? []),
    generatedAt: new Date().toISOString(),
    entrypoints,
    catalog,
    invariants: discoverBusinessInvariants(files),
    boundaries,
    highRiskFiles,
    negativeEvidence: (options.negativeEvidence ?? []).slice(0, 100),
    aiNotes,
    auditArtifacts: options.auditArtifacts ?? [],
    coverage: {
      indexedFiles: files.length,
      entrypointFiles: new Set(entrypoints.map((item) => item.path)).size,
      scannerSeedFiles: new Set(scannerResults.map((item) => item.path).filter(Boolean) as string[]).size,
      boundaries: boundaries.length,
      deterministicCatalogItems: deterministicCatalog.length,
      aiCatalogItems: aiCatalog.length
    }
  };
}

export function boundaryForPath(filePath: string): Pick<BoundaryInfo, "id" | "kind" | "name"> {
  const normalized = normalizePath(filePath);
  const role = boundaryRole(normalized);
  const parts = normalized.split("/");
  const root = parts[0] ?? "root";
  const name = parts[0] === "apps" || parts[0] === "packages" || parts[0] === "services"
    ? `${parts[0]}/${parts[1] ?? "unknown"}`
    : root;
  return {
    id: `${role}:${name}`,
    kind: role,
    name
  };
}

function boundaryRole(normalizedPath: string): FileRole {
  if (/(^|\/)(web|ui|frontend|client|public|components?|views?|pages)(\/|$)/i.test(normalizedPath) && !/(^|\/)(api|routes?|controllers?|server|backend)(\/|$)/i.test(normalizedPath)) return "client";
  return classifyFileRole(normalizedPath);
}

function buildEntrypoints(files: IndexedFile[]): SecurityEntrypoint[] {
  const entrypoints: SecurityEntrypoint[] = [];
  for (const file of files) {
    for (const route of detectRoutes(file.path, file.content)) {
      const boundary = boundaryForPath(file.path);
      entrypoints.push({
        method: route.method,
        routePath: route.routePath,
        path: file.path,
        line: route.startLine,
        framework: route.frameworkGuess,
        boundary: boundary.id
      });
    }
  }
  return dedupeBy(entrypoints, (item) => `${item.method}:${item.routePath}:${item.path}:${item.line}`).slice(0, 500);
}

function buildDeterministicCatalog(files: IndexedFile[]): SecurityCatalogItem[] {
  const graph = buildSecurityGraph(files);
  const items: SecurityCatalogItem[] = [];
  for (const source of graph.sources) {
    items.push({
      kind: "source",
      name: source.expression,
      path: source.path,
      line: source.line,
      category: "request-input",
      evidence: source.expression,
      discoveredBy: "deterministic"
    });
  }
  for (const sink of graph.sinks) {
    items.push({
      kind: "sink",
      name: sink.sinkId,
      path: sink.path,
      line: sink.line,
      category: sink.category,
      evidence: sink.code,
      discoveredBy: "deterministic"
    });
  }
  for (const file of files) {
    const lines = file.content.split(/\r?\n/);
    for (const [index, line] of lines.entries()) {
      if (sanitizerPattern.test(line)) {
        items.push({
          kind: "sanitizer",
          name: line.trim().slice(0, 120),
          path: file.path,
          line: index + 1,
          category: "sanitizer",
          evidence: line.trim().slice(0, 220),
          discoveredBy: "deterministic"
        });
      }
      if (/\b(requireAuth|isAuthenticated|authorize|isAuthorized|requireRole|requireAdmin|policy|permission|guard|can\?|csrf|jwt\.verify|passport\.authenticate)\b/i.test(line)) {
        items.push({
          kind: "guard",
          name: line.trim().slice(0, 120),
          path: file.path,
          line: index + 1,
          category: "authz",
          evidence: line.trim().slice(0, 220),
          discoveredBy: "deterministic"
        });
      }
    }
  }
  return items;
}

function buildAiCatalog(sourceMap: AiSourceMapForIntelligence | undefined, allowedPaths: Set<string>): SecurityCatalogItem[] {
  const catalog = sourceMap?.catalog;
  if (!catalog) return [];
  return [
    ...toCatalog("source", catalog.sources ?? [], allowedPaths),
    ...toCatalog("sink", catalog.sinks ?? [], allowedPaths),
    ...toCatalog("sanitizer", catalog.sanitizers ?? [], allowedPaths),
    ...toCatalog("guard", catalog.guards ?? [], allowedPaths)
  ];
}

function toCatalog(kind: SecurityCatalogItem["kind"], items: CatalogInputItem[], allowedPaths: Set<string>): SecurityCatalogItem[] {
  return items
    .map((item) => ({ ...item, path: normalizePath(item.path) }))
    .filter((item) => allowedPaths.has(item.path))
    .map((item) => ({
      kind,
      name: item.name.slice(0, 160),
      path: item.path,
      line: item.line ? Number(item.line) : null,
      category: item.category ?? kind,
      evidence: item.evidence ?? item.name,
      discoveredBy: "ai" as const
    }));
}

function buildBoundaries(files: IndexedFile[], entrypoints: SecurityEntrypoint[]): BoundaryInfo[] {
  const groups = new Map<string, BoundaryInfo>();
  for (const file of files) {
    const boundary = boundaryForPath(file.path);
    const existing = groups.get(boundary.id) ?? {
      ...boundary,
      paths: [],
      fileCount: 0,
      entrypointCount: 0
    };
    existing.paths.push(file.path);
    existing.fileCount += 1;
    groups.set(boundary.id, existing);
  }
  for (const entrypoint of entrypoints) {
    const boundary = groups.get(entrypoint.boundary);
    if (boundary) boundary.entrypointCount += 1;
  }
  return [...groups.values()]
    .map((item) => ({ ...item, paths: item.paths.slice(0, 20) }))
    .sort((a, b) => b.entrypointCount - a.entrypointCount || b.fileCount - a.fileCount || a.id.localeCompare(b.id));
}

function rankHighRiskFiles(files: IndexedFile[], scannerResults: ScannerResult[], entrypoints: SecurityEntrypoint[], sourceMap?: AiSourceMapForIntelligence): SecurityIntelligence["highRiskFiles"] {
  const scores = new Map<string, { score: number; reasons: string[] }>();
  const bump = (filePath: string | undefined, amount: number, reason: string) => {
    if (!filePath) return;
    const path = normalizePath(filePath);
    const current = scores.get(path) ?? { score: 0, reasons: [] };
    current.score += amount;
    current.reasons.push(reason);
    scores.set(path, current);
  };
  for (const result of scannerResults) {
    const severityScore: Record<string, number> = { critical: 60, high: 45, medium: 25, low: 8, info: 2 };
    bump(result.path, severityScore[result.severity] ?? 5, `${result.scanner}/${result.ruleId}`);
  }
  for (const entrypoint of entrypoints) bump(entrypoint.path, 20, `${entrypoint.method} ${entrypoint.routePath}`);
  for (const filePath of sourceMap?.globalPriorityFiles ?? []) bump(filePath, 25, "AI source-map priority");
  for (const filePath of Object.values(sourceMap?.priorityFilesByClass ?? {}).flat()) bump(filePath, 20, "AI class priority");
  for (const file of files) if (!scores.has(file.path) && classifyFileRole(file.path, file.language) === "server-runtime") bump(file.path, 5, "server-runtime file");
  return [...scores.entries()]
    .map(([path, item]) => ({ path, score: item.score, reasons: [...new Set(item.reasons)].slice(0, 8) }))
    .sort((a, b) => b.score - a.score || a.path.localeCompare(b.path));
}

function summarize(entrypoints: SecurityEntrypoint[], catalog: SecurityCatalogItem[], boundaries: BoundaryInfo[], highRiskFiles: SecurityIntelligence["highRiskFiles"], negativeEvidence: NegativeEvidence[]): string {
  return [
    `${entrypoints.length} network entrypoints`,
    `${catalog.length} cataloged sources/sinks/sanitizers/guards`,
    `${boundaries.length} code boundaries`,
    `${highRiskFiles.length} prioritized files`,
    `${negativeEvidence.length} remembered negative-evidence items`
  ].join("; ");
}

function dedupeCatalog(items: SecurityCatalogItem[]): SecurityCatalogItem[] {
  return dedupeBy(items, (item) => `${item.kind}:${item.discoveredBy}:${item.path}:${item.line ?? ""}:${item.name}`);
}

function dedupeBy<T>(items: T[], keyFor: (item: T) => string): T[] {
  const seen = new Set<string>();
  return items.filter((item) => {
    const key = keyFor(item);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function normalizePath(filePath: string): string {
  return filePath.replaceAll("\\", "/").replace(/^\.\//, "").replace(/^\/+/, "");
}
