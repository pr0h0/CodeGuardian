import type { IndexedFile } from "./repoIndexer.js";
import type { ScannerResult } from "../scanners/types.js";
import { lineSlice } from "../utils/lineMap.js";
import { redactSecrets } from "../utils/redact.js";
import { extractImports } from "./importGraph.js";
import { extractSymbols } from "./symbolExtractor.js";
import { detectRoutes } from "./routeDetector.js";

export interface ContextPack {
  scannerResult: Omit<ScannerResult, "raw">;
  snippets: Array<{ path: string; startLine: number; endLine: number; content: string }>;
  imports: string[];
  nearbySymbols: Array<{ name: string; kind: string; startLine: number; endLine: number; signature: string }>;
  routes: Array<{ method: string; routePath: string; startLine: number; frameworkGuess: string }>;
  configHints: Array<{ path: string; line: number; note: string }>;
  relatedResults: Array<Omit<ScannerResult, "raw">>;
  scannerNegatives: string[];
  aiInstructions?: string;
  requestedContext?: unknown;
}

export function buildContextPack(result: ScannerResult, files: IndexedFile[], results: ScannerResult[], maxChars: number, aiInstructions = ""): ContextPack {
  const target = files.find((file) => file.path === result.path);
  const snippets = [];
  let imports: string[] = [];
  let nearbySymbols: ContextPack["nearbySymbols"] = [];
  let routes: ContextPack["routes"] = [];
  let configHints: ContextPack["configHints"] = [];
  if (target) {
    const start = Math.max(1, (result.startLine ?? 1) - 25);
    const end = Math.min(target.lineCount, (result.endLine ?? result.startLine ?? 1) + 25);
    const isEnvFile = /(^|\/)\.env($|\.|\/)/.test(target.path);
    const isDependencyLock = /(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|Gemfile\.lock|poetry\.lock|go\.sum|Cargo\.lock)$/i.test(target.path);
    const content = isEnvFile
      ? "[REDACTED ENV FILE CONTENT]"
      : isDependencyLock
        ? "[DEPENDENCY LOCKFILE CONTENT OMITTED; scanner result metadata retained]"
        : redactSecrets(lineSlice(target.content, start, end)).slice(0, 12_000);
    snippets.push({ path: target.path, startLine: start, endLine: end, content });
    imports = extractImports(target.content).slice(0, 40);
    nearbySymbols = extractSymbols(target.content)
      .filter((symbol) => Math.abs(symbol.startLine - (result.startLine ?? 1)) <= 80)
      .slice(0, 20)
      .map((symbol) => ({ name: symbol.name, kind: symbol.kind, startLine: symbol.startLine, endLine: symbol.endLine, signature: symbol.signature }));
    routes = detectRoutes(target.path, target.content)
      .filter((route) => Math.abs(route.startLine - (result.startLine ?? 1)) <= 120)
      .slice(0, 20)
      .map((route) => ({ method: route.method, routePath: route.routePath, startLine: route.startLine, frameworkGuess: route.frameworkGuess }));
    configHints = target.content.split(/\r?\n/).flatMap((line, index) => /(process\.env|import\.meta\.env|os\.environ|dotenv|config|secret|token|password)/i.test(line)
      ? [{ path: target.path, line: index + 1, note: redactSecrets(line.trim()).slice(0, 240) }]
      : []).slice(0, 20);
  }
  let pack: ContextPack = { scannerResult: compactResult(result), snippets, imports, nearbySymbols, routes, configHints, relatedResults: results.filter((item) => item.path === result.path).slice(0, 10).map(compactResult), scannerNegatives: scannerNegatives(result, results), aiInstructions: aiInstructions || undefined };
  while (JSON.stringify(pack).length > maxChars && pack.snippets.length > 0) {
    const snippet = pack.snippets[0];
    const mid = Math.floor((snippet.startLine + snippet.endLine) / 2);
    pack = { ...pack, snippets: [{ ...snippet, startLine: Math.max(snippet.startLine, mid - 10), endLine: Math.min(snippet.endLine, mid + 10) }] };
  }
  return pack;
}

function scannerNegatives(result: ScannerResult, results: ScannerResult[]): string[] {
  const scanners = ["semgrep", "bearer", "custom-rules", "taint-lite", "config-checks"];
  const samePath = results.filter((item) => item.path === result.path);
  return scanners.filter((scanner) => !samePath.some((item) => item.scanner === scanner)).map((scanner) => `No ${scanner} result recorded for this file in current scan.`);
}

function compactResult(result: ScannerResult): Omit<ScannerResult, "raw"> {
  return {
    scanner: result.scanner,
    ruleId: result.ruleId,
    title: result.title.slice(0, 500),
    category: result.category,
    severity: result.severity,
    path: result.path,
    startLine: result.startLine,
    endLine: result.endLine,
    message: result.message.slice(0, 1000)
  };
}
