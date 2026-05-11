import fs from "node:fs";
import path from "node:path";
import type { IndexedFile } from "../repo/repoIndexer.js";
import type { ScannerResult } from "./types.js";

export interface SuppressionSummary {
  suppressed: number;
  reasons: string[];
}

interface SuppressionState {
  ignoredPaths: string[];
  fileMap: Map<string, IndexedFile>;
}

export function applySuppressions(repoPath: string, files: IndexedFile[], results: ScannerResult[]): { results: ScannerResult[]; summary: SuppressionSummary } {
  const state: SuppressionState = {
    ignoredPaths: readIgnoreFile(repoPath),
    fileMap: new Map(files.map((file) => [file.path, file]))
  };
  const reasons: string[] = [];
  const kept = results.filter((result) => {
    const reason = suppressionReason(state, result);
    if (reason) reasons.push(reason);
    return !reason;
  });
  return { results: kept, summary: { suppressed: results.length - kept.length, reasons: reasons.slice(0, 100) } };
}

function suppressionReason(state: SuppressionState, result: ScannerResult): string | undefined {
  const filePath = result.path ?? "";
  if (!filePath) return undefined;
  if (state.ignoredPaths.some((pattern) => matchesIgnore(filePath, pattern))) return `${result.ruleId} ignored by .codeguardianignore at ${filePath}`;
  const file = state.fileMap.get(filePath);
  if (!file || !result.startLine) return undefined;
  const lines = file.content.split(/\r?\n/);
  if (rangeDisabled(lines, result.startLine, result.ruleId)) return `${result.ruleId} suppressed by disable/enable block at ${filePath}:${result.startLine}`;
  const previous = lines[Math.max(0, result.startLine - 2)] ?? "";
  const current = lines[Math.max(0, result.startLine - 1)] ?? "";
  if (inlineSuppresses(previous, result.ruleId, true)) return `${result.ruleId} suppressed by previous-line comment at ${filePath}:${result.startLine}`;
  if (inlineSuppresses(current, result.ruleId, false)) return `${result.ruleId} suppressed by same-line comment at ${filePath}:${result.startLine}`;
  return undefined;
}

function rangeDisabled(lines: string[], lineNo: number, ruleId: string): boolean {
  const disabled = new Set<string>();
  for (let i = 0; i < Math.min(lineNo, lines.length); i++) {
    const line = lines[i];
    const disable = line.match(/codeguardian:disable\s+([A-Za-z0-9_./*-]+)/i);
    const enable = line.match(/codeguardian:enable\s+([A-Za-z0-9_./*-]+)/i);
    if (disable) disabled.add(disable[1]);
    if (enable) disabled.delete(enable[1]);
  }
  return disabled.has(ruleId) || disabled.has("all") || disabled.has("*");
}

function inlineSuppresses(line: string, ruleId: string, previousLine: boolean): boolean {
  const lower = line.toLowerCase();
  if (previousLine && !lower.includes("codeguardian-disable-next-line")) return false;
  if (!previousLine && !lower.includes("codeguardian-disable-line")) return false;
  return lower.includes(ruleId.toLowerCase()) || lower.includes(" all") || /codeguardian-disable-(?:next-)?line\s*($|--|#|\/\/)/i.test(line);
}

function readIgnoreFile(repoPath: string): string[] {
  const file = path.join(repoPath, ".codeguardianignore");
  if (!fs.existsSync(file)) return [];
  return fs.readFileSync(file, "utf8").split(/\r?\n/).map((line) => line.trim()).filter((line) => line && !line.startsWith("#"));
}

function matchesIgnore(filePath: string, pattern: string): boolean {
  const normalized = filePath.replaceAll("\\", "/");
  const clean = pattern.replaceAll("\\", "/").replace(/^\/+/, "");
  if (clean.endsWith("/")) return normalized.startsWith(clean);
  if (clean.includes("*")) {
    const regex = new RegExp(`^${clean.split("*").map(escapeRegex).join(".*")}$`);
    return regex.test(normalized);
  }
  return normalized === clean || normalized.startsWith(`${clean}/`) || normalized.endsWith(`/${clean}`);
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
