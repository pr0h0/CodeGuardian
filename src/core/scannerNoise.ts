import type { ScannerResult } from "../scanners/types.js";
import { scoreScannerResult } from "./triagePlanner.js";
import {
  actionabilityBonus,
  appendDeduplicationNote,
  mergeRaw,
  scannerSummary,
  semanticFamily,
  semanticGroupKey
} from "./semanticDedupe.js";

const SEVERITY_WEIGHT: Record<string, number> = { critical: 500, high: 400, medium: 300, low: 200, info: 100 };
const SCANNER_WEIGHT: Record<string, number> = {
  "taint-flow": 55,
  "taint-lite": 50,
  "config-checks": 45,
  bearer: 40,
  semgrep: 35,
  "custom-rules": 30,
  gitleaks: 30
};

export function reduceScannerResultNoise(results: ScannerResult[]): ScannerResult[] {
  const groups = new Map<string, ScannerResult[]>();

  for (const result of results) {
    const key = dedupeKey(result);
    groups.set(key, [...(groups.get(key) ?? []), result]);
  }

  return [...groups.values()].map(mergeScannerGroup);
}

function dedupeKey(result: ScannerResult): string {
  if (result.scanner === "compliance" || result.scanner === "correlation") return `unique|${result.scanner}|${result.ruleId}|${result.path ?? ""}|${result.startLine ?? ""}`;
  return semanticGroupKey(result) ?? `unique|${result.scanner}|${result.ruleId}|${result.path ?? ""}|${result.startLine ?? ""}`;
}

function mergeScannerGroup(group: ScannerResult[]): ScannerResult {
  if (group.length === 1) return group[0];

  const representative = bestScannerResult(group);
  const duplicates = group.filter((result) => result !== representative);
  const duplicateSummaries = duplicates.map(scannerSummary);

  return {
    ...representative,
    message: appendDeduplicationNote(representative.message, duplicates.length, duplicateSummaries),
    raw: mergeRaw(representative.raw, {
      deduplicatedBy: "semantic-noise-reduction",
      family: semanticFamily(representative) ?? "exact",
      deduplicatedCount: duplicates.length,
      kept: scannerSummary(representative),
      deduplicatedFrom: duplicateSummaries
    })
  };
}

function bestScannerResult(group: ScannerResult[]): ScannerResult {
  return [...group].sort((a, b) => scannerWeight(b) - scannerWeight(a))[0];
}

function scannerWeight(result: ScannerResult): number {
  return (SEVERITY_WEIGHT[result.severity] ?? 0)
    + (SCANNER_WEIGHT[result.scanner] ?? 0)
    + actionabilityBonus(result)
    + scoreScannerResult(result);
}
