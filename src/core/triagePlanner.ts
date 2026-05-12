import type { ScannerResult } from "../scanners/types.js";

const TRIAGED_SEVERITIES = new Set(["critical", "high", "medium"]);

export function planAiTriageCandidates(scannerResults: ScannerResult[], maxCandidates: number): ScannerResult[] {
  if (maxCandidates <= 0) return [];
  const sorted = scannerResults
    .filter(isAiTriageCandidate)
    .sort((a, b) => scoreScannerResult(b) - scoreScannerResult(a));
  return breadthFirstByGroup(sorted).slice(0, maxCandidates);
}

export function isAiTriageCandidate(result: ScannerResult): boolean {
  return TRIAGED_SEVERITIES.has(result.severity)
    && result.scanner !== "quality"
    && result.scanner !== "compliance"
    && !isDependencyVulnerabilityScannerResult(result);
}

export function isDependencyVulnerabilityScannerResult(result: ScannerResult): boolean {
  if (result.scanner !== "trivy" && result.scanner !== "osv-scanner") return false;
  const raw = result.raw && typeof result.raw === "object" ? result.raw as Record<string, unknown> : {};
  return Boolean(
    raw.VulnerabilityID
    || raw.id
    || /^CVE-\d{4}-\d+$/i.test(result.ruleId)
    || /^GHSA-/i.test(result.ruleId)
  );
}

export function scoreScannerResult(result: { scanner: string; severity: string; category?: string; path?: string; raw?: unknown }): number {
  const severityScore: Record<string, number> = { critical: 100, high: 80, medium: 50, low: 20, info: 5 };
  let score = severityScore[result.severity] ?? 10;
  if (["correlation", "taint-flow", "taint-lite", "gitleaks", "config-checks"].includes(result.scanner)) score += 12;
  if (/(route|controller|auth|admin|api|bin\/|cli|command|worker|job)/i.test(result.path ?? "")) score += 10;
  if (["command-injection", "deserialization", "ssrf", "secrets"].includes(result.category ?? "")) score += 8;
  if (String(JSON.stringify(result.raw ?? {})).includes("sourceLine")) score += 8;
  return score;
}

function breadthFirstByGroup(results: ScannerResult[]): ScannerResult[] {
  const groups = new Map<string, ScannerResult[]>();
  for (const result of results) {
    const key = `${result.scanner}|${result.ruleId}|${result.severity}|${result.path ?? ""}`;
    groups.set(key, [...(groups.get(key) ?? []), result]);
  }

  const orderedGroups = [...groups.values()];
  const output: ScannerResult[] = [];
  let added = true;
  for (let index = 0; added; index++) {
    added = false;
    for (const group of orderedGroups) {
      const item = group[index];
      if (!item) continue;
      output.push(item);
      added = true;
    }
  }
  return output;
}
