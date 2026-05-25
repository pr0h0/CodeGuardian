import type { Finding } from "../scanners/types.js";
import {
  actionabilityBonus,
  appendDeduplicationNote,
  exactFindingKey,
  mergeRaw,
  semanticFamily,
  semanticGroupKey
} from "./semanticDedupe.js";

const SEVERITY_WEIGHT: Record<string, number> = { critical: 500, high: 400, medium: 300, low: 200, info: 100 };
const STATUS_WEIGHT: Record<string, number> = {
  confirmed_true_positive: 90,
  confirmed: 85,
  likely_true_positive: 75,
  security_hotspot: 65,
  needs_context: 60,
  needs_dynamic_test: 55,
  suspected: 50,
  false_positive: 0
};
const CONFIDENCE_WEIGHT: Record<string, number> = { confirmed: 40, high: 30, medium: 20, low: 0 };

export function dedupeFindings(findings: Finding[]): Finding[] {
  const groups = new Map<string, Finding[]>();

  for (const finding of findings) {
    const key = semanticGroupKey(finding) ?? `exact|${exactFindingKey(finding)}`;
    groups.set(key, [...(groups.get(key) ?? []), finding]);
  }

  return [...groups.values()].map(mergeFindingGroup);
}

export function mergeFindingGroup(group: Finding[]): Finding {
  if (group.length === 1) return group[0];

  const representative = bestFinding(group);
  const duplicates = group.filter((finding) => finding !== representative);
  const family = semanticFamily(representative) ?? "exact";
  const duplicateSummaries = duplicates.map(findingSummary);

  return {
    ...representative,
    evidence: mergeEvidence(group),
    reasoning: appendDeduplicationNote(representative.reasoning, duplicates.length, duplicateSummaries),
    raw: mergeRaw(representative.raw, {
      deduplicatedBy: "semantic-noise-reduction",
      family,
      deduplicatedCount: duplicates.length,
      kept: findingSummary(representative),
      deduplicatedFrom: duplicateSummaries
    })
  };
}

function bestFinding(group: Finding[]): Finding {
  return [...group].sort((a, b) => findingWeight(b) - findingWeight(a))[0];
}

function findingWeight(finding: Finding): number {
  return (SEVERITY_WEIGHT[finding.severity] ?? 0)
    + (STATUS_WEIGHT[finding.status] ?? 0)
    + (CONFIDENCE_WEIGHT[finding.confidence] ?? 0)
    + actionabilityBonus(finding)
    + (finding.exploitabilityScore ?? 0);
}

function mergeEvidence(group: Finding[]): unknown[] {
  const seen = new Set<string>();
  const merged: unknown[] = [];
  for (const finding of group) {
    for (const evidence of finding.evidence ?? []) {
      const key = stableEvidenceKey(evidence);
      if (seen.has(key)) continue;
      seen.add(key);
      merged.push(evidence);
    }
  }
  return merged.slice(0, 30);
}

function stableEvidenceKey(value: unknown): string {
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function findingSummary(finding: Finding): Record<string, unknown> {
  return {
    title: finding.title,
    category: finding.category,
    severity: finding.severity,
    confidence: finding.confidence,
    status: finding.status,
    path: finding.path,
    startLine: finding.startLine,
    scannerSource: finding.scannerSource,
    fingerprint: finding.fingerprint
  };
}
