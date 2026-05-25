import { SEVERITY_ORDER } from "../config/defaults.js";
import type { ReportFilters } from "../config/projectConfig.js";

type Row = Record<string, any>;

const CONFIDENCE_ORDER = ["confirmed", "high", "medium", "low"] as const;

export interface ReportFilterResult<T extends Row> {
  findings: T[];
  filteredCount: number;
}

export function applyReportFilters<T extends Row>(findings: T[], filters: ReportFilters | undefined): ReportFilterResult<T> {
  if (!filters?.minSeverity && !filters?.minConfidence) return { findings, filteredCount: 0 };
  const filtered = findings.filter((finding) => reportFindingAllowed(finding, filters));
  return { findings: filtered, filteredCount: findings.length - filtered.length };
}

function reportFindingAllowed(finding: Row, filters: ReportFilters): boolean {
  if (filters.minSeverity && !meetsThreshold(String(finding.severity ?? ""), filters.minSeverity, SEVERITY_ORDER)) return false;
  if (filters.minConfidence && !meetsThreshold(String(finding.confidence ?? ""), filters.minConfidence, CONFIDENCE_ORDER)) return false;
  return true;
}

function meetsThreshold(value: string, threshold: string, order: readonly string[]): boolean {
  const valueIndex = order.indexOf(value);
  const thresholdIndex = order.indexOf(threshold);
  if (thresholdIndex === -1) return true;
  if (valueIndex === -1) return false;
  return valueIndex <= thresholdIndex;
}
