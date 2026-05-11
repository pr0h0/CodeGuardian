import type { Severity } from "../config/defaults.js";

export interface ScannerResult {
  scanner: string;
  ruleId: string;
  title: string;
  category?: string;
  severity: Severity;
  path?: string;
  startLine?: number;
  endLine?: number;
  message: string;
  fingerprint?: string;
  raw?: unknown;
}

export interface Finding {
  title: string;
  category: string;
  severity: Severity;
  confidence: "confirmed" | "high" | "medium" | "low";
  status: "confirmed" | "suspected" | "needs_dynamic_test" | "false_positive";
  path?: string;
  startLine?: number;
  endLine?: number;
  source?: string;
  sink?: string;
  evidence: unknown[];
  reasoning: string;
  remediation: string;
  scannerSource?: string;
  fingerprint?: string;
  baselineStatus?: "new" | "unchanged" | "resolved";
  exploitabilityScore?: number;
  raw?: unknown;
}

export interface ToolStatus {
  name: string;
  available: boolean;
  version?: string;
  error?: string;
}

export interface ScannerRunResult {
  results: ScannerResult[];
  warning?: string;
  code?: number | null;
}
