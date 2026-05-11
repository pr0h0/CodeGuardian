import crypto from "node:crypto";
import type { Finding, ScannerResult } from "../scanners/types.js";

export function scannerFingerprint(result: ScannerResult): string {
  return hash([
    "scanner",
    result.scanner,
    result.ruleId,
    normalizePath(result.path),
    normalizeLine(result.startLine),
    normalizeTitle(result.title)
  ]);
}

export function findingFingerprint(finding: Finding): string {
  return hash([
    "finding",
    finding.category,
    finding.severity,
    normalizePath(finding.path),
    normalizeLine(finding.startLine),
    normalizeTitle(finding.title),
    String(finding.sink ?? finding.scannerSource ?? "")
  ]);
}

export function attachScannerFingerprints(results: ScannerResult[]): ScannerResult[] {
  return results.map((result) => ({ ...result, fingerprint: scannerFingerprint(result) }) as ScannerResult);
}

export function attachFindingFingerprints(findings: Finding[]): Finding[] {
  return findings.map((finding) => ({ ...finding, fingerprint: findingFingerprint(finding) }) as Finding);
}

function normalizePath(value?: string): string {
  return String(value ?? "").replaceAll("\\", "/").replace(/^\.\//, "");
}

function normalizeLine(value?: number): string {
  if (!value) return "";
  return String(Math.max(1, Math.floor(value / 5) * 5));
}

function normalizeTitle(value?: string): string {
  return String(value ?? "").toLowerCase().replace(/\b(candidate|detected|finding|usage of)\b/g, "").replace(/\s+/g, " ").trim();
}

function hash(parts: unknown[]): string {
  return crypto.createHash("sha256").update(parts.join("|")).digest("hex").slice(0, 16);
}
