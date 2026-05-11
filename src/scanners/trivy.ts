import path from "node:path";
import type { ScannerResult, ScannerRunResult } from "./types.js";
import { safeJsonParse } from "../utils/safeJson.js";
import { runDockerScanner, scannerImages } from "./dockerFallback.js";

export async function runTrivy(repoPath: string, timeoutMs = 300_000): Promise<ScannerRunResult> {
  const result = await runDockerScanner(repoPath, scannerImages().trivy, ["fs", "--format", "json", "--scanners", "vuln,secret,misconfig", "/src"], timeoutMs);
  const warningPrefix = result.warning ? `${result.warning}; ` : "";
  const parsed = safeJsonParse<{ Results?: any[] }>(result.stdout || "{}");
  if (!parsed) return { results: [], warning: `${warningPrefix}trivy returned non-JSON output: ${result.stderr || result.stdout.slice(0, 300)}` };
  const results: ScannerResult[] = [];
  for (const section of parsed.Results ?? []) {
    for (const vuln of section.Vulnerabilities ?? []) {
      results.push({ scanner: "trivy", ruleId: vuln.VulnerabilityID, title: vuln.Title ?? vuln.VulnerabilityID, category: "dependency", severity: map(vuln.Severity), path: normalizeScannerPath(repoPath, section.Target ?? ""), message: vuln.Description ?? "", raw: vuln });
    }
    for (const secret of section.Secrets ?? []) {
      results.push({ scanner: "trivy", ruleId: secret.RuleID, title: secret.Title ?? "Secret detected", category: "secrets", severity: map(secret.Severity), path: normalizeScannerPath(repoPath, section.Target ?? ""), startLine: secret.StartLine, endLine: secret.EndLine, message: secret.Title ?? "", raw: secret });
    }
    for (const mis of section.Misconfigurations ?? []) {
      results.push({ scanner: "trivy", ruleId: mis.ID, title: mis.Title ?? mis.ID, category: "misconfiguration", severity: map(mis.Severity), path: normalizeScannerPath(repoPath, section.Target ?? ""), message: mis.Message ?? mis.Description ?? "", raw: mis });
    }
  }
  return { results, warning: warningPrefix || (result.code ? result.stderr : undefined), code: result.code };
}

function map(sev: string): ScannerResult["severity"] {
  const s = String(sev ?? "").toLowerCase();
  if (["critical", "high", "medium", "low"].includes(s)) return s as ScannerResult["severity"];
  return "info";
}

function normalizeScannerPath(repoPath: string, input: string): string {
  const unix = input.split(path.sep).join("/");
  if (unix.startsWith("/src/")) return unix.slice(5);
  const dockerRel = unix.replace(/^(?:\.\.\/)+src\//, "");
  if (dockerRel !== unix) return dockerRel;
  return path.isAbsolute(input) ? path.relative(repoPath, input).split(path.sep).join("/") : unix;
}
