import path from "node:path";
import type { ScannerResult } from "./types.js";
import { redactSecrets } from "../utils/redact.js";
import { safeJsonParse } from "../utils/safeJson.js";
import { runDockerScanner } from "./dockerFallback.js";

export async function runGitleaks(repoPath: string): Promise<{ results: ScannerResult[]; warning?: string }> {
  const result = await runDockerScanner(repoPath, "zricethezav/gitleaks:latest", ["detect", "--source", "/src", "--no-git", "--report-format", "json", "--no-banner"], 180_000);
  const warningPrefix = result.warning ? `${result.warning}; ` : "";
  const parsed = safeJsonParse<any[]>(result.stdout || "[]");
  if (!parsed) return { results: [], warning: `${warningPrefix}gitleaks returned non-JSON output: ${result.stderr || result.stdout.slice(0, 300)}` };
  return {
    results: parsed.map((item: any): ScannerResult => ({
      scanner: "gitleaks",
      ruleId: item.RuleID ?? "secret",
      title: "Secret detected",
      category: "secrets",
      severity: "high",
      path: normalizeScannerPath(repoPath, item.File ?? ""),
      startLine: item.StartLine,
      endLine: item.EndLine,
      message: redactSecrets(item.Description ?? "Secret candidate detected"),
      raw: { ...item, Secret: "[REDACTED]", Match: redactSecrets(item.Match ?? "") }
    })),
    warning: warningPrefix || (result.code && result.code !== 1 ? result.stderr : undefined)
  };
}

function normalizeScannerPath(repoPath: string, input: string): string {
  const unix = input.split(path.sep).join("/");
  if (unix.startsWith("/src/")) return unix.slice(5);
  const dockerRel = unix.replace(/^(?:\.\.\/)+src\//, "");
  if (dockerRel !== unix) return dockerRel;
  return path.isAbsolute(input) ? path.relative(repoPath, input).split(path.sep).join("/") : unix;
}
