import path from "node:path";
import type { ScannerResult } from "./types.js";
import { safeJsonParse } from "../utils/safeJson.js";
import { runDockerScanner } from "./dockerFallback.js";

export async function runSemgrep(repoPath: string): Promise<{ results: ScannerResult[]; warning?: string }> {
  const result = await runDockerScanner(repoPath, "semgrep/semgrep:latest", ["semgrep", "--json", "--config", "auto", "/src"], 240_000);
  const warningPrefix = result.warning ? `${result.warning}; ` : "";
  const parsed = safeJsonParse<{ results?: any[] }>(result.stdout || "{}");
  if (!parsed) return { results: [], warning: `${warningPrefix}semgrep returned non-JSON output: ${result.stderr || result.stdout.slice(0, 300)}` };
  const results = (parsed.results ?? []).map((item: any): ScannerResult => ({
    scanner: "semgrep",
    ruleId: item.check_id ?? "semgrep",
    title: item.extra?.message ?? item.check_id ?? "Semgrep finding",
    severity: mapSeverity(item.extra?.severity),
    path: normalizeScannerPath(repoPath, item.path ?? ""),
    startLine: item.start?.line,
    endLine: item.end?.line,
    message: item.extra?.message ?? "",
    raw: item
  }));
  return { results, warning: warningPrefix || (result.code && result.code > 1 ? result.stderr : undefined) };
}

function mapSeverity(sev: string): ScannerResult["severity"] {
  const s = String(sev ?? "").toLowerCase();
  if (s === "error") return "high";
  if (s === "warning") return "medium";
  return "low";
}

function normalizeScannerPath(repoPath: string, input: string): string {
  const unix = input.split(path.sep).join("/");
  if (unix.startsWith("/src/")) return unix.slice(5);
  const dockerRel = unix.replace(/^(?:\.\.\/)+src\//, "");
  if (dockerRel !== unix) return dockerRel;
  return path.isAbsolute(input) ? path.relative(repoPath, input).split(path.sep).join("/") : unix;
}
