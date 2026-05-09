import type { ScannerResult } from "./types.js";
import { safeJsonParse } from "../utils/safeJson.js";
import { runDockerScanner } from "./dockerFallback.js";

export async function runOsv(repoPath: string): Promise<{ results: ScannerResult[]; warning?: string }> {
  const result = await runDockerScanner(repoPath, "ghcr.io/google/osv-scanner:latest", ["--format", "json", "--recursive", "/src"], 240_000);
  const warningPrefix = result.warning ? `${result.warning}; ` : "";
  const parsed = safeJsonParse<{ results?: any[] }>(result.stdout || "{}");
  if (!parsed) return { results: [], warning: `${warningPrefix}osv-scanner returned non-JSON output: ${result.stderr || result.stdout.slice(0, 300)}` };
  const results: ScannerResult[] = [];
  for (const item of parsed.results ?? []) {
    for (const pkg of item.packages ?? []) {
      for (const vuln of pkg.vulnerabilities ?? []) {
        const packageName = pkg.package?.name ?? pkg.package?.purl ?? pkg.name ?? "unknown";
        results.push({ scanner: "osv-scanner", ruleId: vuln.id, title: vuln.summary ?? vuln.id, category: "dependency", severity: "high", path: normalizeScannerPath(item.source?.path ?? ""), message: vuln.summary ?? "", raw: { ...vuln, PkgName: packageName } });
      }
    }
  }
  return { results, warning: warningPrefix || (result.code && result.code !== 1 ? result.stderr : undefined) };
}

function normalizeScannerPath(input: string): string {
  const unix = input.replaceAll("\\", "/");
  if (unix.startsWith("/src/")) return unix.slice(5);
  return unix.replace(/^(?:\.\.\/)+src\//, "");
}
