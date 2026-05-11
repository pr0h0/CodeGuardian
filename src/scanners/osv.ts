import type { ScannerResult, ScannerRunResult } from "./types.js";
import { safeJsonParse } from "../utils/safeJson.js";
import { runDockerScanner, scannerImages } from "./dockerFallback.js";

export async function runOsv(repoPath: string, timeoutMs = 240_000): Promise<ScannerRunResult> {
  const result = await runDockerScanner(repoPath, scannerImages()["osv-scanner"], ["--format", "json", "--recursive", "/src"], timeoutMs);
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
  const stderr = result.stderr.trim();
  const benign = /no package sources found|failed to resolve gitignore/i.test(stderr);
  const warning = warningPrefix || (result.code && /error|failed|permission|invalid|denied|panic/i.test(stderr) && !benign ? stderr : undefined);
  return { results, warning, code: result.code };
}

function normalizeScannerPath(input: string): string {
  const unix = input.replaceAll("\\", "/");
  if (unix.startsWith("/src/")) return unix.slice(5);
  return unix.replace(/^(?:\.\.\/)+src\//, "");
}
