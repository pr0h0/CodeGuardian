import path from "node:path";
import type { ScannerResult } from "./types.js";
import { safeJsonParse } from "../utils/safeJson.js";
import { runDockerScanner } from "./dockerFallback.js";

export async function runBearer(repoPath: string): Promise<{ results: ScannerResult[]; warning?: string }> {
  const result = await runDockerScanner(repoPath, "bearer/bearer:latest", ["scan", "/src", "--format", "json"], 360_000);
  const warningPrefix = result.warning ? `${result.warning}; ` : "";
  const parsed = safeJsonParse<any>(result.stdout || "{}");
  if (!parsed) return { results: [], warning: `${warningPrefix}bearer returned non-JSON output: ${result.stderr || result.stdout.slice(0, 300)}` };
  const findings = flattenBearerFindings(parsed);
  return {
    results: findings.map((item: any): ScannerResult => ({
      scanner: "bearer",
      ruleId: String(item.rule_id ?? item.ruleId ?? item.id ?? item.check_id ?? "bearer"),
      title: String(item.title ?? item.message ?? item.description ?? item.rule?.title ?? "Bearer finding"),
      category: bearerCategory(item),
      severity: mapSeverity(item.severity ?? item.level ?? item.impact),
      path: normalizeScannerPath(repoPath, item.filename ?? item.file ?? item.path ?? item.location?.filename ?? item.location?.file ?? ""),
      startLine: Number(item.line_number ?? item.line ?? item.start_line ?? item.location?.line_number ?? item.location?.line) || undefined,
      endLine: Number(item.end_line ?? item.location?.end_line ?? item.line_number ?? item.line) || undefined,
      message: String(item.description ?? item.message ?? item.title ?? "Bearer finding"),
      raw: item
    })),
    warning: warningPrefix || (result.code && result.code > 1 ? result.stderr : undefined)
  };
}

function flattenBearerFindings(parsed: any): any[] {
  if (Array.isArray(parsed)) return parsed;
  if (Array.isArray(parsed.findings)) return parsed.findings;
  if (Array.isArray(parsed.results)) return parsed.results;
  if (Array.isArray(parsed.issues)) return parsed.issues;
  const severityBuckets = ["critical", "high", "medium", "low", "warning"];
  const bucketed = severityBuckets.flatMap((key) => Array.isArray(parsed[key]) ? parsed[key].map((item: any) => ({ ...item, severity: item.severity ?? key })) : []);
  if (bucketed.length) return bucketed;
  if (parsed.report && typeof parsed.report === "object") return flattenBearerFindings(parsed.report);
  return [];
}

function bearerCategory(item: any): string {
  const text = `${item.category ?? ""} ${item.rule?.category ?? ""} ${item.title ?? ""} ${item.description ?? ""}`.toLowerCase();
  if (/secret|token|key|credential/.test(text)) return "secrets";
  if (/sql|injection|command/.test(text)) return "injection";
  if (/xss|html|cross-site/.test(text)) return "xss";
  if (/ssrf|request|url/.test(text)) return "ssrf";
  if (/privacy|pii|data/.test(text)) return "privacy";
  if (/crypto|encrypt|hash/.test(text)) return "weak-crypto";
  return "security";
}

function mapSeverity(sev: string): ScannerResult["severity"] {
  const s = String(sev ?? "").toLowerCase();
  if (["critical", "high", "medium", "low"].includes(s)) return s as ScannerResult["severity"];
  if (s === "warning") return "low";
  return "info";
}

function normalizeScannerPath(repoPath: string, input: string): string {
  const unix = String(input).split(path.sep).join("/");
  if (unix.startsWith("/src/")) return unix.slice(5);
  const dockerRel = unix.replace(/^(?:\.\.\/)+src\//, "");
  if (dockerRel !== unix) return dockerRel;
  return path.isAbsolute(input) ? path.relative(repoPath, input).split(path.sep).join("/") : unix;
}
