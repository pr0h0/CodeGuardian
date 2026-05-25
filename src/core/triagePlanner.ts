import type { ScannerResult } from "../scanners/types.js";
import type { VulnerabilityClass } from "../config/projectConfig.js";
import { classifyFileRole, fileRoleScore } from "../repo/fileRole.js";

const TRIAGED_SEVERITIES = new Set(["critical", "high", "medium"]);

export function planAiTriageCandidates(scannerResults: ScannerResult[], maxCandidates: number, vulnerabilityClasses: VulnerabilityClass[] = []): ScannerResult[] {
  if (maxCandidates <= 0) return [];
  const sorted = scannerResults
    .filter(isAiTriageCandidate)
    .filter((result) => resultMatchesVulnerabilityClasses(result, vulnerabilityClasses))
    .sort((a, b) => scoreScannerResult(b) - scoreScannerResult(a));
  return breadthFirstByGroup(sorted).slice(0, maxCandidates);
}

export function isAiTriageCandidate(result: ScannerResult): boolean {
  return TRIAGED_SEVERITIES.has(result.severity)
    && result.scanner !== "quality"
    && result.scanner !== "compliance"
    && !isDependencyVulnerabilityScannerResult(result);
}

export function isDependencyVulnerabilityScannerResult(result: ScannerResult): boolean {
  if (result.scanner !== "trivy" && result.scanner !== "osv-scanner") return false;
  const raw = result.raw && typeof result.raw === "object" ? result.raw as Record<string, unknown> : {};
  return Boolean(
    raw.VulnerabilityID
    || raw.id
    || /^CVE-\d{4}-\d+$/i.test(result.ruleId)
    || /^GHSA-/i.test(result.ruleId)
  );
}

export function scoreScannerResult(result: { scanner: string; ruleId?: string; severity: string; category?: string; path?: string; raw?: unknown }): number {
  const severityScore: Record<string, number> = { critical: 100, high: 80, medium: 50, low: 20, info: 5 };
  let score = severityScore[result.severity] ?? 10;
  const role = classifyFileRole(result.path ?? "");
  score += fileRoleScore(role);
  if (["correlation", "taint-flow", "taint-lite", "gitleaks", "config-checks"].includes(result.scanner)) score += 12;
  if (result.scanner === "source-patterns") score += 35;
  if (/(route|controller|auth|admin|api|bin\/|cli|command|worker|job)/i.test(result.path ?? "")) score += 10;
  if (["command-injection", "deserialization", "ssrf", "secrets", "xxe", "file-upload", "open-redirect", "business-logic", "authorization"].includes(result.category ?? "")) score += 8;
  if (String(JSON.stringify(result.raw ?? {})).includes("sourceLine")) score += 8;
  if (/generic-secret-assignment/i.test(result.ruleId ?? "")) score -= 20;
  return score;
}

export function resultMatchesVulnerabilityClasses(result: ScannerResult, vulnerabilityClasses: VulnerabilityClass[]): boolean {
  if (!vulnerabilityClasses.length) return true;
  const text = `${result.scanner} ${result.ruleId} ${result.title} ${result.category ?? ""} ${result.path ?? ""} ${result.message} ${JSON.stringify(result.raw ?? {})}`.toLowerCase();
  return vulnerabilityClasses.some((vulnerabilityClass) => classMatchers[vulnerabilityClass].test(text));
}

const classMatchers: Record<VulnerabilityClass, RegExp> = {
  injection: /\b(sql|nosql|command|cmd|injection|rce|exec|eval|template|ssti|deserial|prototype|xpath|ldap)\b/,
  xss: /\b(xss|cross[- ]site|html|dom|script|innerhtml|dangerouslysetinnerhtml|template)\b/,
  auth: /\b(auth|authentication|login|logout|session|jwt|token|password|credential|csrf|mfa|oauth|oidc|sso)\b/,
  authz: /\b(authz|authorization|authorisation|access[- ]?control|idor|tenant|role|permission|privilege|admin|object[- ]?level)\b/,
  ssrf: /\b(ssrf|server[- ]side request forgery|metadata|169\.254|outbound|webhook|fetch|axios|http client|url fetch|internal service)\b/,
  exposure: /\b(secret|credential|password|token|api[_ -]?key|data exposure|information disclosure|log|backup|export|debug|metrics|pii|personal data)\b/,
  validation: /\b(validation|input|upload|file|path|traversal|redirect|coupon|quantity|size|type|extension|mime|archive|zip)\b/,
  dependency: /\b(dependency|package|library|component|cve|ghsa|supply chain|prototype|deserial|vulnerable)\b/,
  crypto: /\b(crypto|cryptographic|hash|md5|sha1|jwt|signature|signing|hmac|cipher|encrypt|decrypt|tls|ssl)\b/,
  misconfig: /\b(misconfig|configuration|cors|csrf|cookie|session|header|helmet|debug|metrics|deprecated|default)\b/,
  xxe: /\b(xxe|xml external|xml|doctype|entity|noent|libxml|parsexml|sax|documentbuilder)\b/,
  "business-logic": /\b(business|logic|basket|cart|order|checkout|payment|coupon|discount|review|feedback|deluxe|workflow|race|quantity|price)\b/
};

function breadthFirstByGroup(results: ScannerResult[]): ScannerResult[] {
  const groups = new Map<string, ScannerResult[]>();
  for (const result of results) {
    const key = `${result.scanner}|${result.ruleId}|${result.severity}|${result.path ?? ""}`;
    groups.set(key, [...(groups.get(key) ?? []), result]);
  }

  const orderedGroups = [...groups.values()];
  const output: ScannerResult[] = [];
  let added = true;
  for (let index = 0; added; index++) {
    added = false;
    for (const group of orderedGroups) {
      const item = group[index];
      if (!item) continue;
      output.push(item);
      added = true;
    }
  }
  return output;
}
