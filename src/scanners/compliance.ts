import type { IndexedFile } from "../repo/repoIndexer.js";
import type { ScannerResult } from "./types.js";
import { lineAtOffset } from "../utils/lineMap.js";

type ComplianceStatus = "pass" | "fail" | "unknown";

interface Evidence {
  path?: string;
  line?: number;
  note: string;
}

interface ComplianceResultInput {
  ruleId: string;
  title: string;
  status: ComplianceStatus;
  frameworks: string[];
  controlIds: string[];
  expectation: string;
  evidence: Evidence[];
  remediation: string;
  severity?: ScannerResult["severity"];
}

export function runComplianceChecks(files: IndexedFile[], scannerResults: ScannerResult[] = []): ScannerResult[] {
  return [
    authAccessControl(files),
    sessionCookieProtection(files),
    auditLogging(files),
    secretManagement(files, scannerResults),
    ciChangeManagement(files),
    vulnerabilityManagement(files),
    cryptoTransport(scannerResults, files)
  ];
}

function authAccessControl(files: IndexedFile[]): ScannerResult {
  const evidence = findEvidence(files, /\b(requireAuth|authenticate|authorize|permission|policy|can\?|current_user|currentUser|before_action\s+:authenticate_user|isAuthenticated|passport\.authenticate|jwt\.verify)\b/i, "authentication or authorization control");
  return complianceResult({
    ruleId: "compliance-auth-access-control",
    title: "Access control evidence",
    status: evidence.length ? "pass" : "unknown",
    frameworks: ["SOC 2", "ISO 27001"],
    controlIds: ["SOC2 CC6.1", "SOC2 CC6.2", "ISO27001 A.5.15", "ISO27001 A.5.18"],
    expectation: "Sensitive actions should require server-side authentication and authorization checks.",
    evidence,
    remediation: "Document protected routes and add explicit auth/authz middleware or policy checks where sensitive actions are handled."
  });
}

function sessionCookieProtection(files: IndexedFile[]): ScannerResult {
  const disabled = findEvidence(files, /(secure\s*[:=]\s*false|SESSION_COOKIE_SECURE\s*=\s*False|httponly\s*[:=]\s*false|SESSION_COOKIE_HTTPONLY\s*=\s*False|session\.cookie_(secure|httponly)\s*=\s*0)/i, "session cookie protection disabled");
  const secure = findEvidence(files, /(secure\s*[:=]\s*true|SESSION_COOKIE_SECURE\s*=\s*True|session\.cookie_secure\s*=\s*1|config\.force_ssl\s*=\s*true)/i, "secure cookie or forced TLS evidence");
  const httpOnly = findEvidence(files, /(httpOnly\s*[:=]\s*true|httponly\s*[:=]\s*true|SESSION_COOKIE_HTTPONLY\s*=\s*True|session\.cookie_httponly\s*=\s*1)/i, "HttpOnly cookie evidence");
  return complianceResult({
    ruleId: "compliance-session-cookie-protection",
    title: "Session cookie protection",
    status: disabled.length ? "fail" : secure.length && httpOnly.length ? "pass" : "unknown",
    severity: disabled.length ? "medium" : "info",
    frameworks: ["SOC 2", "ISO 27001"],
    controlIds: ["SOC2 CC6.1", "ISO27001 A.8.20", "ISO27001 A.8.24"],
    expectation: "Session cookies should use Secure and HttpOnly flags in production.",
    evidence: disabled.length ? disabled : [...secure.slice(0, 2), ...httpOnly.slice(0, 2)],
    remediation: "Set Secure and HttpOnly on session cookies and enforce HTTPS in production."
  });
}

function auditLogging(files: IndexedFile[]): ScannerResult {
  const evidence = findEvidence(files, /\b(audit[_-]?log|security[_-]?event|AuditLog|logger\.(info|warn|error)[^\n]*(auth|login|permission|admin|user[_-]?id|security))\b/i, "security/audit logging evidence");
  return complianceResult({
    ruleId: "compliance-audit-logging",
    title: "Security event logging evidence",
    status: evidence.length ? "pass" : "unknown",
    frameworks: ["SOC 2", "ISO 27001"],
    controlIds: ["SOC2 CC7.2", "SOC2 CC7.3", "ISO27001 A.8.15", "ISO27001 A.8.16"],
    expectation: "Security-relevant events should be logged for monitoring and investigation.",
    evidence,
    remediation: "Log authentication, authorization, admin, data export, and security-sensitive changes with stable event names and actor identifiers."
  });
}

function secretManagement(files: IndexedFile[], scannerResults: ScannerResult[]): ScannerResult {
  const secretFindings = scannerResults.filter((result) => result.category === "secrets");
  const evidence = secretFindings.slice(0, 5).map((result) => ({
    path: result.path,
    line: result.startLine,
    note: `${result.scanner}/${result.ruleId}: ${result.title}`
  }));
  const envEvidence = findEvidence(files, /\b(process\.env|import\.meta\.env|Deno\.env|getenv|ENV\[|os\.environ|credentials|vault|secretsmanager|secret manager)\b/i, "runtime secret loading evidence");
  return complianceResult({
    ruleId: "compliance-secret-management",
    title: "Secret management posture",
    status: secretFindings.length ? "fail" : envEvidence.length ? "pass" : "unknown",
    severity: secretFindings.length ? "high" : "info",
    frameworks: ["SOC 2", "ISO 27001"],
    controlIds: ["SOC2 CC6.1", "ISO27001 A.5.17", "ISO27001 A.8.12"],
    expectation: "Secrets should be loaded from protected runtime stores and not committed to source.",
    evidence: secretFindings.length ? evidence : envEvidence,
    remediation: secretFindings.length ? "Move committed secrets into a secret manager, rotate exposed values, and scrub repository history." : "Document runtime secret storage and rotation ownership."
  });
}

function ciChangeManagement(files: IndexedFile[]): ScannerResult {
  const evidence = [
    ...pathEvidence(files, /(^|\/)(CODEOWNERS|\.github\/CODEOWNERS)$/i, "CODEOWNERS review ownership evidence"),
    ...pathEvidence(files, /(^|\/)(\.github\/workflows\/[^/]+\.ya?ml|\.gitlab-ci\.ya?ml|bitbucket-pipelines\.ya?ml)$/i, "CI workflow evidence")
  ];
  return complianceResult({
    ruleId: "compliance-change-management",
    title: "Change management evidence",
    status: evidence.length ? "pass" : "unknown",
    frameworks: ["SOC 2", "ISO 27001"],
    controlIds: ["SOC2 CC8.1", "ISO27001 A.8.32"],
    expectation: "Code changes should have review ownership and CI evidence.",
    evidence,
    remediation: "Add CODEOWNERS and CI workflows that run tests/security checks before merge."
  });
}

function vulnerabilityManagement(files: IndexedFile[]): ScannerResult {
  const evidence = [
    ...pathEvidence(files, /(^|\/)(dependabot\.ya?ml|renovate\.json|\.github\/workflows\/[^/]*(security|scan|semgrep|trivy|osv|snyk|gitleaks)[^/]*\.ya?ml)$/i, "dependency or security scanning automation"),
    ...findEvidence(files, /\b(npm audit|pnpm audit|yarn audit|bundle audit|pip-audit|safety|trivy|osv-scanner|semgrep|gitleaks|snyk)\b/i, "vulnerability scanning command")
  ];
  return complianceResult({
    ruleId: "compliance-vulnerability-management",
    title: "Vulnerability management evidence",
    status: evidence.length ? "pass" : "unknown",
    frameworks: ["SOC 2", "ISO 27001"],
    controlIds: ["SOC2 CC7.1", "SOC2 CC7.2", "ISO27001 A.8.8"],
    expectation: "Dependencies and source should be scanned regularly with tracked remediation.",
    evidence,
    remediation: "Add scheduled dependency and code scanning in CI, then track remediation for high-risk results."
  });
}

function cryptoTransport(scannerResults: ScannerResult[], files: IndexedFile[]): ScannerResult {
  const cryptoFindings = scannerResults.filter((result) => result.category === "transport-security" || result.category === "weak-crypto");
  const goodEvidence = findEvidence(files, /\b(force_ssl\s*=\s*true|Strict-Transport-Security|helmet\s*\(|HSTS|httpsOnly|sslmode=require)\b/i, "transport security hardening evidence");
  return complianceResult({
    ruleId: "compliance-crypto-transport",
    title: "Cryptography and transport protection",
    status: cryptoFindings.length ? "fail" : goodEvidence.length ? "pass" : "unknown",
    severity: cryptoFindings.length ? "medium" : "info",
    frameworks: ["SOC 2", "ISO 27001"],
    controlIds: ["SOC2 CC6.7", "ISO27001 A.8.20", "ISO27001 A.8.24"],
    expectation: "Production systems should use strong crypto and TLS validation.",
    evidence: cryptoFindings.length ? cryptoFindings.slice(0, 5).map((result) => ({ path: result.path, line: result.startLine, note: `${result.scanner}/${result.ruleId}: ${result.title}` })) : goodEvidence,
    remediation: "Remove weak cryptographic primitives, keep TLS verification enabled, and document approved crypto settings."
  });
}

function complianceResult(input: ComplianceResultInput): ScannerResult {
  const primary = input.evidence[0];
  const statusText = input.status.toUpperCase();
  return {
    scanner: "compliance",
    ruleId: input.ruleId,
    title: `${statusText}: ${input.title}`,
    category: "compliance",
    severity: input.severity ?? (input.status === "fail" ? "medium" : "info"),
    path: primary?.path,
    startLine: primary?.line,
    endLine: primary?.line,
    message: input.status === "unknown" ? `${input.expectation} Evidence not found in indexed files.` : input.remediation,
    raw: {
      status: input.status,
      frameworks: input.frameworks,
      controlIds: input.controlIds,
      expectation: input.expectation,
      evidence: input.evidence.slice(0, 10),
      remediation: input.remediation
    }
  };
}

function findEvidence(files: IndexedFile[], regex: RegExp, note: string): Evidence[] {
  const evidence: Evidence[] = [];
  for (const file of files) {
    const match = file.content.match(regex);
    if (!match) continue;
    evidence.push({ path: file.path, line: lineAtOffset(file.content, match.index ?? 0), note });
    if (evidence.length >= 10) break;
  }
  return evidence;
}

function pathEvidence(files: IndexedFile[], regex: RegExp, note: string): Evidence[] {
  return files
    .filter((file) => regex.test(file.path))
    .slice(0, 10)
    .map((file) => ({ path: file.path, line: 1, note }));
}
