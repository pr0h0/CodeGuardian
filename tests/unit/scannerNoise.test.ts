import { describe, expect, it } from "vitest";
import { reduceScannerResultNoise } from "../../src/core/scannerNoise.js";
import type { ScannerResult } from "../../src/scanners/types.js";

function result(overrides: Partial<ScannerResult>): ScannerResult {
  return {
    scanner: "semgrep",
    ruleId: "rule",
    title: "Scanner result",
    category: "security",
    severity: "medium",
    path: "backend/app.js",
    startLine: 62,
    endLine: 62,
    message: "scanner message",
    ...overrides
  };
}

describe("scanner noise reduction", () => {
  it("collapses duplicate SAST results for session secrets and session cookie hardening", () => {
    const reduced = reduceScannerResultNoise([
      result({
        scanner: "custom-rules",
        ruleId: "generic-secret-assignment",
        title: "Hardcoded secret assignment candidate",
        severity: "high",
        startLine: 63,
        message: "secret: \"[REDACTED]\" (secret classification: real-looking, confidence: medium)"
      }),
      result({
        scanner: "semgrep",
        ruleId: "generic.secrets.security.detected-generic-secret.detected-generic-secret",
        title: "Generic Secret detected",
        severity: "high",
        startLine: 63
      }),
      result({
        scanner: "bearer",
        ruleId: "javascript_express_hardcoded_secret",
        title: "Usage of hard-coded secret",
        severity: "critical",
        startLine: 62
      }),
      result({
        scanner: "semgrep",
        ruleId: "javascript.express.security.audit.express-cookie-settings.express-cookie-session-no-secure",
        title: "Default session middleware settings: `secure` not set",
        severity: "medium",
        startLine: 62
      }),
      result({
        scanner: "semgrep",
        ruleId: "javascript.express.security.audit.express-cookie-settings.express-cookie-session-no-expires",
        title: "Default session middleware settings: `expires` not set",
        severity: "medium",
        startLine: 62
      }),
      result({
        scanner: "bearer",
        ruleId: "javascript_express_default_cookie_config",
        title: "Usage of default cookie configuration",
        severity: "medium",
        startLine: 66
      })
    ]);

    expect(reduced).toHaveLength(2);
    const secret = reduced.find((item) => item.ruleId === "javascript_express_hardcoded_secret");
    expect(secret?.severity).toBe("critical");
    expect((secret?.raw as any).semanticDeduplication.deduplicatedCount).toBe(2);
    expect(secret?.message).toContain("secret classification: real-looking");

    const cookie = reduced.find((item) => item.ruleId.includes("no-secure"));
    expect(cookie?.title).toContain("secure");
    expect((cookie?.raw as any).semanticDeduplication.deduplicatedCount).toBe(2);
  });

  it("does not collapse dependency CVE results", () => {
    const reduced = reduceScannerResultNoise([
      result({
        scanner: "trivy",
        ruleId: "CVE-2026-0001",
        title: "next: CVE-2026-0001",
        category: "dependency",
        severity: "critical",
        path: "package-lock.json",
        raw: { VulnerabilityID: "CVE-2026-0001", PkgName: "next" }
      }),
      result({
        scanner: "osv-scanner",
        ruleId: "GHSA-aaaa-bbbb-cccc",
        title: "axios vulnerable",
        category: "dependency",
        severity: "high",
        path: "package-lock.json",
        raw: { id: "GHSA-aaaa-bbbb-cccc", package: { name: "axios" } }
      })
    ]);

    expect(reduced.map((item) => item.ruleId)).toEqual(["CVE-2026-0001", "GHSA-aaaa-bbbb-cccc"]);
  });

  it("keeps different vulnerability concepts in the same line bucket separate", () => {
    const reduced = reduceScannerResultNoise([
      result({
        ruleId: "express-session-hardcoded-secret",
        title: "Hardcoded session secret",
        category: "secrets",
        severity: "high",
        startLine: 63
      }),
      result({
        ruleId: "express-open-redirect",
        title: "Open redirect through returnUrl",
        category: "open-redirect",
        severity: "high",
        startLine: 70
      })
    ]);

    expect(reduced.map((item) => item.ruleId).sort()).toEqual(["express-open-redirect", "express-session-hardcoded-secret"]);
  });
});
