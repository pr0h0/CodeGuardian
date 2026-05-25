import { describe, expect, it } from "vitest";
import { dedupeFindings } from "../../src/core/findingDeduper.js";
import { dedupeFindingsWithAi } from "../../src/ai/dedupe.js";
import type { AiProvider } from "../../src/ai/types.js";
import type { Finding } from "../../src/scanners/types.js";

function finding(overrides: Partial<Finding>): Finding {
  return {
    title: "Finding",
    category: "security",
    severity: "medium",
    confidence: "medium",
    status: "needs_context",
    path: "backend/app.js",
    startLine: 62,
    endLine: 62,
    source: "scanner",
    sink: "app.use(session())",
    evidence: [],
    reasoning: "scanner result needs review",
    remediation: "review and remediate",
    ...overrides
  };
}

describe("finding deduper", () => {
  it("collapses duplicate session secret findings while preserving provenance", () => {
    const deduped = dedupeFindings([
      finding({
        title: "Hardcoded session secret in Express session configuration",
        category: "secrets",
        severity: "critical",
        confidence: "medium",
        status: "needs_context",
        startLine: 62,
        evidence: [{ scanner: "bearer", ruleId: "javascript_express_hardcoded_secret" }]
      }),
      finding({
        title: "Hard-coded session secret in express-session configuration",
        category: "security",
        severity: "high",
        confidence: "medium",
        status: "needs_context",
        startLine: 63,
        evidence: [{ scanner: "semgrep", ruleId: "express-session-hardcoded-secret" }]
      }),
      finding({
        title: "Hardcoded session secret",
        category: "security",
        severity: "medium",
        confidence: "low",
        status: "false_positive",
        startLine: 63,
        evidence: [{ scanner: "custom-rules", ruleId: "generic-secret-assignment" }]
      })
    ]);

    expect(deduped).toHaveLength(1);
    expect(deduped[0].title).toBe("Hardcoded session secret in Express session configuration");
    expect(deduped[0].severity).toBe("critical");
    expect(deduped[0].status).toBe("needs_context");
    expect(deduped[0].category).toBe("secrets");
    expect(deduped[0].evidence).toHaveLength(3);
    expect(deduped[0].reasoning).toContain("Deduplicated 2 related findings");
    expect((deduped[0].raw as any).semanticDeduplication.deduplicatedCount).toBe(2);
  });

  it("collapses session cookie hardening variants into the actionable secure-flag finding", () => {
    const deduped = dedupeFindings([
      finding({
        title: "Don’t use the default session cookie name",
        severity: "medium",
        status: "false_positive",
        startLine: 62,
        reasoning: "fingerprinting best practice only"
      }),
      finding({
        title: "Default session middleware settings: `expires` not set",
        severity: "medium",
        status: "false_positive",
        startLine: 62,
        reasoning: "session cookie lifetime best practice only"
      }),
      finding({
        title: "Session cookie missing Secure flag",
        severity: "medium",
        status: "needs_context",
        startLine: 62,
        reasoning: "cookie may be sent over HTTP"
      }),
      finding({
        title: "Usage of default cookie configuration",
        category: "xss",
        severity: "medium",
        status: "false_positive",
        startLine: 66,
        reasoning: "scanner categorized cookie hardening as XSS"
      })
    ]);

    expect(deduped).toHaveLength(1);
    expect(deduped[0].title).toBe("Session cookie missing Secure flag");
    expect(deduped[0].status).toBe("needs_context");
    expect(deduped[0].reasoning).toContain("Deduplicated 3 related findings");
    expect((deduped[0].raw as any).semanticDeduplication.deduplicatedFrom.map((item: any) => item.title)).toContain("Usage of default cookie configuration");
  });

  it("keeps distinct security issues in the same file separate", () => {
    const deduped = dedupeFindings([
      finding({
        title: "Hardcoded session secret",
        category: "secrets",
        severity: "critical",
        startLine: 63
      }),
      finding({
        title: "Open redirect through returnUrl parameter",
        category: "open-redirect",
        severity: "high",
        startLine: 70,
        sink: "res.redirect(returnUrl)"
      })
    ]);

    expect(deduped.map((item) => item.category).sort()).toEqual(["open-redirect", "secrets"]);
  });

  it("collapses same-line transport security variants", () => {
    const deduped = dedupeFindings([
      finding({
        title: "Missing secure HTTP server configuration",
        category: "transport-security",
        severity: "critical",
        confidence: "high",
        status: "confirmed_true_positive",
        path: "backend/bin/www",
        startLine: 25,
        sink: "http.createServer"
      }),
      finding({
        title: "HTTP server without TLS encryption",
        category: "security",
        severity: "medium",
        confidence: "confirmed",
        status: "confirmed_true_positive",
        path: "backend/bin/www",
        startLine: 25,
        sink: "http.createServer(app)"
      })
    ]);

    expect(deduped).toHaveLength(1);
    expect(deduped[0].severity).toBe("critical");
    expect(deduped[0].reasoning).toContain("Deduplicated 1 related finding");
  });

  it("uses AI clustering to collapse ambiguous same-location duplicates", async () => {
    const provider: AiProvider = {
      name: "fake",
      async complete() {
        return {
          text: JSON.stringify({ groups: [{ canonicalId: "f0", duplicateIds: ["f1"], reason: "same file, line, and sink" }] }),
          raw: {}
        };
      }
    };

    const deduped = await dedupeFindingsWithAi(provider, [
      finding({
        title: "Open redirect through returnUrl",
        category: "open-redirect",
        severity: "high",
        confidence: "medium",
        path: "backend/admin.js",
        startLine: 70,
        sink: "res.redirect"
      }),
      finding({
        title: "Unvalidated redirect after login",
        category: "security",
        severity: "medium",
        confidence: "medium",
        path: "backend/admin.js",
        startLine: 70,
        sink: "res.redirect(req.body.redirect)"
      })
    ]);

    expect(deduped).toHaveLength(1);
    expect(deduped[0].title).toBe("Open redirect through returnUrl");
    expect((deduped[0].raw as any).semanticDeduplication.deduplicatedBy).toBe("semantic-noise-reduction");
  });

  it("retries invalid AI dedupe JSON before falling back to deterministic results", async () => {
    const calls: string[] = [];
    const provider: AiProvider = {
      name: "fake",
      async complete(input) {
        calls.push(input.messages.at(-1)?.content ?? "");
        if (calls.length === 1) return { text: "{ \"groups\": [", raw: {} };
        return {
          text: JSON.stringify({ groups: [{ canonicalId: "f0", duplicateIds: ["f1"], reason: "same issue" }] }),
          raw: {}
        };
      }
    };

    const findings = [
      finding({
        title: "Unvalidated destination passed to navigation helper",
        category: "security",
        severity: "high",
        path: "backend/admin.js",
        startLine: 70,
        sink: "navigateTo",
        reasoning: "untrusted value reaches helper",
        remediation: "validate destination"
      }),
      finding({
        title: "Navigation helper receives attacker destination",
        category: "security",
        severity: "medium",
        path: "backend/admin.js",
        startLine: 70,
        sink: "navigateTo",
        reasoning: "untrusted value reaches helper",
        remediation: "validate destination"
      })
    ];

    expect(dedupeFindings(findings)).toHaveLength(2);
    const deduped = await dedupeFindingsWithAi(provider, findings);

    expect(calls).toHaveLength(2);
    expect(calls[1]).toContain("Previous dedupe response was invalid");
    expect(deduped).toHaveLength(1);
  });

  it("uses a repair prompt to salvage malformed AI dedupe output", async () => {
    const calls: string[] = [];
    const provider: AiProvider = {
      name: "fake",
      async complete(input) {
        calls.push(input.messages.at(-1)?.content ?? "");
        if (calls.length < 3) return { text: "{ \"groups\": [", raw: {} };
        return {
          text: JSON.stringify({ groups: [{ canonicalId: "f0", duplicateIds: ["f1"], reason: "same issue" }] }),
          raw: {}
        };
      }
    };

    const findings = [
      finding({
        title: "Unchecked destination value reaches response helper",
        category: "security",
        severity: "high",
        path: "routes/login.ts",
        startLine: 34,
        sink: "renderTarget",
        reasoning: "untrusted value reaches helper",
        remediation: "validate destination"
      }),
      finding({
        title: "Response helper uses untrusted target value",
        category: "security",
        severity: "high",
        path: "routes/login.ts",
        startLine: 34,
        sink: "renderTarget",
        reasoning: "untrusted value reaches helper",
        remediation: "validate destination"
      })
    ];

    expect(dedupeFindings(findings)).toHaveLength(2);
    const deduped = await dedupeFindingsWithAi(provider, findings);

    expect(calls).toHaveLength(3);
    expect(calls[2]).toContain("Invalid dedupe JSON to repair");
    expect(deduped).toHaveLength(1);
  });

  it("deterministically collapses common scanner variants when AI dedupe is unavailable", () => {
    const deduped = dedupeFindings([
      finding({
        title: "SQL injection in login query via email",
        category: "sql-injection",
        severity: "high",
        confidence: "high",
        status: "confirmed_true_positive",
        path: "routes/login.ts",
        startLine: 34,
        sink: "models.sequelize.query"
      }),
      finding({
        title: "Unsanitized user input in SQL query at login endpoint",
        category: "injection",
        severity: "critical",
        confidence: "high",
        status: "confirmed_true_positive",
        path: "routes/login.ts",
        startLine: 34,
        sink: "raw SQL execution"
      }),
      finding({
        title: "SSRF via profile image URL upload",
        category: "ssrf",
        severity: "high",
        confidence: "high",
        status: "confirmed_true_positive",
        path: "routes/profileImageUrlUpload.ts",
        startLine: 19,
        sink: "fetch(url)"
      }),
      finding({
        title: "Unsanitized user input in HTTP request (SSRF)",
        category: "security",
        severity: "high",
        confidence: "high",
        status: "confirmed_true_positive",
        path: "routes/profileImageUrlUpload.ts",
        startLine: 24,
        sink: "fetch(url)"
      }),
      finding({
        title: "Unsanitized user input in eval() call",
        category: "security",
        severity: "critical",
        confidence: "high",
        status: "confirmed_true_positive",
        path: "routes/userProfile.ts",
        startLine: 61,
        sink: "eval"
      }),
      finding({
        title: "User-controllable data flows to eval in user profile route",
        category: "code-injection",
        severity: "high",
        confidence: "medium",
        status: "likely_true_positive",
        path: "routes/userProfile.ts",
        startLine: 61,
        sink: "eval"
      })
    ]);

    expect(deduped).toHaveLength(3);
    expect(deduped.map((item) => item.path).sort()).toEqual([
      "routes/login.ts",
      "routes/profileImageUrlUpload.ts",
      "routes/userProfile.ts"
    ]);
    expect(deduped.every((item) => item.reasoning.includes("Deduplicated 1 related finding"))).toBe(true);
  });
});
