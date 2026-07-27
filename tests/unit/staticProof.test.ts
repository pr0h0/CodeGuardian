import { describe, expect, it } from "vitest";
import { buildStaticProofPacks } from "../../src/core/staticProof.js";
import type { Finding } from "../../src/scanners/types.js";

describe("static proof packs", () => {
  it("builds source-only proof packs for active findings", () => {
    const findings: Finding[] = [
      {
        title: "Tenant object read lacks ownership guard",
        category: "authz",
        severity: "high",
        confidence: "high",
        status: "confirmed_true_positive",
        path: "src/routes/documents.ts",
        startLine: 42,
        source: "req.params.documentId",
        sink: "Document.findById",
        evidence: [{ path: "src/routes/documents.ts", line: 42, code: "Document.findById(req.params.documentId)" }],
        reasoning: "Attacker-controlled document ID reaches read. Missing control: document.organizationId is not compared with req.user.organizationId. Preconditions: authenticated user, known document id",
        remediation: "Scope document reads to the current organization.",
        fingerprint: "abcdef1234567890"
      },
      {
        title: "False positive",
        category: "xss",
        severity: "low",
        confidence: "low",
        status: "false_positive",
        evidence: [],
        reasoning: "not reachable",
        remediation: "none"
      }
    ];

    const packs = buildStaticProofPacks(findings);

    expect(packs).toHaveLength(1);
    expect(packs[0]).toMatchObject({
      id: "abcdef123456",
      location: "src/routes/documents.ts:42",
      runtimeValidated: false,
      missingControl: "document.organizationId is not compared with req.user.organizationId."
    });
    expect(packs[0].exploitPreconditions).toEqual(["authenticated user", "known document id"]);
    expect(packs[0].safeRegressionGuidance.join(" ")).toContain("another principal");
  });
});
