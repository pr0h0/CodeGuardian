import { describe, expect, it } from "vitest";
import { buildStaticReconArtifact } from "../../src/core/staticRecon.js";
import type { IndexedFile } from "../../src/repo/repoIndexer.js";

describe("static recon artifact", () => {
  it("summarizes source-only attack surface evidence", () => {
    const files: IndexedFile[] = [{
      path: "src/server.ts",
      absolutePath: "/repo/src/server.ts",
      language: "typescript",
      lineCount: 7,
      content: [
        "app.get('/api/documents/:documentId', requireAuth, async (req, res) => {",
        "  const id = req.params.documentId;",
        "  return res.json(await Document.findById(id));",
        "});"
      ].join("\n")
    }];

    const artifact = buildStaticReconArtifact({
      files,
      scannerResults: [{
        scanner: "business-invariants",
        ruleId: "business-invariant-missing-ownership-guard",
        title: "Route uses request-controlled object identifiers without an obvious ownership guard",
        category: "business-logic",
        severity: "high",
        path: "src/server.ts",
        startLine: 1,
        message: "GET /api/documents/:documentId"
      }],
      securityIntelligence: {
        generatedAt: "now",
        summary: "summary",
        entrypoints: [],
        catalog: [{ kind: "sink", name: "Document.findById", path: "src/server.ts", line: 3, category: "database-read", evidence: "Document.findById(id)", discoveredBy: "deterministic" }],
        invariants: [{ id: "ownership:src/server.ts:1", title: "Object ownership must be enforced", category: "ownership", path: "src/server.ts", line: 1, rule: "Route must bind documentId to tenant.", evidence: "route", confidence: "high" }],
        boundaries: [{ id: "server-runtime:src", kind: "server-runtime", name: "src", paths: ["src/server.ts"], fileCount: 1, entrypointCount: 1 }],
        highRiskFiles: [],
        negativeEvidence: [],
        aiNotes: [],
        auditArtifacts: [],
        coverage: { indexedFiles: 1, entrypointFiles: 1, scannerSeedFiles: 1, boundaries: 1, deterministicCatalogItems: 1, aiCatalogItems: 0 }
      }
    });

    expect(artifact.endpoints[0]).toMatchObject({ method: "GET", routePath: "/api/documents/:documentId", objectIdParameters: ["documentId"] });
    expect(artifact.guards[0].detail).toContain("requireAuth");
    expect(artifact.inputVectors[0].detail).toContain("req.params.documentId");
    expect(artifact.sinks.some((item) => item.detail.includes("Document.findById"))).toBe(true);
    expect(artifact.invariants[0].category).toBe("ownership");
  });
});
