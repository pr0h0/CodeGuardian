import { describe, expect, it } from "vitest";
import { buildBaselineDiff } from "../../src/core/baseline.js";
import { openDatabase } from "../../src/db/database.js";
import { createScan, finishScan, insertFinding } from "../../src/db/repositories.js";

describe("baseline diff", () => {
  it("uses persisted fingerprints before falling back to derived fingerprints", () => {
    const db = openDatabase(":memory:");
    const repoPath = "/repo";
    const baselineScanId = createScan(db, repoPath, {});
    const currentScanId = createScan(db, repoPath, {});

    insertFinding(db, baselineScanId, {
      title: "Old scanner title",
      category: "command-injection",
      severity: "high",
      confidence: "high",
      status: "likely_true_positive",
      path: "src/app.ts",
      startLine: 10,
      evidence: [],
      reasoning: "old reasoning",
      remediation: "fix it",
      fingerprint: "same-fingerprint"
    });
    insertFinding(db, currentScanId, {
      title: "New AI title",
      category: "command-injection",
      severity: "high",
      confidence: "high",
      status: "likely_true_positive",
      path: "src/app.ts",
      startLine: 11,
      evidence: [],
      reasoning: "new reasoning",
      remediation: "fix it",
      fingerprint: "same-fingerprint"
    });
    finishScan(db, baselineScanId, "completed");

    const diff = buildBaselineDiff(db, repoPath, currentScanId, baselineScanId);

    expect(diff.newFindings).toBe(0);
    expect(diff.resolvedFindings).toBe(0);
    expect(diff.unchangedFindings).toBe(1);

    db.close();
  });
});
