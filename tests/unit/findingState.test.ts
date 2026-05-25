import { describe, expect, it } from "vitest";
import { applyRememberedFindingState, classifyFindingState } from "../../src/core/scanner.js";
import type { Finding } from "../../src/scanners/types.js";

function finding(overrides: Partial<Finding>): Finding {
  return {
    title: "Finding",
    category: "secrets",
    severity: "critical",
    confidence: "high",
    status: "confirmed_true_positive",
    evidence: [],
    reasoning: "confirmed by AI",
    remediation: "fix it",
    ...overrides
  };
}

describe("finding state classification", () => {
  it("preserves explicit confirmed true-positive status", () => {
    expect(classifyFindingState(finding({ status: "confirmed_true_positive" })).status).toBe("confirmed_true_positive");
  });

  it("preserves explicit needs-context status instead of promoting on severity alone", () => {
    expect(classifyFindingState(finding({ status: "needs_context", severity: "critical", confidence: "high" })).status).toBe("needs_context");
  });

  it("applies prior false-positive memory when the cited file hash is unchanged", () => {
    const remembered = { status: "false_positive" as const, reasoning: "known framework invariant", fileSha256: "same" };
    const result = applyRememberedFindingState(finding({ status: "suspected", confidence: "high" }), remembered, "same");

    expect(result.status).toBe("false_positive");
    expect(result.reasoning).toContain("previous scan marked this fingerprint false_positive");
  });

  it("does not apply prior memory when the cited file hash changed", () => {
    const remembered = { status: "false_positive" as const, reasoning: "old code", fileSha256: "old" };
    const result = applyRememberedFindingState(finding({ status: "suspected", confidence: "high" }), remembered, "new");

    expect(result.status).toBe("suspected");
    expect(result.confidence).toBe("high");
  });
});
