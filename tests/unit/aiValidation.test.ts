import { describe, expect, it } from "vitest";
import { aiFindingSchema } from "../../src/ai/types.js";

describe("ai schema", () => {
  it("validates finding shape", () => {
    const parsed = aiFindingSchema.safeParse({
      isFinding: true, title: "x", category: "x", severity: "high", confidence: "high", status: "suspected",
      affectedLocations: [{ path: "a", startLine: 1, endLine: 1 }],
      source: "", sink: "", attackScenario: "", evidence: [], falsePositiveConsiderations: [], recommendedDynamicTests: [], remediation: "", secureCodeExample: null
    });
    expect(parsed.success).toBe(true);
  });
});
