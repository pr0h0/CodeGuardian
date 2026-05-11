import { describe, expect, it } from "vitest";
import { aiFindingSchema } from "../../src/ai/types.js";

describe("ai schema", () => {
  it("validates finding shape", () => {
    const parsed = aiFindingSchema.safeParse({
      isFinding: true, title: "x", category: "x", severity: "high", confidence: "high", status: "suspected",
      affectedLocations: [{ path: "a", startLine: 1, endLine: 1 }],
      source: "", sourceLine: 1, sink: "", sinkLine: 1, dataFlow: [], missingControl: "", exploitPreconditions: [], safeRepro: [],
      exploitabilityRubric: { userControl: 1, reachability: 1, authRequired: 1, sanitizerPresent: 1, sinkDanger: 1, prodExposure: 1, score: 6 },
      attackScenario: "", evidence: [], falsePositiveConsiderations: [], recommendedDynamicTests: [], remediation: "", secureCodeExample: null
    });
    expect(parsed.success).toBe(true);
  });
});
