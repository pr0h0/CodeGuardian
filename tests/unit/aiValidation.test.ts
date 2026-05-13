import { describe, expect, it } from "vitest";
import { buildSecurityCriticSystemPrompt, buildSecurityTriageSystemPrompt, buildSecurityTriageUserPrompt } from "../../src/ai/prompts.js";
import { aiFindingJsonSchema, categoryValues } from "../../src/ai/schemas.js";
import { aiFindingSchema } from "../../src/ai/types.js";

describe("ai schema", () => {
  it("validates finding shape", () => {
    const parsed = aiFindingSchema.safeParse({
      isFinding: true, title: "x", category: "security", severity: "high", confidence: "high", status: "suspected",
      affectedLocations: [{ path: "a", startLine: 1, endLine: 1 }],
      source: "", sourceLine: 1, sink: "", sinkLine: 1, dataFlow: [], missingControl: "", exploitPreconditions: [], safeRepro: [],
      exploitabilityRubric: { userControl: 1, reachability: 1, authRequired: 1, sanitizerPresent: 1, sinkDanger: 1, prodExposure: 1, score: 6 },
      attackScenario: "", evidence: [], falsePositiveConsiderations: [], recommendedDynamicTests: [], remediation: "", secureCodeExample: null
    });
    expect(parsed.success).toBe(true);
  });

  it("prompts require raw JSON and predefined enum values", () => {
    const system = buildSecurityTriageSystemPrompt();
    const critic = buildSecurityCriticSystemPrompt();
    const user = buildSecurityTriageUserPrompt({
      scannerResult: { scanner: "semgrep", ruleId: "x", title: "x", severity: "high", message: "x" },
      snippets: [],
      imports: [],
      nearbySymbols: [],
      routes: [],
      configHints: [],
      relatedResults: [],
      aiInstructions: "",
      scannerNegatives: []
    });

    expect(system).toContain("Return raw JSON object only");
    expect(system).toContain("Use only enum values explicitly listed");
    expect(critic).toContain("No prose, markdown, code fences, comments, or extra keys");
    expect(user).toContain(JSON.stringify(categoryValues));
    expect(aiFindingJsonSchema.schema).toMatchObject({
      type: "object",
      additionalProperties: false
    });
  });
});
