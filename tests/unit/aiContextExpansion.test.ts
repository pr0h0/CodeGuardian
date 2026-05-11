import { describe, expect, it } from "vitest";
import { aiTriage } from "../../src/ai/triage.js";
import type { AiCompletionInput, AiCompletionOutput, AiProvider } from "../../src/ai/types.js";
import type { ContextPack } from "../../src/repo/contextPackBuilder.js";

describe("ai context expansion", () => {
  it("retries once with requested files before storing final decision", async () => {
    const calls: AiCompletionInput[] = [];
    const provider: AiProvider = {
      name: "fake",
      async complete(input): Promise<AiCompletionOutput> {
        calls.push(input);
        return { text: JSON.stringify(calls.length === 1 ? response({ requestedFiles: ["src/auth.ts"] }) : response({ isFinding: false, status: "false_positive" })), raw: {} };
      }
    };
    const pack: ContextPack = {
      scannerResult: { scanner: "semgrep", ruleId: "x", title: "Possible issue", severity: "high", path: "src/index.ts", startLine: 1, endLine: 1, message: "possible issue" },
      snippets: [],
      imports: [],
      nearbySymbols: [],
      routes: [],
      configHints: [],
      relatedResults: [],
      scannerNegatives: []
    };

    const findings = await aiTriage(provider, [pack], () => undefined, undefined, () => ({
      files: [{ path: "src/auth.ts", startLine: 1, endLine: 2, content: "1: export function auth() {}\n2:" }],
      symbols: [],
      missing: []
    }));

    expect(calls).toHaveLength(2);
    expect(calls[1].messages[0].content).toContain("requestedContext");
    expect(findings[0].status).toBe("false_positive");
  });
});

function response(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    isFinding: true,
    title: "Possible issue",
    category: "security",
    severity: "high",
    confidence: "medium",
    status: "needs_dynamic_test",
    affectedLocations: [{ path: "src/index.ts", startLine: 1, endLine: 1 }],
    source: "source",
    sourceLine: 1,
    sink: "sink",
    sinkLine: 1,
    dataFlow: [],
    missingControl: "unknown",
    exploitPreconditions: [],
    safeRepro: [],
    exploitabilityRubric: { userControl: 1, reachability: 1, authRequired: 1, sanitizerPresent: 1, sinkDanger: 1, prodExposure: 1, score: 6 },
    attackScenario: "needs context",
    evidence: [{ path: "src/index.ts", line: 1, note: "possible issue" }],
    falsePositiveConsiderations: [],
    recommendedDynamicTests: [],
    requestedFiles: [],
    requestedSymbols: [],
    remediation: "review",
    secureCodeExample: null,
    ...overrides
  };
}
