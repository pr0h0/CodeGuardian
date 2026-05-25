import { describe, expect, it } from "vitest";
import { aiTriage } from "../../src/ai/triage.js";
import { AiJobRecorder } from "../../src/ai/jobs.js";
import type { AiCompletionInput, AiCompletionOutput, AiProvider } from "../../src/ai/types.js";
import type { ContextPack } from "../../src/repo/contextPackBuilder.js";

class SequenceProvider implements AiProvider {
  name = "fake";
  calls: AiCompletionInput[] = [];
  private index = 0;

  constructor(private readonly responses: string[]) {}

  async complete(input: AiCompletionInput): Promise<AiCompletionOutput> {
    this.calls.push(input);
    const text = this.responses[Math.min(this.index++, this.responses.length - 1)];
    return { text, raw: {} };
  }
}

function pack(overrides: Partial<ContextPack> = {}): ContextPack {
  return {
    scannerResult: {
      scanner: "semgrep",
      ruleId: "test/rule",
      title: "Possible issue",
      category: "security",
      severity: "high",
      path: "src/app.ts",
      startLine: 2,
      endLine: 2,
      message: "possible issue"
    },
    snippets: [{ path: "src/app.ts", startLine: 1, endLine: 4, content: "1: const user = req.query.x;\n2: sink(user);\n3:\n4:" }],
    imports: [],
    nearbySymbols: [],
    routes: [],
    configHints: [],
    relatedResults: [],
    scannerNegatives: [],
    ...overrides
  };
}

function validFinding(overrides: Record<string, unknown> = {}) {
  return {
    isFinding: true,
    title: "Request input reaches sink",
    category: "security",
    severity: "high",
    confidence: "high",
    status: "confirmed_true_positive",
    affectedLocations: [{ path: "src/app.ts", startLine: 2, endLine: 2 }],
    source: "req.query.x",
    sourceLine: 1,
    sink: "sink(user)",
    sinkLine: 2,
    dataFlow: [{ path: "src/app.ts", line: 2, step: "user -> sink" }],
    missingControl: "input validation",
    exploitPreconditions: ["attacker controls x"],
    safeRepro: ["review route locally"],
    exploitabilityRubric: { userControl: 10, reachability: 10, authRequired: 0, sanitizerPresent: 10, sinkDanger: 10, prodExposure: 5, score: 45 },
    attackScenario: "attacker controls x and reaches sink",
    evidence: [{ path: "src/app.ts", line: 2, note: "sink uses request input" }],
    falsePositiveConsiderations: [],
    recommendedDynamicTests: [],
    requestedFiles: [],
    requestedSymbols: [],
    remediation: "validate x",
    secureCodeExample: null,
    ...overrides
  };
}

describe("AI trust gates", () => {
  it("retries invalid first-pass verdict JSON before dropping a candidate", async () => {
    const provider = new SequenceProvider([
      "",
      JSON.stringify({ verdict: "true_positive", confidence: "high", reason: "retry recovered verdict", requestedFiles: [], requestedSymbols: [] }),
      JSON.stringify(validFinding())
    ]);

    const findings = await aiTriage(provider, [pack()]);

    expect(provider.calls).toHaveLength(3);
    expect(provider.calls[1].messages[0].content).toContain("Previous verdict response was invalid");
    expect(findings).toHaveLength(1);
  });

  it("repairs invalid first-pass verdict JSON after retry failure", async () => {
    const provider = new SequenceProvider([
      "{",
      "{",
      JSON.stringify({ verdict: "true_positive", confidence: "high", reason: "repair recovered verdict", requestedFiles: [], requestedSymbols: [] }),
      JSON.stringify(validFinding())
    ]);

    const findings = await aiTriage(provider, [pack()]);

    expect(provider.calls).toHaveLength(4);
    expect(provider.calls[2].messages[0].content).toContain("Validation errors");
    expect(provider.calls[2].messages[0].content).toContain("Invalid verdict JSON to repair");
    expect(findings).toHaveLength(1);
  });

  it("falls back to full triage when verdict retry and repair stay invalid", async () => {
    const provider = new SequenceProvider([
      "{",
      "{",
      "{",
      JSON.stringify(validFinding())
    ]);

    const findings = await aiTriage(provider, [pack()]);

    expect(provider.calls).toHaveLength(4);
    expect(provider.calls[3].messages[0].content).toContain("Inputs:");
    expect(findings).toHaveLength(1);
  });

  it("normalizes singleton enum arrays from DeepSeek into valid finding fields", async () => {
    const provider = new SequenceProvider([
      JSON.stringify({ verdict: "true_positive", confidence: "high", reason: "plausible", requestedFiles: [], requestedSymbols: [] }),
      JSON.stringify(validFinding({
        category: ["open-redirect"],
        severity: ["high"],
        confidence: ["high"],
        status: ["confirmed_true_positive"]
      }))
    ]);

    const findings = await aiTriage(provider, [pack()], () => undefined, undefined, undefined, undefined, provider);

    expect(provider.calls).toHaveLength(2);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      category: "open-redirect",
      severity: "high",
      confidence: "high",
      status: "confirmed_true_positive"
    });
  });

  it("sends schema validation issues to the repair prompt before accepting repaired JSON", async () => {
    const calls: AiCompletionInput[] = [];
    const provider: AiProvider = {
      name: "fake",
      async complete(input): Promise<AiCompletionOutput> {
        calls.push(input);
        if (calls.length === 1) return { text: JSON.stringify({ verdict: "true_positive", confidence: "high", reason: "plausible", requestedFiles: [], requestedSymbols: [] }), raw: {} };
        if (calls.length === 2) return { text: JSON.stringify(validFinding({ category: ["not-a-category"] })), raw: {} };
        if (calls.length === 3) return { text: JSON.stringify(validFinding({ category: ["not-a-category"] })), raw: {} };
        return { text: JSON.stringify(validFinding({ category: "security" })), raw: {} };
      }
    };

    const findings = await aiTriage(provider, [pack()], () => undefined, undefined, undefined, undefined, provider);

    expect(calls).toHaveLength(4);
    expect(calls[3].messages[0].content).toContain("Validation errors");
    expect(calls[3].messages[0].content).toContain("category");
    expect(calls[3].messages[0].content).toContain("not-a-category");
    expect(findings).toHaveLength(1);
    expect(findings[0].category).toBe("security");
  });

  it("retries invalid full-finding JSON with original context before repair", async () => {
    const provider = new SequenceProvider([
      JSON.stringify({ verdict: "true_positive", confidence: "high", reason: "plausible", requestedFiles: [], requestedSymbols: [] }),
      "{",
      JSON.stringify(validFinding())
    ]);

    const findings = await aiTriage(provider, [pack()]);

    expect(provider.calls).toHaveLength(3);
    expect(provider.calls[2].messages[0].content).toContain("Previous full finding response was invalid");
    expect(findings).toHaveLength(1);
  });

  it("normalizes zero source/sink lines from context retry responses", async () => {
    const provider = new SequenceProvider([
      JSON.stringify({ verdict: "true_positive", confidence: "high", reason: "secret needs context", requestedFiles: [], requestedSymbols: [] }),
      JSON.stringify(validFinding({
        isFinding: false,
        status: "false_positive",
        requestedFiles: ["src/.env"]
      })),
      JSON.stringify(validFinding({
        sourceLine: 0,
        sink: "not applicable",
        sinkLine: 0
      }))
    ]);
    const resolve = () => ({
      files: [{ path: "src/.env", startLine: 1, endLine: 1, content: "1: API_KEY=secret" }],
      symbols: [],
      missing: []
    });

    const findings = await aiTriage(provider, [pack()], () => undefined, undefined, resolve);

    expect(provider.calls).toHaveLength(3);
    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe("confirmed_true_positive");
  });

  it("promotes a deterministic fallback when a true-positive verdict has malformed full-finding JSON", async () => {
    const provider = new SequenceProvider([
      JSON.stringify({ verdict: "true_positive", confidence: "high", reason: "scanner evidence is plausible", requestedFiles: [], requestedSymbols: [] }),
      "{\"isFinding\": true",
      "{\"isFinding\": true"
    ]);
    const recorder = new AiJobRecorder();

    const findings = await aiTriage(provider, [pack()], () => undefined, undefined, undefined, ["1/1 semgrep/test src/app.ts:2"], provider, recorder);

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      status: "likely_true_positive",
      confidence: "medium",
      path: "src/app.ts",
      scannerSource: "semgrep"
    });
    expect(provider.calls).toHaveLength(4);
    expect(recorder.summary().events[0].metadata).toMatchObject({ status: "likely_true_positive", fallback: "verdict_true_positive" });
  });

  it("does not promote malformed full-finding output without a true-positive verdict", async () => {
    const provider = new SequenceProvider([
      "{",
      "{",
      "{",
      "{\"isFinding\": true",
      "{\"isFinding\": true"
    ]);
    const recorder = new AiJobRecorder();

    const findings = await aiTriage(provider, [pack()], () => undefined, undefined, undefined, ["1/1 semgrep/test src/app.ts:2"], provider, recorder);

    expect(findings).toHaveLength(0);
    expect(provider.calls).toHaveLength(6);
    expect(recorder.summary().events[0].metadata).toMatchObject({ status: "parse_failed" });
  });

  it("records a false-positive finding from a false-positive verdict without requesting full finding JSON", async () => {
    const provider = new SequenceProvider([
      JSON.stringify({ verdict: "false_positive", confidence: "high", reason: "test-only fixture", requestedFiles: [], requestedSymbols: [] })
    ]);

    const findings = await aiTriage(provider, [pack()]);

    expect(provider.calls).toHaveLength(1);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      status: "false_positive",
      confidence: "low",
      reasoning: "AI verdict marked this scanner result false_positive: test-only fixture"
    });
  });

  it("rejects validly shaped AI findings that cite files outside supplied context", async () => {
    const provider = new SequenceProvider([
      JSON.stringify({ verdict: "true_positive", confidence: "high", reason: "plausible", requestedFiles: [], requestedSymbols: [] }),
      JSON.stringify(validFinding({
        affectedLocations: [{ path: "src/other.ts", startLine: 2, endLine: 2 }],
        evidence: [{ path: "src/other.ts", line: 2, note: "not in context" }]
      }))
    ]);
    const recorder = new AiJobRecorder();

    const findings = await aiTriage(provider, [pack()], () => undefined, undefined, undefined, undefined, provider, recorder);

    expect(findings).toHaveLength(0);
    expect(recorder.summary().events[0].metadata).toMatchObject({ status: "validator_rejected" });
  });
});
