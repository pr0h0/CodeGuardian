import { describe, expect, it } from "vitest";
import { preflightAiProviders } from "../../src/ai/preflight.js";
import { classifyAiError, withAiReliability } from "../../src/ai/reliability.js";
import type { AiCompletionInput, AiCompletionOutput, AiProvider } from "../../src/ai/types.js";
import type { AiTier } from "../../src/ai/usage.js";
import { AiJobRecorder } from "../../src/ai/jobs.js";

class SequencedProvider implements AiProvider {
  name = "fake";
  calls: AiCompletionInput[] = [];
  private index = 0;

  constructor(private readonly results: Array<AiCompletionOutput | Error>) {}

  async complete(input: AiCompletionInput): Promise<AiCompletionOutput> {
    this.calls.push(input);
    const next = this.results[Math.min(this.index++, this.results.length - 1)];
    if (next instanceof Error) throw next;
    return next;
  }
}

const okOutput = (text = "{\"ok\":true}"): AiCompletionOutput => ({ text, parsedJson: { ok: true }, raw: { usage: { input_tokens: 1, output_tokens: 1 } } });

describe("AI provider reliability", () => {
  it("retries retryable rate-limit failures before returning the successful response", async () => {
    const provider = new SequencedProvider([new Error("429 rate limit exceeded"), okOutput()]);
    const reliable = withAiReliability(provider, { maxAttempts: 2 });

    const output = await reliable.complete({ system: "s", messages: [{ role: "user", content: "u" }] });

    expect(output.text).toBe("{\"ok\":true}");
    expect(provider.calls).toHaveLength(2);
  });

  it("does not retry authentication or configuration failures", async () => {
    const provider = new SequencedProvider([new Error("401 invalid API key"), okOutput()]);
    const reliable = withAiReliability(provider, { maxAttempts: 3 });

    await expect(reliable.complete({ system: "s", messages: [{ role: "user", content: "u" }] })).rejects.toMatchObject({
      kind: "authentication",
      retryable: false
    });
    expect(provider.calls).toHaveLength(1);
  });

  it("detects provider text responses that indicate spending-cap or billing failures", async () => {
    const provider = new SequencedProvider([okOutput("Your spending cap has been reached. Please visit Plans & Billing.")]);
    const reliable = withAiReliability(provider, { maxAttempts: 1 });

    await expect(reliable.complete({ system: "s", messages: [{ role: "user", content: "u" }] })).rejects.toMatchObject({
      kind: "billing",
      retryable: true
    });
  });

  it("classifies server and invalid-request errors differently", () => {
    expect(classifyAiError(new Error("503 server overloaded"))).toMatchObject({ kind: "server", retryable: true });
    expect(classifyAiError(new Error("400 invalid request: schema rejected"))).toMatchObject({ kind: "invalid_request", retryable: false });
  });
});

describe("AI provider preflight", () => {
  it("checks each model tier with a tiny structured request and records job outcomes", async () => {
    const providers = Object.fromEntries(
      (["low", "medium", "high"] as AiTier[]).map((tier) => [tier, new SequencedProvider([okOutput(`{"ok":true,"tier":"${tier}"}`)])])
    ) as Record<AiTier, SequencedProvider>;
    const recorder = new AiJobRecorder();
    const logs: string[] = [];

    await preflightAiProviders(providers, (message) => logs.push(message), recorder);

    expect(providers.low.calls[0]).toMatchObject({ temperature: 0, maxTokens: 128 });
    expect(providers.medium.calls[0].jsonSchema).toMatchObject({ name: "ai_provider_preflight" });
    expect(providers.high.calls).toHaveLength(1);
    expect(logs.join("\n")).toContain("ai-preflight: high provider=fake ok");
    expect(recorder.summary()).toMatchObject({ total: 3, succeeded: 3, failed: 0 });
    expect(recorder.summary().events.map((event) => event.type)).toEqual(["preflight", "preflight", "preflight"]);
  });

  it("retries malformed preflight text before failing the scan", async () => {
    const providers = {
      low: new SequencedProvider([{ text: "", raw: {} }, { text: "{\"ok\":", raw: {} }, okOutput()]),
      medium: new SequencedProvider([okOutput()]),
      high: new SequencedProvider([okOutput()])
    };

    await preflightAiProviders(providers);

    expect(providers.low.calls).toHaveLength(3);
  });
});
