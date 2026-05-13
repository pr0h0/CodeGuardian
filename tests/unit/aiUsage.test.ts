import { describe, expect, it } from "vitest";
import { AiUsageTracker, extractAiUsage } from "../../src/ai/usage.js";

describe("AI usage accounting", () => {
  it("extracts OpenAI-style token usage", () => {
    expect(extractAiUsage({ usage: { input_tokens: 100, output_tokens: 25, total_tokens: 125 } })).toMatchObject({
      inputTokens: 100,
      outputTokens: 25,
      totalTokens: 125,
      costUsd: null
    });
  });

  it("extracts OpenAI-compatible usage and cost fields", () => {
    expect(extractAiUsage({
      usage: {
        prompt_tokens: 200,
        completion_tokens: 50,
        total_tokens: 250,
        cost: "0.0042",
        cost_details: {
          prompt_tokens_cost: "0.0012",
          completion_tokens_cost: "0.003"
        }
      }
    })).toMatchObject({
      inputTokens: 200,
      outputTokens: 50,
      totalTokens: 250,
      inputCostUsd: 0.0012,
      outputCostUsd: 0.003,
      costUsd: 0.0042
    });
  });

  it("aggregates usage by provider, tier, and model", () => {
    const tracker = new AiUsageTracker();
    tracker.track("openrouter", "low", "cheap", { usage: { prompt_tokens: 10, completion_tokens: 2, cost: 0.001 } });
    tracker.track("openrouter", "low", "cheap", { usage: { prompt_tokens: 20, completion_tokens: 3, cost: 0.002 } });

    expect(tracker.summary()).toEqual([{
      provider: "openrouter",
      tier: "low",
      model: "cheap",
      requests: 2,
      inputTokens: 30,
      outputTokens: 5,
      totalTokens: 35,
      inputCostUsd: null,
      outputCostUsd: null,
      costUsd: 0.003
    }]);
  });
});
