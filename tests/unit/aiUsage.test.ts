import { describe, expect, it } from "vitest";
import { AiUsageTracker, extractAiUsage } from "../../src/ai/usage.js";

describe("AI usage accounting", () => {
  it("extracts OpenAI-style token usage", () => {
    expect(extractAiUsage({ usage: { input_tokens: 100, output_tokens: 25, total_tokens: 125 } })).toMatchObject({
      inputTokens: 100,
      outputTokens: 25,
      totalTokens: 125,
      cachedInputTokens: 0,
      costUsd: null
    });
  });

  it("extracts cached token usage from Anthropic and DeepSeek fields", () => {
    expect(extractAiUsage({ usage: { input_tokens: 100, cache_creation_input_tokens: 20, cache_read_input_tokens: 50, output_tokens: 10 } })).toMatchObject({
      inputTokens: 170,
      outputTokens: 10,
      totalTokens: 180,
      cachedInputTokens: 50,
      cacheWriteInputTokens: 20
    });

    expect(extractAiUsage({ usage: { prompt_cache_miss_tokens: 500, prompt_cache_hit_tokens: 250, completion_tokens: 75 } })).toMatchObject({
      inputTokens: 750,
      outputTokens: 75,
      totalTokens: 825,
      cachedInputTokens: 250,
      cacheWriteInputTokens: 0
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
      cachedInputTokens: 0,
      cacheWriteInputTokens: 0,
      cachedInputCostUsd: null,
      inputCostUsd: null,
      outputCostUsd: null,
      costUsd: 0.003
    }]);
  });

  it("estimates OpenAI model cost when the provider only returns tokens", () => {
    const tracker = new AiUsageTracker();
    tracker.track("openai", "high", "gpt-5.5", {
      usage: {
        input_tokens: 1_000_000,
        input_tokens_details: { cached_tokens: 200_000 },
        output_tokens: 100_000
      }
    });

    expect(tracker.summary()).toEqual([{
      provider: "openai",
      tier: "high",
      model: "gpt-5.5",
      requests: 1,
      inputTokens: 1_000_000,
      outputTokens: 100_000,
      totalTokens: 1_100_000,
      cachedInputTokens: 200_000,
      cacheWriteInputTokens: 0,
      cachedInputCostUsd: 0.1,
      inputCostUsd: 4.1,
      outputCostUsd: 3,
      costUsd: 7.1
    }]);
  });

  it("estimates DeepSeek cache-hit pricing when cache token counts are returned", () => {
    const tracker = new AiUsageTracker();
    tracker.track("deepseek", "low", "deepseek-v4-flash", {
      usage: {
        prompt_cache_miss_tokens: 500_000,
        prompt_cache_hit_tokens: 500_000,
        completion_tokens: 100_000
      }
    });

    expect(tracker.summary()).toEqual([{
      provider: "deepseek",
      tier: "low",
      model: "deepseek-v4-flash",
      requests: 1,
      inputTokens: 1_000_000,
      outputTokens: 100_000,
      totalTokens: 1_100_000,
      cachedInputTokens: 500_000,
      cacheWriteInputTokens: 0,
      cachedInputCostUsd: 0.0014,
      inputCostUsd: 0.0714,
      outputCostUsd: 0.028,
      costUsd: 0.0994
    }]);
  });

  it("uses Anthropic cache read and default cache write prices when present", () => {
    const tracker = new AiUsageTracker();
    tracker.track("anthropic", "high", "claude-opus-4-7", {
      usage: {
        input_tokens: 100,
        cache_creation_input_tokens: 20,
        cache_read_input_tokens: 50,
        output_tokens: 10
      }
    });

    expect(tracker.summary()[0]).toMatchObject({
      provider: "anthropic",
      tier: "high",
      model: "claude-opus-4-7",
      requests: 1,
      inputTokens: 170,
      outputTokens: 10,
      totalTokens: 180,
      cachedInputTokens: 50,
      cacheWriteInputTokens: 20,
      cachedInputCostUsd: 0.000025,
      inputCostUsd: 0.00065,
      outputCostUsd: 0.00025,
      costUsd: 0.0009
    });
  });

  it("matches common latest and routed model aliases", () => {
    const tracker = new AiUsageTracker();
    tracker.track("anthropic", "low", "claude-3-5-haiku-latest", { usage: { input_tokens: 1_000_000, output_tokens: 100_000 } });
    tracker.track("openrouter", "high", "anthropic/claude-opus-4-7-latest", { usage: { input_tokens: 1_000_000, output_tokens: 100_000 } });

    expect(tracker.summary()).toEqual([
      {
        provider: "openrouter",
        tier: "high",
        model: "anthropic/claude-opus-4-7-latest",
        requests: 1,
        inputTokens: 1_000_000,
        outputTokens: 100_000,
        totalTokens: 1_100_000,
        cachedInputTokens: 0,
        cacheWriteInputTokens: 0,
        cachedInputCostUsd: 0,
        inputCostUsd: 5,
        outputCostUsd: 2.5,
        costUsd: 7.5
      },
      {
        provider: "anthropic",
        tier: "low",
        model: "claude-3-5-haiku-latest",
        requests: 1,
        inputTokens: 1_000_000,
        outputTokens: 100_000,
        totalTokens: 1_100_000,
        cachedInputTokens: 0,
        cacheWriteInputTokens: 0,
        cachedInputCostUsd: 0,
        inputCostUsd: 0.8,
        outputCostUsd: 0.4,
        costUsd: 1.2
      }
    ]);
  });
});
