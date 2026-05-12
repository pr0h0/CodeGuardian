import { describe, expect, it } from "vitest";
import { buildOpenAiResponseParams, supportsTemperature } from "../../src/ai/openai.js";
import { aiFastModel, aiStrongModel, createAiProvider } from "../../src/ai/provider.js";
import { loadEnv } from "../../src/config/env.js";

describe("provider config", () => {
  it("fails clearly without key", () => {
    expect(() => createAiProvider(loadEnv({ AI_PROVIDER: "openai" }))).toThrow(/requires/);
  });
  it("selects DeepSeek fast and strong defaults", () => {
    const env = loadEnv({ AI_PROVIDER: "deepseek", DEEPSEEK_API_KEY: "x" });
    expect(aiFastModel(env, "deepseek")).toBe("deepseek-v4-flash");
    expect(aiStrongModel(env, "deepseek")).toBe("deepseek-v4-pro");
  });

  it("omits temperature for OpenAI models that reject it", () => {
    expect(supportsTemperature("gpt-5.5")).toBe(false);
    expect(supportsTemperature("gpt-5.4-mini")).toBe(false);
    expect(supportsTemperature("openai/gpt-5.4-mini")).toBe(false);
    expect(supportsTemperature("gpt-4.1-mini")).toBe(true);

    const params = buildOpenAiResponseParams("gpt-5.4-mini", {
      system: "system",
      messages: [{ role: "user", content: "hi" }],
      temperature: 0,
      maxTokens: 100
    });
    expect(params).not.toHaveProperty("temperature");
  });
});
