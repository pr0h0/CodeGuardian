import { describe, expect, it } from "vitest";
import { buildOpenAiResponseParams, supportsTemperature } from "../../src/ai/openai.js";
import { buildOpenAiCompatibleChatParams } from "../../src/ai/openaiCompatible.js";
import { aiHighModel, aiLowModel, aiMediumModel, createAiProvider } from "../../src/ai/provider.js";
import { aiFindingJsonSchema } from "../../src/ai/schemas.js";
import { loadEnv } from "../../src/config/env.js";

describe("provider config", () => {
  it("fails clearly without key", () => {
    expect(() => createAiProvider(loadEnv({ AI_PROVIDER: "openai" }))).toThrow(/requires/);
  });
  it("falls tier models back to AI_MODEL", () => {
    const env = loadEnv({ AI_PROVIDER: "deepseek", DEEPSEEK_API_KEY: "x", AI_MODEL: "shared-model" });
    expect(aiLowModel(env)).toBe("shared-model");
    expect(aiMediumModel(env)).toBe("shared-model");
    expect(aiHighModel(env)).toBe("shared-model");
  });

  it("uses explicit low, medium, and high tier models before AI_MODEL", () => {
    const env = loadEnv({
      AI_PROVIDER: "deepseek",
      DEEPSEEK_API_KEY: "x",
      AI_MODEL: "shared-model",
      AI_LOW_MODEL: "cheap-model",
      AI_MEDIUM_MODEL: "balanced-model",
      AI_HIGH_MODEL: "hard-model"
    });
    expect(aiLowModel(env)).toBe("cheap-model");
    expect(aiMediumModel(env)).toBe("balanced-model");
    expect(aiHighModel(env)).toBe("hard-model");
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

  it("passes strict JSON schema to OpenAI responses", () => {
    const params = buildOpenAiResponseParams("gpt-4.1-mini", {
      system: "system",
      messages: [{ role: "user", content: "hi" }],
      jsonSchema: aiFindingJsonSchema,
      temperature: 0,
      maxTokens: 100
    });
    expect(params.text?.format).toMatchObject({
      type: "json_schema",
      name: "security_triage_finding",
      strict: true
    });
  });

  it("uses JSON object mode for DeepSeek-compatible chat completions", () => {
    const directParams = buildOpenAiCompatibleChatParams("deepseek", "deepseek-v4-pro", {
      system: "Return raw JSON only.",
      messages: [{ role: "user", content: "hi" }],
      jsonSchema: aiFindingJsonSchema,
      temperature: 0,
      maxTokens: 100
    });
    const routedParams = buildOpenAiCompatibleChatParams("openrouter", "deepseek/deepseek-v4-pro", {
      system: "Return raw JSON only.",
      messages: [{ role: "user", content: "hi" }],
      jsonSchema: aiFindingJsonSchema,
      temperature: 0,
      maxTokens: 100
    });

    expect(directParams.response_format).toEqual({ type: "json_object" });
    expect(routedParams.response_format).toEqual({ type: "json_object" });
  });
});
