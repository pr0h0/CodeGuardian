import { describe, expect, it } from "vitest";
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
});
