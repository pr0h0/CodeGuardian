import { describe, expect, it } from "vitest";
import { createAiProvider } from "../../src/ai/provider.js";
import { loadEnv } from "../../src/config/env.js";

describe("provider config", () => {
  it("fails clearly without key", () => {
    expect(() => createAiProvider(loadEnv({ AI_PROVIDER: "openai" }))).toThrow(/requires/);
  });
});
