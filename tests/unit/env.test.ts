import { describe, expect, it } from "vitest";
import { loadEnv } from "../../src/config/env.js";

describe("env", () => {
  it("parses defaults", () => {
    const env = loadEnv({});
    expect(env.AI_PROVIDER).toBe("openai");
    expect(env.CODEGUARDIAN_MAX_FILE_SIZE).toBe(1048576);
    expect(env.CODEGUARDIAN_MAX_AI_FINDINGS).toBe(25);
    expect(env.CODEGUARDIAN_MAX_AI_FINDINGS_LIMIT).toBe(1000);
  });
});
