import { describe, expect, it } from "vitest";
import { loadEnv } from "../../src/config/env.js";

describe("env", () => {
  it("parses defaults", () => {
    const env = loadEnv({});
    expect(env.AI_PROVIDER).toBe("openai");
    expect(env.CODEGUARDIAN_MAX_FILE_SIZE).toBe(1048576);
    expect(env.CODEGUARDIAN_MAX_AI_FINDINGS).toBe(100);
    expect(env.CODEGUARDIAN_MAX_AI_FINDINGS_LIMIT).toBe(1000);
    expect(env.CODEGUARDIAN_AI_TRIAGE_TARGET_CODE_FINDINGS).toBe(25);
    expect(env.CODEGUARDIAN_AI_AUDIT_MAX_FILES).toBe(100);
    expect(env.CODEGUARDIAN_AI_AUDIT_MAX_ROUNDS).toBe(30);
    expect(env.CODEGUARDIAN_AI_AUDIT_MAX_CHARS).toBe(500000);
    expect(env.AI_LOW_MODEL).toBe("");
    expect(env.AI_MEDIUM_MODEL).toBe("");
    expect(env.AI_HIGH_MODEL).toBe("");
  });
});
