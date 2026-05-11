import { describe, expect, it } from "vitest";
import { redactSecrets, setRedactionEnabled } from "../../src/utils/redact.js";
import { loadEnv } from "../../src/config/env.js";

describe("redaction", () => {
  it("redacts secret values", () => {
    setRedactionEnabled(true);
    expect(redactSecrets("API_KEY=abcdef1234567890")).toContain("[REDACTED]");
  });

  it("can be disabled through env", () => {
    loadEnv({ CODEGUARDIAN_REDACT_SECRETS: "false" });
    expect(redactSecrets("API_KEY=abcdef1234567890")).toContain("abcdef1234567890");
    setRedactionEnabled(true);
  });
});
