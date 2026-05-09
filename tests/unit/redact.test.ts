import { describe, expect, it } from "vitest";
import { redactSecrets } from "../../src/utils/redact.js";

describe("redaction", () => {
  it("redacts secret values", () => {
    expect(redactSecrets("API_KEY=abcdef1234567890")).toContain("[REDACTED]");
  });
});
