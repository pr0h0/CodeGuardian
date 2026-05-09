import { describe, expect, it } from "vitest";
import { buildContextPack } from "../../src/repo/contextPackBuilder.js";

describe("context packs", () => {
  it("redacts env file content", () => {
    const pack = buildContextPack(
      { scanner: "custom", ruleId: "secret", title: "secret", severity: "high", path: ".env", startLine: 1, endLine: 1, message: "secret" },
      [{ path: ".env", absolutePath: ".env", language: "unknown", content: "API_KEY=secret-value", lineCount: 1 }],
      [],
      10000
    );
    expect(pack.snippets[0].content).toBe("[REDACTED ENV FILE CONTENT]");
  });
});
