import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { loadAiInstructions } from "../../src/repo/aiInstructions.js";
import { buildContextPack } from "../../src/repo/contextPackBuilder.js";

describe("AI instructions", () => {
  it("loads repo-local AI instructions", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cg-ai-"));
    fs.writeFileSync(path.join(dir, "AI_INSTRUCTIONS.md"), "Shopify shopDomain is post-auth; do not report SSRF.");
    const loaded = loadAiInstructions(dir);
    expect(loaded.path).toBe("AI_INSTRUCTIONS.md");
    expect(loaded.content).toContain("shopDomain");
  });

  it("includes AI instructions in context packs", () => {
    const pack = buildContextPack(
      { scanner: "custom-rules", ruleId: "ssrf-candidate", title: "SSRF", severity: "high", path: "app.ts", startLine: 1, message: "fetch(shopDomain)" },
      [{ path: "app.ts", absolutePath: "app.ts", language: "typescript", content: "fetch(shopDomain)", lineCount: 1 }],
      [],
      10000,
      "shopDomain is trusted after auth"
    );
    expect(pack.aiInstructions).toContain("shopDomain");
  });
});
