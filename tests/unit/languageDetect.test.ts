import { describe, expect, it } from "vitest";
import { detectLanguage } from "../../src/repo/languageDetect.js";

describe("language detection", () => {
  it("detects common extensions and shebangs", () => {
    expect(detectLanguage("x.ts")).toBe("typescript");
    expect(detectLanguage("tool", "#!/usr/bin/env python")).toBe("python");
  });
});
