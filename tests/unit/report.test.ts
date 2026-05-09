import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { writeMarkdownReport } from "../../src/reports/markdown.js";

describe("report", () => {
  it("writes markdown", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cg-"));
    const file = writeMarkdownReport(dir, { scan: { id: "1", repo_path: ".", status: "completed" }, files: [], findings: [], scannerResults: [] });
    expect(fs.existsSync(file)).toBe(true);
  });

  it("escapes html tags in markdown output", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cg-"));
    const file = writeMarkdownReport(dir, {
      scan: { id: "1", repo_path: ".", status: "completed" },
      files: [],
      findings: [{
        title: "<script>alert(1)</script>",
        category: "xss",
        severity: "high",
        confidence: "high",
        status: "confirmed",
        path: "app.ts",
        start_line: 1,
        reasoning: "<img src=x onerror=alert(1)>",
        remediation: "escape < and >",
        evidence_json: "[]"
      }],
      scannerResults: []
    });
    const content = fs.readFileSync(file, "utf8");
    expect(content).toContain("&lt;script&gt;");
    expect(content).not.toContain("<script>");
  });
});
