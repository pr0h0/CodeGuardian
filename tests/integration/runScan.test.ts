import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../src/tools/commandRunner.js", () => ({
  checkTool: vi.fn(async (name: string) => ({ available: true, version: `${name} test` })),
  runCommand: vi.fn()
}));

vi.mock("../../src/scanners/semgrep.js", () => ({
  runSemgrep: vi.fn(async () => ({
    results: [
      { scanner: "semgrep", ruleId: "outside-scope", title: "outside", severity: "high", path: "node_modules/out.js", message: "drop me" }
    ],
    code: 0
  }))
}));
vi.mock("../../src/scanners/gitleaks.js", () => ({ runGitleaks: vi.fn(async () => ({ results: [], code: 0 })) }));
vi.mock("../../src/scanners/trivy.js", () => ({ runTrivy: vi.fn(async () => ({ results: [], code: 0 })) }));
vi.mock("../../src/scanners/osv.js", () => ({ runOsv: vi.fn(async () => ({ results: [], code: 0 })) }));
vi.mock("../../src/scanners/bearer.js", () => ({ runBearer: vi.fn(async () => ({ results: [], code: 0 })) }));

describe("runScan integration", () => {
  beforeEach(() => {
    delete process.env.CODEGUARDIAN_DB_PATH;
    delete process.env.CODEGUARDIAN_REPORT_DIR;
  });

  it("runs the deterministic scan path, filters external results to scope, and writes enriched JSON", async () => {
    const { createRunContext } = await import("../../src/core/runContext.js");
    const { runScan } = await import("../../src/core/scanner.js");
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "cg-run-scan-"));
    process.env.CODEGUARDIAN_DB_PATH = path.join(tempDir, "codeguardian.sqlite");

    const ctx = createRunContext("fixtures/vulnerable-app", {
      out: tempDir,
      format: "json",
      ai: false,
      include: ["server.js"]
    });
    const result = await runScan(ctx);
    const jsonReport = result.reportFiles.find((file) => file.endsWith(".json"));
    expect(jsonReport).toBeTruthy();

    const report = JSON.parse(fs.readFileSync(jsonReport!, "utf8"));
    expect(report.scannerResults.some((item: any) => item.rule_id === "js-eval")).toBe(true);
    expect(report.scannerResults.some((item: any) => item.rule_id === "outside-scope")).toBe(false);
    expect(report.reportModel).toBeTruthy();
    expect(report.securityIntelligence).toEqual(expect.objectContaining({
      summary: expect.any(String),
      boundaries: expect.any(Array),
      catalog: expect.any(Array)
    }));
    expect(report.aiJobs.total).toBe(0);
  });
});
