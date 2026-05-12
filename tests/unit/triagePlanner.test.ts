import { describe, expect, it } from "vitest";
import { planAiTriageCandidates } from "../../src/core/triagePlanner.js";
import type { ScannerResult } from "../../src/scanners/types.js";

function result(overrides: Partial<ScannerResult>): ScannerResult {
  return {
    scanner: "semgrep",
    ruleId: "rule",
    title: "Finding",
    category: "security",
    severity: "high",
    path: "src/app.ts",
    startLine: 1,
    endLine: 1,
    message: "finding",
    ...overrides
  };
}

describe("triage planner", () => {
  it("spreads AI triage across scanner groups before taking duplicate rows", () => {
    const planned = planAiTriageCandidates([
      result({ ruleId: "eval", path: "src/a.ts", startLine: 1 }),
      result({ ruleId: "eval", path: "src/a.ts", startLine: 2 }),
      result({ scanner: "taint-flow", ruleId: "cmd", category: "command-injection", path: "src/b.ts", startLine: 3 }),
      result({ ruleId: "xss", path: "src/c.ts", startLine: 4 })
    ], 4);

    expect(planned.map((item) => `${item.scanner}/${item.ruleId}:${item.startLine}`)).toEqual([
      "taint-flow/cmd:3",
      "semgrep/eval:1",
      "semgrep/xss:4",
      "semgrep/eval:2"
    ]);
  });

  it("skips low-signal, quality, and dependency vulnerability rows", () => {
    const planned = planAiTriageCandidates([
      result({ severity: "low", startLine: 1 }),
      result({ scanner: "quality", severity: "medium", startLine: 2 }),
      result({ scanner: "trivy", ruleId: "CVE-2024-1234", severity: "high", startLine: 3 }),
      result({ scanner: "semgrep", ruleId: "real", severity: "medium", startLine: 4 })
    ], 10);

    expect(planned).toHaveLength(1);
    expect(planned[0].ruleId).toBe("real");
  });
});
