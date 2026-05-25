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
      result({ scanner: "compliance", ruleId: "compliance-auth-access-control", severity: "medium", startLine: 4 }),
      result({ scanner: "semgrep", ruleId: "real", severity: "medium", startLine: 5 })
    ], 10);

    expect(planned).toHaveLength(1);
    expect(planned[0].ruleId).toBe("real");
  });

  it("limits AI triage candidates to configured vulnerability classes", () => {
    const planned = planAiTriageCandidates([
      result({ ruleId: "ssrf-user-url-fetch", category: "ssrf", title: "User controlled URL reaches fetch", startLine: 1 }),
      result({ ruleId: "raw-html", category: "xss", title: "Raw HTML render", startLine: 2 }),
      result({ ruleId: "tenant-id-bypass", category: "authorization", title: "Tenant authorization bypass", startLine: 3 }),
      result({ ruleId: "sql-string-concat", category: "sql-injection", title: "SQL injection", startLine: 4 })
    ], 10, ["ssrf", "authz"]);

    expect(planned.map((item) => item.ruleId).sort()).toEqual(["ssrf-user-url-fetch", "tenant-id-bypass"]);
  });

  it("prioritizes source-pattern seeds over generic secret and test noise", () => {
    const planned = planAiTriageCandidates([
      result({ scanner: "custom-rules", ruleId: "generic-secret-assignment", category: "secrets", path: "routes/login.ts", startLine: 1 }),
      result({ scanner: "custom-rules", ruleId: "generic-secret-assignment", category: "secrets", path: "test/api/login.test.ts", startLine: 2 }),
      result({ scanner: "source-patterns", ruleId: "source-xxe-unsafe-parser", category: "xxe", path: "routes/fileUpload.ts", startLine: 3, raw: { sourceLine: "parseXml(xml, { noent: true })" } }),
      result({ scanner: "source-patterns", ruleId: "source-open-redirect-variable", category: "open-redirect", severity: "medium", path: "routes/redirect.ts", startLine: 4, raw: { sourceLine: "res.redirect(to)" } })
    ], 4);

    expect(planned.map((item) => `${item.scanner}/${item.ruleId}:${item.startLine}`)).toEqual([
      "source-patterns/source-xxe-unsafe-parser:3",
      "source-patterns/source-open-redirect-variable:4",
      "custom-rules/generic-secret-assignment:1",
      "custom-rules/generic-secret-assignment:2"
    ]);
  });

  it("uses file role classification to prefer runtime findings over client, CI, fixture, and generated noise", () => {
    const planned = planAiTriageCandidates([
      result({ scanner: "custom-rules", ruleId: "generic-secret-assignment", category: "secrets", path: "frontend/src/app/Services/user.service.ts", startLine: 1 }),
      result({ scanner: "semgrep", ruleId: "workflow-token", category: "secrets", path: ".github/workflows/scan.yml", startLine: 2 }),
      result({ scanner: "semgrep", ruleId: "example-sql", category: "sql-injection", path: "data/static/codefixes/example.ts", startLine: 3 }),
      result({ scanner: "source-patterns", ruleId: "source-nosql-where-concat", category: "injection", path: "routes/reviews.ts", startLine: 4, raw: { sourceLine: "$where: 'this.id == ' + id" } }),
      result({ scanner: "semgrep", ruleId: "generated-xss", category: "xss", path: "dist/bundle.min.js", startLine: 5 })
    ], 5);

    expect(planned.map((item) => item.path)).toEqual([
      "routes/reviews.ts",
      "frontend/src/app/Services/user.service.ts",
      "data/static/codefixes/example.ts",
      ".github/workflows/scan.yml",
      "dist/bundle.min.js"
    ]);
  });
});
