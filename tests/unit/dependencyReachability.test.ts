import { describe, expect, it } from "vitest";
import type { IndexedFile } from "../../src/repo/repoIndexer.js";
import { analyzeDependencyReachability } from "../../src/repo/dependencyReachability.js";
import { runCorrelationChecks } from "../../src/scanners/correlations.js";
import type { ScannerResult } from "../../src/scanners/types.js";

function file(filePath: string, content: string): IndexedFile {
  return { path: filePath, absolutePath: filePath, language: "typescript", content, lineCount: content.split(/\r?\n/).length };
}

function dependencyResult(): ScannerResult {
  return {
    scanner: "osv-scanner",
    ruleId: "GHSA-lodash-template",
    title: "lodash template command execution vulnerability",
    category: "dependency",
    severity: "high",
    path: "package-lock.json",
    message: "lodash template is vulnerable when attacker-controlled templates are compiled",
    raw: { PkgName: "lodash", aliases: ["CVE-2021-23337"] }
  };
}

describe("dependency reachability", () => {
  it("maps dependency CVEs to exact vulnerable API usage when source calls the API", () => {
    const files = [
      file("src/render.ts", [
        "import _ from 'lodash';",
        "export function render(req) {",
        "  return _.template(req.query.template)({ name: 'test' });",
        "}"
      ].join("\n"))
    ];

    const reachability = analyzeDependencyReachability(files, dependencyResult());
    const correlations = runCorrelationChecks(files, [dependencyResult()]);

    expect(reachability.status).toBe("vulnerable-api-reachable");
    expect(reachability.vulnerableApis).toContain("template");
    expect(reachability.vulnerableApiUsages[0]).toEqual(expect.objectContaining({ path: "src/render.ts", line: 3 }));
    expect(correlations).toEqual(expect.arrayContaining([
      expect.objectContaining({
        ruleId: "reachable-vulnerable-api-lodash-template",
        title: "Reachable vulnerable API: lodash.template"
      })
    ]));
  });

  it("keeps package-import reachability separate from exact vulnerable API reachability", () => {
    const files = [file("src/render.ts", "import _ from 'lodash';\nexport const size = _.size([1]);")];
    const reachability = analyzeDependencyReachability(files, dependencyResult());

    expect(reachability.status).toBe("package-imported");
    expect(reachability.vulnerableApiUsages).toHaveLength(0);
    expect(reachability.packageUsages).toHaveLength(1);
  });
});
