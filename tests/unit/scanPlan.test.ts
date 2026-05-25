import { describe, expect, it } from "vitest";
import { buildScanPlan, filterResultsToScanScope, persistScanPlanCache } from "../../src/core/scanPlan.js";
import { openDatabase } from "../../src/db/database.js";
import type { IndexedFile } from "../../src/repo/repoIndexer.js";
import type { ScannerResult } from "../../src/scanners/types.js";

function indexedFile(path: string, content: string): IndexedFile {
  return {
    path,
    absolutePath: `/repo/${path}`,
    language: "typescript",
    content,
    lineCount: content.split(/\r?\n/).length
  };
}

describe("scan plan", () => {
  it("computes changed files from persisted scan cache", () => {
    const db = openDatabase(":memory:");
    const repoPath = "/repo";
    const files = [indexedFile("src/a.ts", "const a = 1;"), indexedFile("src/b.ts", "const b = 1;")];

    const first = buildScanPlan(db, repoPath, files, { incremental: true });
    expect([...first.changedPaths].sort()).toEqual(["src/a.ts", "src/b.ts"]);
    expect(first.localFiles.map((file) => file.path).sort()).toEqual(["src/a.ts", "src/b.ts"]);

    persistScanPlanCache(db, repoPath, files);
    const second = buildScanPlan(db, repoPath, files, { incremental: true });
    expect([...second.changedPaths]).toEqual([]);
    expect(second.localFiles).toEqual([]);

    const third = buildScanPlan(db, repoPath, [files[0], indexedFile("src/b.ts", "const b = 2;")], { incremental: true });
    expect([...third.changedPaths]).toEqual(["src/b.ts"]);
    expect(third.localFiles.map((file) => file.path)).toEqual(["src/b.ts"]);

    db.close();
  });

  it("filters scanner results to the indexed file scope", () => {
    const db = openDatabase(":memory:");
    const plan = buildScanPlan(db, "/repo", [indexedFile("src/a.ts", "const a = 1;")], { incremental: false });
    const results: ScannerResult[] = [
      { scanner: "semgrep", ruleId: "kept", title: "kept", severity: "high", path: "src/a.ts", message: "kept" },
      { scanner: "semgrep", ruleId: "dropped", title: "dropped", severity: "high", path: "dist/generated.js", message: "drop" },
      { scanner: "trivy", ruleId: "repo-level", title: "repo-level", severity: "medium", message: "keep pathless" },
      { scanner: "bearer", ruleId: "windows", title: "windows", severity: "medium", path: "src\\a.ts", message: "normalize" }
    ];

    expect(filterResultsToScanScope(results, plan).map((result) => result.ruleId)).toEqual(["kept", "repo-level", "windows"]);

    db.close();
  });
});
