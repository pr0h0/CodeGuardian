import { describe, expect, it } from "vitest";
import { openDatabase } from "../../src/db/database.js";
import { createScan } from "../../src/db/repositories.js";
import { indexRepository } from "../../src/repo/repoIndexer.js";
import { runCustomRules } from "../../src/scanners/customRules.js";

describe("vulnerable fixture", () => {
  it("finds deterministic issues", () => {
    const db = openDatabase(":memory:");
    const scanId = createScan(db, "fixtures/vulnerable-app", {});
    const files = indexRepository(db, scanId, "fixtures/vulnerable-app", { maxFileSize: 1048576 });
    const results = runCustomRules(files);
    expect(results.some((r) => r.ruleId === "js-eval")).toBe(true);
    expect(results.some((r) => r.ruleId === "permissive-cors")).toBe(true);
    db.close();
  });
});
