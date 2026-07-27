import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { buildResumeFingerprint, buildSourceTreeFingerprint, listScanWorkspaces, readStageSnapshot, resolveScanWorkspace, summarizeScanWorkspace, writeStageSnapshot } from "../../src/core/resume.js";

describe("scan resume workspaces", () => {
  it("resolves stable sanitized workspace names", () => {
    const repo = fs.mkdtempSync(path.join(os.tmpdir(), "cg-repo-"));
    const workspace = resolveScanWorkspace(repo, { workspace: "q1 audit/../prod" });
    expect(workspace.name).toBe("q1-audit-..-prod");
    expect(workspace.dir).toBe(path.join(repo, ".codeguardian", "workspaces", "q1-audit-..-prod"));
  });

  it("round-trips stage snapshots and lists status", () => {
    const repo = fs.mkdtempSync(path.join(os.tmpdir(), "cg-repo-"));
    const workspace = resolveScanWorkspace(repo, { workspace: "audit-1", resume: true });
    writeStageSnapshot(workspace, "index", "abc", [{ path: "src/app.ts" }]);

    expect(readStageSnapshot<Array<{ path: string }>>(workspace, "index", "abc")).toEqual([{ path: "src/app.ts" }]);
    expect(readStageSnapshot(workspace, "index", "wrong")).toBeUndefined();
    expect(() => readStageSnapshot(workspace, "index", "wrong", { strict: true })).toThrow(/fingerprint mismatch/);

    const summary = summarizeScanWorkspace(repo, "audit-1");
    expect(summary.status).toBe("ready");
    expect(summary.stages.map((stage) => stage.stage)).toEqual(["index"]);
    expect(listScanWorkspaces(repo).map((item) => item.name)).toEqual(["audit-1"]);
  });

  it("builds fingerprints from relevant options and source tree metadata", () => {
    const repo = fs.mkdtempSync(path.join(os.tmpdir(), "cg-repo-"));
    fs.mkdirSync(path.join(repo, "src"));
    fs.writeFileSync(path.join(repo, "src", "app.ts"), "console.log('x');\n");
    const sourceTreeFingerprint = buildSourceTreeFingerprint(repo, { include: ["src/**"] });
    const first = buildResumeFingerprint({
      repoPath: repo,
      options: { include: ["src/**"], out: "/tmp/a", format: "json", maxFiles: 10 },
      projectConfig: { vulnerabilityClasses: ["xss"] },
      sourceTreeFingerprint
    });
    const second = buildResumeFingerprint({
      repoPath: repo,
      options: { include: ["src/**"], out: "/tmp/b", format: "markdown", maxFiles: 10 },
      projectConfig: { vulnerabilityClasses: ["xss"] },
      sourceTreeFingerprint
    });
    const third = buildResumeFingerprint({
      repoPath: repo,
      options: { include: ["src/**"], out: "/tmp/b", format: "markdown", maxFiles: 11 },
      projectConfig: { vulnerabilityClasses: ["xss"] },
      sourceTreeFingerprint
    });

    expect(first).toBe(second);
    expect(first).not.toBe(third);
  });
});
