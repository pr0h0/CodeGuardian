import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import type { IndexedFile } from "../../src/repo/repoIndexer.js";
import { runComplianceChecks } from "../../src/scanners/compliance.js";
import { runConfigChecks } from "../../src/scanners/configChecks.js";
import { applySuppressions } from "../../src/scanners/suppressions.js";
import { runTaintLite } from "../../src/scanners/taintLite.js";

function file(pathName: string, language: string, content: string): IndexedFile {
  return { path: pathName, absolutePath: pathName, language, content, lineCount: content.split(/\r?\n/).length };
}

describe("new scanner helpers", () => {
  it("finds simple source-to-sink flows", () => {
    const results = runTaintLite([file("bin/import.rb", "ruby", "cmd = ARGV[0]\nOpen3.capture3(cmd)")]);
    expect(results.some((result) => result.ruleId === "taint-command")).toBe(true);
  });

  it("propagates aliases in source-to-sink flows", () => {
    const results = runTaintLite([file("bin/import.rb", "ruby", "cmd = ARGV[0]\nsafe = cmd\nOpen3.capture3(safe)")]);
    expect(results.some((result) => result.ruleId === "taint-command")).toBe(true);
  });

  it("finds security config posture issues", () => {
    const results = runConfigChecks([file("config/environments/production.rb", "ruby", "config.force_ssl = false")]);
    expect(results.some((result) => result.ruleId === "rails-force-ssl-disabled")).toBe(true);
  });

  it("builds SOC2/ISO compliance evidence rows", () => {
    const results = runComplianceChecks([
      file("src/auth.ts", "typescript", "export const requireAuth = () => true;"),
      file("src/session.ts", "typescript", "cookie = { secure: true, httpOnly: true };"),
      file(".github/workflows/security.yml", "yaml", "steps:\n  - run: semgrep ci")
    ], []);

    expect(results.every((result) => result.scanner === "compliance")).toBe(true);
    expect(results.some((result) => result.ruleId === "compliance-auth-access-control" && (result.raw as any).status === "pass")).toBe(true);
    expect(results.some((result) => result.ruleId === "compliance-vulnerability-management" && (result.raw as any).status === "pass")).toBe(true);
  });

  it("marks compliance controls failed when scanner evidence shows violations", () => {
    const results = runComplianceChecks([], [
      { scanner: "custom-rules", ruleId: "generic-secret-assignment", title: "Hardcoded secret", category: "secrets", severity: "high", path: "src/config.ts", startLine: 1, message: "secret" }
    ]);

    const secret = results.find((result) => result.ruleId === "compliance-secret-management");
    expect((secret?.raw as any).status).toBe("fail");
    expect(secret?.severity).toBe("high");
  });

  it("applies inline and file suppressions", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cg-suppress-"));
    fs.writeFileSync(path.join(dir, ".codeguardianignore"), "ignored.php\n");
    const files = [
      file("app.php", "php", "// codeguardian-disable-next-line php-eval\n eval($_GET['x']);"),
      file("ignored.php", "php", "eval($_GET['x']);")
    ];
    const results = applySuppressions(dir, files, [
      { scanner: "custom-rules", ruleId: "php-eval", title: "PHP eval", severity: "high", path: "app.php", startLine: 2, endLine: 2, message: "eval" },
      { scanner: "custom-rules", ruleId: "php-eval", title: "PHP eval", severity: "high", path: "ignored.php", startLine: 1, endLine: 1, message: "eval" }
    ]);
    expect(results.results).toHaveLength(0);
    expect(results.summary.suppressed).toBe(2);
  });
});
