import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { loadProjectConfig, ruleAllowedByProfile } from "../../src/config/projectConfig.js";
import { findingFingerprint, scannerFingerprint } from "../../src/core/fingerprint.js";
import { createRunContext } from "../../src/core/runContext.js";

describe("project config and fingerprints", () => {
  it("loads simple yaml config", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cg-config-"));
    fs.writeFileSync(path.join(dir, ".codeguardian.yml"), [
      "profile: cli",
      "disabledRules:",
      "  - custom-rules/debug-endpoint",
      "severityOverrides:",
      "  custom-rules/js-eval: critical",
      "aiLowModel: cheap-model",
      "aiMediumModel: balanced-model",
      "aiHighModel: hard-model",
      "incremental: true"
    ].join("\n"));
    const config = loadProjectConfig(dir);
    expect(config.profile).toBe("cli");
    expect(config.disabledRules).toContain("custom-rules/debug-endpoint");
    expect(config.severityOverrides["custom-rules/js-eval"]).toBe("critical");
    expect(config.aiLowModel).toBe("cheap-model");
    expect(config.aiMediumModel).toBe("balanced-model");
    expect(config.aiHighModel).toBe("hard-model");
    expect(config.incremental).toBe(true);
  });

  it("loads Shannon-style scan strategy fields", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cg-config-"));
    fs.writeFileSync(path.join(dir, ".codeguardian.yml"), [
      "focusPaths:",
      "  - src/routes/**",
      "  - app/controllers/**",
      "avoidPaths:",
      "  - tests/**",
      "vulnerabilityClasses:",
      "  - injection",
      "  - authz",
      "  - ssrf",
      "rulesOfEngagement: No destructive testing against shared environments.",
      "reportFilters:",
      "  minSeverity: medium",
      "  minConfidence: medium",
      "  guidance: Drop missing-header-only findings."
    ].join("\n"));

    const config = loadProjectConfig(dir);

    expect(config.focusPaths).toEqual(["src/routes/**", "app/controllers/**"]);
    expect(config.avoidPaths).toEqual(["tests/**"]);
    expect(config.vulnerabilityClasses).toEqual(["injection", "authz", "ssrf"]);
    expect(config.rulesOfEngagement).toBe("No destructive testing against shared environments.");
    expect(config.reportFilters).toEqual({
      minSeverity: "medium",
      minConfidence: "medium",
      guidance: "Drop missing-header-only findings."
    });
  });

  it("uses config focus and avoid paths as scan include/exclude defaults", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cg-config-"));
    fs.mkdirSync(path.join(dir, "src/routes"), { recursive: true });
    fs.mkdirSync(path.join(dir, "tests"), { recursive: true });
    fs.writeFileSync(path.join(dir, "src/routes/app.ts"), "export const route = true;");
    fs.writeFileSync(path.join(dir, "tests/app.test.ts"), "export const test = true;");
    fs.writeFileSync(path.join(dir, ".codeguardian.yml"), [
      "focusPaths:",
      "  - src/routes/**",
      "avoidPaths:",
      "  - tests/**"
    ].join("\n"));

    const ctx = createRunContext(dir, { out: path.join(dir, "reports"), exclude: ["fixtures/**"] });

    expect(ctx.options.include).toEqual(["src/routes/**"]);
    expect(ctx.options.exclude).toEqual(["tests/**", "fixtures/**"]);
  });

  it("fails preflight when configured scan strategy paths match nothing", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cg-config-"));
    fs.mkdirSync(path.join(dir, "src"), { recursive: true });
    fs.writeFileSync(path.join(dir, "src/app.ts"), "export const app = true;");
    fs.writeFileSync(path.join(dir, ".codeguardian.yml"), [
      "focusPaths:",
      "  - src/missing/**",
      "avoidPaths:",
      "  - tests/missing/**"
    ].join("\n"));

    expect(() => createRunContext(dir, { out: path.join(dir, "reports") })).toThrow(/scan strategy path preflight failed/i);
  });

  it("filters rules by profile", () => {
    expect(ruleAllowedByProfile("cli-argv-command-sink", "command-injection", "bin/import.rb", "cli")).toBe(true);
    expect(ruleAllowedByProfile("raw-html", "xss", "app/views/index.erb", "cli")).toBe(false);
  });

  it("creates stable fingerprints", () => {
    const scanner = scannerFingerprint({ scanner: "custom-rules", ruleId: "php-eval", title: "PHP eval", severity: "high", path: "a.php", startLine: 11, message: "eval" });
    const finding = findingFingerprint({ title: "PHP eval candidate", category: "code-injection", severity: "high", confidence: "medium", status: "suspected", path: "a.php", startLine: 12, evidence: [], reasoning: "", remediation: "" });
    expect(scanner).toHaveLength(16);
    expect(finding).toHaveLength(16);
  });
});
