import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { loadProjectConfig, ruleAllowedByProfile } from "../../src/config/projectConfig.js";
import { findingFingerprint, scannerFingerprint } from "../../src/core/fingerprint.js";

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
