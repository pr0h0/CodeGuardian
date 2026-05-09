import { describe, expect, it } from "vitest";
import type { IndexedFile } from "../../src/repo/repoIndexer.js";
import { loadCustomRules, runCustomRules } from "../../src/scanners/customRules.js";

function file(path: string, language: string, content: string): IndexedFile {
  return { path, absolutePath: path, language, content, lineCount: content.split(/\r?\n/).length };
}

describe("custom rules", () => {
  it("flags PHP injection and deserialization sinks", () => {
    const results = runCustomRules([
      file("public/index.php", "php", [
        "<?php",
        "system($_GET['cmd']);",
        "include $_REQUEST['page'];",
        "unserialize($_POST['payload']);"
      ].join("\n"))
    ]);

    expect(results.some((result) => result.ruleId === "php-command-exec-user-input")).toBe(true);
    expect(results.some((result) => result.ruleId === "php-file-include-user-input")).toBe(true);
    expect(results.some((result) => result.ruleId === "php-unserialize-user-input")).toBe(true);
  });

  it("flags Ruby CLI and Rails dangerous sinks", () => {
    const results = runCustomRules([
      file("app/controllers/files_controller.rb", "ruby", [
        "redirect_to params[:next]",
        "render inline: params[:template]",
        "File.read(ARGV[0])",
        "Open3.capture3(params[:cmd])"
      ].join("\n"))
    ]);

    expect(results.some((result) => result.ruleId === "rails-open-redirect")).toBe(true);
    expect(results.some((result) => result.ruleId === "rails-render-inline-user-input")).toBe(true);
    expect(results.some((result) => result.ruleId === "ruby-path-traversal-user-input")).toBe(true);
    expect(results.some((result) => result.ruleId === "ruby-command-exec-user-input")).toBe(true);
  });

  it("keeps bundled rule regexes valid", () => {
    for (const rule of loadCustomRules()) {
      expect(() => new RegExp(rule.regex, "gim")).not.toThrow();
    }
  });
});
