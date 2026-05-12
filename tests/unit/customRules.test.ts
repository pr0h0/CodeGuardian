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

  it("flags JavaScript prototype pollution candidates", () => {
    const results = runCustomRules([
      file("src/settings.ts", "typescript", [
        "merge(defaults, req.body);",
        "target[req.query.key] = req.body.value;",
        "config['__proto__'] = payload;"
      ].join("\n"))
    ]);

    expect(results.some((result) => result.ruleId === "js-prototype-pollution-unsafe-merge")).toBe(true);
    expect(results.some((result) => result.ruleId === "js-dynamic-object-key-assignment")).toBe(true);
    expect(results.some((result) => result.ruleId === "js-prototype-pollution-assignment")).toBe(true);
  });

  it("does not flag secret assignments loaded from runtime environment", () => {
    const results = runCustomRules([
      file("src/config.ts", "typescript", [
        "const apiKey = process.env.API_KEY;",
        "const token = import.meta.env.VITE_TOKEN;",
        "const secret = Deno.env.get(\"APP_SECRET\");"
      ].join("\n")),
      file("settings.py", "python", [
        "api_key = os.environ[\"API_KEY\"]",
        "token = getenv(\"SERVICE_TOKEN\")"
      ].join("\n")),
      file("config.ru", "ruby", "secret = ENV[\"APP_SECRET\"]")
    ]);

    expect(results.filter((result) => result.category === "secrets")).toHaveLength(0);
  });

  it("still flags hardcoded secret literals", () => {
    const results = runCustomRules([
      file("src/config.ts", "typescript", [
        "const apiKey = \"abcdef1234567890\";",
        "const token = \"hardcoded-token-value\";"
      ].join("\n")),
      file(".env", "unknown", "API_KEY=abcdef1234567890")
    ]);

    expect(results.filter((result) => result.ruleId === "generic-secret-assignment")).toHaveLength(3);
  });

  it("keeps bundled rule regexes valid", () => {
    for (const rule of loadCustomRules()) {
      expect(() => new RegExp(rule.regex, "gim")).not.toThrow();
    }
  });
});
