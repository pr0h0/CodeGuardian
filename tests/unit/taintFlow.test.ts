import { describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import type { IndexedFile } from "../../src/repo/repoIndexer.js";
import { buildSecurityGraph } from "../../src/repo/securityGraph.js";
import { runTaintFlow } from "../../src/scanners/taintFlow.js";

function file(path: string, content: string): IndexedFile {
  return { path, absolutePath: path, language: "typescript", content, lineCount: content.split(/\r?\n/).length };
}

describe("taint-flow", () => {
  it("builds an AST-lite function/sink graph", () => {
    const graph = buildSecurityGraph([
      file("src/exec.ts", [
        "import { exec } from 'node:child_process';",
        "export function dangerousExec(cmd) {",
        "  exec(cmd);",
        "}"
      ].join("\n"))
    ]);

    expect(graph.functions.some((fn) => fn.name === "dangerousExec")).toBe(true);
    expect(graph.functionSinks.some((model) => model.fn.name === "dangerousExec" && model.sink.category === "command-injection")).toBe(true);
  });

  it("detects interprocedural source to sink flow", () => {
    const results = runTaintFlow([
      file("src/server.ts", [
        "import { dangerousExec } from './exec';",
        "app.get('/run', (req, res) => dangerousExec(req.query.cmd));"
      ].join("\n")),
      file("src/exec.ts", [
        "import { exec } from 'node:child_process';",
        "export function dangerousExec(cmd) {",
        "  exec(cmd);",
        "}"
      ].join("\n"))
    ]);

    expect(results.some((result) => result.ruleId === "flow-command-interprocedural" && result.path === "src/server.ts")).toBe(true);
  });

  it("detects request data reaching template rendering sinks", () => {
    const results = runTaintFlow([
      file("src/views.ts", "res.render('profile', req.query);"),
      file("app.py", "return render_template('profile.html', name=request.args['name'])")
    ]);

    expect(results.some((result) => result.ruleId === "flow-template-direct" && result.category === "template-injection")).toBe(true);
    expect(results.some((result) => result.path === "app.py" && result.category === "template-injection")).toBe(true);
  });

  it("detects benchmark fixture true positive", () => {
    const root = path.resolve("fixtures/benchmark-express/src");
    const files = ["server.js", "exec.js"].map((name) => file(`src/${name}`, fs.readFileSync(path.join(root, name), "utf8")));
    const results = runTaintFlow(files);
    expect(results.some((result) => result.category === "command-injection")).toBe(true);
  });
});
