import type { IndexedFile } from "../repo/repoIndexer.js";
import { buildSecurityGraph, callRegex, sanitizerPattern, sourcePattern, splitArguments } from "../repo/securityGraph.js";
import type { ScannerResult } from "./types.js";

export function runTaintFlow(files: IndexedFile[]): ScannerResult[] {
  const graph = buildSecurityGraph(files);
  const results: ScannerResult[] = [];
  const byPath = new Map(files.map((file) => [file.path, file]));

  for (const model of graph.functionSinks) {
    const regex = callRegex(model.fn.name);
    for (const file of files) {
      const lines = file.content.split(/\r?\n/);
      for (const [index, line] of lines.entries()) {
        const match = line.match(regex);
        if (!match || sanitizerPattern.test(line)) continue;
        const args = splitArguments(match[1] ?? "");
        const taintedArg = model.taintedParams.find((param) => sourcePattern.test(args[param.index] ?? ""));
        if (!taintedArg) continue;
        const lineNo = index + 1;
        results.push({
          scanner: "taint-flow",
          ruleId: `${model.sink.sinkId}-interprocedural`,
          title: model.sink.title,
          category: model.sink.category,
          severity: model.sink.category === "xss" ? "medium" : "high",
          path: file.path,
          startLine: lineNo,
          endLine: lineNo,
          message: `User-controlled argument flows into ${model.fn.name} parameter ${taintedArg.name}, which reaches ${model.sink.category} sink at ${model.fn.path}:${model.sink.line}.`,
          raw: {
            sourceLine: lineNo,
            sinkLine: model.sink.line,
            sinkPath: model.fn.path,
            function: model.fn.name,
            parameter: taintedArg.name,
            dataFlow: [
              { path: file.path, line: lineNo, step: "user-controlled argument at call site" },
              { path: model.fn.path, line: model.fn.startLine, step: `enters ${model.fn.name}(${model.fn.params.join(", ")})` },
              { path: model.fn.path, line: model.sink.line, step: `reaches ${model.sink.category} sink` }
            ]
          }
        });
      }
    }
  }

  for (const sink of graph.sinks) {
    const file = byPath.get(sink.path);
    const line = file?.content.split(/\r?\n/)[sink.line - 1] ?? "";
    if (!sourcePattern.test(line) || sanitizerPattern.test(line)) continue;
    results.push({
      scanner: "taint-flow",
      ruleId: `${sink.sinkId}-direct`,
      title: sink.title,
      category: sink.category,
      severity: sink.category === "xss" ? "medium" : "high",
      path: sink.path,
      startLine: sink.line,
      endLine: sink.line,
      message: "User-controlled source appears directly inside dangerous sink.",
      raw: { sourceLine: sink.line, sinkLine: sink.line, dataFlow: [{ path: sink.path, line: sink.line, step: "source reaches sink on same line" }] }
    });
  }

  return dedupe(results);
}

function dedupe(results: ScannerResult[]): ScannerResult[] {
  const seen = new Set<string>();
  return results.filter((result) => {
    const key = `${result.path}:${result.startLine}:${result.ruleId}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
