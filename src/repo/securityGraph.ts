import path from "node:path";
import type { IndexedFile } from "./repoIndexer.js";

export interface GraphFunction {
  path: string;
  name: string;
  params: string[];
  startLine: number;
  endLine: number;
  body: string[];
  exported: boolean;
}

export interface SinkSpec {
  id: string;
  category: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  regex: RegExp;
}

export interface SourceOccurrence {
  path: string;
  line: number;
  expression: string;
}

export interface SinkOccurrence {
  path: string;
  line: number;
  category: string;
  sinkId: string;
  title: string;
  code: string;
}

export interface FunctionSinkModel {
  fn: GraphFunction;
  sink: SinkOccurrence;
  taintedParams: Array<{ index: number; name: string }>;
}

const supported = new Set([".js", ".jsx", ".ts", ".tsx", ".py", ".php", ".rb"]);

export const sourcePattern = /\b(?:req\.(?:query|body|params|headers|cookies)|request\.(?:query|body|params|headers|args|form|json|files)|params(?:\[[^\]]+\])?|\$_(?:GET|POST|REQUEST|COOKIE|FILES)|ARGV|process\.argv|sys\.argv)\b/i;

export const sanitizerPattern = /\b(?:sanitize|escape|validate|schema|zod|joi|allowlist|whitelist|realpath|normalize|basename|prepared|parameterized|encodeURIComponent|htmlspecialchars)\b/i;

export const sinkSpecs: SinkSpec[] = [
  { id: "flow-command", category: "command-injection", title: "User-controlled value reaches command execution sink", severity: "high", regex: /\b(?:exec|execSync|spawn|spawnSync|system|shell_exec|passthru|proc_open|popen|subprocess\.(?:run|call|Popen)|os\.system|Open3\.(?:capture2|capture2e|capture3|popen3))\s*\(/ },
  { id: "flow-sql", category: "sql-injection", title: "User-controlled value reaches SQL execution sink", severity: "high", regex: /\b(?:query|execute|raw|find_by_sql|where|mysqli_query|pg_query)\s*\(/ },
  { id: "flow-filesystem", category: "path-traversal", title: "User-controlled value reaches filesystem sink", severity: "high", regex: /\b(?:readFile|writeFile|createReadStream|open|File\.(?:read|open|write|delete)|IO\.read|file_get_contents|fopen|readfile|unlink|send_file|sendFile)\s*\(/ },
  { id: "flow-ssrf", category: "ssrf", title: "User-controlled value reaches outbound request sink", severity: "high", regex: /\b(?:fetch|axios\.|request\(|http\.get|https\.get|Net::HTTP\.(?:get|get_response|post)|URI\.open|Faraday\.(?:get|post)|HTTParty\.(?:get|post)|curl_setopt)\s*\(/ },
  { id: "flow-xss", category: "xss", title: "User-controlled value reaches HTML rendering sink", severity: "high", regex: /\b(?:innerHTML|dangerouslySetInnerHTML|render\s+inline|v-html)\b/ },
  { id: "flow-deserialization", category: "deserialization", title: "User-controlled value reaches unsafe deserialization sink", severity: "high", regex: /\b(?:unserialize|Marshal\.load|YAML\.load|Psych\.load|pickle\.loads?)\s*\(/ }
];

export function buildSecurityGraph(files: IndexedFile[]): { functions: GraphFunction[]; sources: SourceOccurrence[]; sinks: SinkOccurrence[]; functionSinks: FunctionSinkModel[] } {
  const auditable = files.filter((file) => supported.has(path.extname(file.path)));
  const functions = auditable.flatMap(extractGraphFunctions);
  const sources = auditable.flatMap((file) => findSources(file));
  const sinks = auditable.flatMap((file) => findSinks(file));
  const functionSinks = functions.flatMap((fn) => modelFunctionSinks(fn));
  return { functions, sources, sinks, functionSinks };
}

export function extractGraphFunctions(file: IndexedFile): GraphFunction[] {
  const ext = path.extname(file.path);
  const lines = file.content.split(/\r?\n/);
  const functions: GraphFunction[] = [];
  for (const [index, line] of lines.entries()) {
    const parsed = parseFunctionSignature(line, ext);
    if (!parsed) continue;
    const startLine = index + 1;
    const endLine = findFunctionEnd(lines, index, ext);
    functions.push({
      path: file.path,
      name: parsed.name,
      params: parsed.params,
      startLine,
      endLine,
      body: lines.slice(index, endLine),
      exported: parsed.exported
    });
  }
  return functions;
}

function parseFunctionSignature(line: string, ext: string): { name: string; params: string[]; exported: boolean } | undefined {
  const js = line.match(/^\s*(export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)/)
    ?? line.match(/^\s*(export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>/)
    ?? line.match(/^\s*(export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?([A-Za-z_$][\w$]*)\s*=>/);
  if (js && [".js", ".jsx", ".ts", ".tsx"].includes(ext)) return { name: js[2], params: splitParams(js[3]), exported: Boolean(js[1]) };
  const py = line.match(/^\s*def\s+([A-Za-z_][\w]*)\s*\(([^)]*)\)\s*:/);
  if (py && ext === ".py") return { name: py[1], params: splitParams(py[2]).filter((item) => item !== "self" && item !== "cls"), exported: true };
  const php = line.match(/^\s*(?:public|private|protected)?\s*function\s+([A-Za-z_][\w]*)\s*\(([^)]*)\)/);
  if (php && ext === ".php") return { name: php[1], params: splitParams(php[2]).map((item) => item.replace(/^\$/, "")), exported: true };
  const rb = line.match(/^\s*def\s+([A-Za-z_][\w!?=]*)\s*(?:\(([^)]*)\)|\s+([^#]+))?/);
  if (rb && ext === ".rb") return { name: rb[1], params: splitParams(rb[2] ?? rb[3] ?? ""), exported: true };
  return undefined;
}

function splitParams(input: string): string[] {
  return input.split(",").map((part) => part.trim().replace(/[?:].*$/, "").replace(/=.*/, "").replace(/^\.\.\./, "").replace(/^\$/, "")).filter(Boolean);
}

function findFunctionEnd(lines: string[], startIndex: number, ext: string): number {
  if (ext === ".py" || ext === ".rb") {
    const indent = lines[startIndex].match(/^\s*/)?.[0].length ?? 0;
    for (let index = startIndex + 1; index < lines.length; index++) {
      const line = lines[index];
      if (!line.trim()) continue;
      const currentIndent = line.match(/^\s*/)?.[0].length ?? 0;
      if (currentIndent <= indent) return index;
    }
    return lines.length;
  }
  let depth = 0;
  let seenBrace = false;
  for (let index = startIndex; index < lines.length; index++) {
    for (const char of lines[index]) {
      if (char === "{") {
        depth++;
        seenBrace = true;
      } else if (char === "}") {
        depth--;
      }
    }
    if (seenBrace && depth <= 0) return index + 1;
  }
  return Math.min(lines.length, startIndex + 80);
}

function findSources(file: IndexedFile): SourceOccurrence[] {
  return file.content.split(/\r?\n/).flatMap((line, index) => sourcePattern.test(line) ? [{ path: file.path, line: index + 1, expression: line.trim().slice(0, 220) }] : []);
}

function findSinks(file: IndexedFile): SinkOccurrence[] {
  return file.content.split(/\r?\n/).flatMap((line, index) => {
    const spec = sinkSpecs.find((item) => item.regex.test(line));
    return spec ? [{ path: file.path, line: index + 1, category: spec.category, sinkId: spec.id, title: spec.title, code: line.trim().slice(0, 220) }] : [];
  });
}

function modelFunctionSinks(fn: GraphFunction): FunctionSinkModel[] {
  const models: FunctionSinkModel[] = [];
  for (const [offset, line] of fn.body.entries()) {
    const spec = sinkSpecs.find((item) => item.regex.test(line));
    if (!spec || sanitizerPattern.test(line)) continue;
    const taintedParams = fn.params.flatMap((param, index) => new RegExp(`\\b${escapeRegExp(param)}\\b`).test(line) ? [{ index, name: param }] : []);
    if (!taintedParams.length) continue;
    models.push({
      fn,
      sink: { path: fn.path, line: fn.startLine + offset, category: spec.category, sinkId: spec.id, title: spec.title, code: line.trim().slice(0, 220) },
      taintedParams
    });
  }
  return models;
}

export function callRegex(name: string): RegExp {
  return new RegExp(`\\b${escapeRegExp(name)}\\s*\\(([^)]*)\\)`);
}

export function splitArguments(input: string): string[] {
  return input.split(",").map((arg) => arg.trim()).filter(Boolean);
}

export function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
