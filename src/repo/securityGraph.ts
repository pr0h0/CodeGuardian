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

export interface SinkBacktracePath {
  source: SourceOccurrence;
  sink: SinkOccurrence;
  dataFlow: Array<{ path: string; line: number; step: string }>;
  sanitizerAssessment: {
    sanitizers: Array<{ path: string; line: number; code: string }>;
    sufficient: boolean;
    reason: string;
  };
}

const supported = new Set([".js", ".jsx", ".ts", ".tsx", ".py", ".php", ".rb"]);

export const sourcePattern = /\b(?:req\.(?:query|body|params|headers|cookies|host|hostname|ip|ips)|req\.get\(['"][^'"]+['"]\)|request\.(?:query|body|params|headers|args|form|json|files|host|remote_addr|META|GET|POST|COOKIES)|params(?:\[[^\]]+\])?|cookies(?:\[[^\]]+\])?|x-forwarded-(?:for|host)|x-real-ip|HTTP_(?:HOST|X_FORWARDED_FOR|X_FORWARDED_HOST|X_REAL_IP)|request\.get(?:Parameter|Header)\(|Request\.(?:Query|Form|Headers|Cookies|Host)|r\.(?:URL\.Query|FormValue|Header\.Get|Cookie|Host|RemoteAddr)\b|\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)|ARGV|process\.argv|sys\.argv)\b/i;

export const sanitizerPattern = /\b(?:sanitize\w*|escape\w*|validate\w*|schema|zod|joi|allowlist\w*|whitelist\w*|realpath|normalize|basename|prepared|parameterized|encodeURIComponent|htmlspecialchars)\b/i;

export const sinkSpecs: SinkSpec[] = [
  { id: "flow-command", category: "command-injection", title: "User-controlled value reaches command execution sink", severity: "high", regex: /\b(?:exec|execSync|spawn|spawnSync|system|shell_exec|passthru|proc_open|popen|subprocess\.(?:run|call|Popen)|os\.system|Open3\.(?:capture2|capture2e|capture3|popen3))\s*\(/ },
  { id: "flow-sql", category: "sql-injection", title: "User-controlled value reaches SQL execution sink", severity: "high", regex: /\b(?:query|execute|raw|find_by_sql|where|mysqli_query|pg_query)\s*\(/ },
  { id: "flow-filesystem", category: "path-traversal", title: "User-controlled value reaches filesystem sink", severity: "high", regex: /\b(?:readFile|writeFile|createReadStream|open|File\.(?:read|open|write|delete)|IO\.read|file_get_contents|fopen|readfile|unlink|send_file|sendFile)\s*\(/ },
  { id: "flow-ssrf", category: "ssrf", title: "User-controlled value reaches outbound request sink", severity: "high", regex: /\b(?:fetch|axios\.|request\(|http\.get|https\.get|Net::HTTP\.(?:get|get_response|post)|URI\.open|Faraday\.(?:get|post)|HTTParty\.(?:get|post)|curl_setopt)\s*\(/ },
  { id: "flow-xss", category: "xss", title: "User-controlled value reaches HTML rendering sink", severity: "high", regex: /\b(?:innerHTML|dangerouslySetInnerHTML|render\s+inline|v-html)\b/ },
  { id: "flow-template", category: "template-injection", title: "User-controlled value reaches template rendering sink", severity: "high", regex: /\b(?:res\.render|reply\.view|eta\.render|Eta\.render|renderFile|renderString|render_template|Template\(|template\.render|render_to_string|render\s+inline|ERB\.new|Twig\\Environment|Blade::render|view\s*\(|templateEngine\.process|ModelAndView|template\s*\()\s*\(/ },
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

export function traceSinkBackPaths(files: IndexedFile[]): SinkBacktracePath[] {
  const graph = buildSecurityGraph(files);
  const byPath = new Map(files.map((file) => [file.path, file]));
  const functionsByPath = new Map<string, GraphFunction[]>();
  for (const fn of graph.functions) functionsByPath.set(fn.path, [...(functionsByPath.get(fn.path) ?? []), fn]);
  const paths: SinkBacktracePath[] = [];

  for (const sink of graph.sinks) {
    const file = byPath.get(sink.path);
    if (!file) continue;
    const lines = file.content.split(/\r?\n/);
    const fn = containingFunction(functionsByPath.get(sink.path) ?? [], sink.line);
    const startLine = fn?.startLine ?? Math.max(1, sink.line - 40);
    const context = lines.slice(startLine - 1, sink.line);
    const variables = identifiersFromSink(sink.code);
    for (const variable of variables) {
      const trace = traceVariable(variable, context, startLine, sink);
      if (!trace) continue;
      if (trace.sanitizerAssessment.sufficient) continue;
      paths.push(trace);
    }
    const directSource = sourcePattern.test(sink.code) ? {
      source: { path: sink.path, line: sink.line, expression: sink.code },
      sink,
      dataFlow: [{ path: sink.path, line: sink.line, step: "request-controlled source appears directly in sink call" }],
      sanitizerAssessment: { sanitizers: [], sufficient: false, reason: "No context-appropriate sanitizer appears before the sink." }
    } satisfies SinkBacktracePath : undefined;
    if (directSource && !paths.some((item) => item.sink.path === sink.path && item.sink.line === sink.line && item.source.line === sink.line)) paths.push(directSource);
  }
  return dedupeSinkBacktrace(paths);
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

function containingFunction(functions: GraphFunction[], line: number): GraphFunction | undefined {
  return functions.find((fn) => line >= fn.startLine && line <= fn.endLine);
}

function identifiersFromSink(code: string): string[] {
  const callArgs = code.match(/\((.*)\)/)?.[1] ?? code;
  const identifiers = [...callArgs.matchAll(/\b[A-Za-z_$][\w$]*\b/g)].map((match) => match[0]);
  const ignored = new Set(["req", "request", "res", "response", "await", "return", "true", "false", "null", "undefined", "http", "https"]);
  return [...new Set(identifiers.filter((item) => !ignored.has(item) && !/^[A-Z_]+$/.test(item)))].slice(0, 8);
}

function traceVariable(variable: string, contextLines: string[], startLine: number, sink: SinkOccurrence): SinkBacktracePath | undefined {
  let current = variable;
  const dataFlow: Array<{ path: string; line: number; step: string }> = [
    { path: sink.path, line: sink.line, step: `${variable} reaches ${sink.category} sink` }
  ];
  const sanitizers: Array<{ path: string; line: number; code: string }> = [];

  for (let index = contextLines.length - 1; index >= 0; index--) {
    const line = contextLines[index] ?? "";
    const lineNo = startLine + index;
    const assignment = assignmentFor(line, current);
    if (!assignment) {
      if (mentionsVariable(line, current) && sanitizerPattern.test(line)) sanitizers.push({ path: sink.path, line: lineNo, code: line.trim().slice(0, 220) });
      continue;
    }
    dataFlow.push({ path: sink.path, line: lineNo, step: `${current} assigned from ${assignment.slice(0, 120)}` });
    if (sanitizerPattern.test(assignment) || sanitizerPattern.test(line)) sanitizers.push({ path: sink.path, line: lineNo, code: line.trim().slice(0, 220) });
    if (sourcePattern.test(assignment)) {
      const assessment = assessSanitizers(sink, sanitizers);
      return {
        source: { path: sink.path, line: lineNo, expression: assignment.trim().slice(0, 220) },
        sink,
        dataFlow: [
          { path: sink.path, line: lineNo, step: "request-controlled source assigned to local value" },
          ...dataFlow.reverse()
        ],
        sanitizerAssessment: assessment
      };
    }
    const nextIdentifier = assignment.match(/\b[A-Za-z_$][\w$]*\b/)?.[0];
    if (!nextIdentifier || nextIdentifier === current) break;
    current = nextIdentifier;
  }
  return undefined;
}

function assignmentFor(line: string, variable: string): string | undefined {
  const escaped = escapeRegExp(variable);
  const declaration = line.match(new RegExp(`\\b(?:const|let|var)\\s+${escaped}\\s*=\\s*(.+?);?\\s*$`));
  if (declaration?.[1]) return declaration[1];
  const assignment = line.match(new RegExp(`\\b${escaped}\\s*=\\s*(.+?);?\\s*$`));
  return assignment?.[1];
}

function mentionsVariable(line: string, variable: string): boolean {
  return new RegExp(`\\b${escapeRegExp(variable)}\\b`).test(line);
}

function assessSanitizers(sink: SinkOccurrence, sanitizers: Array<{ path: string; line: number; code: string }>): SinkBacktracePath["sanitizerAssessment"] {
  if (!sanitizers.length) return { sanitizers, sufficient: false, reason: "No sanitizer or guard was found between source and sink." };
  const text = sanitizers.map((item) => item.code).join("\n");
  const sufficient =
    sink.category === "ssrf" ? /\b(allowlist\w*|allowedHosts|URLPattern|isAllowedUrl|validateUrl|sameOrigin|privateIp|dnsLookup)\b/i.test(text)
      : sink.category === "path-traversal" ? /\b(realpath|resolve|normalize|basename|safeJoin|startsWith|allowlist)\b/i.test(text)
        : sink.category === "sql-injection" ? /\b(prepared|parameterized|bind|where\s*\(|queryBuilder|prisma|sequelize)\b/i.test(text)
          : sink.category === "command-injection" ? /\b(execFile|shell\s*:\s*false|allowlist|shlex\.quote|spawn)\b/i.test(text)
            : /\b(sanitize|escape|encode|validate|allowlist|schema|zod|joi)\b/i.test(text);
  return {
    sanitizers,
    sufficient,
    reason: sufficient
      ? "A context-appropriate sanitizer or allowlist appears before the sink."
      : `Sanitizer-like code exists, but it is not clearly sufficient for ${sink.category}.`
  };
}

function dedupeSinkBacktrace(paths: SinkBacktracePath[]): SinkBacktracePath[] {
  const seen = new Set<string>();
  return paths.filter((item) => {
    const key = `${item.source.path}:${item.source.line}:${item.sink.path}:${item.sink.line}:${item.sink.sinkId}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
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
