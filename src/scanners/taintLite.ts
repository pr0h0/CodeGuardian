import path from "node:path";
import type { IndexedFile } from "../repo/repoIndexer.js";
import type { ScannerResult } from "./types.js";

interface Sink {
  id: string;
  title: string;
  category: string;
  severity: ScannerResult["severity"];
  regex: RegExp;
}

const sourceRegex = /\b(?:req\.(?:query|body|params|headers)|request\.(?:query|body|params|headers)|params(?:\[[^\]]+\])?|\$_(?:GET|POST|REQUEST|COOKIE|SERVER)|ARGV|process\.argv|sys\.argv|ENV\[|os\.environ)\b/i;
const assignmentRegex = /^\s*(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*=\s*(.+)$/;

const sinks: Sink[] = [
  { id: "taint-command", title: "User-controlled value reaches command execution sink", category: "command-injection", severity: "high", regex: /\b(?:exec|execSync|spawn|spawnSync|system|shell_exec|passthru|proc_open|popen|subprocess\.(?:run|call|Popen)|os\.system|Open3\.(?:capture2|capture2e|capture3|popen3))\s*\(/ },
  { id: "taint-sql", title: "User-controlled value reaches SQL execution sink", category: "sql-injection", severity: "high", regex: /\b(?:query|execute|raw|find_by_sql|where|mysqli_query|pg_query)\s*\(/ },
  { id: "taint-filesystem", title: "User-controlled value reaches filesystem sink", category: "path-traversal", severity: "high", regex: /\b(?:readFile|writeFile|createReadStream|open|File\.(?:read|open|write|delete)|IO\.read|file_get_contents|fopen|readfile|unlink|send_file)\s*\(/ },
  { id: "taint-ssrf", title: "User-controlled value reaches outbound request sink", category: "ssrf", severity: "high", regex: /\b(?:fetch|axios\.|request\(|http\.get|https\.get|Net::HTTP\.(?:get|get_response|post)|URI\.open|Faraday\.(?:get|post)|HTTParty\.(?:get|post)|curl_setopt|file_get_contents)\s*\(/ },
  { id: "taint-deserialization", title: "User-controlled value reaches unsafe deserialization sink", category: "deserialization", severity: "high", regex: /\b(?:unserialize|Marshal\.load|YAML\.load|Psych\.load|pickle\.loads?)\s*\(/ }
];

const supported = new Set([".js", ".jsx", ".ts", ".tsx", ".py", ".php", ".rb"]);

export function runTaintLite(files: IndexedFile[]): ScannerResult[] {
  const results: ScannerResult[] = [];
  for (const file of files) {
    if (!supported.has(path.extname(file.path))) continue;
    const tainted = new Map<string, number>();
    const lines = file.content.split(/\r?\n/);
    lines.forEach((line, index) => {
      const lineNo = index + 1;
      const assignment = line.match(assignmentRegex);
      if (assignment && sourceRegex.test(assignment[2])) tainted.set(assignment[1], lineNo);
      if (assignment && [...tainted.keys()].some((name) => new RegExp(`\\b${escapeRegex(name)}\\b`).test(assignment[2]))) tainted.set(assignment[1], lineNo);
      for (const [name, sourceLine] of tainted) {
        if (!new RegExp(`\\b${escapeRegex(name)}\\b`).test(line)) continue;
        const sink = sinks.find((item) => item.regex.test(line));
        if (sink && !hasSanitizer(line)) {
          results.push({
            scanner: "taint-lite",
            ruleId: sink.id,
            title: sink.title,
            category: sink.category,
            severity: sink.severity,
            path: file.path,
            startLine: lineNo,
            endLine: lineNo,
            message: `Variable ${name} assigned from user-controlled source at line ${sourceLine} reaches sink at line ${lineNo}.`,
            raw: { sourceLine, sinkLine: lineNo, variable: name, cwe: cweFor(sink.category), owasp: owaspFor(sink.category) }
          });
        }
      }
      const directSink = sinks.find((item) => item.regex.test(line));
      if (directSink && sourceRegex.test(line) && !hasSanitizer(line)) {
        results.push({
          scanner: "taint-lite",
          ruleId: `${directSink.id}-direct`,
          title: directSink.title,
          category: directSink.category,
          severity: directSink.severity,
          path: file.path,
          startLine: lineNo,
          endLine: lineNo,
          message: "User-controlled source appears directly inside dangerous sink.",
          raw: { sourceLine: lineNo, sinkLine: lineNo, cwe: cweFor(directSink.category), owasp: owaspFor(directSink.category) }
        });
      }
    });
  }
  return dedupe(results);
}

function hasSanitizer(line: string): boolean {
  return /\b(?:htmlspecialchars|sanitize|sanitize_sql|sanitize_sql_like|prepared|parameterized|basename|realpath|path\.normalize|allowlist|whitelist|URI\.parse|Addressable::URI)\b/i.test(line);
}

function cweFor(category: string): string {
  return ({ "command-injection": "CWE-78", "sql-injection": "CWE-89", "path-traversal": "CWE-22", ssrf: "CWE-918", deserialization: "CWE-502" } as Record<string, string>)[category] ?? "CWE-20";
}

function owaspFor(category: string): string {
  return category === "ssrf" ? "A10:2021-Server-Side Request Forgery" : "A03:2021-Injection";
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

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
