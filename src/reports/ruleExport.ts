import fs from "node:fs";
import path from "node:path";
import { ensureDir } from "../utils/paths.js";

type Row = Record<string, any>;

export function writeRuleExport(outDir: string, bundle: any, reportBase = "report"): string | undefined {
  const findings = (bundle.findings ?? []).filter((item: Row) => isTruePositive(item));
  if (!findings.length) return undefined;
  ensureDir(outDir);
  const rules = findings.slice(0, 50).map((finding: Row, index: number) => semgrepRuleFor(finding, index));
  const file = path.join(outDir, `${reportBase}.semgrep.yml`);
  fs.writeFileSync(file, ["rules:", ...rules].join("\n"));
  return file;
}

function isTruePositive(item: Row): boolean {
  return ["confirmed", "confirmed_true_positive", "likely_true_positive"].includes(String(item.status)) && String(item.status) !== "false_positive";
}

function semgrepRuleFor(item: Row, index: number): string {
  const category = String(item.category ?? "security").toLowerCase();
  const sink = sinkPattern(category);
  const id = `codeguardian.${slug(category)}.${slug(item.title ?? "finding")}.${index + 1}`;
  return [
    `  - id: ${id}`,
    `    message: ${yamlString(`Codeguardian-confirmed pattern near ${item.path ?? "unknown"}:${item.start_line ?? "?"}: ${item.title ?? "finding"}`)}`,
    `    severity: ${semgrepSeverity(item.severity)}`,
    "    languages: [javascript, typescript, python, php, ruby]",
    "    patterns:",
    sourcePattern(category),
    `      - pattern-regex: ${yamlString(sink)}`,
    "    metadata:",
    `      category: ${yamlString(category)}`,
    `      confidence: ${yamlString(item.confidence ?? "unknown")}`,
    `      source: ${yamlString("codeguardian-rule-export")}`
  ].join("\n");
}

function sourcePattern(category: string): string {
  if (category.includes("secret")) return "      - pattern-regex: \"(?i)(api[_-]?key|token|password|secret|client[_-]?secret)\\\\s*[:=]\\\\s*['\\\"][^'\\\"]{8,}['\\\"]\"";
  return "      - pattern-regex: \"(?i)(req\\\\.|request\\\\.|params|ARGV|process\\\\.argv|\\\\$_(GET|POST|REQUEST|COOKIE|FILES))\"";
}

function sinkPattern(category: string): string {
  if (category.includes("command")) return "\\b(exec|execSync|spawn|spawnSync|system|shell_exec|subprocess\\.(run|Popen)|Open3\\.)\\s*\\(";
  if (category.includes("sql")) return "\\b(query|execute|raw|find_by_sql|where|mysqli_query|pg_query)\\s*\\(";
  if (category.includes("ssrf")) return "\\b(fetch|axios\\.|request\\(|http\\.get|https\\.get|Net::HTTP|curl_setopt)\\s*\\(";
  if (category.includes("path") || category.includes("file")) return "\\b(readFile|writeFile|createReadStream|sendFile|open|file_get_contents|fopen|File\\.read)\\s*\\(";
  if (category.includes("xss")) return "\\b(innerHTML|dangerouslySetInnerHTML|v-html|render\\s+inline)\\b";
  if (category.includes("secret")) return "(?i)(api[_-]?key|token|password|secret)";
  return "\\b(eval|exec|fetch|query|open)\\s*\\(";
}

function semgrepSeverity(severity: unknown): string {
  return String(severity).toLowerCase() === "critical" || String(severity).toLowerCase() === "high" ? "ERROR" : "WARNING";
}

function slug(value: unknown): string {
  return String(value ?? "finding").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 60) || "finding";
}

function yamlString(value: unknown): string {
  return JSON.stringify(String(value ?? ""));
}
