import type { ScannerResult } from "../scanners/types.js";
import type { IndexedFile } from "./repoIndexer.js";

export interface DependencyUsage {
  path: string;
  line: number;
  code: string;
  api?: string;
}

export interface DependencyReachability {
  packageName: string;
  vulnerableApis: string[];
  status: "not-reachable" | "package-imported" | "vulnerable-api-reachable";
  confidence: "high" | "medium" | "low";
  packageUsages: DependencyUsage[];
  vulnerableApiUsages: DependencyUsage[];
}

const apiHints: Array<{ packagePattern: RegExp; textPattern: RegExp; apis: string[] }> = [
  { packagePattern: /^lodash(?:$|\/)/i, textPattern: /\b(template|prototype|pollution|command|code execution|rce)\b/i, apis: ["template", "merge", "defaultsDeep", "zipObjectDeep", "set"] },
  { packagePattern: /^(js-yaml|yaml)$/i, textPattern: /\b(load|deserialize|schema|code execution|rce)\b/i, apis: ["load", "safeLoad", "parse"] },
  { packagePattern: /^eta$/i, textPattern: /\b(render|compile|template|rce|prototype)\b/i, apis: ["render", "compile", "renderFile"] },
  { packagePattern: /^(handlebars|mustache|ejs|pug)$/i, textPattern: /\b(render|compile|template|prototype|rce)\b/i, apis: ["render", "compile", "renderFile"] },
  { packagePattern: /^(axios|node-fetch|request|got)$/i, textPattern: /\b(ssrf|redirect|proxy|url)\b/i, apis: ["get", "post", "request", "fetch"] },
  { packagePattern: /^(express-fileupload|multer|formidable)$/i, textPattern: /\b(upload|path traversal|file|dos)\b/i, apis: ["mv", "single", "array", "fields", "parse"] }
];

export function analyzeDependencyReachability(files: IndexedFile[], result: ScannerResult): DependencyReachability {
  const packageName = packageNameFromResult(result);
  const vulnerableApis = inferVulnerableApis(packageName, result);
  const packageUsages = findPackageUsages(files, packageName);
  const vulnerableApiUsages = vulnerableApis.length ? findVulnerableApiUsages(files, packageName, vulnerableApis) : [];
  const status = vulnerableApiUsages.length ? "vulnerable-api-reachable" : packageUsages.length ? "package-imported" : "not-reachable";
  return {
    packageName,
    vulnerableApis,
    status,
    confidence: status === "vulnerable-api-reachable" ? "high" : status === "package-imported" ? "medium" : "low",
    packageUsages,
    vulnerableApiUsages
  };
}

export function packageNameFromResult(result: ScannerResult): string {
  const raw = result.raw && typeof result.raw === "object" ? result.raw as Record<string, unknown> : {};
  return String(raw.PkgName ?? raw.packageName ?? (raw.package as Record<string, unknown> | undefined)?.name ?? raw.name ?? result.title.split(":")[0] ?? "unknown").trim();
}

function inferVulnerableApis(packageName: string, result: ScannerResult): string[] {
  const text = `${result.ruleId} ${result.title} ${result.message} ${JSON.stringify(result.raw ?? {})}`;
  const inferred = apiHints
    .filter((hint) => hint.packagePattern.test(packageName) && hint.textPattern.test(text))
    .flatMap((hint) => hint.apis.filter((api) => new RegExp(`\\b${escapeRegExp(api)}\\b`, "i").test(text) || hint.apis.length <= 3));
  const functionMatches = [...text.matchAll(/\b(?:function|method|api|call|sink)\s*[:=]\s*['"`]?([A-Za-z_$][\w$-]*)/gi)].map((match) => match[1]);
  return [...new Set([...inferred, ...functionMatches])].slice(0, 8);
}

function findPackageUsages(files: IndexedFile[], packageName: string): DependencyUsage[] {
  const patterns = dependencyImportPatterns(packageName);
  return findSourceLines(files, (line) => patterns.some((pattern) => pattern.test(line))).slice(0, 20);
}

function findVulnerableApiUsages(files: IndexedFile[], packageName: string, apis: string[]): DependencyUsage[] {
  const importsByPath = new Map<string, ImportBinding[]>();
  for (const file of files) {
    importsByPath.set(file.path, parseImportBindings(file.content, packageName));
  }
  const results: DependencyUsage[] = [];
  for (const file of files.filter((item) => isSourceFile(item.path))) {
    const bindings = importsByPath.get(file.path) ?? [];
    if (!bindings.length) continue;
    const lines = file.content.split(/\r?\n/);
    for (const [index, line] of lines.entries()) {
      for (const api of apis) {
        if (!lineUsesApi(line, api, bindings)) continue;
        results.push({ path: file.path, line: index + 1, code: line.trim().slice(0, 220), api });
      }
    }
  }
  return dedupeUsages(results).slice(0, 20);
}

interface ImportBinding {
  local: string;
  kind: "namespace" | "default" | "named" | "require";
  imported?: string;
}

function parseImportBindings(content: string, packageName: string): ImportBinding[] {
  const bindings: ImportBinding[] = [];
  const spec = dependencySpecifierPattern(packageName);
  for (const match of content.matchAll(new RegExp(`import\\s+([A-Za-z_$][\\w$]*)\\s+from\\s+["']${spec}["']`, "g"))) {
    bindings.push({ local: match[1], kind: "default" });
  }
  for (const match of content.matchAll(new RegExp(`import\\s+\\*\\s+as\\s+([A-Za-z_$][\\w$]*)\\s+from\\s+["']${spec}["']`, "g"))) {
    bindings.push({ local: match[1], kind: "namespace" });
  }
  for (const match of content.matchAll(new RegExp(`import\\s+\\{([^}]+)\\}\\s+from\\s+["']${spec}["']`, "g"))) {
    for (const part of match[1].split(",")) {
      const [importedRaw, localRaw] = part.split(/\s+as\s+/i).map((item) => item.trim());
      if (!importedRaw) continue;
      bindings.push({ local: localRaw || importedRaw, imported: importedRaw, kind: "named" });
    }
  }
  for (const match of content.matchAll(new RegExp(`(?:const|let|var)\\s+([A-Za-z_$][\\w$]*)\\s*=\\s*require\\(["']${spec}["']\\)`, "g"))) {
    bindings.push({ local: match[1], kind: "require" });
  }
  for (const match of content.matchAll(new RegExp(`(?:const|let|var)\\s+\\{([^}]+)\\}\\s*=\\s*require\\(["']${spec}["']\\)`, "g"))) {
    for (const part of match[1].split(",")) {
      const [importedRaw, localRaw] = part.split(":").map((item) => item.trim());
      if (!importedRaw) continue;
      bindings.push({ local: localRaw || importedRaw, imported: importedRaw, kind: "named" });
    }
  }
  return bindings;
}

function lineUsesApi(line: string, api: string, bindings: ImportBinding[]): boolean {
  for (const binding of bindings) {
    const local = escapeRegExp(binding.local);
    const imported = binding.imported ?? binding.local;
    if (binding.kind === "named" && imported === api && new RegExp(`\\b${local}\\s*\\(`).test(line)) return true;
    if ((binding.kind === "default" || binding.kind === "namespace" || binding.kind === "require")
      && new RegExp(`\\b${local}\\.${escapeRegExp(api)}\\s*\\(`).test(line)) return true;
  }
  return false;
}

function findSourceLines(files: IndexedFile[], predicate: (line: string) => boolean): DependencyUsage[] {
  const results: DependencyUsage[] = [];
  for (const file of files.filter((item) => isSourceFile(item.path))) {
    const lines = file.content.split(/\r?\n/);
    for (const [index, line] of lines.entries()) {
      if (!predicate(line)) continue;
      results.push({ path: file.path, line: index + 1, code: line.trim().slice(0, 220) });
    }
  }
  return dedupeUsages(results);
}

function dependencyImportPatterns(packageName: string): RegExp[] {
  const specifier = dependencySpecifierPattern(packageName);
  return [
    new RegExp(`\\bfrom\\s+["']${specifier}["']`),
    new RegExp(`\\bimport\\s*\\(\\s*["']${specifier}["']\\s*\\)`),
    new RegExp(`\\bimport\\s+["']${specifier}["']`),
    new RegExp(`\\brequire\\s*\\(\\s*["']${specifier}["']\\s*\\)`)
  ];
}

function dependencySpecifierPattern(packageName: string): string {
  return `${escapeRegExp(packageName)}(?:/[^"']+)?`;
}

function isSourceFile(filePath: string): boolean {
  return /\.(js|jsx|mjs|cjs|ts|tsx|py|php|rb|go|java|cs)$/i.test(filePath);
}

function dedupeUsages(usages: DependencyUsage[]): DependencyUsage[] {
  const seen = new Set<string>();
  return usages.filter((usage) => {
    const key = `${usage.path}:${usage.line}:${usage.api ?? ""}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
