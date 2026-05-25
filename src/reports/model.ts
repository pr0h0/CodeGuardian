import path from "node:path";
import type { IndexedFile } from "../repo/repoIndexer.js";
import { lineSlice } from "../utils/lineMap.js";
import { redactSecrets } from "../utils/redact.js";

type Row = Record<string, any>;

export interface ReportModel {
  sourceSnippets: Record<string, string[]>;
  dependencyUsage: Record<string, string[]>;
  dependencyDirect: Record<string, boolean>;
  dependencyPackagePath: Record<string, string>;
}

export function prepareReportBundle<T extends Row>(bundle: T, indexedFiles: IndexedFile[]): T & { reportModel: ReportModel } {
  const reportModel: ReportModel = {
    sourceSnippets: buildSourceSnippets(bundle.findings ?? [], indexedFiles),
    dependencyUsage: buildDependencyUsage(bundle.scannerResults ?? [], indexedFiles),
    dependencyDirect: buildDirectDependencyMap(bundle.scannerResults ?? [], indexedFiles),
    dependencyPackagePath: buildDependencyPathMap(bundle.scannerResults ?? [], indexedFiles)
  };
  return { ...bundle, reportModel };
}

export function sourceSnippetKey(filePath: unknown, startLine: unknown, endLine: unknown): string {
  return `${String(filePath ?? "")}:${Number(startLine ?? 0)}:${Number(endLine ?? startLine ?? 0)}`;
}

function buildSourceSnippets(findings: Row[], files: IndexedFile[]): Record<string, string[]> {
  const byPath = new Map(files.map((file) => [normalizePath(file.path), file]));
  const snippets: Record<string, string[]> = {};
  for (const finding of findings) {
    if (!finding.path || !finding.start_line) continue;
    const file = byPath.get(normalizePath(finding.path));
    if (!file) continue;
    const start = Math.max(1, Number(finding.start_line) - 4);
    const end = Math.min(file.lineCount, Number(finding.end_line || finding.start_line) + 4);
    snippets[sourceSnippetKey(finding.path, finding.start_line, finding.end_line || finding.start_line)] = renderSnippet(file, start, end);
  }
  return snippets;
}

function renderSnippet(file: IndexedFile, startLine: number, endLine: number): string[] {
  if (/(^|\/)\.env($|\.|\/)/.test(file.path)) return ["```text", "[REDACTED ENV FILE CONTENT]", "```"];
  const body = redactSecrets(lineSlice(file.content, startLine, endLine))
    .split(/\r?\n/)
    .map((line, offset) => `${String(startLine + offset).padStart(4, " ")} | ${escapeCodeFence(line)}`)
    .join("\n");
  return ["```text", body, "```"];
}

function buildDependencyUsage(results: Row[], files: IndexedFile[]): Record<string, string[]> {
  const output: Record<string, string[]> = {};
  for (const packageName of dependencyPackages(results)) {
    output[packageName] = findDependencyUsageInFiles(files, packageName);
  }
  return output;
}

function buildDirectDependencyMap(results: Row[], files: IndexedFile[]): Record<string, boolean> {
  const packageJsonFiles = files.filter((file) => path.basename(normalizePath(file.path)) === "package.json");
  const composerJsonFiles = files.filter((file) => path.basename(normalizePath(file.path)) === "composer.json");
  const gemfiles = files.filter((file) => path.basename(normalizePath(file.path)) === "Gemfile");
  const output: Record<string, boolean> = {};
  for (const packageName of dependencyPackages(results)) {
    output[packageName] = Boolean(
      packageJsonFiles.some((file) => packageJsonHasDependency(file.content, packageName))
      || composerJsonFiles.some((file) => composerJsonHasDependency(file.content, packageName))
      || gemfiles.some((file) => new RegExp(`gem\\s+['"]${escapeRegExp(packageName.split("/").pop() ?? packageName)}['"]`).test(file.content))
    );
  }
  return output;
}

function buildDependencyPathMap(results: Row[], files: IndexedFile[]): Record<string, string> {
  const packageLocks = files.filter((file) => path.basename(normalizePath(file.path)) === "package-lock.json");
  const output: Record<string, string> = {};
  for (const packageName of dependencyPackages(results)) {
    const lock = packageLocks.find((file) => packageLockHasPackage(file.content, packageName));
    output[packageName] = lock ? `${normalizePath(lock.path)} -> node_modules/${packageName}` : `transitive dependency -> ${packageName}`;
  }
  return output;
}

function dependencyPackages(results: Row[]): string[] {
  const packages = new Set<string>();
  for (const result of results) {
    if (result.scanner !== "trivy" && result.scanner !== "osv-scanner") continue;
    const raw = parseRaw(result.raw_json);
    const name = raw.PkgName ?? raw.package?.name ?? raw.Package?.Name ?? raw.name ?? String(result.title ?? "").split(":")[0]?.trim();
    if (name && name !== "unknown") packages.add(String(name).trim());
  }
  return [...packages];
}

function findDependencyUsageInFiles(files: IndexedFile[], packageName: string): string[] {
  const evidence: string[] = [];
  const patterns = dependencyImportPatterns(packageName);
  for (const file of files) {
    if (!isSourceFile(file.path)) continue;
    const lines = file.content.split(/\r?\n/);
    for (const [index, line] of lines.entries()) {
      if (!patterns.some((pattern) => pattern.test(line))) continue;
      evidence.push(`${file.path}:${index + 1} - ${line.trim().slice(0, 160)}`);
      if (evidence.length >= 5) return evidence;
    }
  }
  return evidence;
}

function dependencyImportPatterns(packageName: string): RegExp[] {
  const specifier = dependencySpecifierPattern(packageName);
  return [
    new RegExp(`\\bfrom\\s+["']${specifier}["']`),
    new RegExp(`\\bimport\\s*\\(\\s*["']${specifier}["']\\s*\\)`),
    new RegExp(`\\bimport\\s+["']${specifier}["']`),
    new RegExp(`\\brequire\\s*\\(\\s*["']${specifier}["']\\s*\\)`),
    new RegExp(`\\bmodule\\.require\\s*\\(\\s*["']${specifier}["']\\s*\\)`)
  ];
}

function dependencySpecifierPattern(packageName: string): string {
  return `${escapeRegExp(packageName)}(?:/[^"']+)?`;
}

function packageJsonHasDependency(content: string, packageName: string): boolean {
  const parsed = parseRaw(content);
  return Boolean(parsed.dependencies?.[packageName] || parsed.devDependencies?.[packageName] || parsed.peerDependencies?.[packageName] || parsed.optionalDependencies?.[packageName]);
}

function composerJsonHasDependency(content: string, packageName: string): boolean {
  const parsed = parseRaw(content);
  return Boolean(parsed.require?.[packageName] || parsed["require-dev"]?.[packageName]);
}

function packageLockHasPackage(content: string, packageName: string): boolean {
  const parsed = parseRaw(content);
  return Boolean(parsed.packages?.[`node_modules/${packageName}`]);
}

function isSourceFile(filePath: string): boolean {
  return new Set([".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py", ".go", ".rb", ".php", ".java", ".cs"]).has(path.extname(filePath));
}

function normalizePath(filePath: string): string {
  return filePath.replaceAll("\\", "/").replace(/^\.\//, "");
}

function parseRaw(rawJson: unknown): Row {
  if (!rawJson || typeof rawJson !== "string") return {};
  try {
    return JSON.parse(rawJson);
  } catch {
    return {};
  }
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function escapeCodeFence(value: string): string {
  return value.replaceAll("```", "`\u200b``");
}
