import fs from "node:fs";
import path from "node:path";
import { z } from "zod";
import { minimatch } from "minimatch";
import { DEFAULT_IGNORES } from "./defaults.js";

export const VULNERABILITY_CLASSES = [
  "injection",
  "xss",
  "auth",
  "authz",
  "ssrf",
  "exposure",
  "validation",
  "dependency",
  "crypto",
  "misconfig",
  "xxe",
  "business-logic"
] as const;

const reportFiltersSchema = z.object({
  minSeverity: z.enum(["critical", "high", "medium", "low", "info"]).optional(),
  minConfidence: z.enum(["confirmed", "high", "medium", "low"]).optional(),
  guidance: z.string().optional()
}).default({});

const schema = z.object({
  profile: z.enum(["all", "web", "cli", "php", "ruby", "rails", "laravel", "node", "python"]).optional(),
  focusPaths: z.array(z.string()).optional().default([]),
  avoidPaths: z.array(z.string()).optional().default([]),
  vulnerabilityClasses: z.array(z.enum(VULNERABILITY_CLASSES)).optional().default([]),
  rulesOfEngagement: z.string().optional().default(""),
  reportFilters: reportFiltersSchema,
  disabledRules: z.array(z.string()).optional().default([]),
  severityOverrides: z.record(z.enum(["critical", "high", "medium", "low", "info"])).optional().default({}),
  failOn: z.enum(["critical", "high", "medium", "low", "none"]).optional(),
  maxAdditionalSastFindings: z.number().int().positive().optional(),
  maxAiFindings: z.number().int().positive().optional(),
  aiTriageTargetCodeFindings: z.number().int().positive().optional(),
  maxAiAuditFiles: z.number().int().positive().optional(),
  maxAiAuditRounds: z.number().int().positive().optional(),
  maxAiAuditChars: z.number().int().positive().optional(),
  aiLowModel: z.string().optional(),
  aiMediumModel: z.string().optional(),
  aiHighModel: z.string().optional(),
  aiCritic: z.boolean().optional().default(true),
  scannerTimeouts: z.record(z.number().int().positive()).optional().default({}),
  suppressionsExpireDays: z.number().int().positive().optional(),
  incremental: z.boolean().optional().default(false)
});

export type ProjectConfig = z.infer<typeof schema>;
export type Profile = NonNullable<ProjectConfig["profile"]>;
export type VulnerabilityClass = (typeof VULNERABILITY_CLASSES)[number];
export type ReportFilters = ProjectConfig["reportFilters"];

export function loadProjectConfig(repoPath: string): ProjectConfig {
  for (const name of [".codeguardian.json", ".codeguardian.yml", ".codeguardian.yaml"]) {
    const file = path.join(repoPath, name);
    if (!fs.existsSync(file)) continue;
    const parsed = name.endsWith(".json") ? JSON.parse(fs.readFileSync(file, "utf8")) : parseSimpleYaml(fs.readFileSync(file, "utf8"));
    return schema.parse(parsed);
  }
  return schema.parse({});
}

export function assertProjectConfigPreflight(repoPath: string, config: ProjectConfig): void {
  const missing = [
    ...missingConfiguredPaths(repoPath, "focusPaths", config.focusPaths),
    ...missingConfiguredPaths(repoPath, "avoidPaths", config.avoidPaths)
  ];
  if (!missing.length) return;
  const details = missing.map((item) => `${item.field}: ${item.pattern}`).join(", ");
  throw new Error(`Scan strategy path preflight failed. Configured paths must match at least one repository file or directory: ${details}`);
}

function parseSimpleYaml(input: string): Record<string, unknown> {
  const root: Record<string, unknown> = {};
  let activeArray: string | undefined;
  let activeMap: string | undefined;
  for (const raw of input.split(/\r?\n/)) {
    const line = raw.replace(/\s+#.*$/, "").trimEnd();
    if (!line.trim() || line.trimStart().startsWith("#")) continue;
    const arrayItem = line.match(/^\s*-\s+(.+)$/);
    if (arrayItem && activeArray) {
      (root[activeArray] as unknown[]).push(coerce(arrayItem[1]));
      continue;
    }
    const nestedMap = line.match(/^\s+([A-Za-z0-9_./*-]+):\s*(.+)$/);
    if (nestedMap && activeMap) {
      const nestedKey = activeMap === "reportFilters"
        ? nestedMap[1].replace(/-([a-z])/g, (_, char) => char.toUpperCase())
        : nestedMap[1];
      (root[activeMap] as Record<string, unknown>)[nestedKey] = coerce(nestedMap[2].trim());
      continue;
    }
    activeArray = undefined;
    activeMap = undefined;
    const match = line.match(/^([A-Za-z0-9_-]+):\s*(.*)$/);
    if (!match) continue;
    const key = match[1].replace(/-([a-z])/g, (_, char) => char.toUpperCase());
    const value = match[2].trim();
    if (!value) {
      if (["severityOverrides", "scannerTimeouts", "reportFilters"].includes(key)) {
        root[key] = {};
        activeMap = key;
      } else {
        root[key] = [];
        activeArray = key;
      }
    } else if (value.startsWith("[") && value.endsWith("]")) {
      root[key] = value.slice(1, -1).split(",").map((item) => coerce(item.trim())).filter((item) => item !== "");
    } else {
      root[key] = coerce(value);
    }
  }
  return root;
}

function coerce(value: string): unknown {
  const clean = value.replace(/^['"]|['"]$/g, "");
  if (/^(true|false)$/i.test(clean)) return clean.toLowerCase() === "true";
  if (/^\d+$/.test(clean)) return Number(clean);
  return clean;
}

function missingConfiguredPaths(repoPath: string, field: "focusPaths" | "avoidPaths", patterns: string[]): Array<{ field: string; pattern: string }> {
  return patterns
    .filter((pattern) => !repoEntryMatchesPattern(repoPath, pattern))
    .map((pattern) => ({ field, pattern }));
}

function repoEntryMatchesPattern(repoPath: string, pattern: string): boolean {
  const normalizedPattern = normalizePath(pattern);
  if (!normalizedPattern) return false;
  if (fs.existsSync(path.join(repoPath, normalizedPattern))) return true;

  const ignored = new Set(DEFAULT_IGNORES);
  const stack = [repoPath];
  while (stack.length) {
    const dir = stack.pop()!;
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (ignored.has(entry.name)) continue;
      const absolute = path.join(dir, entry.name);
      const relative = normalizePath(path.relative(repoPath, absolute));
      if (pathMatches(relative, normalizedPattern, entry.isDirectory())) return true;
      if (entry.isDirectory()) stack.push(absolute);
    }
  }
  return false;
}

function pathMatches(relativePath: string, pattern: string, isDirectory: boolean): boolean {
  return relativePath === pattern
    || minimatch(relativePath, pattern, { dot: true })
    || (isDirectory && minimatch(`${relativePath}/`, pattern, { dot: true }));
}

function normalizePath(value: string): string {
  return value.replaceAll("\\", "/").replace(/^\.\//, "").replace(/^\/+/, "");
}

export function ruleAllowedByProfile(ruleId: string, category: string | undefined, filePath: string | undefined, profile: Profile): boolean {
  if (profile === "all") return true;
  const text = `${ruleId} ${category ?? ""} ${filePath ?? ""}`.toLowerCase();
  if (profile === "cli") return /(cli|argv|command|shell|bin\/|scripts\/|task|rake|cobra|click|argparse)/.test(text);
  if (profile === "web") return !/(cli|argv|shell-script)/.test(text);
  if (profile === "php" || profile === "laravel") return text.includes("php") || text.includes("laravel") || /\.(php|blade\.php)$/.test(filePath ?? "");
  if (profile === "ruby" || profile === "rails") return text.includes("ruby") || text.includes("rails") || /\.(rb|erb)$/.test(filePath ?? "");
  if (profile === "node") return text.includes("js-") || text.includes("node") || /\.(js|jsx|ts|tsx)$/.test(filePath ?? "");
  if (profile === "python") return text.includes("python") || /\.(py)$/.test(filePath ?? "");
  return true;
}
