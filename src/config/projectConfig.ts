import fs from "node:fs";
import path from "node:path";
import { z } from "zod";

const schema = z.object({
  profile: z.enum(["all", "web", "cli", "php", "ruby", "rails", "laravel", "node", "python"]).optional(),
  disabledRules: z.array(z.string()).optional().default([]),
  severityOverrides: z.record(z.enum(["critical", "high", "medium", "low", "info"])).optional().default({}),
  failOn: z.enum(["critical", "high", "medium", "low", "none"]).optional(),
  maxAdditionalSastFindings: z.number().int().positive().optional(),
  maxAiFindings: z.number().int().positive().optional(),
  maxAiAuditFiles: z.number().int().positive().optional(),
  maxAiAuditRounds: z.number().int().positive().optional(),
  maxAiAuditChars: z.number().int().positive().optional(),
  aiFastModel: z.string().optional(),
  aiStrongModel: z.string().optional(),
  aiCritic: z.boolean().optional().default(true),
  scannerTimeouts: z.record(z.number().int().positive()).optional().default({}),
  suppressionsExpireDays: z.number().int().positive().optional(),
  incremental: z.boolean().optional().default(false)
});

export type ProjectConfig = z.infer<typeof schema>;
export type Profile = NonNullable<ProjectConfig["profile"]>;

export function loadProjectConfig(repoPath: string): ProjectConfig {
  for (const name of [".codeguardian.json", ".codeguardian.yml", ".codeguardian.yaml"]) {
    const file = path.join(repoPath, name);
    if (!fs.existsSync(file)) continue;
    const parsed = name.endsWith(".json") ? JSON.parse(fs.readFileSync(file, "utf8")) : parseSimpleYaml(fs.readFileSync(file, "utf8"));
    return schema.parse(parsed);
  }
  return schema.parse({});
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
      (root[activeMap] as Record<string, unknown>)[nestedMap[1]] = coerce(nestedMap[2].trim());
      continue;
    }
    activeArray = undefined;
    activeMap = undefined;
    const match = line.match(/^([A-Za-z0-9_-]+):\s*(.*)$/);
    if (!match) continue;
    const key = match[1].replace(/-([a-z])/g, (_, char) => char.toUpperCase());
    const value = match[2].trim();
    if (!value) {
      if (["severityOverrides", "scannerTimeouts"].includes(key)) {
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
