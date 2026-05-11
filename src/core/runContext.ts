import path from "node:path";
import { mkdirSync } from "node:fs";
import { loadEnv, type AppEnv } from "../config/env.js";
import { DEFAULT_REPORT_DIR, type Severity } from "../config/defaults.js";
import { Logger } from "./logger.js";
import { loadProjectConfig, type ProjectConfig, type Profile } from "../config/projectConfig.js";

export interface CliOptions {
  out?: string;
  format?: "markdown" | "json" | "sarif" | "all";
  ai?: boolean;
  provider?: "openai" | "anthropic" | "deepseek" | "openrouter";
  model?: string;
  target?: string;
  allowHost?: string[];
  maxFiles?: number;
  maxFileSize?: number;
  maxAiFindings?: number;
  aiAudit?: boolean;
  maxAiAuditFiles?: number;
  maxAiAuditRounds?: number;
  maxAiAuditChars?: number;
  include?: string[];
  exclude?: string[];
  failOn?: Severity | "none";
  runApproved?: boolean;
  baseline?: string;
  verbose?: boolean;
  profile?: Profile;
  incremental?: boolean;
}

export interface RunContext {
  env: AppEnv;
  logger: Logger;
  projectConfig: ProjectConfig;
  repoPath: string;
  outDir: string;
  options: Required<Omit<CliOptions, "provider" | "model" | "target">> & Pick<CliOptions, "provider" | "model" | "target">;
}

export function createRunContext(repoPath: string, options: CliOptions = {}): RunContext {
  const env = loadEnv();
  const absoluteRepo = path.resolve(repoPath);
  const projectConfig = loadProjectConfig(absoluteRepo);
  const outDir = path.resolve(options.out ?? env.CODEGUARDIAN_REPORT_DIR ?? DEFAULT_REPORT_DIR);
  mkdirSync(outDir, { recursive: true });
  return {
    env,
    logger: new Logger(Boolean(options.verbose)),
    projectConfig,
    repoPath: absoluteRepo,
    outDir,
    options: {
      out: outDir,
      format: options.format ?? "all",
      ai: options.ai ?? false,
      allowHost: options.allowHost ?? [],
      maxFiles: options.maxFiles ?? Number.MAX_SAFE_INTEGER,
      maxFileSize: options.maxFileSize ?? env.CODEGUARDIAN_MAX_FILE_SIZE,
      maxAiFindings: Math.min(options.maxAiFindings ?? projectConfig.maxAiFindings ?? env.CODEGUARDIAN_MAX_AI_FINDINGS, env.CODEGUARDIAN_MAX_AI_FINDINGS_LIMIT),
      aiAudit: options.aiAudit ?? env.CODEGUARDIAN_AI_AUDIT.toLowerCase() !== "false",
      maxAiAuditFiles: options.maxAiAuditFiles ?? projectConfig.maxAiAuditFiles ?? env.CODEGUARDIAN_AI_AUDIT_MAX_FILES,
      maxAiAuditRounds: options.maxAiAuditRounds ?? projectConfig.maxAiAuditRounds ?? env.CODEGUARDIAN_AI_AUDIT_MAX_ROUNDS,
      maxAiAuditChars: options.maxAiAuditChars ?? projectConfig.maxAiAuditChars ?? env.CODEGUARDIAN_AI_AUDIT_MAX_CHARS,
      include: options.include ?? [],
      exclude: options.exclude ?? [],
      failOn: options.failOn ?? projectConfig.failOn ?? "none",
      runApproved: options.runApproved ?? false,
      baseline: options.baseline ?? "latest",
      verbose: options.verbose ?? false,
      provider: options.provider,
      model: options.model,
      target: options.target,
      profile: options.profile ?? projectConfig.profile ?? "all",
      incremental: options.incremental ?? projectConfig.incremental ?? false
    }
  };
}
