import path from "node:path";
import { mkdirSync } from "node:fs";
import { loadEnv, type AppEnv } from "../config/env.js";
import { DEFAULT_REPORT_DIR, type Severity } from "../config/defaults.js";
import { Logger } from "./logger.js";

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
  verbose?: boolean;
}

export interface RunContext {
  env: AppEnv;
  logger: Logger;
  repoPath: string;
  outDir: string;
  options: Required<Omit<CliOptions, "provider" | "model" | "target">> & Pick<CliOptions, "provider" | "model" | "target">;
}

export function createRunContext(repoPath: string, options: CliOptions = {}): RunContext {
  const env = loadEnv();
  const outDir = path.resolve(options.out ?? env.CODEGUARDIAN_REPORT_DIR ?? DEFAULT_REPORT_DIR);
  mkdirSync(outDir, { recursive: true });
  return {
    env,
    logger: new Logger(Boolean(options.verbose)),
    repoPath: path.resolve(repoPath),
    outDir,
    options: {
      out: outDir,
      format: options.format ?? "all",
      ai: options.ai ?? false,
      allowHost: options.allowHost ?? [],
      maxFiles: options.maxFiles ?? Number.MAX_SAFE_INTEGER,
      maxFileSize: options.maxFileSize ?? env.CODEGUARDIAN_MAX_FILE_SIZE,
      maxAiFindings: Math.min(options.maxAiFindings ?? env.CODEGUARDIAN_MAX_AI_FINDINGS, env.CODEGUARDIAN_MAX_AI_FINDINGS_LIMIT),
      aiAudit: options.aiAudit ?? env.CODEGUARDIAN_AI_AUDIT.toLowerCase() !== "false",
      maxAiAuditFiles: options.maxAiAuditFiles ?? env.CODEGUARDIAN_AI_AUDIT_MAX_FILES,
      maxAiAuditRounds: options.maxAiAuditRounds ?? env.CODEGUARDIAN_AI_AUDIT_MAX_ROUNDS,
      maxAiAuditChars: options.maxAiAuditChars ?? env.CODEGUARDIAN_AI_AUDIT_MAX_CHARS,
      include: options.include ?? [],
      exclude: options.exclude ?? [],
      failOn: options.failOn ?? "none",
      runApproved: options.runApproved ?? false,
      verbose: options.verbose ?? false,
      provider: options.provider,
      model: options.model,
      target: options.target
    }
  };
}
