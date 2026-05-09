import dotenv from "dotenv";
import { z } from "zod";
import { DEFAULT_ALLOW_HOSTS, DEFAULT_CONTEXT_CHARS, DEFAULT_DB_PATH, DEFAULT_MAX_FILE_SIZE, DEFAULT_REPORT_DIR } from "./defaults.js";

dotenv.config();

const envSchema = z.object({
  AI_PROVIDER: z.enum(["openai", "anthropic", "deepseek", "openrouter"]).default("openai"),
  AI_MODEL: z.string().optional().default(""),
  AI_API_KEY: z.string().optional().default(""),
  AI_BASE_URL: z.string().optional().default(""),
  OPENAI_API_KEY: z.string().optional().default(""),
  OPENAI_MODEL: z.string().optional().default(""),
  ANTHROPIC_API_KEY: z.string().optional().default(""),
  ANTHROPIC_MODEL: z.string().optional().default(""),
  DEEPSEEK_API_KEY: z.string().optional().default(""),
  DEEPSEEK_MODEL: z.string().optional().default(""),
  DEEPSEEK_BASE_URL: z.string().optional().default("https://api.deepseek.com"),
  OPENROUTER_API_KEY: z.string().optional().default(""),
  OPENROUTER_MODEL: z.string().optional().default(""),
  OPENROUTER_BASE_URL: z.string().optional().default("https://openrouter.ai/api/v1"),
  CODEGUARDIAN_DB_PATH: z.string().optional().default(DEFAULT_DB_PATH),
  CODEGUARDIAN_REPORT_DIR: z.string().optional().default(DEFAULT_REPORT_DIR),
  CODEGUARDIAN_DEFAULT_TARGET: z.string().optional().default("http://localhost:3000"),
  CODEGUARDIAN_ALLOW_HOSTS: z.string().optional().default(DEFAULT_ALLOW_HOSTS.join(",")),
  CODEGUARDIAN_REQUIRE_APPROVAL: z.string().optional().default("true"),
  CODEGUARDIAN_MAX_FILE_SIZE: z.coerce.number().positive().default(DEFAULT_MAX_FILE_SIZE),
  CODEGUARDIAN_MAX_CONTEXT_CHARS: z.coerce.number().positive().default(DEFAULT_CONTEXT_CHARS),
  CODEGUARDIAN_MAX_AI_FINDINGS: z.coerce.number().int().positive().default(25),
  CODEGUARDIAN_MAX_AI_FINDINGS_LIMIT: z.coerce.number().int().positive().default(1000),
  CODEGUARDIAN_AI_AUDIT: z.string().optional().default("true"),
  CODEGUARDIAN_AI_AUDIT_MAX_FILES: z.coerce.number().int().positive().default(40),
  CODEGUARDIAN_AI_AUDIT_MAX_ROUNDS: z.coerce.number().int().positive().default(6),
  CODEGUARDIAN_AI_AUDIT_MAX_CHARS: z.coerce.number().int().positive().default(160000),
  CODEGUARDIAN_REDACT_SECRETS: z.string().optional().default("true")
});

export type AppEnv = z.infer<typeof envSchema>;

export function loadEnv(source: NodeJS.ProcessEnv = process.env): AppEnv {
  return envSchema.parse(source);
}

export function boolEnv(value: string | undefined): boolean {
  return String(value ?? "").toLowerCase() !== "false";
}

export function envAllowHosts(env: AppEnv): string[] {
  return env.CODEGUARDIAN_ALLOW_HOSTS.split(",").map((host) => host.trim()).filter(Boolean);
}
