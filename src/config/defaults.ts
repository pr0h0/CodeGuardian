export const DEFAULT_IGNORES = [
  ".git",
  "node_modules",
  "vendor",
  "dist",
  "build",
  "coverage",
  "codeguardian-report",
  ".codeguardian",
  ".next",
  ".nuxt",
  "target",
  "obj",
  ".venv",
  "venv",
  "__pycache__"
];

export const DEFAULT_MAX_FILE_SIZE = 1_048_576;
export const DEFAULT_CONTEXT_CHARS = 60_000;
export const DEFAULT_REPORT_DIR = "codeguardian-report";
export const DEFAULT_DB_PATH = ".codeguardian/codeguardian.sqlite";
export const DEFAULT_ALLOW_HOSTS = ["localhost", "127.0.0.1"];
export const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;

export type Severity = (typeof SEVERITY_ORDER)[number];
