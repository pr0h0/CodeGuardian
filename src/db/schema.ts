export const schemaSql = `
CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY,
  repo_path TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  status TEXT NOT NULL,
  provider TEXT,
  model TEXT,
  options_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS files (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  path TEXT NOT NULL,
  language TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  sha256 TEXT NOT NULL,
  line_count INTEGER NOT NULL,
  indexed INTEGER NOT NULL,
  skipped_reason TEXT
);
CREATE TABLE IF NOT EXISTS chunks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  file_id INTEGER NOT NULL,
  path TEXT NOT NULL,
  start_line INTEGER NOT NULL,
  end_line INTEGER NOT NULL,
  content TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  summary TEXT
);
CREATE TABLE IF NOT EXISTS symbols (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  file_id INTEGER NOT NULL,
  path TEXT NOT NULL,
  name TEXT NOT NULL,
  kind TEXT NOT NULL,
  start_line INTEGER,
  end_line INTEGER,
  signature TEXT,
  exported INTEGER NOT NULL DEFAULT 0,
  metadata_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS edges (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  from_type TEXT, from_id INTEGER, to_type TEXT, to_id INTEGER,
  edge_type TEXT NOT NULL,
  metadata_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS routes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  file_id INTEGER,
  method TEXT,
  route_path TEXT,
  handler_name TEXT,
  start_line INTEGER,
  end_line INTEGER,
  framework_guess TEXT,
  metadata_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS scanner_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  scanner TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  path TEXT,
  start_line INTEGER,
  end_line INTEGER,
  message TEXT NOT NULL,
  raw_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  title TEXT NOT NULL,
  category TEXT NOT NULL,
  severity TEXT NOT NULL,
  confidence TEXT NOT NULL,
  status TEXT NOT NULL,
  path TEXT,
  start_line INTEGER,
  end_line INTEGER,
  source TEXT,
  sink TEXT,
  evidence_json TEXT NOT NULL,
  reasoning TEXT NOT NULL,
  remediation TEXT NOT NULL,
  poc_path TEXT,
  dynamic_evidence_json TEXT,
  raw_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS approvals (
  id TEXT PRIMARY KEY,
  scan_id TEXT,
  action_type TEXT NOT NULL,
  command_preview TEXT NOT NULL,
  risk TEXT NOT NULL,
  reason TEXT NOT NULL,
  target TEXT,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  resolved_at TEXT,
  metadata_json TEXT NOT NULL DEFAULT '{}'
);
`;
