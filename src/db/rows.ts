export interface ScanRow {
  id: string;
  repo_path: string;
  started_at: string;
  finished_at?: string | null;
  status: string;
  provider?: string | null;
  model?: string | null;
  options_json: string;
}

export interface FileRow {
  id: number;
  scan_id: string;
  path: string;
  language: string;
  size_bytes: number;
  sha256: string;
  line_count: number;
  indexed: number;
  skipped_reason?: string | null;
}

export interface ScannerResultRow {
  id: number;
  scan_id: string;
  scanner: string;
  rule_id: string;
  title: string;
  severity: string;
  path?: string | null;
  start_line?: number | null;
  end_line?: number | null;
  message: string;
  raw_json: string;
  fingerprint?: string | null;
}

export interface ScannerRunRow {
  id: number;
  scan_id: string;
  scanner: string;
  image?: string | null;
  command?: string | null;
  started_at: string;
  elapsed_ms: number;
  exit_code?: number | null;
  result_count: number;
  warning?: string | null;
  metadata_json: string;
}

export interface FindingRow {
  id: number;
  scan_id: string;
  title: string;
  category: string;
  severity: string;
  confidence: string;
  status: string;
  path?: string | null;
  start_line?: number | null;
  end_line?: number | null;
  source?: string | null;
  sink?: string | null;
  evidence_json: string;
  reasoning: string;
  remediation: string;
  poc_path?: string | null;
  dynamic_evidence_json?: string | null;
  raw_json: string;
  fingerprint?: string | null;
  baseline_status?: string | null;
  exploitability_score?: number | null;
}

export interface ApprovalRow {
  id: string;
  scan_id?: string | null;
  action_type: string;
  command_preview: string;
  risk: string;
  reason: string;
  target?: string | null;
  status: string;
  created_at: string;
  resolved_at?: string | null;
  metadata_json: string;
}

export interface ScanBundle {
  scan?: ScanRow;
  files: FileRow[];
  scannerResults: ScannerResultRow[];
  scannerRuns: ScannerRunRow[];
  findings: FindingRow[];
  approvals: ApprovalRow[];
}

export interface SymbolInsertRow {
  scanId: string;
  fileId: number;
  path: string;
  name: string;
  kind: string;
  startLine?: number | null;
  endLine?: number | null;
  signature?: string | null;
  exported: number;
  metadataJson: string;
}

export interface RouteInsertRow {
  scanId: string;
  fileId: number;
  method?: string | null;
  routePath?: string | null;
  handlerName?: string | null;
  startLine?: number | null;
  endLine?: number | null;
  frameworkGuess?: string | null;
  metadataJson: string;
}

export interface EdgeInsertRow {
  scanId: string;
  fromType?: string | null;
  fromId?: number | null;
  toType?: string | null;
  toId?: number | null;
  edgeType: string;
  metadataJson: string;
}

export interface ScannerRunInsertRow {
  scanId: string;
  scanner: string;
  image?: string | null;
  command?: string | null;
  startedAt: string;
  elapsedMs: number;
  exitCode?: number | null;
  resultCount: number;
  warning?: string | null;
  metadataJson: string;
}
