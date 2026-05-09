import crypto from "node:crypto";
import type { Db } from "./database.js";
import type { Finding, ScannerResult } from "../scanners/types.js";

export interface FileRecord {
  id?: number;
  scanId: string;
  path: string;
  language: string;
  sizeBytes: number;
  sha256: string;
  lineCount: number;
  indexed: boolean;
  skippedReason?: string;
}

export function createScan(db: Db, repoPath: string, options: unknown, provider?: string, model?: string): string {
  const id = crypto.randomUUID();
  db.prepare("INSERT INTO scans (id, repo_path, started_at, status, provider, model, options_json) VALUES (?, ?, ?, ?, ?, ?, ?)")
    .run(id, repoPath, new Date().toISOString(), "running", provider ?? null, model ?? null, JSON.stringify(options));
  return id;
}

export function finishScan(db: Db, scanId: string, status: string): void {
  db.prepare("UPDATE scans SET finished_at = ?, status = ? WHERE id = ?").run(new Date().toISOString(), status, scanId);
}

export function insertFile(db: Db, file: FileRecord): number {
  const result = db.prepare(`INSERT INTO files (scan_id,path,language,size_bytes,sha256,line_count,indexed,skipped_reason)
    VALUES (?,?,?,?,?,?,?,?)`).run(file.scanId, file.path, file.language, file.sizeBytes, file.sha256, file.lineCount, file.indexed ? 1 : 0, file.skippedReason ?? null);
  return Number(result.lastInsertRowid);
}

export function insertChunk(db: Db, scanId: string, fileId: number, path: string, start: number, end: number, content: string, sha: string, summary = ""): void {
  db.prepare("INSERT INTO chunks (scan_id,file_id,path,start_line,end_line,content,sha256,summary) VALUES (?,?,?,?,?,?,?,?)")
    .run(scanId, fileId, path, start, end, content, sha, summary);
}

export function insertSymbol(db: Db, row: Record<string, unknown>): void {
  db.prepare(`INSERT INTO symbols (scan_id,file_id,path,name,kind,start_line,end_line,signature,exported,metadata_json)
    VALUES (@scanId,@fileId,@path,@name,@kind,@startLine,@endLine,@signature,@exported,@metadataJson)`).run(row);
}

export function insertRoute(db: Db, row: Record<string, unknown>): void {
  db.prepare(`INSERT INTO routes (scan_id,file_id,method,route_path,handler_name,start_line,end_line,framework_guess,metadata_json)
    VALUES (@scanId,@fileId,@method,@routePath,@handlerName,@startLine,@endLine,@frameworkGuess,@metadataJson)`).run(row);
}

export function insertEdge(db: Db, row: Record<string, unknown>): void {
  db.prepare(`INSERT INTO edges (scan_id,from_type,from_id,to_type,to_id,edge_type,metadata_json)
    VALUES (@scanId,@fromType,@fromId,@toType,@toId,@edgeType,@metadataJson)`).run(row);
}

export function insertScannerResult(db: Db, scanId: string, result: ScannerResult): void {
  db.prepare(`INSERT INTO scanner_results (scan_id,scanner,rule_id,title,severity,path,start_line,end_line,message,raw_json)
    VALUES (?,?,?,?,?,?,?,?,?,?)`).run(scanId, result.scanner, result.ruleId, result.title, result.severity, result.path ?? null, result.startLine ?? null, result.endLine ?? null, result.message, JSON.stringify(result.raw ?? {}));
}

export function insertFinding(db: Db, scanId: string, finding: Finding): void {
  db.prepare(`INSERT INTO findings (scan_id,title,category,severity,confidence,status,path,start_line,end_line,source,sink,evidence_json,reasoning,remediation,raw_json)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(scanId, finding.title, finding.category, finding.severity, finding.confidence, finding.status, finding.path ?? null, finding.startLine ?? null, finding.endLine ?? null, finding.source ?? null, finding.sink ?? null, JSON.stringify(finding.evidence), finding.reasoning, finding.remediation, JSON.stringify(finding.raw ?? {}));
}

export function getScanBundle(db: Db, scanId: string) {
  return {
    scan: db.prepare("SELECT * FROM scans WHERE id = ?").get(scanId),
    files: db.prepare("SELECT * FROM files WHERE scan_id = ?").all(scanId),
    scannerResults: db.prepare("SELECT * FROM scanner_results WHERE scan_id = ?").all(scanId),
    findings: db.prepare("SELECT * FROM findings WHERE scan_id = ?").all(scanId),
    approvals: db.prepare("SELECT * FROM approvals WHERE scan_id = ? OR scan_id IS NULL").all(scanId)
  };
}
