import type { Db } from "../db/database.js";
import type { NegativeEvidence } from "../repo/securityIntelligence.js";

export function loadNegativeEvidenceMemory(db: Db, repoPath: string, currentScanId: string, limit = 80): NegativeEvidence[] {
  const rows = db.prepare(`
    SELECT f.title, f.path, f.start_line AS startLine, f.reasoning, f.status, f.fingerprint
    FROM findings f
    JOIN scans s ON s.id = f.scan_id
    WHERE s.repo_path = ?
      AND f.scan_id != ?
      AND f.status = 'false_positive'
    ORDER BY s.started_at DESC
    LIMIT ?
  `).all(repoPath, currentScanId, limit) as Array<{
    title: string;
    path?: string | null;
    startLine?: number | null;
    reasoning?: string | null;
    status: string;
    fingerprint?: string | null;
  }>;
  return rows.map((row) => ({
    title: row.title,
    path: row.path,
    startLine: row.startLine,
    reason: row.reasoning ?? "previous scan marked this candidate as false positive",
    status: row.status,
    fingerprint: row.fingerprint
  }));
}
