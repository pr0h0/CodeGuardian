import type { Db } from "../db/database.js";

export interface BaselineDiff {
  baselineScanId?: string;
  newFindings: number;
  resolvedFindings: number;
  unchangedFindings: number;
  newFingerprints: string[];
  resolvedFingerprints: string[];
}

export function buildBaselineDiff(db: Db, repoPath: string, currentScanId: string, requested?: string): BaselineDiff {
  if (requested === "none") return empty();
  const baselineScanId = requested && requested !== "latest" ? requested : latestPreviousScan(db, repoPath, currentScanId);
  if (!baselineScanId) return empty();
  const current = findingFingerprints(db, currentScanId);
  const baseline = findingFingerprints(db, baselineScanId);
  const currentSet = new Set(current);
  const baselineSet = new Set(baseline);
  const newFingerprints = current.filter((item) => !baselineSet.has(item));
  const resolvedFingerprints = baseline.filter((item) => !currentSet.has(item));
  markBaselineStatus(db, currentScanId, baselineSet);
  return {
    baselineScanId,
    newFindings: newFingerprints.length,
    resolvedFindings: resolvedFingerprints.length,
    unchangedFindings: current.filter((item) => baselineSet.has(item)).length,
    newFingerprints: newFingerprints.slice(0, 50),
    resolvedFingerprints: resolvedFingerprints.slice(0, 50)
  };
}

function markBaselineStatus(db: Db, scanId: string, baselineSet: Set<string>): void {
  const rows = db.prepare("SELECT id, fingerprint FROM findings WHERE scan_id = ?").all(scanId) as Array<{ id: number; fingerprint?: string }>;
  const update = db.prepare("UPDATE findings SET baseline_status = ? WHERE id = ?");
  for (const row of rows) update.run(row.fingerprint && baselineSet.has(row.fingerprint) ? "unchanged" : "new", row.id);
}

function latestPreviousScan(db: Db, repoPath: string, currentScanId: string): string | undefined {
  const row = db.prepare(`
    SELECT id FROM scans
    WHERE repo_path = ? AND id != ? AND status = 'completed'
    ORDER BY datetime(started_at) DESC
    LIMIT 1
  `).get(repoPath, currentScanId) as { id?: string } | undefined;
  return row?.id;
}

function findingFingerprints(db: Db, scanId: string): string[] {
  const rows = db.prepare("SELECT fingerprint, title, category, severity, path, start_line, source FROM findings WHERE scan_id = ? AND status != 'false_positive'").all(scanId) as Record<string, unknown>[];
  return rows.map((row) => row.fingerprint ? String(row.fingerprint) : [
    row.category ?? "",
    row.severity ?? "",
    row.path ?? "",
    row.start_line ?? "",
    normalizeTitle(String(row.title ?? "")),
    normalizeSource(String(row.source ?? ""))
  ].join("|").toLowerCase());
}

function normalizeTitle(value: string): string {
  return value.replace(/\s+/g, " ").replace(/\b(candidate|detected|finding)\b/gi, "").trim();
}

function normalizeSource(value: string): string {
  return value.split(/[/:]/)[0] ?? value;
}

function empty(): BaselineDiff {
  return { newFindings: 0, resolvedFindings: 0, unchangedFindings: 0, newFingerprints: [], resolvedFingerprints: [] };
}
