import type { Db } from "../db/database.js";
import { upsertScanCache } from "../db/repositories.js";
import type { IndexedFile } from "../repo/repoIndexer.js";
import type { ScannerResult } from "../scanners/types.js";
import { sha256 } from "../utils/hashing.js";

export interface ScanPlan {
  files: IndexedFile[];
  localFiles: IndexedFile[];
  indexedPaths: Set<string>;
  changedPaths: Set<string>;
  incremental: boolean;
}

export function buildScanPlan(db: Db, repoPath: string, files: IndexedFile[], options: { incremental: boolean }): ScanPlan {
  const changedPaths = new Set(files.filter((file) => {
    const cached = db.prepare("SELECT sha256 FROM scan_cache WHERE repo_path = ? AND path = ?").get(repoPath, file.path) as { sha256?: string } | undefined;
    return cached?.sha256 !== sha256(file.content);
  }).map((file) => normalizePath(file.path)));
  const localFiles = options.incremental ? files.filter((file) => changedPaths.has(normalizePath(file.path))) : files;
  return {
    files,
    localFiles,
    indexedPaths: new Set(files.map((file) => normalizePath(file.path))),
    changedPaths,
    incremental: options.incremental
  };
}

export function persistScanPlanCache(db: Db, repoPath: string, files: IndexedFile[]): void {
  for (const file of files) {
    upsertScanCache(db, repoPath, {
      path: normalizePath(file.path),
      sha256: sha256(file.content),
      language: file.language,
      lineCount: file.lineCount
    });
  }
}

export function filterResultsToScanScope<T extends ScannerResult>(results: T[], plan: Pick<ScanPlan, "indexedPaths">): T[] {
  return results.filter((result) => !result.path || plan.indexedPaths.has(normalizePath(result.path)));
}

function normalizePath(value: string): string {
  return value.replaceAll("\\", "/").replace(/^\.\//, "").replace(/^\/src\//, "");
}
