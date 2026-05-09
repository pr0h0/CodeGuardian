import type { IndexedFile } from "../repo/repoIndexer.js";
import type { ScannerResult } from "./types.js";

export function runQualityChecks(files: IndexedFile[]): ScannerResult[] {
  const results: ScannerResult[] = [];
  for (const file of files) {
    if (file.lineCount > 1000) {
      results.push({ scanner: "quality", ruleId: "large-file", title: "Large source file", category: "maintainability", severity: "low", path: file.path, startLine: 1, endLine: file.lineCount, message: "Large files are harder to review for security-critical behavior." });
    }
  }
  return results;
}
