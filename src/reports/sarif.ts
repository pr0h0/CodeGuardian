import fs from "node:fs";
import path from "node:path";
import { ensureDir } from "../utils/paths.js";

export function writeSarifReport(outDir: string, bundle: any, reportBase = "report"): string {
  ensureDir(outDir);
  const results = (bundle.findings ?? []).map((finding: any) => ({
    ruleId: finding.category,
    level: mapLevel(finding.severity),
    message: { text: finding.title },
    locations: finding.path ? [{
      physicalLocation: {
        artifactLocation: { uri: finding.path },
        region: { startLine: finding.start_line ?? 1, endLine: finding.end_line ?? finding.start_line ?? 1 }
      }
    }] : []
  }));
  const sarif = {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [{ tool: { driver: { name: "codeguardian", rules: [] } }, results }]
  };
  const file = path.join(outDir, `${reportBase}.sarif`);
  fs.writeFileSync(file, JSON.stringify(sarif, null, 2));
  return file;
}

function mapLevel(sev: string): string {
  if (["critical", "high"].includes(sev)) return "error";
  if (sev === "medium") return "warning";
  return "note";
}
