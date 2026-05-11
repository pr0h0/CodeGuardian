import fs from "node:fs";
import path from "node:path";
import { ensureDir } from "../utils/paths.js";

export function writeSarifReport(outDir: string, bundle: any, reportBase = "report"): string {
  ensureDir(outDir);
  const rules = buildRules(bundle.findings ?? []);
  const results = (bundle.findings ?? []).map((finding: any) => ({
    ruleId: ruleId(finding),
    level: mapLevel(finding.severity),
    message: { text: `${finding.title}${finding.reasoning ? ` - ${finding.reasoning}` : ""}` },
    fingerprints: finding.fingerprint ? { codeguardian: finding.fingerprint } : undefined,
    locations: finding.path ? [{
      physicalLocation: {
        artifactLocation: { uri: finding.path },
        region: { startLine: finding.start_line ?? 1, endLine: finding.end_line ?? finding.start_line ?? 1 }
      }
    }] : [],
    properties: {
      baselineStatus: finding.baseline_status,
      exploitabilityScore: finding.exploitability_score,
      confidence: finding.confidence,
      status: finding.status
    }
  }));
  const sarif = {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [{ tool: { driver: { name: "codeguardian", rules } }, results }]
  };
  const file = path.join(outDir, `${reportBase}.sarif`);
  fs.writeFileSync(file, JSON.stringify(sarif, null, 2));
  return file;
}

function buildRules(findings: any[]): any[] {
  const seen = new Map<string, any>();
  for (const finding of findings) {
    const raw = safeParse(finding.raw_json);
    const meta = raw.rule ?? raw;
    const id = ruleId(finding);
    if (seen.has(id)) continue;
    seen.set(id, {
      id,
      name: finding.category,
      shortDescription: { text: finding.title },
      fullDescription: { text: meta.description ?? finding.reasoning ?? finding.title },
      help: { text: meta.fix ?? finding.remediation ?? "" },
      properties: {
        tags: [finding.category, meta.cwe, meta.owasp].filter(Boolean),
        precision: finding.confidence === "confirmed" || finding.confidence === "high" ? "high" : "medium"
      }
    });
  }
  return [...seen.values()];
}

function ruleId(finding: any): string {
  const raw = safeParse(finding.raw_json);
  return String(raw.rule?.id ?? raw.ruleId ?? raw.cwe ?? finding.category ?? "codeguardian");
}

function safeParse(value: unknown): any {
  if (typeof value !== "string") return value ?? {};
  try { return JSON.parse(value); } catch { return {}; }
}

function mapLevel(sev: string): string {
  if (["critical", "high"].includes(sev)) return "error";
  if (sev === "medium") return "warning";
  return "note";
}
