import type { ContextPack } from "../repo/contextPackBuilder.js";
import type { Finding, ScannerResult } from "../scanners/types.js";
import { safeJsonParse } from "../utils/safeJson.js";
import { aiFindingSchema, type AiProvider } from "./types.js";
import { buildSecurityTriageSystemPrompt, buildSecurityTriageUserPrompt } from "./prompts.js";

export function deterministicFinding(result: ScannerResult): Finding {
  return {
    title: result.title,
    category: result.category ?? "security",
    severity: result.severity,
    confidence: result.scanner === "custom-rules" ? "medium" : "high",
    status: "suspected",
    path: result.path,
    startLine: result.startLine,
    endLine: result.endLine,
    source: result.scanner,
    sink: result.ruleId,
    evidence: [{ path: result.path, line: result.startLine, note: result.message }],
    reasoning: `${result.scanner} reported ${result.ruleId}: ${result.message}`,
    remediation: "Review the affected code, validate inputs, enforce least privilege, and use safe framework APIs.",
    scannerSource: result.scanner,
    raw: result.raw
  };
}

export async function aiTriage(provider: AiProvider, packs: ContextPack[], log: (message: string) => void = () => undefined): Promise<Finding[]> {
  const findings: Finding[] = [];
  for (const [index, pack] of packs.entries()) {
    const label = `${index + 1}/${packs.length} ${pack.scannerResult.scanner}/${pack.scannerResult.ruleId} ${pack.scannerResult.path ?? ""}:${pack.scannerResult.startLine ?? ""}`;
    try {
      log(`ai: triage ${label} start`);
      const output = await withTimeout(provider.complete({
        system: buildSecurityTriageSystemPrompt(),
        messages: [{ role: "user", content: buildSecurityTriageUserPrompt(pack) }],
        temperature: 0,
        maxTokens: 2500
      }), 45_000, "AI triage request timed out after 45s");
      log(`ai: triage ${label} response chars=${output.text.length}`);
      let parsed = normalizeAiFindingJson(safeJsonParse(output.text));
      let checked = aiFindingSchema.safeParse(parsed);
      if (!checked.success) {
        log(`ai: triage ${label} schema invalid, repairing`);
        const repair = await withTimeout(provider.complete({ system: "Repair invalid JSON to match requested schema. Output JSON only.", messages: [{ role: "user", content: output.text }], temperature: 0, maxTokens: 2500 }), 45_000, "AI JSON repair request timed out after 45s");
        log(`ai: triage ${label} repair response chars=${repair.text.length}`);
        parsed = normalizeAiFindingJson(safeJsonParse(repair.text));
        checked = aiFindingSchema.safeParse(parsed);
      }
      if (checked.success) {
        const loc = checked.data.affectedLocations[0];
        findings.push({
          title: checked.data.title,
          category: checked.data.category,
          severity: checked.data.severity,
          confidence: checked.data.confidence,
          status: checked.data.isFinding ? checked.data.status : "false_positive",
          path: loc?.path,
          startLine: loc?.startLine,
          endLine: loc?.endLine,
          source: checked.data.source,
          sink: checked.data.sink,
          evidence: checked.data.evidence,
          reasoning: checked.data.isFinding ? checked.data.attackScenario : checked.data.falsePositiveConsiderations.join(" ") || "AI marked this scanner result as a false positive based on supplied context.",
          remediation: checked.data.remediation,
          raw: checked.data
        });
        log(`ai: triage ${label} stored status=${checked.data.isFinding ? checked.data.status : "false_positive"}`);
      } else {
        findings.push(coerceAiFallback(pack.scannerResult, parsed, checked.error.issues.map((issue) => issue.path.join(".")).slice(0, 5)));
        log(`ai: triage ${label} stored fallback`);
      }
    } catch (error) {
      findings.push({ ...deterministicFinding(pack.scannerResult), confidence: "low", reasoning: `AI triage failed: ${error instanceof Error ? error.message : String(error)}` });
      log(`ai: triage ${label} failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  return findings;
}

async function withTimeout<T>(promise: Promise<T>, timeoutMs: number, message: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<T>((_, reject) => {
        timer = setTimeout(() => reject(new Error(message)), timeoutMs);
      })
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function coerceAiFallback(result: ScannerResult, parsed: unknown, issues: string[]): Finding {
  const base = deterministicFinding(result);
  const object = parsed && typeof parsed === "object" ? parsed as Record<string, unknown> : {};
  const evidence = Array.isArray(object.evidence) ? object.evidence : base.evidence;
  const reasoning = [object.attackScenario, object.reasoning, object.summary, object.analysis, object.falsePositiveConsiderations]
    .flatMap((value) => Array.isArray(value) ? value : value ? [value] : [])
    .map(String)
    .join(" ");
  const statusText = String(object.status ?? "").toLowerCase();
  const isFalsePositive = object.isFinding === false || statusText.includes("false");
  return {
    ...base,
    title: typeof object.title === "string" ? object.title : base.title,
    category: typeof object.category === "string" ? object.category : base.category,
    status: isFalsePositive ? "false_positive" : base.status,
    confidence: "low",
    evidence,
    reasoning: reasoning || `AI returned partial JSON; schema gaps: ${issues.join(", ")}`,
    remediation: typeof object.remediation === "string" ? object.remediation : base.remediation,
    raw: parsed
  };
}

function normalizeAiFindingJson(parsed: unknown): unknown {
  if (parsed && typeof parsed === "object") {
    const object = parsed as Record<string, unknown>;
    if (object.finding && typeof object.finding === "object") return object.finding;
    if (object.result && typeof object.result === "object") return object.result;
    if (Array.isArray(object.findings) && object.findings[0]) return object.findings[0];
  }
  return parsed;
}
