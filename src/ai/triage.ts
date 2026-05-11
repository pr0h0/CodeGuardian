import type { ContextPack } from "../repo/contextPackBuilder.js";
import type { Finding, ScannerResult } from "../scanners/types.js";
import { safeJsonParse } from "../utils/safeJson.js";
import { aiFindingSchema, type AiProvider } from "./types.js";
import { buildSecurityCriticSystemPrompt, buildSecurityCriticUserPrompt, buildSecurityTriageSystemPrompt, buildSecurityTriageUserPrompt } from "./prompts.js";
import { z } from "zod";

const criticSchema = z.object({
  verdict: z.enum(["keep", "downgrade", "reject"]),
  confidence: z.enum(["high", "medium", "low"]),
  reasons: z.array(z.string()).default([]),
  revisedStatus: z.enum(["confirmed", "suspected", "needs_dynamic_test", "false_positive"]),
  revisedConfidence: z.enum(["confirmed", "high", "medium", "low"])
});

export interface RequestedContext {
  files: Array<{ path: string; startLine: number; endLine: number; content: string }>;
  symbols: Array<{ query: string; path: string; startLine: number; endLine: number; content: string }>;
  missing: string[];
}

export type RequestedContextResolver = (files: string[], symbols: string[]) => RequestedContext;

export function deterministicFinding(result: ScannerResult): Finding {
  const raw = result.raw && typeof result.raw === "object" ? result.raw as Record<string, any> : {};
  const rule = raw.rule && typeof raw.rule === "object" ? raw.rule : raw;
  const summary = summarize(result.message || result.title, 260);
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
    evidence: [{ path: result.path, line: result.startLine, note: summary }],
    reasoning: `${result.scanner} reported ${result.ruleId}: ${rule.description ?? summary}`,
    remediation: rule.fix ?? "Review the affected code, validate inputs, enforce least privilege, and use safe framework APIs.",
    scannerSource: result.scanner,
    raw: result.raw
  };
}

function summarize(value: string, max: number): string {
  return String(value ?? "")
    .replace(/```[\s\S]*?```/g, "[code sample omitted]")
    .replace(/#+\s*/g, "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, max);
}

export async function aiTriage(provider: AiProvider, packs: ContextPack[], log: (message: string) => void = () => undefined, criticProvider?: AiProvider, resolveRequestedContext?: RequestedContextResolver): Promise<Finding[]> {
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
      }), 120_000, "AI triage request timed out after 120s");
      log(`ai: triage ${label} response chars=${output.text.length}`);
      let parsed = normalizeAiFindingJson(safeJsonParse(output.text));
      let checked = aiFindingSchema.safeParse(parsed);
      if (!checked.success) {
        log(`ai: triage ${label} schema invalid, repairing`);
        const repair = await withTimeout(provider.complete({ system: "Repair invalid JSON to match requested schema. Output JSON only.", messages: [{ role: "user", content: output.text }], temperature: 0, maxTokens: 2500 }), 120_000, "AI JSON repair request timed out after 120s");
        log(`ai: triage ${label} repair response chars=${repair.text.length}`);
        parsed = normalizeAiFindingJson(safeJsonParse(repair.text));
        checked = aiFindingSchema.safeParse(parsed);
      }
      if (checked.success) {
        let data = checked.data;
        let criticPack = pack;
        if (resolveRequestedContext && (data.requestedFiles.length || data.requestedSymbols.length)) {
          const requestedContext = resolveRequestedContext(data.requestedFiles, data.requestedSymbols);
          const hasContext = requestedContext.files.length || requestedContext.symbols.length;
          log(`ai: triage ${label} requested extra context files=${data.requestedFiles.length} symbols=${data.requestedSymbols.length} resolved=${hasContext ? "yes" : "no"}`);
          if (hasContext) {
            const expandedPack = { ...pack, requestedContext };
            criticPack = expandedPack;
            const retry = await withTimeout(provider.complete({
              system: buildSecurityTriageSystemPrompt(),
              messages: [{ role: "user", content: `${buildSecurityTriageUserPrompt(expandedPack)}\n\nYou already requested extra context and it is now present in inputs.requestedContext. Make the final decision now. Do not request more context.` }],
              temperature: 0,
              maxTokens: 3000
            }), 120_000, "AI triage context expansion request timed out after 120s");
            const retryChecked = aiFindingSchema.safeParse(normalizeAiFindingJson(safeJsonParse(retry.text)));
            if (retryChecked.success) data = retryChecked.data;
            else log(`ai: triage ${label} extra-context retry invalid, using first response`);
          }
        }
        if (criticProvider && data.isFinding) {
          data = await applyCritic(criticProvider, criticPack, data, log, label);
        }
        const loc = data.affectedLocations[0];
        findings.push({
          title: data.title,
          category: data.category,
          severity: data.severity,
          confidence: data.confidence,
          status: data.isFinding ? data.status : "false_positive",
          path: loc?.path,
          startLine: loc?.startLine,
          endLine: loc?.endLine,
          source: `${data.source}${data.sourceLine ? `:${data.sourceLine}` : ""}`,
          sink: `${data.sink}${data.sinkLine ? `:${data.sinkLine}` : ""}`,
          evidence: data.evidence,
          reasoning: data.isFinding ? `${data.attackScenario}\nMissing control: ${data.missingControl}\nPreconditions: ${data.exploitPreconditions.join("; ")}` : data.falsePositiveConsiderations.join(" ") || "AI marked this scanner result as a false positive based on supplied context.",
          remediation: data.remediation,
          raw: data
        });
        log(`ai: triage ${label} stored status=${data.isFinding ? data.status : "false_positive"}`);
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

async function applyCritic(provider: AiProvider, pack: ContextPack, data: z.infer<typeof aiFindingSchema>, log: (message: string) => void, label: string): Promise<z.infer<typeof aiFindingSchema>> {
  log(`ai: critic ${label} start`);
  const output = await withTimeout(provider.complete({
    system: buildSecurityCriticSystemPrompt(),
    messages: [{ role: "user", content: buildSecurityCriticUserPrompt(pack, data) }],
    temperature: 0,
    maxTokens: 1200
  }), 120_000, "AI critic request timed out after 120s");
  const checked = criticSchema.safeParse(normalizeAiFindingJson(safeJsonParse(output.text)));
  if (!checked.success) {
    log(`ai: critic ${label} invalid response, keeping finding`);
    return data;
  }
  log(`ai: critic ${label} verdict=${checked.data.verdict}`);
  if (checked.data.verdict === "reject") {
    return { ...data, isFinding: false, status: "false_positive", confidence: "low", falsePositiveConsiderations: checked.data.reasons.length ? checked.data.reasons : ["Critic rejected exploitability based on supplied context."] };
  }
  if (checked.data.verdict === "downgrade") {
    return { ...data, status: checked.data.revisedStatus, confidence: checked.data.revisedConfidence, falsePositiveConsiderations: [...data.falsePositiveConsiderations, ...checked.data.reasons] };
  }
  return data;
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
