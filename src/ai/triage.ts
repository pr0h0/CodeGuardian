import type { ContextPack } from "../repo/contextPackBuilder.js";
import type { Finding, ScannerResult } from "../scanners/types.js";
import { safeJsonParse } from "../utils/safeJson.js";
import { aiFindingSchema, type AiCompletionOutput, type AiProvider } from "./types.js";
import { buildSecurityCriticSystemPrompt, buildSecurityCriticUserPrompt, buildSecurityTriageSystemPrompt, buildSecurityTriageUserPrompt, buildSecurityVerdictSystemPrompt, buildSecurityVerdictUserPrompt } from "./prompts.js";
import { aiFindingJsonSchema, aiVerdictJsonSchema, criticJsonSchema } from "./schemas.js";
import { z } from "zod";
import type { AiJobRecorder } from "./jobs.js";
import { aiVerdictSchema, normalizeAiVerdictJson, shouldRequestFullFinding, type AiTriageVerdict } from "./verdict.js";
import { validateAiFindingCandidate } from "./findingValidator.js";
import { normalizeAiFindingJson } from "./jsonNormalize.js";

type ValidationIssue = { path: Array<string | number>; message: string };

const AI_JSON_RETRY_ATTEMPTS = 2;

const criticSchema = z.object({
  verdict: z.enum(["keep", "downgrade", "reject"]),
  confidence: z.enum(["high", "medium", "low"]),
  reasons: z.array(z.string()).default([]),
  revisedStatus: z.enum(["confirmed", "confirmed_true_positive", "likely_true_positive", "security_hotspot", "needs_context", "suspected", "needs_dynamic_test", "false_positive"]),
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

export async function aiTriage(
  provider: AiProvider,
  packs: ContextPack[],
  log: (message: string) => void = () => undefined,
  criticProvider?: AiProvider,
  resolveRequestedContext?: RequestedContextResolver,
  labels?: string[],
  repairProvider?: AiProvider,
  jobRecorder?: AiJobRecorder
): Promise<Finding[]> {
  const findings: Finding[] = [];
  for (const [index, pack] of packs.entries()) {
    const label = labels?.[index] ?? `${index + 1}/${packs.length} ${pack.scannerResult.scanner}/${pack.scannerResult.ruleId} ${pack.scannerResult.path ?? ""}:${pack.scannerResult.startLine ?? ""}`;
    const jobId = jobRecorder?.start("triage", label, { provider: provider.name, scanner: pack.scannerResult.scanner, ruleId: pack.scannerResult.ruleId });
    try {
      log(`ai: triage ${label} start`);
      const verdictSystemPrompt = buildSecurityVerdictSystemPrompt();
      const verdictUserPrompt = buildSecurityVerdictUserPrompt(pack);
      const verdictResponse = await requestVerdictWithRecovery(provider, verdictSystemPrompt, verdictUserPrompt, jobRecorder, jobId, repairProvider ?? provider);
      const verdict = verdictResponse.verdict;
      let directFull = verdictResponse.directFull;
      let activePack = pack;
      if (verdict) {
        log(`ai: triage ${label} verdict=${verdict.verdict} confidence=${verdict.confidence}`);
        if (verdict.verdict === "false_positive") {
          findings.push(falsePositiveFromVerdict(pack.scannerResult, verdict));
          jobRecorder?.succeed(jobId, { status: "false_positive", verdict: verdict.verdict, verdictConfidence: verdict.confidence });
          continue;
        }
        if (!shouldRequestFullFinding(verdict)) {
          jobRecorder?.succeed(jobId, { status: "parse_failed", verdict: verdict.verdict, verdictConfidence: verdict.confidence });
          continue;
        }
        if (resolveRequestedContext && (verdict.requestedFiles.length || verdict.requestedSymbols.length)) {
          const requestedContext = resolveRequestedContext(verdict.requestedFiles, verdict.requestedSymbols);
          const hasContext = requestedContext.files.length || requestedContext.symbols.length;
          log(`ai: triage ${label} verdict requested context files=${verdict.requestedFiles.length} symbols=${verdict.requestedSymbols.length} resolved=${hasContext ? "yes" : "no"}`);
          if (hasContext) activePack = { ...pack, requestedContext };
        }
      } else if (!directFull.success) {
        log(`ai: triage ${label} verdict invalid, falling back to full triage`);
      }

      const systemPrompt = buildSecurityTriageSystemPrompt();
      const userPrompt = buildSecurityTriageUserPrompt(activePack);
      let output = directFull.success
        ? verdictResponse.output
        : await withTimeout(provider.complete({
          system: systemPrompt,
          messages: [{ role: "user", content: userPrompt }],
          jsonSchema: aiFindingJsonSchema,
          temperature: 0,
          maxTokens: 2500
        }), 120_000, "AI triage request timed out after 120s");
      if (!directFull.success) jobRecorder?.trace(jobId, { label: "triage", prompt: `${systemPrompt}\n\n${userPrompt}`, response: output.text });
      log(`ai: triage ${label} response chars=${output.text.length}`);
      let parsed = normalizeAiFindingJson(safeJsonParse(output.text));
      let checked = directFull.success ? directFull : aiFindingSchema.safeParse(parsed);
      if (!checked.success) {
        log(`ai: triage ${label} schema invalid, retrying full triage`);
        const retryUserPrompt = buildFullFindingRetryPrompt(userPrompt, output.text, checked.error.issues);
        const retry = await withTimeout(provider.complete({
          system: systemPrompt,
          messages: [{ role: "user", content: retryUserPrompt }],
          jsonSchema: aiFindingJsonSchema,
          temperature: 0,
          maxTokens: 3000
        }), 120_000, "AI triage retry request timed out after 120s");
        jobRecorder?.trace(jobId, { label: "triage-retry", prompt: `${systemPrompt}\n\n${retryUserPrompt}`, response: retry.text });
        output = retry;
        log(`ai: triage ${label} retry response chars=${output.text.length}`);
        parsed = normalizeAiFindingJson(safeJsonParse(output.text));
        checked = aiFindingSchema.safeParse(parsed);
      }
      if (!checked.success) {
        log(`ai: triage ${label} schema invalid, repairing`);
        const repairSystem = "Repair invalid JSON to match requested schema. Output raw JSON only. No prose, markdown, comments, code fences, or extra keys. Use only enum values allowed by schema. Enum fields must be single strings, never arrays.";
        const repairPrompt = buildJsonRepairPrompt(output.text, checked.error.issues);
        const repair = await withTimeout((repairProvider ?? provider).complete({ system: repairSystem, messages: [{ role: "user", content: repairPrompt }], jsonSchema: aiFindingJsonSchema, temperature: 0, maxTokens: 2500 }), 120_000, "AI JSON repair request timed out after 120s");
        jobRecorder?.trace(jobId, { label: "repair", prompt: `${repairSystem}\n\n${repairPrompt}`, response: repair.text });
        log(`ai: triage ${label} repair response chars=${repair.text.length}`);
        parsed = normalizeAiFindingJson(safeJsonParse(repair.text));
        checked = aiFindingSchema.safeParse(parsed);
      }
      if (checked.success) {
        let data = checked.data;
        let criticPack = activePack;
        if (resolveRequestedContext && (data.requestedFiles.length || data.requestedSymbols.length)) {
          const requestedContext = resolveRequestedContext(data.requestedFiles, data.requestedSymbols);
          const hasContext = requestedContext.files.length || requestedContext.symbols.length;
          log(`ai: triage ${label} requested extra context files=${data.requestedFiles.length} symbols=${data.requestedSymbols.length} resolved=${hasContext ? "yes" : "no"}`);
          if (hasContext) {
            const expandedPack = { ...pack, requestedContext };
            criticPack = expandedPack;
            const retryUserPrompt = `${buildSecurityTriageUserPrompt(expandedPack)}\n\nYou already requested extra context and it is now present in inputs.requestedContext. Make the final decision now. Do not request more context.`;
            const retry = await withTimeout(provider.complete({
              system: systemPrompt,
              messages: [{ role: "user", content: retryUserPrompt }],
              jsonSchema: aiFindingJsonSchema,
              temperature: 0,
              maxTokens: 3000
            }), 120_000, "AI triage context expansion request timed out after 120s");
            jobRecorder?.trace(jobId, { label: "context-retry", prompt: `${systemPrompt}\n\n${retryUserPrompt}`, response: retry.text });
            const retryChecked = aiFindingSchema.safeParse(normalizeAiFindingJson(safeJsonParse(retry.text)));
            if (retryChecked.success) data = retryChecked.data;
            else log(`ai: triage ${label} extra-context retry invalid, using first response`);
          }
        }
        const validation = validateAiFindingCandidate(data, criticPack);
        if (!validation.valid) {
          log(`ai: triage ${label} validator rejected: ${validation.reasons.join("; ")}`);
          jobRecorder?.succeed(jobId, { status: "validator_rejected", validatorReasons: validation.reasons });
          continue;
        }
        if (criticProvider && data.isFinding) {
          data = await applyCritic(criticProvider, criticPack, data, log, label, jobRecorder);
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
        jobRecorder?.succeed(jobId, { status: data.isFinding ? data.status : "false_positive", finding: data.isFinding });
      } else {
        const issues = checked.error.issues.map((issue) => issue.path.join(".")).slice(0, 8);
        if (verdict?.verdict === "true_positive") {
          const fallback = fallbackFindingFromTruePositiveVerdict(pack.scannerResult, verdict, checked.error.issues);
          findings.push(fallback);
          log(`ai: triage ${label} parse failed, promoted true-positive verdict fallback`);
          jobRecorder?.succeed(jobId, { status: fallback.status, fallback: "verdict_true_positive", issues });
        } else {
          log(`ai: triage ${label} parse failed, not promoting fallback`);
          jobRecorder?.succeed(jobId, { status: "parse_failed", issues });
        }
      }
    } catch (error) {
      findings.push({ ...deterministicFinding(pack.scannerResult), confidence: "low", reasoning: `AI triage failed: ${error instanceof Error ? error.message : String(error)}` });
      log(`ai: triage ${label} failed: ${error instanceof Error ? error.message : String(error)}`);
      jobRecorder?.fail(jobId, error);
    }
  }
  return findings;
}

function fallbackFindingFromTruePositiveVerdict(result: ScannerResult, verdict: AiTriageVerdict, issues: z.ZodIssue[]): Finding {
  const fallback = deterministicFinding(result);
  const confidence = verdict.confidence === "high" ? "medium" : "low";
  return {
    ...fallback,
    confidence,
    status: "likely_true_positive",
    reasoning: [
      `AI first-pass verdict marked this scanner result true_positive with ${verdict.confidence} confidence: ${summarize(verdict.reason, 300) || "no reason supplied"}.`,
      "The full finding JSON stayed invalid after retry and repair, so Codeguardian preserved the scanner-backed candidate instead of dropping it.",
      fallback.reasoning
    ].join("\n"),
    raw: {
      scannerRaw: result.raw,
      aiVerdictFallback: {
        verdict,
        validationIssues: issues.map((issue) => ({ path: issue.path, message: issue.message })).slice(0, 12)
      }
    }
  };
}

type DirectFullParse = ReturnType<typeof parseDirectFullFinding>;

async function requestVerdictWithRecovery(
  provider: AiProvider,
  systemPrompt: string,
  userPrompt: string,
  jobRecorder: AiJobRecorder | undefined,
  jobId: string | undefined,
  repairProvider: AiProvider
): Promise<{ output: AiCompletionOutput; verdict: AiTriageVerdict | null; directFull: DirectFullParse }> {
  let lastOutput: AiCompletionOutput = { text: "", raw: {} };
  let lastIssues: ValidationIssue[] = [{ path: [], message: "No verdict response was received" }];
  for (let attempt = 1; attempt <= AI_JSON_RETRY_ATTEMPTS; attempt++) {
    const prompt = attempt === 1 ? userPrompt : buildVerdictRetryPrompt(userPrompt, lastOutput.text, lastIssues);
    const output = await withTimeout(provider.complete({
      system: systemPrompt,
      messages: [{ role: "user", content: prompt }],
      jsonSchema: aiVerdictJsonSchema,
      temperature: 0,
      maxTokens: 900
    }), 120_000, "AI triage verdict request timed out after 120s");
    jobRecorder?.trace(jobId, { label: attempt === 1 ? "verdict" : `verdict-retry-${attempt}`, prompt: `${systemPrompt}\n\n${prompt}`, response: output.text });
    const parsed = parseVerdictOrDirectFull(output.text);
    if (parsed.verdict || parsed.directFull.success) return { output, verdict: parsed.verdict, directFull: parsed.directFull };
    lastOutput = output;
    lastIssues = parsed.issues;
  }

  if (lastOutput.text.trim()) {
    const repairSystem = "Repair invalid verdict JSON to match the strict schema exactly. Output raw JSON only. No prose, markdown, comments, code fences, or extra keys.";
    const repairPrompt = buildVerdictRepairPrompt(lastOutput.text, lastIssues);
    const repair = await withTimeout(repairProvider.complete({
      system: repairSystem,
      messages: [{ role: "user", content: repairPrompt }],
      jsonSchema: aiVerdictJsonSchema,
      temperature: 0,
      maxTokens: 900
    }), 120_000, "AI triage verdict repair request timed out after 120s");
    jobRecorder?.trace(jobId, { label: "verdict-repair", prompt: `${repairSystem}\n\n${repairPrompt}`, response: repair.text });
    const repaired = parseVerdictOrDirectFull(repair.text);
    if (repaired.verdict || repaired.directFull.success) return { output: repair, verdict: repaired.verdict, directFull: repaired.directFull };
    lastOutput = repair;
  }

  return { output: lastOutput, verdict: null, directFull: parseDirectFullFinding(lastOutput.text) };
}

function parseVerdictOrDirectFull(text: string): { verdict: AiTriageVerdict | null; directFull: DirectFullParse; issues: ValidationIssue[] } {
  const parsed = safeJsonParse(text);
  const verdictChecked = aiVerdictSchema.safeParse(normalizeAiVerdictJson(parsed));
  const directFull = aiFindingSchema.safeParse(normalizeAiFindingJson(parsed));
  return {
    verdict: verdictChecked.success ? verdictChecked.data : null,
    directFull,
    issues: verdictChecked.success ? [] : toValidationIssues(verdictChecked.error.issues)
  };
}

function parseDirectFullFinding(text: string) {
  return aiFindingSchema.safeParse(normalizeAiFindingJson(safeJsonParse(text)));
}

function buildVerdictRetryPrompt(originalPrompt: string, invalidJson: string, issues: ValidationIssue[]): string {
  return [
    "Previous verdict response was invalid. Retry the same first-pass triage and return complete verdict JSON.",
    "Validation errors:",
    ...formatValidationIssues(issues),
    "",
    "Previous response:",
    truncateForPrompt(invalidJson || "<empty>", 2_000),
    "",
    "Return raw JSON only: {verdict, confidence, reason, requestedFiles, requestedSymbols}.",
    "",
    originalPrompt
  ].join("\n");
}

function buildVerdictRepairPrompt(invalidJson: string, issues: ValidationIssue[]): string {
  return [
    "Validation errors:",
    ...formatValidationIssues(issues),
    "",
    "Invalid verdict JSON to repair:",
    truncateForPrompt(invalidJson, 4_000),
    "",
    "Return the corrected raw JSON object only with keys: verdict, confidence, reason, requestedFiles, requestedSymbols."
  ].join("\n");
}

function formatValidationIssues(issues: readonly ValidationIssue[]): string[] {
  return issues.slice(0, 20).map((issue) => `- ${issue.path.join(".") || "<root>"}: ${issue.message}`);
}

function toValidationIssues(issues: readonly z.ZodIssue[]): ValidationIssue[] {
  return issues.map((issue) => ({ path: [...issue.path], message: issue.message }));
}

function truncateForPrompt(value: string, maxChars: number): string {
  if (value.length <= maxChars) return value;
  return `${value.slice(0, maxChars)}\n...[truncated]`;
}

function falsePositiveFromVerdict(result: ScannerResult, verdict: AiTriageVerdict): Finding {
  const base = deterministicFinding(result);
  return {
    ...base,
    status: "false_positive",
    confidence: "low",
    reasoning: `AI verdict marked this scanner result false_positive: ${verdict.reason || "No reason supplied."}`,
    remediation: "No code change needed unless scanner evidence changes.",
    raw: { aiVerdict: verdict, scannerResult: result }
  };
}

function buildFullFindingRetryPrompt(originalPrompt: string, invalidJson: string, issues: z.ZodIssue[]): string {
  return [
    "Previous full finding response was invalid. Retry from the original scanner context and return a complete JSON object.",
    "Validation errors:",
    ...issues.slice(0, 20).map((issue) => `- ${issue.path.join(".") || "<root>"}: ${issue.message}`),
    "",
    "Previous response:",
    truncateForPrompt(invalidJson || "<empty>", 4_000),
    "",
    "Requirements:",
    "- Return raw JSON only.",
    "- Include every required field from the schema.",
    "- Enum fields must be single strings, never arrays.",
    "- If this is not a real finding, return isFinding=false with the same required fields populated.",
    "",
    originalPrompt
  ].join("\n");
}

function buildJsonRepairPrompt(invalidJson: string, issues: z.ZodIssue[]): string {
  return [
    "Validation errors:",
    ...issues.slice(0, 20).map((issue) => `- ${issue.path.join(".") || "<root>"}: ${issue.message}`),
    "",
    "Invalid JSON to repair:",
    invalidJson,
    "",
    "Return the corrected raw JSON object only. Do not explain the changes."
  ].join("\n");
}

async function applyCritic(provider: AiProvider, pack: ContextPack, data: z.infer<typeof aiFindingSchema>, log: (message: string) => void, label: string, jobRecorder?: AiJobRecorder): Promise<z.infer<typeof aiFindingSchema>> {
  log(`ai: critic ${label} start`);
  const jobId = jobRecorder?.start("critic", label, { provider: provider.name });
  try {
    const systemPrompt = buildSecurityCriticSystemPrompt();
    const userPrompt = buildSecurityCriticUserPrompt(pack, data);
    const output = await withTimeout(provider.complete({
      system: systemPrompt,
      messages: [{ role: "user", content: userPrompt }],
      jsonSchema: criticJsonSchema,
      temperature: 0,
      maxTokens: 1200
    }), 120_000, "AI critic request timed out after 120s");
    jobRecorder?.trace(jobId, { label: "critic", prompt: `${systemPrompt}\n\n${userPrompt}`, response: output.text });
    const checked = criticSchema.safeParse(normalizeAiFindingJson(safeJsonParse(output.text)));
    if (!checked.success) {
      log(`ai: critic ${label} invalid response, keeping finding`);
      jobRecorder?.succeed(jobId, { valid: false, verdict: "keep" });
      return data;
    }
    log(`ai: critic ${label} verdict=${checked.data.verdict}`);
    if (checked.data.verdict === "reject") {
      jobRecorder?.succeed(jobId, { valid: true, verdict: checked.data.verdict });
      return { ...data, isFinding: false, status: "false_positive", confidence: "low", falsePositiveConsiderations: checked.data.reasons.length ? checked.data.reasons : ["Critic rejected exploitability based on supplied context."] };
    }
    if (checked.data.verdict === "downgrade") {
      jobRecorder?.succeed(jobId, { valid: true, verdict: checked.data.verdict });
      return { ...data, status: checked.data.revisedStatus, confidence: checked.data.revisedConfidence, falsePositiveConsiderations: [...data.falsePositiveConsiderations, ...checked.data.reasons] };
    }
    jobRecorder?.succeed(jobId, { valid: true, verdict: checked.data.verdict });
    return data;
  } catch (error) {
    jobRecorder?.fail(jobId, error);
    throw error;
  }
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
