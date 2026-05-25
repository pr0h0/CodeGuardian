import { z } from "zod";
import { dedupeFindings, mergeFindingGroup } from "../core/findingDeduper.js";
import { normalizePath, semanticFamily } from "../core/semanticDedupe.js";
import type { Finding } from "../scanners/types.js";
import { safeJsonParse } from "../utils/safeJson.js";
import { AiJobRecorder } from "./jobs.js";
import { aiDedupeJsonSchema } from "./schemas.js";
import type { AiProvider } from "./types.js";

const aiDedupeResponseSchema = z.object({
  groups: z.array(z.object({
    canonicalId: z.string(),
    duplicateIds: z.array(z.string()).default([]),
    reason: z.string().default("")
  })).default([])
});

type ValidationIssue = { path: Array<string | number>; message: string };
type ParseResult<T> = { ok: true; data: T } | { ok: false; issues: ValidationIssue[] };
const AI_DEDUPE_RETRY_ATTEMPTS = 2;

interface Candidate {
  id: string;
  title: string;
  category: string;
  severity: string;
  confidence: string;
  status: string;
  path: string;
  startLine: number | null;
  endLine: number | null;
  source: string;
  sink: string;
  family: string;
}

export async function dedupeFindingsWithAi(
  provider: AiProvider,
  findings: Finding[],
  jobRecorder?: AiJobRecorder,
  log: (message: string) => void = () => undefined
): Promise<Finding[]> {
  const deterministic = dedupeFindings(findings);
  const candidates = candidateFindings(deterministic);
  if (candidates.length < 2) return deterministic;

  const systemPrompt = [
    "Role: security finding deduplication reviewer.",
    "Group only duplicate reports for the same vulnerability instance.",
    "A valid duplicate group must refer to the same file and same or nearby line, and the same sink or same vulnerability family.",
    "Do not group separate controls on the same line, such as session secret and cookie hardening.",
    "Return raw JSON only."
  ].join("\n");
  const userPrompt = JSON.stringify({
    instructions: [
      "Use canonicalId for the best representative finding.",
      "List duplicateIds that should be merged into that canonical finding.",
      "Leave findings unmentioned when they are distinct or uncertain."
    ],
    findings: candidates
  });
  const jobId = jobRecorder?.start("dedupe", "finding clustering", { provider: provider.name, candidates: candidates.length });

  try {
    log(`ai-dedupe: start candidates=${candidates.length}`);
    let lastOutput = "";
    let lastIssues: ValidationIssue[] = [{ path: [], message: "No dedupe response was received" }];
    for (let attempt = 1; attempt <= AI_DEDUPE_RETRY_ATTEMPTS; attempt++) {
      const prompt = attempt === 1 ? userPrompt : buildDedupeRetryPrompt(userPrompt, lastOutput, lastIssues);
      const output = await provider.complete({
        system: systemPrompt,
        messages: [{ role: "user", content: prompt }],
        jsonSchema: aiDedupeJsonSchema,
        temperature: 0,
        maxTokens: 1600
      });
      jobRecorder?.trace(jobId, { label: attempt === 1 ? "dedupe" : `dedupe-retry-${attempt}`, prompt: `${systemPrompt}\n\n${prompt}`, response: output.text });
      const parsed = parseDedupeResponse(output.text, output.parsedJson);
      if (parsed.ok) {
        const merged = applyAiDedupeGroups(deterministic, parsed.data.groups, log);
        const collapsed = deterministic.length - merged.length;
        log(`ai-dedupe: groups=${parsed.data.groups.length} collapsed=${collapsed}`);
        jobRecorder?.succeed(jobId, { valid: true, groups: parsed.data.groups.length, collapsed });
        return merged;
      }
      lastOutput = output.text;
      lastIssues = parsed.issues;
      if (attempt < AI_DEDUPE_RETRY_ATTEMPTS) log(`ai-dedupe: invalid response, retrying attempt ${attempt + 1}/${AI_DEDUPE_RETRY_ATTEMPTS}`);
    }
    if (lastOutput.trim()) {
      log("ai-dedupe: invalid response, repairing");
      const repairPrompt = buildDedupeRepairPrompt(lastOutput, lastIssues);
      const repair = await provider.complete({
        system: "Repair invalid dedupe JSON to match the strict schema exactly. Output raw JSON only. No prose, markdown, comments, code fences, or extra keys.",
        messages: [{ role: "user", content: repairPrompt }],
        jsonSchema: aiDedupeJsonSchema,
        temperature: 0,
        maxTokens: 1400
      });
      jobRecorder?.trace(jobId, { label: "dedupe-repair", prompt: repairPrompt, response: repair.text });
      const repaired = parseDedupeResponse(repair.text, repair.parsedJson);
      if (repaired.ok) {
        const merged = applyAiDedupeGroups(deterministic, repaired.data.groups, log);
        const collapsed = deterministic.length - merged.length;
        log(`ai-dedupe: groups=${repaired.data.groups.length} collapsed=${collapsed}`);
        jobRecorder?.succeed(jobId, { valid: true, repaired: true, groups: repaired.data.groups.length, collapsed });
        return merged;
      }
    }
    log("ai-dedupe: invalid response, keeping deterministic result");
    jobRecorder?.succeed(jobId, { valid: false, groups: 0, collapsed: 0 });
    return deterministic;
  } catch (error) {
    log(`ai-dedupe: failed: ${error instanceof Error ? error.message : String(error)}`);
    jobRecorder?.fail(jobId, error);
    return deterministic;
  }
}

function parseDedupeResponse(text: string, parsedJson?: unknown): ParseResult<z.infer<typeof aiDedupeResponseSchema>> {
  const raw = parsedJson ?? safeJsonParse(text);
  const checked = aiDedupeResponseSchema.safeParse(raw);
  if (checked.success && isRecord(raw) && Object.prototype.hasOwnProperty.call(raw, "groups")) return { ok: true, data: checked.data };
  return { ok: false, issues: checked.success ? [{ path: [], message: "Response did not include dedupe groups" }] : toValidationIssues(checked.error.issues) };
}

function buildDedupeRetryPrompt(originalPrompt: string, invalidJson: string, issues: ValidationIssue[]): string {
  return [
    "Previous dedupe response was invalid. Retry from the same finding list and return a complete JSON object.",
    "Validation errors:",
    ...formatValidationIssues(issues),
    "",
    "Previous response:",
    truncateForPrompt(invalidJson || "<empty>", 4_000),
    "",
    "Requirements:",
    "- Return raw JSON only: {\"groups\":[{\"canonicalId\":\"f0\",\"duplicateIds\":[\"f1\"],\"reason\":\"same vulnerability instance\"}]}",
    "- Do not include markdown fences, comments, prose, or extra keys.",
    "- Leave groups empty when uncertain.",
    "",
    originalPrompt
  ].join("\n");
}

function buildDedupeRepairPrompt(invalidJson: string, issues: ValidationIssue[]): string {
  return [
    "Validation errors:",
    ...formatValidationIssues(issues),
    "",
    "Invalid dedupe JSON to repair:",
    truncateForPrompt(invalidJson, 8_000),
    "",
    "Return the corrected raw JSON object only with key: groups."
  ].join("\n");
}

function formatValidationIssues(issues: readonly ValidationIssue[]): string[] {
  return issues.slice(0, 20).map((issue) => `- ${issue.path.join(".") || "<root>"}: ${issue.message}`);
}

function toValidationIssues(issues: readonly z.ZodIssue[]): ValidationIssue[] {
  return issues.map((issue) => ({ path: [...issue.path], message: issue.message }));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function truncateForPrompt(value: string, maxChars: number): string {
  if (value.length <= maxChars) return value;
  return `${value.slice(0, maxChars)}\n...[truncated]`;
}

function candidateFindings(findings: Finding[]): Candidate[] {
  const ids = findings.map((finding, index) => ({ id: `f${index}`, finding }));
  const buckets = new Map<string, Array<{ id: string; finding: Finding }>>();
  for (const item of ids) {
    if (!item.finding.path || !item.finding.startLine) continue;
    const key = `${normalizePath(item.finding.path)}:${Math.floor((item.finding.startLine - 1) / 5)}`;
    buckets.set(key, [...(buckets.get(key) ?? []), item]);
  }
  const duplicateProne = [...buckets.values()].filter((bucket) => bucket.length > 1).flat();
  return duplicateProne.slice(0, 120).map(({ id, finding }) => ({
    id,
    title: finding.title,
    category: finding.category,
    severity: finding.severity,
    confidence: finding.confidence,
    status: finding.status,
    path: finding.path ?? "",
    startLine: finding.startLine ?? null,
    endLine: finding.endLine ?? null,
    source: finding.source ?? "",
    sink: finding.sink ?? "",
    family: semanticFamily(finding) ?? ""
  }));
}

function applyAiDedupeGroups(
  findings: Finding[],
  groups: Array<z.infer<typeof aiDedupeResponseSchema>["groups"][number]>,
  log: (message: string) => void
): Finding[] {
  const idToIndex = new Map<string, number>(findings.map((_finding, index) => [`f${index}`, index]));
  const consumed = new Set<number>();
  const mergedByIndex = new Map<number, Finding>();

  for (const group of groups) {
    const canonicalIndex = idToIndex.get(group.canonicalId);
    if (canonicalIndex === undefined || consumed.has(canonicalIndex) || mergedByIndex.has(canonicalIndex)) continue;
    const duplicateIndexes = [...new Set(group.duplicateIds)]
      .map((id) => idToIndex.get(id))
      .filter((index): index is number => index !== undefined && index !== canonicalIndex && !consumed.has(index) && !mergedByIndex.has(index));
    if (!duplicateIndexes.length) continue;

    const canonical = findings[canonicalIndex];
    const compatibleIndexes = duplicateIndexes.filter((index) => findingsCompatible(canonical, findings[index]));
    const skipped = duplicateIndexes.length - compatibleIndexes.length;
    if (skipped) log(`ai-dedupe: skipped ${skipped} unsafe duplicate merge${skipped === 1 ? "" : "s"}`);
    if (!compatibleIndexes.length) continue;

    const members = [canonical, ...compatibleIndexes.map((index) => findings[index])];
    mergedByIndex.set(canonicalIndex, mergeFindingGroup(members));
    for (const index of compatibleIndexes) consumed.add(index);
  }

  return findings.flatMap((finding, index) => {
    const merged = mergedByIndex.get(index);
    if (merged) return [merged];
    if (consumed.has(index)) return [];
    return [finding];
  });
}

function findingsCompatible(a: Finding, b: Finding): boolean {
  if (!a.path || !b.path || normalizePath(a.path) !== normalizePath(b.path)) return false;
  const familyA = semanticFamily(a);
  const familyB = semanticFamily(b);
  if (familyA && familyB && familyA !== familyB) return false;

  const lineA = primaryLine(a);
  const lineB = primaryLine(b);
  const nearby = lineA !== undefined && lineB !== undefined && Math.abs(lineA - lineB) <= 5;
  if (!nearby) return false;

  if (familyA && familyB && familyA === familyB) return true;
  if (sameNormalizedSink(a, b)) return true;
  return titleTokenOverlap(a.title, b.title) >= 0.35;
}

function primaryLine(finding: Finding): number | undefined {
  return finding.startLine ?? finding.endLine;
}

function sameNormalizedSink(a: Finding, b: Finding): boolean {
  const left = normalizeLoose(a.sink);
  const right = normalizeLoose(b.sink);
  return left.length >= 6 && left === right;
}

function titleTokenOverlap(a: string, b: string): number {
  const left = new Set(normalizeLoose(a).split(" ").filter((token) => token.length > 3));
  const right = new Set(normalizeLoose(b).split(" ").filter((token) => token.length > 3));
  if (!left.size || !right.size) return 0;
  const shared = [...left].filter((token) => right.has(token)).length;
  return shared / Math.min(left.size, right.size);
}

function normalizeLoose(value?: string): string {
  return String(value ?? "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}
