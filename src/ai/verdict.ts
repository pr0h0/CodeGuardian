import { z } from "zod";
import { safeJsonParse } from "../utils/safeJson.js";

export const aiVerdictSchema = z.object({
  verdict: z.enum(["true_positive", "false_positive", "needs_context", "parse_failed"]),
  confidence: z.enum(["high", "medium", "low"]).default("low"),
  reason: z.string().default(""),
  requestedFiles: z.array(z.string()).default([]),
  requestedSymbols: z.array(z.string()).default([])
});

export type AiTriageVerdict = z.infer<typeof aiVerdictSchema>;

export function parseAiVerdict(text: string): AiTriageVerdict | null {
  const parsed = normalizeAiVerdictJson(safeJsonParse(text));
  const checked = aiVerdictSchema.safeParse(parsed);
  return checked.success ? checked.data : null;
}

export function normalizeAiVerdictJson(parsed: unknown): unknown {
  if (parsed && typeof parsed === "object") {
    const object = parsed as Record<string, unknown>;
    if (object.verdict && typeof object.verdict === "object") return object.verdict;
    if (object.result && typeof object.result === "object") return object.result;
  }
  return parsed;
}

export function shouldRequestFullFinding(verdict: AiTriageVerdict): boolean {
  return verdict.verdict === "true_positive" || verdict.verdict === "needs_context";
}
