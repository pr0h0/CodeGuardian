import type { z } from "zod";
import type { ContextPack } from "../repo/contextPackBuilder.js";
import type { aiFindingSchema } from "./types.js";

export interface AiFindingValidationResult {
  valid: boolean;
  reasons: string[];
}

type AiFindingData = z.infer<typeof aiFindingSchema>;

export function validateAiFindingCandidate(data: AiFindingData, pack: ContextPack): AiFindingValidationResult {
  const reasons: string[] = [];
  if (!data.isFinding) return { valid: true, reasons };

  if (/\b(schema gaps?|partial json|invalid json|parse failed|repair failed)\b/i.test(`${data.attackScenario} ${data.missingControl} ${data.remediation}`)) {
    reasons.push("finding contains parser/schema fallback language");
  }
  if (!data.affectedLocations.length) reasons.push("finding has no affected locations");
  if (!data.evidence.length) reasons.push("finding has no evidence");
  if (!data.source.trim()) reasons.push("finding source is empty");
  if (!data.sink.trim()) reasons.push("finding sink is empty");
  if (!data.missingControl.trim()) reasons.push("finding missingControl is empty");

  const ranges = contextRanges(pack);
  for (const location of data.affectedLocations) {
    if (!lineInRanges(location.path, location.startLine, ranges) || !lineInRanges(location.path, location.endLine, ranges)) {
      reasons.push(`affected location not present in supplied context: ${location.path}:${location.startLine}-${location.endLine}`);
      break;
    }
  }

  const evidenceInsideContext = data.evidence.some((item) => lineInRanges(item.path, item.line, ranges));
  if (!evidenceInsideContext) reasons.push("evidence does not cite supplied context");

  return { valid: reasons.length === 0, reasons };
}

function contextRanges(pack: ContextPack): Map<string, Array<{ startLine: number; endLine: number }>> {
  const ranges = new Map<string, Array<{ startLine: number; endLine: number }>>();
  const add = (path: string, startLine: number, endLine: number) => {
    const normalized = normalizePath(path);
    ranges.set(normalized, [...(ranges.get(normalized) ?? []), { startLine, endLine }]);
  };
  for (const snippet of pack.snippets) add(snippet.path, snippet.startLine, snippet.endLine);
  const requested = pack.requestedContext && typeof pack.requestedContext === "object" ? pack.requestedContext as Record<string, unknown> : {};
  for (const item of requestedItems(requested.files)) add(item.path, item.startLine, item.endLine);
  for (const item of requestedItems(requested.symbols)) add(item.path, item.startLine, item.endLine);
  return ranges;
}

function requestedItems(value: unknown): Array<{ path: string; startLine: number; endLine: number }> {
  if (!Array.isArray(value)) return [];
  return value.flatMap((item) => {
    if (!item || typeof item !== "object") return [];
    const object = item as Record<string, unknown>;
    const path = typeof object.path === "string" ? object.path : "";
    const startLine = Number(object.startLine);
    const endLine = Number(object.endLine);
    return path && Number.isFinite(startLine) && Number.isFinite(endLine) ? [{ path, startLine, endLine }] : [];
  });
}

function lineInRanges(path: string, line: number | null | undefined, ranges: Map<string, Array<{ startLine: number; endLine: number }>>): boolean {
  if (!line) return false;
  return (ranges.get(normalizePath(path)) ?? []).some((range) => line >= range.startLine && line <= range.endLine);
}

function normalizePath(value: string): string {
  return value.replaceAll("\\", "/").replace(/^\/+/, "").replace(/^\.\//, "");
}
