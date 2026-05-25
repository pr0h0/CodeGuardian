import { categoryValues, confidenceValues, severityValues, statusValues } from "./schemas.js";

const findingEnumFields = {
  category: categoryValues,
  severity: severityValues,
  confidence: confidenceValues,
  status: statusValues
} as const;

export function normalizeAiFindingJson(parsed: unknown): unknown {
  const unwrapped = unwrapFinding(parsed);
  return normalizeFinding(unwrapped);
}

export function normalizeAuditResponseJson(parsed: unknown): unknown {
  const unwrapped = unwrapAudit(parsed);
  if (!isRecord(unwrapped)) return unwrapped;
  return {
    ...unwrapped,
    toolCalls: Array.isArray(unwrapped.toolCalls)
      ? unwrapped.toolCalls.map((call) => isRecord(call) ? { ...call, category: enumScalar(call.category, [...categoryValues, ""]) } : call)
      : unwrapped.toolCalls,
    findings: Array.isArray(unwrapped.findings)
      ? unwrapped.findings.map(normalizeFinding)
      : unwrapped.findings
  };
}

function normalizeFinding(value: unknown): unknown {
  if (!isRecord(value)) return value;
  const next: Record<string, unknown> = { ...value };
  for (const [field, allowed] of Object.entries(findingEnumFields)) {
    next[field] = enumScalar(next[field], allowed);
  }
  next.sourceLine = nullablePositiveLine(next.sourceLine);
  next.sinkLine = nullablePositiveLine(next.sinkLine);
  next.recommendedDynamicTests = Array.isArray(next.recommendedDynamicTests)
    ? next.recommendedDynamicTests.map((item) => isRecord(item) ? { ...item, risk: enumScalar(item.risk, ["safe", "medium", "high"]) } : item)
    : next.recommendedDynamicTests;
  return next;
}

function enumScalar(value: unknown, allowed: readonly string[]): unknown {
  if (!Array.isArray(value)) return value;
  const valid = value.find((item): item is string => typeof item === "string" && allowed.includes(item));
  if (valid !== undefined) return valid;
  const firstString = value.find((item): item is string => typeof item === "string");
  return firstString ?? value;
}

function nullablePositiveLine(value: unknown): unknown {
  if (typeof value === "number" && value <= 0) return null;
  return value;
}

function unwrapFinding(parsed: unknown): unknown {
  if (isRecord(parsed)) {
    if (isRecord(parsed.finding)) return parsed.finding;
    if (isRecord(parsed.result)) return parsed.result;
    if (Array.isArray(parsed.findings) && parsed.findings[0]) return parsed.findings[0];
  }
  return parsed;
}

function unwrapAudit(parsed: unknown): unknown {
  if (isRecord(parsed)) {
    if (isRecord(parsed.audit)) return parsed.audit;
    if (isRecord(parsed.result)) return parsed.result;
  }
  return parsed;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}
