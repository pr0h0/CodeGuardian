import type { Finding } from "../scanners/types.js";

export interface StaticProofPack {
  id: string;
  title: string;
  category: string;
  severity: string;
  confidence: string;
  status: string;
  location: string;
  source: string;
  sink: string;
  evidence: string[];
  missingControl: string;
  exploitPreconditions: string[];
  safeRegressionGuidance: string[];
  confidenceBlockers: string[];
  runtimeValidated: false;
}

export function buildStaticProofPacks(findings: Finding[], options: { limit?: number } = {}): StaticProofPack[] {
  const limit = options.limit ?? 50;
  return findings
    .filter((finding) => finding.status !== "false_positive" && finding.category !== "dependency")
    .sort((a, b) => severityWeight(b.severity) - severityWeight(a.severity) || confidenceWeight(b.confidence) - confidenceWeight(a.confidence))
    .slice(0, limit)
    .map((finding, index) => buildStaticProofPack(finding, index + 1));
}

function buildStaticProofPack(finding: Finding, index: number): StaticProofPack {
  return {
    id: finding.fingerprint?.slice(0, 12) || `proof-${index}`,
    title: finding.title,
    category: finding.category,
    severity: finding.severity,
    confidence: finding.confidence,
    status: finding.status,
    location: formatLocation(finding),
    source: finding.source || "source not isolated in static evidence",
    sink: finding.sink || "sink/control point not isolated in static evidence",
    evidence: summarizeEvidence(finding.evidence),
    missingControl: extractMissingControl(finding.reasoning),
    exploitPreconditions: extractPreconditions(finding),
    safeRegressionGuidance: regressionGuidance(finding),
    confidenceBlockers: confidenceBlockers(finding),
    runtimeValidated: false
  };
}

function formatLocation(finding: Finding): string {
  if (!finding.path) return "repository-level finding";
  const line = finding.startLine ? `:${finding.startLine}` : "";
  return `${finding.path}${line}`;
}

function summarizeEvidence(evidence: unknown[]): string[] {
  const lines = evidence.flatMap((item) => {
    if (typeof item === "string") return [item];
    if (item && typeof item === "object") return [JSON.stringify(item)];
    if (item === null || item === undefined) return [];
    return [String(item)];
  }).map((item) => item.replace(/\s+/g, " ").trim()).filter(Boolean);
  return (lines.length ? lines : ["No structured evidence was attached; inspect the cited source location and scanner context."]).slice(0, 6);
}

function extractMissingControl(reasoning: string): string {
  const match = reasoning.match(/Missing control:\s*([\s\S]*?)(?:\s+Preconditions:|$)/i);
  if (match?.[1]) return match[1].trim();
  return firstSentence(reasoning) || "Missing or insufficient security control must be verified in the cited code path.";
}

function extractPreconditions(finding: Finding): string[] {
  const fromRaw = rawArray(finding.raw, "exploitPreconditions");
  if (fromRaw.length) return fromRaw;
  const match = finding.reasoning.match(/Preconditions:\s*([^\n]+)/i);
  if (match?.[1]) return match[1].split(/;|,/).map((item) => item.trim()).filter(Boolean).slice(0, 6);
  if (finding.source && finding.sink) return [`Untrusted data can reach ${finding.sink} from ${finding.source}.`];
  if (finding.path) return [`The vulnerable code path at ${finding.path}${finding.startLine ? `:${finding.startLine}` : ""} is reachable in production code.`];
  return ["Static reachability and production exposure must be confirmed before remediation is prioritized as exploitable."];
}

function regressionGuidance(finding: Finding): string[] {
  const text = `${finding.category} ${finding.title}`.toLowerCase();
  if (/(authz|authorization|idor|tenant|ownership|business-logic)/.test(text)) {
    return [
      "Add a source-level test where an authenticated principal references another principal's object identifier.",
      "Assert the handler returns a denial path before any read/write side effect."
    ];
  }
  if (/(ssrf|server-side request)/.test(text)) {
    return [
      "Add unit coverage for URL parsing and destination allowlisting.",
      "Assert localhost, link-local metadata, private-network, and non-HTTP schemes are rejected."
    ];
  }
  if (/(xss|cross-site|html|template)/.test(text)) {
    return [
      "Add rendering tests for encoded HTML, attribute, URL, and script contexts.",
      "Assert attacker-controlled markup is displayed as text or rejected before rendering."
    ];
  }
  if (/(command|sql|injection|deserialization|template-injection)/.test(text)) {
    return [
      "Add a unit test with metacharacters or structured payloads at the cited source.",
      "Assert the sink receives parameterized, escaped, allowlisted, or rejected data."
    ];
  }
  if (/(secret|credential|token|key)/.test(text)) {
    return [
      "Add a repository secret-scanning fixture that rejects committed live credential formats.",
      "Assert runtime configuration reads secrets from an approved secret source, not source files."
    ];
  }
  return [
    "Add a regression test around the cited source path and missing control.",
    "Assert unsafe input is rejected, normalized, or authorized before the sensitive operation."
  ];
}

function confidenceBlockers(finding: Finding): string[] {
  const blockers: string[] = [];
  if (finding.confidence === "medium" || finding.confidence === "low") blockers.push("Static evidence is not high confidence.");
  if (finding.status === "security_hotspot" || finding.status === "needs_context") blockers.push("Finding needs more source context before it should be treated as confirmed.");
  if (!finding.source) blockers.push("Source expression was not isolated.");
  if (!finding.sink) blockers.push("Sink or guard location was not isolated.");
  return blockers.length ? blockers : ["No major static blockers recorded; still not runtime-validated."];
}

function rawArray(raw: unknown, key: string): string[] {
  if (!raw || typeof raw !== "object") return [];
  const value = (raw as Record<string, unknown>)[key];
  return Array.isArray(value) ? value.map(String).filter(Boolean).slice(0, 6) : [];
}

function firstSentence(value: string): string {
  return value.replace(/\s+/g, " ").split(/(?<=[.!?])\s+/)[0]?.slice(0, 400) ?? "";
}

function severityWeight(severity: string): number {
  return { critical: 5, high: 4, medium: 3, low: 2, info: 1 }[severity] ?? 0;
}

function confidenceWeight(confidence: string): number {
  return { confirmed: 4, high: 3, medium: 2, low: 1 }[confidence] ?? 0;
}
