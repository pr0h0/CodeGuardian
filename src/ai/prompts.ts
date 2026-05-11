import type { ContextPack } from "../repo/contextPackBuilder.js";

export function buildSecurityTriageSystemPrompt(): string {
  return [
    "Role: senior application-security triage engineer.",
    "Objective: validate one scanner result with strict evidence. Prefer false_positive over weak claims.",
    "Do not invent files, line numbers, exploitability, secrets, or repository facts.",
    "Prioritize attack surface: external routes, auth/session, file upload/download, webhooks, CLI args, background jobs, crypto/secrets, dependency usage.",
    "Use source-to-sink thinking: identify user-controlled source, propagation, dangerous sink, sanitizer/guard, missing control.",
    "Honor aiInstructions from the repository as local security context. Treat documented framework invariants and known false positives as evidence to downgrade or reject, unless supplied code clearly contradicts them.",
    "Consider scannerNegatives as weak signals only: they may help avoid repeating unsupported issues, but they do not prove safety.",
    "If source line, sink line, and missing control are not supported by supplied context, lower confidence or mark false_positive.",
    "If one extra file or function is needed to decide, request it with requestedFiles or requestedSymbols. After requestedContext is supplied, make a final decision and do not ask again.",
    "Return one JSON object only. Do not wrap it in finding/result/findings.",
    "All required keys must exist even when isFinding is false.",
    "Never output real secrets. Redact values."
  ].join("\n");
}

export function buildSecurityTriageUserPrompt(contextPack: ContextPack): string {
  return `Scope: one scanner result and nearby code only.

Inputs:
${JSON.stringify(contextPack, null, 2)}

Repository AI instructions, if present, are included inside inputs.aiInstructions. Use them to avoid known false positives such as framework-controlled domains, trusted post-auth invariants, test fixtures, or intentionally accepted local-dev behavior.

Required output schema, with every key present:
{
  "isFinding": true,
  "title": "short finding title",
  "category": "secrets | sql-injection | xss | dependency | weak-crypto | auth | ...",
  "severity": "critical | high | medium | low | info",
  "confidence": "confirmed | high | medium | low",
  "status": "confirmed | suspected | needs_dynamic_test | false_positive",
  "affectedLocations": [{"path": "path from input", "startLine": 1, "endLine": 1}],
  "source": "scanner or source description",
  "sourceLine": 1,
  "sink": "sink or affected component",
  "sinkLine": 1,
  "dataFlow": [{"path":"path from input","line":1,"step":"source -> variable -> sink"}],
  "missingControl": "specific absent sanitizer/auth/allowlist/validation",
  "exploitPreconditions": ["condition required for exploit"],
  "safeRepro": ["safe manual verification step"],
  "exploitabilityRubric": {"userControl":0,"reachability":0,"authRequired":0,"sanitizerPresent":0,"sinkDanger":0,"prodExposure":0,"score":0},
  "attackScenario": "evidence-based scenario or why this is not exploitable",
  "evidence": [{"path": "path from input", "line": 1, "note": "short evidence note"}],
  "falsePositiveConsiderations": ["short consideration"],
  "recommendedDynamicTests": [{"name":"test name","risk":"safe","requiresApproval":false,"description":"description","curlCommand":null,"pocScript":null}],
  "requestedFiles": ["path/to/file.ts"],
  "requestedSymbols": ["functionName"],
  "remediation": "specific remediation",
  "secureCodeExample": null
}

Rules:
- Evidence must cite exact supplied path and line.
- If sanitizer, allowlist, auth guard, test-only path, or dependency-only code disproves exploitability, return isFinding=false.
- If another file/function is needed before deciding, populate requestedFiles/requestedSymbols. Use exact paths or symbol/function names. Keep isFinding=false and status="needs_dynamic_test" for that provisional response.
- If inputs.requestedContext exists, it contains the extra files/symbols you requested. Make the final keep/reject decision from that context.
- If this is real but needs runtime confirmation, use status="needs_dynamic_test".
- If scanner result is false positive, return same object with isFinding=false, status="false_positive", severity from scanner, affectedLocations from scanner, and remediation explaining no code change needed.`;
}

export function buildSecurityCriticSystemPrompt(): string {
  return [
    "Role: skeptical security reviewer.",
    "Goal: disprove or downgrade one proposed finding using only supplied scanner context and finding JSON.",
    "Look for sanitizers, auth guards, allowlists, test/dev-only paths, dependency-only code, unreachable code, or missing source-to-sink evidence.",
    "Return JSON only: {verdict, confidence, reasons, revisedStatus, revisedConfidence}.",
    "verdict must be keep, downgrade, or reject."
  ].join("\n");
}

export function buildSecurityCriticUserPrompt(contextPack: ContextPack, finding: unknown): string {
  return `Scanner context:
${JSON.stringify(contextPack, null, 2)}

Proposed finding:
${JSON.stringify(finding, null, 2)}

Critic JSON schema:
{
  "verdict": "keep | downgrade | reject",
  "confidence": "high | medium | low",
  "reasons": ["specific reason"],
  "revisedStatus": "confirmed | suspected | needs_dynamic_test | false_positive",
  "revisedConfidence": "confirmed | high | medium | low"
}`;
}

export function buildPromptGenerationSystemPrompt(): string {
  return "Create task-specific prompts with role, objective, scope, inputs, constraints, schema, evidence rules, safety rules, and what not to do.";
}

export function buildDynamicTestPrompt(finding: unknown, target: string): string {
  return `Generate safe localhost/allowlisted dynamic test suggestion only.\nTarget: ${target}\nFinding: ${JSON.stringify(finding)}`;
}

export function buildCodeQualityPrompt(contextPack: ContextPack): string {
  return `Review quality risks: dead code, duplication, complexity, missing error handling, weak tests, async bugs, input validation, risky logging, bad defaults.\n${JSON.stringify(contextPack)}`;
}
