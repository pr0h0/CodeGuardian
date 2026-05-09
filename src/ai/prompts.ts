import type { ContextPack } from "../repo/contextPackBuilder.js";

export function buildSecurityTriageSystemPrompt(): string {
  return [
    "Role: senior security triage engineer.",
    "Objective: validate one evidence-based scanner result using only supplied context.",
    "Do not invent files, line numbers, exploitability, secrets, or repository facts.",
    "Prioritize auth/authz, IDOR, injection, XSS, SSRF, path traversal, upload, deserialization, secrets, weak crypto, dependency vulns, tenant isolation, webhooks, CORS, CSRF, sessions.",
    "Return one JSON object only. Do not wrap it in finding/result/findings.",
    "All required keys must exist even when isFinding is false.",
    "Mark uncertainty as suspected or false_positive. Never output real secrets."
  ].join("\n");
}

export function buildSecurityTriageUserPrompt(contextPack: ContextPack): string {
  return `Scope: one scanner result and nearby code only.

Inputs:
${JSON.stringify(contextPack, null, 2)}

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
  "sink": "sink or affected component",
  "attackScenario": "evidence-based scenario or why this is not exploitable",
  "evidence": [{"path": "path from input", "line": 1, "note": "short evidence note"}],
  "falsePositiveConsiderations": ["short consideration"],
  "recommendedDynamicTests": [{"name":"test name","risk":"safe","requiresApproval":false,"description":"description","curlCommand":null,"pocScript":null}],
  "remediation": "specific remediation",
  "secureCodeExample": null
}

If scanner result is false positive, still return this same object with isFinding=false, status="false_positive", severity from scanner, affectedLocations from scanner, and remediation explaining no code change needed.`;
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
