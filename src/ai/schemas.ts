export const severityValues = ["critical", "high", "medium", "low", "info"] as const;
export const confidenceValues = ["confirmed", "high", "medium", "low"] as const;
export const statusValues = ["confirmed", "confirmed_true_positive", "likely_true_positive", "security_hotspot", "needs_context", "suspected", "needs_dynamic_test", "false_positive"] as const;
export const categoryValues = [
  "security",
  "secrets",
  "sql-injection",
  "xss",
  "dependency",
  "weak-crypto",
  "transport-security",
  "auth",
  "authorization",
  "tenant-isolation",
  "session",
  "ssrf",
  "command-injection",
  "path-traversal",
  "open-redirect",
  "file-upload",
  "deserialization",
  "template-injection",
  "prototype-pollution",
  "rce",
  "code-injection",
  "injection",
  "misconfiguration",
  "compliance",
  "csrf",
  "cors",
  "logging",
  "maintainability"
] as const;

export interface AiJsonSchema {
  name: string;
  description: string;
  schema: Record<string, unknown>;
}

const stringArray = { type: "array", items: { type: "string" } };
const lineNumber = { type: "integer", minimum: 1 };
const nullableLineNumber = { anyOf: [lineNumber, { type: "null" }] };

const evidenceItem = {
  type: "object",
  additionalProperties: false,
  required: ["path", "line", "note"],
  properties: {
    path: { type: "string" },
    line: lineNumber,
    note: { type: "string" }
  }
};

const dataFlowItem = {
  type: "object",
  additionalProperties: false,
  required: ["path", "line", "step"],
  properties: {
    path: { type: "string" },
    line: lineNumber,
    step: { type: "string" }
  }
};

const dynamicTestItem = {
  type: "object",
  additionalProperties: false,
  required: ["name", "risk", "requiresApproval", "description", "curlCommand", "pocScript"],
  properties: {
    name: { type: "string" },
    risk: { type: "string", enum: ["safe", "medium", "high"] },
    requiresApproval: { type: "boolean" },
    description: { type: "string" },
    curlCommand: { anyOf: [{ type: "string" }, { type: "null" }] },
    pocScript: { anyOf: [{ type: "string" }, { type: "null" }] }
  }
};

export const aiFindingJsonSchema: AiJsonSchema = {
  name: "security_triage_finding",
  description: "Strict security triage decision. Raw JSON only; no prose.",
  schema: {
    type: "object",
    additionalProperties: false,
    required: [
      "isFinding",
      "title",
      "category",
      "severity",
      "confidence",
      "status",
      "affectedLocations",
      "source",
      "sourceLine",
      "sink",
      "sinkLine",
      "dataFlow",
      "missingControl",
      "exploitPreconditions",
      "safeRepro",
      "exploitabilityRubric",
      "attackScenario",
      "evidence",
      "falsePositiveConsiderations",
      "recommendedDynamicTests",
      "requestedFiles",
      "requestedSymbols",
      "remediation",
      "secureCodeExample"
    ],
    properties: {
      isFinding: { type: "boolean" },
      title: { type: "string" },
      category: { type: "string", enum: categoryValues },
      severity: { type: "string", enum: severityValues },
      confidence: { type: "string", enum: confidenceValues },
      status: { type: "string", enum: statusValues },
      affectedLocations: {
        type: "array",
        items: {
          type: "object",
          additionalProperties: false,
          required: ["path", "startLine", "endLine"],
          properties: { path: { type: "string" }, startLine: lineNumber, endLine: lineNumber }
        }
      },
      source: { type: "string" },
      sourceLine: nullableLineNumber,
      sink: { type: "string" },
      sinkLine: nullableLineNumber,
      dataFlow: { type: "array", items: dataFlowItem },
      missingControl: { type: "string" },
      exploitPreconditions: stringArray,
      safeRepro: stringArray,
      exploitabilityRubric: {
        type: "object",
        additionalProperties: false,
        required: ["userControl", "reachability", "authRequired", "sanitizerPresent", "sinkDanger", "prodExposure", "score"],
        properties: {
          userControl: { type: "number", minimum: 0, maximum: 20 },
          reachability: { type: "number", minimum: 0, maximum: 20 },
          authRequired: { type: "number", minimum: 0, maximum: 10 },
          sanitizerPresent: { type: "number", minimum: 0, maximum: 20 },
          sinkDanger: { type: "number", minimum: 0, maximum: 20 },
          prodExposure: { type: "number", minimum: 0, maximum: 10 },
          score: { type: "number", minimum: 0, maximum: 100 }
        }
      },
      attackScenario: { type: "string" },
      evidence: { type: "array", items: evidenceItem },
      falsePositiveConsiderations: stringArray,
      recommendedDynamicTests: { type: "array", items: dynamicTestItem },
      requestedFiles: stringArray,
      requestedSymbols: stringArray,
      remediation: { type: "string" },
      secureCodeExample: { anyOf: [{ type: "string" }, { type: "null" }] }
    }
  }
};

export const criticJsonSchema: AiJsonSchema = {
  name: "security_critic_verdict",
  description: "Strict critic verdict. Raw JSON only; no prose.",
  schema: {
    type: "object",
    additionalProperties: false,
    required: ["verdict", "confidence", "reasons", "revisedStatus", "revisedConfidence"],
    properties: {
      verdict: { type: "string", enum: ["keep", "downgrade", "reject"] },
      confidence: { type: "string", enum: ["high", "medium", "low"] },
      reasons: stringArray,
      revisedStatus: { type: "string", enum: statusValues },
      revisedConfidence: { type: "string", enum: confidenceValues }
    }
  }
};

export const auditResponseJsonSchema: AiJsonSchema = {
  name: "exploratory_audit_response",
  description: "Strict exploratory audit response. Raw JSON only; no prose.",
  schema: {
    type: "object",
    additionalProperties: false,
    required: ["summary", "requestedFiles", "toolCalls", "complete", "findings"],
    properties: {
      summary: { type: "string" },
      requestedFiles: stringArray,
      toolCalls: {
        type: "array",
        items: {
          type: "object",
          additionalProperties: false,
          required: ["type", "path", "query", "symbol", "category", "reason"],
          properties: {
            type: { type: "string", enum: ["read_file", "search_text", "search_symbol", "find_category"] },
            path: { type: "string" },
            query: { type: "string" },
            symbol: { type: "string" },
            category: { type: "string", enum: [...categoryValues, ""] },
            reason: { type: "string" }
          }
        }
      },
      complete: { type: "boolean" },
      findings: {
        type: "array",
        items: {
          type: "object",
          additionalProperties: false,
          required: ["title", "category", "severity", "confidence", "status", "path", "startLine", "endLine", "source", "sourceLine", "sink", "sinkLine", "dataFlow", "missingControl", "exploitPreconditions", "safeRepro", "evidence", "reasoning", "remediation"],
          properties: {
            title: { type: "string" },
            category: { type: "string", enum: categoryValues },
            severity: { type: "string", enum: severityValues },
            confidence: { type: "string", enum: confidenceValues },
            status: { type: "string", enum: statusValues },
            path: { type: "string" },
            startLine: lineNumber,
            endLine: lineNumber,
            source: { type: "string" },
            sourceLine: nullableLineNumber,
            sink: { type: "string" },
            sinkLine: nullableLineNumber,
            dataFlow: { type: "array", items: dataFlowItem },
            missingControl: { type: "string" },
            exploitPreconditions: stringArray,
            safeRepro: stringArray,
            evidence: { type: "array", items: evidenceItem },
            reasoning: { type: "string" },
            remediation: { type: "string" }
          }
        }
      }
    }
  }
};
