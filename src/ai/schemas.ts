import type { VulnerabilityClass } from "../config/projectConfig.js";

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
  "xxe",
  "code-injection",
  "injection",
  "misconfiguration",
  "business-logic",
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

type FindingCategory = (typeof categoryValues)[number];

const auditClassCategories: Record<VulnerabilityClass, FindingCategory[]> = {
  injection: ["sql-injection", "command-injection", "code-injection", "injection", "template-injection", "deserialization", "prototype-pollution", "rce"],
  xss: ["xss"],
  auth: ["auth", "session", "csrf"],
  authz: ["authorization", "tenant-isolation"],
  ssrf: ["ssrf"],
  exposure: ["secrets", "logging", "security"],
  validation: ["path-traversal", "open-redirect", "file-upload", "xss", "security"],
  dependency: ["dependency", "deserialization", "prototype-pollution"],
  crypto: ["weak-crypto", "transport-security", "secrets"],
  misconfig: ["misconfiguration", "cors", "session", "security"],
  xxe: ["xxe"],
  "business-logic": ["business-logic", "authorization", "auth", "security"]
};

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

const catalogItem = {
  type: "object",
  additionalProperties: false,
  required: ["name", "path", "line", "category", "evidence"],
  properties: {
    name: { type: "string" },
    path: { type: "string" },
    line: nullableLineNumber,
    category: { type: "string" },
    evidence: { type: "string" }
  }
};

const auditHypothesisItem = {
  type: "object",
  additionalProperties: false,
  required: ["id", "vulnerabilityClass", "title", "path", "source", "sink", "evidence", "status", "reason"],
  properties: {
    id: { type: "string" },
    vulnerabilityClass: { type: "string" },
    title: { type: "string" },
    path: { type: "string" },
    source: { type: "string" },
    sink: { type: "string" },
    evidence: { type: "array", items: evidenceItem },
    status: { type: "string", enum: ["candidate", "validated", "rejected"] },
    reason: { type: "string" }
  }
};

const rejectedHypothesisItem = {
  type: "object",
  additionalProperties: false,
  required: ["id", "title", "path", "reason"],
  properties: {
    id: { type: "string" },
    title: { type: "string" },
    path: { type: "string" },
    reason: { type: "string" }
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

export const aiVerdictJsonSchema: AiJsonSchema = {
  name: "security_triage_verdict",
  description: "Small first-pass triage verdict. Raw JSON only; no prose.",
  schema: {
    type: "object",
    additionalProperties: false,
    required: ["verdict", "confidence", "reason", "requestedFiles", "requestedSymbols"],
    properties: {
      verdict: { type: "string", enum: ["true_positive", "false_positive", "needs_context", "parse_failed"] },
      confidence: { type: "string", enum: ["high", "medium", "low"] },
      reason: { type: "string" },
      requestedFiles: stringArray,
      requestedSymbols: stringArray
    }
  }
};

export const aiPreflightJsonSchema: AiJsonSchema = {
  name: "ai_provider_preflight",
  description: "Tiny readiness check for configured AI provider and model. Raw JSON only; no prose.",
  schema: {
    type: "object",
    additionalProperties: false,
    required: ["ok"],
    properties: {
      ok: { type: "boolean" }
    }
  }
};

export const aiDedupeJsonSchema: AiJsonSchema = {
  name: "security_finding_dedupe",
  description: "Strict grouping of duplicate security findings. Raw JSON only; no prose.",
  schema: {
    type: "object",
    additionalProperties: false,
    required: ["groups"],
    properties: {
      groups: {
        type: "array",
        items: {
          type: "object",
          additionalProperties: false,
          required: ["canonicalId", "duplicateIds", "reason"],
          properties: {
            canonicalId: { type: "string" },
            duplicateIds: { type: "array", items: { type: "string" } },
            reason: { type: "string" }
          }
        }
      }
    }
  }
};

export const auditSourceMapJsonSchema: AiJsonSchema = {
  name: "exploratory_audit_source_map",
  description: "Repository-level security source map for class-specific audit passes. Raw JSON only; no prose.",
  schema: {
    type: "object",
    additionalProperties: false,
    required: ["summary", "globalPriorityFiles", "priorityFilesByClass", "notes"],
    properties: {
      summary: { type: "string" },
      globalPriorityFiles: stringArray,
      priorityFilesByClass: {
        type: "object",
        additionalProperties: { type: "array", items: { type: "string" } }
      },
      notes: stringArray,
      catalog: {
        type: "object",
        additionalProperties: false,
        required: ["sources", "sinks", "sanitizers", "guards"],
        properties: {
          sources: { type: "array", items: catalogItem },
          sinks: { type: "array", items: catalogItem },
          sanitizers: { type: "array", items: catalogItem },
          guards: { type: "array", items: catalogItem }
        }
      }
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
          required: ["type", "path", "query", "symbol", "category", "startLine", "endLine", "reason"],
          properties: {
            type: { type: "string", enum: ["read_file", "search_text", "search_symbol", "find_category"] },
            path: { type: "string" },
            query: { type: "string" },
            symbol: { type: "string" },
            category: { type: "string", enum: [...categoryValues, ""] },
            startLine: nullableLineNumber,
            endLine: nullableLineNumber,
            reason: { type: "string" }
          }
        }
      },
      complete: { type: "boolean" },
      hypotheses: { type: "array", items: auditHypothesisItem },
      rejectedHypotheses: { type: "array", items: rejectedHypothesisItem },
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

export const auditValidationJsonSchema: AiJsonSchema = {
  name: "exploratory_audit_validation",
  description: "Second-pass validation decisions for AI exploratory audit findings. Raw JSON only; no prose.",
  schema: {
    type: "object",
    additionalProperties: false,
    required: ["decisions"],
    properties: {
      decisions: {
        type: "array",
        items: {
          type: "object",
          additionalProperties: false,
          required: ["findingIndex", "verdict", "revisedStatus", "revisedConfidence", "reasons"],
          properties: {
            findingIndex: { type: "integer", minimum: 0 },
            verdict: { type: "string", enum: ["keep", "downgrade", "reject"] },
            revisedStatus: { type: "string", enum: statusValues },
            revisedConfidence: { type: "string", enum: confidenceValues },
            reasons: stringArray
          }
        }
      }
    }
  }
};

export function auditCategoriesForClasses(classes: readonly VulnerabilityClass[] = []): FindingCategory[] {
  const selected = classes.flatMap((item) => auditClassCategories[item] ?? []);
  return selected.length ? [...new Set(selected)] : [...categoryValues];
}

export function auditResponseJsonSchemaForClasses(classes: readonly VulnerabilityClass[] = []): AiJsonSchema {
  const selected = auditCategoriesForClasses(classes);
  if (!classes.length || selected.length === categoryValues.length) return auditResponseJsonSchema;
  const next = cloneJsonSchema(auditResponseJsonSchema);
  next.name = `exploratory_audit_response_${classes.join("_")}`;
  const properties = next.schema.properties as Record<string, any>;
  properties.findings.items.properties.category.enum = selected;
  properties.toolCalls.items.properties.category.enum = [...selected, ""];
  return next;
}

function cloneJsonSchema(schema: AiJsonSchema): AiJsonSchema {
  return JSON.parse(JSON.stringify(schema)) as AiJsonSchema;
}
