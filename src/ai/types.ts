import { z } from "zod";

export interface AiMessage { role: "user" | "assistant"; content: string }
export interface AiCompletionInput {
  system: string;
  messages: AiMessage[];
  jsonSchema?: unknown;
  temperature?: number;
  maxTokens?: number;
}
export interface AiCompletionOutput { text: string; parsedJson?: unknown; raw: unknown }
export interface AiProvider { name: string; complete(input: AiCompletionInput): Promise<AiCompletionOutput> }

export const aiFindingSchema = z.object({
  isFinding: z.boolean(),
  title: z.string(),
  category: z.string(),
  severity: z.enum(["critical", "high", "medium", "low", "info"]),
  confidence: z.enum(["confirmed", "high", "medium", "low"]),
  status: z.enum(["confirmed", "suspected", "needs_dynamic_test", "false_positive"]),
  affectedLocations: z.array(z.object({ path: z.string(), startLine: z.number(), endLine: z.number() })),
  source: z.string(),
  sourceLine: z.number().int().positive().nullable().default(null),
  sink: z.string(),
  sinkLine: z.number().int().positive().nullable().default(null),
  dataFlow: z.array(z.object({ path: z.string(), line: z.number().int().positive(), step: z.string() })).default([]),
  missingControl: z.string().default(""),
  exploitPreconditions: z.array(z.string()).default([]),
  safeRepro: z.array(z.string()).default([]),
  exploitabilityRubric: z.object({
    userControl: z.number().min(0).max(20),
    reachability: z.number().min(0).max(20),
    authRequired: z.number().min(0).max(10),
    sanitizerPresent: z.number().min(0).max(20),
    sinkDanger: z.number().min(0).max(20),
    prodExposure: z.number().min(0).max(10),
    score: z.number().min(0).max(100)
  }).default({ userControl: 0, reachability: 0, authRequired: 0, sanitizerPresent: 0, sinkDanger: 0, prodExposure: 0, score: 0 }),
  attackScenario: z.string(),
  evidence: z.array(z.object({ path: z.string(), line: z.number(), note: z.string() })),
  falsePositiveConsiderations: z.array(z.string()),
  recommendedDynamicTests: z.array(z.object({
    name: z.string(),
    risk: z.enum(["safe", "medium", "high"]),
    requiresApproval: z.boolean(),
    description: z.string(),
    curlCommand: z.string().nullable(),
    pocScript: z.string().nullable()
  })),
  requestedFiles: z.array(z.string()).default([]),
  requestedSymbols: z.array(z.string()).default([]),
  remediation: z.string(),
  secureCodeExample: z.string().nullable()
});

export type AiFinding = z.infer<typeof aiFindingSchema>;
