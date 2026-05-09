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
  sink: z.string(),
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
  remediation: z.string(),
  secureCodeExample: z.string().nullable()
});

export type AiFinding = z.infer<typeof aiFindingSchema>;
