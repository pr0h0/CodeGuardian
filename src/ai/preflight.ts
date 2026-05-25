import { safeJsonParse } from "../utils/safeJson.js";
import type { AiProvider } from "./types.js";
import type { AiTier } from "./usage.js";
import type { AiJobRecorder } from "./jobs.js";
import { aiPreflightJsonSchema } from "./schemas.js";
import { AiProviderError, toAiProviderError } from "./reliability.js";

const PREFLIGHT_TIERS: AiTier[] = ["low", "medium", "high"];
const PREFLIGHT_ATTEMPTS = 3;
const PREFLIGHT_MAX_TOKENS = 128;

export async function preflightAiProviders(
  providers: Record<AiTier, AiProvider>,
  log: (message: string) => void = () => undefined,
  jobRecorder?: AiJobRecorder
): Promise<void> {
  for (const tier of PREFLIGHT_TIERS) {
    const provider = providers[tier];
    const jobId = jobRecorder?.start("preflight", tier, { provider: provider.name, tier });
    try {
      log(`ai-preflight: ${tier} provider=${provider.name} checking`);
      const prompt = "Return {\"ok\":true} to confirm this configured provider and model can answer structured JSON requests.";
      for (let attempt = 1; attempt <= PREFLIGHT_ATTEMPTS; attempt++) {
        const output = await provider.complete({
          system: "You are an AI provider readiness check. Output raw JSON only.",
          messages: [{ role: "user", content: prompt }],
          jsonSchema: aiPreflightJsonSchema,
          temperature: 0,
          maxTokens: PREFLIGHT_MAX_TOKENS
        });
        jobRecorder?.trace(jobId, { label: `preflight-${attempt}`, prompt, response: output.text });
        if (preflightOk(output.parsedJson ?? safeJsonParse(output.text))) {
          jobRecorder?.succeed(jobId, { attempts: attempt });
          log(`ai-preflight: ${tier} provider=${provider.name} ok`);
          break;
        }
        if (attempt >= PREFLIGHT_ATTEMPTS) {
          throw new AiProviderError({ kind: "invalid_request", retryable: false, message: `AI preflight for ${tier} did not return {"ok":true}` });
        }
        log(`ai-preflight: ${tier} provider=${provider.name} malformed response attempt=${attempt}/${PREFLIGHT_ATTEMPTS}; retrying`);
      }
    } catch (error) {
      const classified = toAiProviderError(error);
      jobRecorder?.fail(jobId, classified, { kind: classified.kind, retryable: classified.retryable });
      log(`ai-preflight: ${tier} provider=${provider.name} failed kind=${classified.kind} retryable=${classified.retryable}`);
      throw classified;
    }
  }
}

function preflightOk(parsed: unknown): boolean {
  return Boolean(parsed && typeof parsed === "object" && (parsed as Record<string, unknown>).ok === true);
}
