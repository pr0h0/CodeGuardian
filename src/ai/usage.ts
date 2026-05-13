import type { AiCompletionInput, AiCompletionOutput, AiProvider } from "./types.js";

export type AiTier = "low" | "medium" | "high";

export interface AiUsageRow {
  provider: string;
  tier: AiTier;
  model: string;
  requests: number;
  inputTokens: number;
  outputTokens: number;
  totalTokens: number;
  inputCostUsd: number | null;
  outputCostUsd: number | null;
  costUsd: number | null;
}

export class AiUsageTracker {
  private rows = new Map<string, AiUsageRow>();

  track(provider: string, tier: AiTier, model: string, raw: unknown): void {
    const usage = extractAiUsage(raw);
    const key = `${provider}|${tier}|${model}`;
    const row = this.rows.get(key) ?? { provider, tier, model, requests: 0, inputTokens: 0, outputTokens: 0, totalTokens: 0, inputCostUsd: null, outputCostUsd: null, costUsd: null };
    row.requests += 1;
    row.inputTokens += usage.inputTokens;
    row.outputTokens += usage.outputTokens;
    row.totalTokens += usage.totalTokens || usage.inputTokens + usage.outputTokens;
    if (usage.inputCostUsd !== null) row.inputCostUsd = (row.inputCostUsd ?? 0) + usage.inputCostUsd;
    if (usage.outputCostUsd !== null) row.outputCostUsd = (row.outputCostUsd ?? 0) + usage.outputCostUsd;
    if (usage.costUsd !== null) row.costUsd = (row.costUsd ?? 0) + usage.costUsd;
    this.rows.set(key, row);
  }

  summary(): AiUsageRow[] {
    return [...this.rows.values()].sort((a, b) => a.tier.localeCompare(b.tier) || a.model.localeCompare(b.model));
  }
}

export function withUsageTracking(provider: AiProvider, tracker: AiUsageTracker, tier: AiTier, model: string): AiProvider {
  return {
    name: provider.name,
    async complete(input: AiCompletionInput): Promise<AiCompletionOutput> {
      const output = await provider.complete(input);
      tracker.track(provider.name, tier, model, output.raw);
      return output;
    }
  };
}

export function extractAiUsage(raw: unknown): { inputTokens: number; outputTokens: number; totalTokens: number; inputCostUsd: number | null; outputCostUsd: number | null; costUsd: number | null } {
  const object = raw && typeof raw === "object" ? raw as Record<string, any> : {};
  const usage = object.usage && typeof object.usage === "object" ? object.usage : object;
  const costDetails = usage.cost_details ?? usage.costDetails ?? object.cost_details ?? object.costDetails ?? {};
  const inputTokens = firstNumber([
    usage.input_tokens,
    usage.prompt_tokens,
    usage.inputTokens,
    usage.promptTokens,
    usage.cache_creation_input_tokens,
    object.input_tokens
  ]);
  const outputTokens = firstNumber([
    usage.output_tokens,
    usage.completion_tokens,
    usage.outputTokens,
    usage.completionTokens,
    object.output_tokens
  ]);
  const totalTokens = firstNumber([
    usage.total_tokens,
    usage.totalTokens,
    object.total_tokens,
    inputTokens + outputTokens
  ]);
  const inputCostUsd = firstNullableNumber([
    usage.input_cost_usd,
    usage.prompt_cost_usd,
    usage.inputCostUsd,
    usage.promptCostUsd,
    usage.input_cost,
    usage.prompt_cost,
    costDetails.input_cost_usd,
    costDetails.prompt_cost_usd,
    costDetails.inputCostUsd,
    costDetails.promptCostUsd,
    costDetails.input_tokens_cost,
    costDetails.prompt_tokens_cost
  ]);
  const outputCostUsd = firstNullableNumber([
    usage.output_cost_usd,
    usage.completion_cost_usd,
    usage.outputCostUsd,
    usage.completionCostUsd,
    usage.output_cost,
    usage.completion_cost,
    costDetails.output_cost_usd,
    costDetails.completion_cost_usd,
    costDetails.outputCostUsd,
    costDetails.completionCostUsd,
    costDetails.output_tokens_cost,
    costDetails.completion_tokens_cost
  ]);
  const explicitCostUsd = firstNullableNumber([
    usage.cost_usd,
    usage.costUsd,
    usage.total_cost,
    usage.totalCost,
    usage.cost,
    object.cost_usd,
    object.costUsd,
    object.total_cost,
    object.cost,
    object.billing?.cost,
    object.billing?.cost_usd
  ]);
  const costUsd = explicitCostUsd ?? (inputCostUsd !== null || outputCostUsd !== null ? (inputCostUsd ?? 0) + (outputCostUsd ?? 0) : null);
  return { inputTokens, outputTokens, totalTokens, inputCostUsd, outputCostUsd, costUsd };
}

function firstNumber(values: unknown[]): number {
  return firstNullableNumber(values) ?? 0;
}

function firstNullableNumber(values: unknown[]): number | null {
  for (const value of values) {
    const number = typeof value === "number" ? value : typeof value === "string" && value.trim() ? Number(value) : NaN;
    if (Number.isFinite(number)) return number;
  }
  return null;
}
