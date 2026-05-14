import type { AiCompletionInput, AiCompletionOutput, AiProvider } from "./types.js";
import { findModelPricing, type AiModelPricing } from "./pricing.js";

export type AiTier = "low" | "medium" | "high";

export interface AiUsageRow {
  provider: string;
  tier: AiTier;
  model: string;
  requests: number;
  inputTokens: number;
  cachedInputTokens: number;
  cacheWriteInputTokens: number;
  outputTokens: number;
  totalTokens: number;
  cachedInputCostUsd: number | null;
  inputCostUsd: number | null;
  outputCostUsd: number | null;
  costUsd: number | null;
}

interface ExtractedAiUsage {
  inputTokens: number;
  cachedInputTokens: number;
  cacheWriteInputTokens: number;
  uncachedInputTokens: number;
  outputTokens: number;
  totalTokens: number;
  cachedInputCostUsd: number | null;
  inputCostUsd: number | null;
  outputCostUsd: number | null;
  costUsd: number | null;
}

export class AiUsageTracker {
  private rows = new Map<string, AiUsageRow>();

  track(provider: string, tier: AiTier, model: string, raw: unknown): void {
    const usage = applyPricingFallback(extractAiUsage(raw), findModelPricing(provider, model));
    const key = `${provider}|${tier}|${model}`;
    const row = this.rows.get(key) ?? {
      provider,
      tier,
      model,
      requests: 0,
      inputTokens: 0,
      cachedInputTokens: 0,
      cacheWriteInputTokens: 0,
      outputTokens: 0,
      totalTokens: 0,
      cachedInputCostUsd: null,
      inputCostUsd: null,
      outputCostUsd: null,
      costUsd: null
    };
    row.requests += 1;
    row.inputTokens += usage.inputTokens;
    row.cachedInputTokens += usage.cachedInputTokens;
    row.cacheWriteInputTokens += usage.cacheWriteInputTokens;
    row.outputTokens += usage.outputTokens;
    row.totalTokens += usage.totalTokens || usage.inputTokens + usage.outputTokens;
    if (usage.cachedInputCostUsd !== null) row.cachedInputCostUsd = addCost(row.cachedInputCostUsd, usage.cachedInputCostUsd);
    if (usage.inputCostUsd !== null) row.inputCostUsd = addCost(row.inputCostUsd, usage.inputCostUsd);
    if (usage.outputCostUsd !== null) row.outputCostUsd = addCost(row.outputCostUsd, usage.outputCostUsd);
    if (usage.costUsd !== null) row.costUsd = addCost(row.costUsd, usage.costUsd);
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

export function extractAiUsage(raw: unknown): ExtractedAiUsage {
  const object = raw && typeof raw === "object" ? raw as Record<string, any> : {};
  const usage = object.usage && typeof object.usage === "object" ? object.usage : object;
  const costDetails = usage.cost_details ?? usage.costDetails ?? object.cost_details ?? object.costDetails ?? {};
  const tokenDetails = usage.input_tokens_details ?? usage.inputTokensDetails ?? usage.prompt_tokens_details ?? usage.promptTokensDetails ?? object.input_tokens_details ?? object.prompt_tokens_details ?? {};
  const cacheWriteInputTokens = firstNumber([
    usage.cache_creation_input_tokens,
    usage.cacheCreationInputTokens,
    object.cache_creation_input_tokens
  ]);
  const cachedInputTokens = firstNumber([
    usage.cache_read_input_tokens,
    usage.cacheReadInputTokens,
    usage.prompt_cache_hit_tokens,
    usage.promptCacheHitTokens,
    tokenDetails.cached_tokens,
    tokenDetails.cachedTokens,
    object.cache_read_input_tokens,
    object.prompt_cache_hit_tokens
  ]);
  const cacheMissInputTokens = firstNullableNumber([
    usage.prompt_cache_miss_tokens,
    usage.promptCacheMissTokens,
    object.prompt_cache_miss_tokens
  ]);
  const rawInputTokens = firstNullableNumber([
    usage.input_tokens,
    usage.prompt_tokens,
    usage.inputTokens,
    usage.promptTokens,
    object.input_tokens
  ]);
  const hasAnthropicCacheShape = cacheWriteInputTokens > 0 || (cachedInputTokens > 0 && rawInputTokens !== null && usage.cache_read_input_tokens !== undefined);
  const inputTokens = cacheMissInputTokens !== null
    ? cacheMissInputTokens + cachedInputTokens + cacheWriteInputTokens
    : rawInputTokens !== null
      ? rawInputTokens + (hasAnthropicCacheShape ? cachedInputTokens + cacheWriteInputTokens : 0)
      : cachedInputTokens + cacheWriteInputTokens;
  const uncachedInputTokens = cacheMissInputTokens !== null
    ? cacheMissInputTokens
    : Math.max(inputTokens - cachedInputTokens - cacheWriteInputTokens, 0);
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
  const cachedInputCostUsd = firstNullableNumber([
    usage.cached_input_cost_usd,
    usage.cachedInputCostUsd,
    usage.cache_read_input_cost_usd,
    usage.cacheReadInputCostUsd,
    usage.cache_hit_cost_usd,
    usage.cacheHitCostUsd,
    costDetails.cached_input_cost_usd,
    costDetails.cachedInputCostUsd,
    costDetails.cache_read_input_cost_usd,
    costDetails.cacheReadInputCostUsd,
    costDetails.cache_hit_cost_usd,
    costDetails.cacheHitCostUsd
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
  return { inputTokens, cachedInputTokens, cacheWriteInputTokens, uncachedInputTokens, outputTokens, totalTokens, cachedInputCostUsd, inputCostUsd, outputCostUsd, costUsd };
}

function applyPricingFallback(usage: ExtractedAiUsage, pricing: AiModelPricing | null): ExtractedAiUsage {
  if (!pricing) return usage;

  const cachedInputCostUsd = usage.cachedInputCostUsd ?? (pricing.cachedInputUsdPer1M !== null ? usage.cachedInputTokens * pricing.cachedInputUsdPer1M / 1_000_000 : null);
  const cacheWriteCostUsd = usage.cacheWriteInputTokens * (pricing.cacheWriteInputUsdPer1M ?? pricing.inputUsdPer1M) / 1_000_000;
  const uncachedInputCostUsd = usage.uncachedInputTokens * pricing.inputUsdPer1M / 1_000_000;
  const pricedInputCostUsd = uncachedInputCostUsd + cacheWriteCostUsd + (cachedInputCostUsd ?? usage.cachedInputTokens * pricing.inputUsdPer1M / 1_000_000);
  const inputCostUsd = usage.inputCostUsd ?? pricedInputCostUsd;
  const outputCostUsd = usage.outputCostUsd ?? usage.outputTokens * pricing.outputUsdPer1M / 1_000_000;
  const costUsd = usage.costUsd ?? inputCostUsd + outputCostUsd;

  return {
    ...usage,
    cachedInputCostUsd: cachedInputCostUsd === null ? null : roundCost(cachedInputCostUsd),
    inputCostUsd: roundCost(inputCostUsd),
    outputCostUsd: roundCost(outputCostUsd),
    costUsd: roundCost(costUsd)
  };
}

function addCost(current: number | null, next: number): number {
  return roundCost((current ?? 0) + next);
}

function roundCost(value: number): number {
  return Number(value.toFixed(12));
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
