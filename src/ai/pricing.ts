export interface AiModelPricing {
  provider: string;
  model: string;
  aliases: string[];
  inputUsdPer1M: number;
  cachedInputUsdPer1M: number | null;
  cacheWriteInputUsdPer1M?: number;
  outputUsdPer1M: number;
  source: string;
  checkedAt: string;
  notes?: string;
}

export const AI_MODEL_PRICES: AiModelPricing[] = [
  {
    provider: "openai",
    model: "gpt-5.5",
    aliases: ["gpt-5.5", "openai/gpt-5.5"],
    inputUsdPer1M: 5,
    cachedInputUsdPer1M: 0.5,
    outputUsdPer1M: 30,
    source: "https://openai.com/api/pricing/",
    checkedAt: "2026-05-14"
  },
  {
    provider: "openai",
    model: "gpt-5.4-mini",
    aliases: ["gpt-5.4-mini", "openai/gpt-5.4-mini"],
    inputUsdPer1M: 0.75,
    cachedInputUsdPer1M: 0.075,
    outputUsdPer1M: 4.5,
    source: "https://openai.com/api/pricing/",
    checkedAt: "2026-05-14"
  },
  {
    provider: "deepseek",
    model: "deepseek-v4-pro",
    aliases: ["deepseek-v4-pro", "deepseek/deepseek-v4-pro"],
    inputUsdPer1M: 0.435,
    cachedInputUsdPer1M: 0.003625,
    outputUsdPer1M: 0.87,
    source: "https://api-docs.deepseek.com/quick_start/pricing",
    checkedAt: "2026-05-14",
    notes: "Current 75% promotional price, listed by DeepSeek as extended until 2026-05-31 15:59 UTC."
  },
  {
    provider: "deepseek",
    model: "deepseek-v4-flash",
    aliases: ["deepseek-v4-flash", "deepseek/deepseek-v4-flash", "deepseek-chat", "deepseek-reasoner"],
    inputUsdPer1M: 0.14,
    cachedInputUsdPer1M: 0.0028,
    outputUsdPer1M: 0.28,
    source: "https://api-docs.deepseek.com/quick_start/pricing",
    checkedAt: "2026-05-14"
  },
  {
    provider: "anthropic",
    model: "claude-opus-4-7",
    aliases: ["claude-opus-4-7", "claude-opus-4.7", "anthropic/claude-opus-4-7", "anthropic/claude-opus-4.7"],
    inputUsdPer1M: 5,
    cachedInputUsdPer1M: 0.5,
    cacheWriteInputUsdPer1M: 6.25,
    outputUsdPer1M: 25,
    source: "https://platform.claude.com/docs/en/about-claude/pricing",
    checkedAt: "2026-05-14"
  },
  {
    provider: "anthropic",
    model: "claude-opus-4-6",
    aliases: ["claude-opus-4-6", "claude-opus-4.6", "anthropic/claude-opus-4-6", "anthropic/claude-opus-4.6"],
    inputUsdPer1M: 5,
    cachedInputUsdPer1M: 0.5,
    cacheWriteInputUsdPer1M: 6.25,
    outputUsdPer1M: 25,
    source: "https://platform.claude.com/docs/en/about-claude/pricing",
    checkedAt: "2026-05-14"
  },
  {
    provider: "anthropic",
    model: "claude-sonnet-4-6",
    aliases: ["claude-sonnet-4-6", "claude-sonnet-4.6", "anthropic/claude-sonnet-4-6", "anthropic/claude-sonnet-4.6"],
    inputUsdPer1M: 3,
    cachedInputUsdPer1M: 0.3,
    cacheWriteInputUsdPer1M: 3.75,
    outputUsdPer1M: 15,
    source: "https://platform.claude.com/docs/en/about-claude/pricing",
    checkedAt: "2026-05-14"
  },
  {
    provider: "anthropic",
    model: "claude-sonnet-4-5",
    aliases: ["claude-sonnet-4-5", "claude-sonnet-4.5", "anthropic/claude-sonnet-4-5", "anthropic/claude-sonnet-4.5"],
    inputUsdPer1M: 3,
    cachedInputUsdPer1M: 0.3,
    cacheWriteInputUsdPer1M: 3.75,
    outputUsdPer1M: 15,
    source: "https://platform.claude.com/docs/en/about-claude/pricing",
    checkedAt: "2026-05-14"
  },
  {
    provider: "anthropic",
    model: "claude-sonnet-4",
    aliases: ["claude-sonnet-4", "anthropic/claude-sonnet-4"],
    inputUsdPer1M: 3,
    cachedInputUsdPer1M: 0.3,
    cacheWriteInputUsdPer1M: 3.75,
    outputUsdPer1M: 15,
    source: "https://platform.claude.com/docs/en/about-claude/pricing",
    checkedAt: "2026-05-14"
  },
  {
    provider: "anthropic",
    model: "claude-haiku-4-5",
    aliases: ["claude-haiku-4-5", "claude-haiku-4.5", "anthropic/claude-haiku-4-5", "anthropic/claude-haiku-4.5"],
    inputUsdPer1M: 1,
    cachedInputUsdPer1M: 0.1,
    cacheWriteInputUsdPer1M: 1.25,
    outputUsdPer1M: 5,
    source: "https://platform.claude.com/docs/en/about-claude/pricing",
    checkedAt: "2026-05-14"
  },
  {
    provider: "anthropic",
    model: "claude-haiku-3-5",
    aliases: [
      "claude-haiku-3-5",
      "claude-haiku-3.5",
      "claude-3-5-haiku",
      "claude-3.5-haiku",
      "anthropic/claude-haiku-3-5",
      "anthropic/claude-haiku-3.5",
      "anthropic/claude-3-5-haiku",
      "anthropic/claude-3.5-haiku"
    ],
    inputUsdPer1M: 0.8,
    cachedInputUsdPer1M: 0.08,
    cacheWriteInputUsdPer1M: 1,
    outputUsdPer1M: 4,
    source: "https://platform.claude.com/docs/en/about-claude/pricing",
    checkedAt: "2026-05-14"
  }
];

export function findModelPricing(provider: string, model: string): AiModelPricing | null {
  const providerKey = normalize(provider);
  const modelKey = normalize(model);
  const modelSuffix = modelKey.split("/").pop() ?? modelKey;

  return AI_MODEL_PRICES.find((price) => {
    const aliases = [price.model, ...price.aliases].map(normalize);
    return aliases.some((alias) => matchesAlias(modelKey, alias) || matchesAlias(modelSuffix, alias))
      || (providerKey === normalize(price.provider) && aliases.some((alias) => alias.endsWith(`/${modelSuffix}`)));
  }) ?? null;
}

function matchesAlias(model: string, alias: string): boolean {
  return model === alias || model.startsWith(`${alias}-`);
}

function normalize(value: string): string {
  return value.trim().toLowerCase();
}
