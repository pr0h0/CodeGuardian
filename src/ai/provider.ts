import type { AppEnv } from "../config/env.js";
import type { AiProvider } from "./types.js";
import { OpenAiProvider } from "./openai.js";
import { AnthropicProvider } from "./anthropic.js";
import { DeepSeekProvider } from "./deepseek.js";
import { OpenRouterProvider } from "./openrouter.js";

export function createAiProvider(env: AppEnv, overrideProvider?: string, overrideModel?: string): { provider: AiProvider; model: string } {
  const name = overrideProvider ?? env.AI_PROVIDER;
  const genericKey = env.AI_API_KEY;
  if (name === "openai") {
    const key = genericKey || env.OPENAI_API_KEY;
    const model = overrideModel || env.AI_MODEL || env.OPENAI_MODEL || "gpt-4.1-mini";
    if (!key) throw new Error("AI provider openai requires OPENAI_API_KEY or AI_API_KEY");
    return { provider: new OpenAiProvider(key, model, env.AI_BASE_URL), model };
  }
  if (name === "anthropic") {
    const key = genericKey || env.ANTHROPIC_API_KEY;
    const model = overrideModel || env.AI_MODEL || env.ANTHROPIC_MODEL || "claude-3-5-haiku-latest";
    if (!key) throw new Error("AI provider anthropic requires ANTHROPIC_API_KEY or AI_API_KEY");
    return { provider: new AnthropicProvider(key, model), model };
  }
  if (name === "deepseek") {
    const key = genericKey || env.DEEPSEEK_API_KEY;
    const model = overrideModel || env.AI_MODEL || env.DEEPSEEK_MODEL || "deepseek-chat";
    if (!key) throw new Error("AI provider deepseek requires DEEPSEEK_API_KEY or AI_API_KEY");
    return { provider: new DeepSeekProvider(key, model, env.AI_BASE_URL || env.DEEPSEEK_BASE_URL), model };
  }
  const key = genericKey || env.OPENROUTER_API_KEY;
  const model = overrideModel || env.AI_MODEL || env.OPENROUTER_MODEL;
  if (!key || !model) throw new Error("AI provider openrouter requires OPENROUTER_API_KEY/AI_API_KEY and OPENROUTER_MODEL/AI_MODEL");
  return { provider: new OpenRouterProvider(key, model, env.AI_BASE_URL || env.OPENROUTER_BASE_URL), model };
}

export function aiFastModel(env: AppEnv, provider: string, configModel?: string, cliModel?: string): string | undefined {
  if (cliModel) return cliModel;
  if (configModel) return configModel;
  if (env.AI_FAST_MODEL) return env.AI_FAST_MODEL;
  if (provider === "deepseek") return env.DEEPSEEK_FAST_MODEL || "deepseek-v4-flash";
  return env.AI_MODEL || undefined;
}

export function aiStrongModel(env: AppEnv, provider: string, configModel?: string, cliModel?: string): string | undefined {
  if (cliModel) return cliModel;
  if (configModel) return configModel;
  if (env.AI_STRONG_MODEL) return env.AI_STRONG_MODEL;
  if (provider === "deepseek") return env.DEEPSEEK_STRONG_MODEL || "deepseek-v4-pro";
  return env.AI_MODEL || undefined;
}
