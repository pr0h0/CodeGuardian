import OpenAI from "openai";
import type { AiCompletionInput, AiCompletionOutput, AiProvider } from "./types.js";
import { supportsTemperature, toChatJsonSchema } from "./openai.js";

export class OpenAiCompatibleProvider implements AiProvider {
  private client: OpenAI;

  constructor(public readonly name: string, apiKey: string, private readonly model: string, baseURL: string) {
    this.client = new OpenAI({ apiKey, baseURL, timeout: 120_000, maxRetries: 1 });
  }

  async complete(input: AiCompletionInput): Promise<AiCompletionOutput> {
    const response = await this.client.chat.completions.create(buildOpenAiCompatibleChatParams(this.name, this.model, input));
    const text = response.choices[0]?.message?.content ?? "";
    return { text, raw: response };
  }
}

export function buildOpenAiCompatibleChatParams(provider: string, model: string, input: AiCompletionInput): OpenAI.Chat.ChatCompletionCreateParamsNonStreaming {
  return {
    model,
    messages: [{ role: "system", content: input.system }, ...input.messages],
    ...(supportsTemperature(model) ? { temperature: input.temperature ?? 0 } : {}),
    max_tokens: input.maxTokens ?? 2000,
    response_format: responseFormatFor(provider, model, input.jsonSchema)
  };
}

function responseFormatFor(provider: string, model: string, jsonSchema: unknown): OpenAI.Chat.ChatCompletionCreateParamsNonStreaming["response_format"] {
  if (!jsonSchema || isJsonObjectOnly(provider, model)) return { type: "json_object" };
  return toChatJsonSchema(jsonSchema);
}

function isJsonObjectOnly(provider: string, model: string): boolean {
  const providerKey = provider.toLowerCase();
  const modelKey = model.toLowerCase();
  return providerKey === "deepseek" || modelKey.includes("deepseek");
}
