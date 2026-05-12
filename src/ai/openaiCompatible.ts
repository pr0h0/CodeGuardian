import OpenAI from "openai";
import type { AiCompletionInput, AiCompletionOutput, AiProvider } from "./types.js";
import { supportsTemperature } from "./openai.js";

export class OpenAiCompatibleProvider implements AiProvider {
  private client: OpenAI;

  constructor(public readonly name: string, apiKey: string, private readonly model: string, baseURL: string) {
    this.client = new OpenAI({ apiKey, baseURL, timeout: 120_000, maxRetries: 1 });
  }

  async complete(input: AiCompletionInput): Promise<AiCompletionOutput> {
    const response = await this.client.chat.completions.create({
      model: this.model,
      messages: [{ role: "system", content: input.system }, ...input.messages],
      ...(supportsTemperature(this.model) ? { temperature: input.temperature ?? 0 } : {}),
      max_tokens: input.maxTokens ?? 2000,
      response_format: { type: "json_object" }
    });
    const text = response.choices[0]?.message?.content ?? "";
    return { text, raw: response };
  }
}
