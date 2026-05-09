import OpenAI from "openai";
import type { AiCompletionInput, AiCompletionOutput, AiProvider } from "./types.js";

export class OpenAiProvider implements AiProvider {
  name = "openai";
  private client: OpenAI;
  constructor(apiKey: string, private readonly model: string, baseURL?: string) {
    this.client = new OpenAI({ apiKey, baseURL: baseURL || undefined, timeout: 45_000, maxRetries: 1 });
  }
  async complete(input: AiCompletionInput): Promise<AiCompletionOutput> {
    const response = await this.client.responses.create({
      model: this.model,
      input: [{ role: "system", content: input.system }, ...input.messages.map((m) => ({ role: m.role, content: m.content }))],
      temperature: input.temperature ?? 0,
      max_output_tokens: input.maxTokens ?? 2000
    });
    const text = response.output_text;
    return { text, raw: response };
  }
}
