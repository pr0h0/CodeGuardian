import Anthropic from "@anthropic-ai/sdk";
import type { AiCompletionInput, AiCompletionOutput, AiProvider } from "./types.js";

export class AnthropicProvider implements AiProvider {
  name = "anthropic";
  private client: Anthropic;
  constructor(apiKey: string, private readonly model: string) {
    this.client = new Anthropic({ apiKey, timeout: 45_000, maxRetries: 1 });
  }
  async complete(input: AiCompletionInput): Promise<AiCompletionOutput> {
    const response = await this.client.messages.create({
      model: this.model,
      system: input.system,
      messages: input.messages,
      temperature: input.temperature ?? 0,
      max_tokens: input.maxTokens ?? 2000
    });
    const text = response.content.map((part) => part.type === "text" ? part.text : "").join("");
    return { text, raw: response };
  }
}
