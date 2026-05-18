import Anthropic from "@anthropic-ai/sdk";
import type { AiCompletionInput, AiCompletionOutput, AiProvider } from "./types.js";

export class AnthropicProvider implements AiProvider {
  name = "anthropic";
  private client: Anthropic;
  constructor(apiKey: string, private readonly model: string) {
    this.client = new Anthropic({ apiKey, timeout: 120_000, maxRetries: 1 });
  }
  async complete(input: AiCompletionInput): Promise<AiCompletionOutput> {
    const systemText = input.jsonSchema
      ? `${input.system}\n\nReturn raw JSON only. No prose, markdown, comments, or code fences. Strict JSON schema:\n${JSON.stringify(input.jsonSchema)}`
      : input.system;
    const response = await this.client.messages.create({
      model: this.model,
      system: [{ type: "text", text: systemText, cache_control: { type: "ephemeral" } } as Anthropic.TextBlockParam],
      messages: input.messages as Anthropic.MessageParam[],
      temperature: input.temperature ?? 0,
      max_tokens: input.maxTokens ?? 2000
    });
    const text = response.content.map((part) => part.type === "text" ? part.text : "").join("");
    return { text, raw: response };
  }
}
