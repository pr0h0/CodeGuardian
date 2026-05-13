import OpenAI from "openai";
import type { AiCompletionInput, AiCompletionOutput, AiProvider } from "./types.js";
import type { AiJsonSchema } from "./schemas.js";

export class OpenAiProvider implements AiProvider {
  name = "openai";
  private client: OpenAI;
  constructor(apiKey: string, private readonly model: string, baseURL?: string) {
    this.client = new OpenAI({ apiKey, baseURL: baseURL || undefined, timeout: 120_000, maxRetries: 1 });
  }
  async complete(input: AiCompletionInput): Promise<AiCompletionOutput> {
    const response = await this.client.responses.create(buildOpenAiResponseParams(this.model, input));
    const text = response.output_text;
    return { text, raw: response };
  }
}

export function buildOpenAiResponseParams(model: string, input: AiCompletionInput): OpenAI.Responses.ResponseCreateParamsNonStreaming {
  return {
    model,
    input: [{ role: "system", content: input.system }, ...input.messages.map((m) => ({ role: m.role, content: m.content }))],
    ...(input.jsonSchema ? { text: { format: toResponseJsonSchema(input.jsonSchema) } } : {}),
    ...(supportsTemperature(model) ? { temperature: input.temperature ?? 0 } : {}),
    max_output_tokens: input.maxTokens ?? 2000
  };
}

export function toResponseJsonSchema(jsonSchema: unknown): OpenAI.Responses.ResponseFormatTextJSONSchemaConfig {
  const schema = jsonSchema as AiJsonSchema;
  return {
    type: "json_schema",
    name: schema.name,
    description: schema.description,
    schema: schema.schema,
    strict: true
  };
}

export function toChatJsonSchema(jsonSchema: unknown): OpenAI.Chat.ChatCompletionCreateParamsNonStreaming["response_format"] {
  const schema = jsonSchema as AiJsonSchema;
  return {
    type: "json_schema",
    json_schema: {
      name: schema.name,
      description: schema.description,
      schema: schema.schema,
      strict: true
    }
  };
}

export function supportsTemperature(model: string): boolean {
  const normalized = model.toLowerCase().split("/").pop() ?? model.toLowerCase();
  return !(
    /^gpt-5(?:[.-]|$)/.test(normalized)
    || /^o\d(?:[.-]|$)/.test(normalized)
  );
}
