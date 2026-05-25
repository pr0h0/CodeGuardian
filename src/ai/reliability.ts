import type { AiCompletionInput, AiCompletionOutput, AiProvider } from "./types.js";

export type AiErrorKind = "authentication" | "billing" | "rate_limit" | "server" | "invalid_request" | "unknown";

export interface AiErrorClassification {
  kind: AiErrorKind;
  retryable: boolean;
  message: string;
}

export class AiProviderError extends Error {
  readonly kind: AiErrorKind;
  readonly retryable: boolean;

  constructor(classification: AiErrorClassification) {
    super(classification.message);
    this.name = "AiProviderError";
    this.kind = classification.kind;
    this.retryable = classification.retryable;
  }
}

export interface AiReliabilityOptions {
  maxAttempts?: number;
  log?: (message: string) => void;
}

export function withAiReliability(provider: AiProvider, options: AiReliabilityOptions = {}): AiProvider {
  const maxAttempts = Math.max(1, options.maxAttempts ?? 2);
  return {
    name: provider.name,
    async complete(input: AiCompletionInput): Promise<AiCompletionOutput> {
      let lastError: AiProviderError | undefined;
      for (let attempt = 1; attempt <= maxAttempts; attempt++) {
        try {
          const output = await provider.complete(input);
          const textFailure = classifyAiTextFailure(output.text);
          if (textFailure) throw new AiProviderError(textFailure);
          return output;
        } catch (error) {
          const classified = toAiProviderError(error);
          lastError = classified;
          if (!classified.retryable || attempt >= maxAttempts) throw classified;
          options.log?.(`ai: provider=${provider.name} ${classified.kind} failure attempt=${attempt}/${maxAttempts}; retrying`);
        }
      }
      throw lastError ?? new AiProviderError({ kind: "unknown", retryable: false, message: "AI provider failed" });
    }
  };
}

export function classifyAiError(error: unknown): AiErrorClassification {
  if (error instanceof AiProviderError) {
    return { kind: error.kind, retryable: error.retryable, message: error.message };
  }
  const message = extractErrorText(error);
  const text = message.toLowerCase();
  if (/(^|\b)(401|403)(\b|$)|unauthori[sz]ed|authentication|invalid api key|api key[^.:\n]*(invalid|missing)|forbidden|permission denied/.test(text)) {
    return { kind: "authentication", retryable: false, message };
  }
  if (/spending cap|spending limit|cap reached|budget exceeded|billing|credit balance is too low|insufficient credits|usage is blocked due to insufficient credits|plans?\s*(?:&|and)\s*billing|billing limit reached/.test(text)) {
    return { kind: "billing", retryable: true, message };
  }
  if (/(^|\b)429(\b|$)|rate limit|too many requests|quota exceeded|usage limit reached|daily rate limit|limit will reset/.test(text)) {
    return { kind: "rate_limit", retryable: true, message };
  }
  if (/(^|\b)(500|502|503|504)(\b|$)|server error|temporarily unavailable|service unavailable|overloaded|timeout|timed out|econnreset|etimedout/.test(text)) {
    return { kind: "server", retryable: true, message };
  }
  if (/(^|\b)400(\b|$)|invalid request|bad request|schema rejected|schema validation|json validation|invalid json|context length|max(?:imum)? output tokens/.test(text)) {
    return { kind: "invalid_request", retryable: false, message };
  }
  return { kind: "unknown", retryable: false, message };
}

export function toAiProviderError(error: unknown): AiProviderError {
  return error instanceof AiProviderError ? error : new AiProviderError(classifyAiError(error));
}

export function classifyAiTextFailure(text: string): AiErrorClassification | null {
  const trimmed = text.trim();
  if (!trimmed) return null;
  const classification = classifyAiError(new Error(trimmed));
  return classification.kind === "billing" ? classification : null;
}

function extractErrorText(error: unknown): string {
  const values = collectErrorValues(error);
  const message = values.map(String).filter(Boolean).join(" ");
  return message || "AI provider failed";
}

function collectErrorValues(value: unknown): unknown[] {
  if (value instanceof Error) return [value.message, ...(value.cause ? collectErrorValues(value.cause) : [])];
  if (!value || typeof value !== "object") return [value];
  const object = value as Record<string, any>;
  return [
    object.message,
    object.status,
    object.statusCode,
    object.code,
    object.type,
    object.error?.message,
    object.error?.status,
    object.error?.code,
    object.error?.type
  ].filter((item) => item !== undefined && item !== null);
}
