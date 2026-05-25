import { redactSecrets } from "../utils/redact.js";

export type AiJobType = "preflight" | "triage" | "audit" | "repair" | "critic" | "dedupe";
export type AiJobStatus = "running" | "succeeded" | "failed";

export interface AiJobTrace {
  label: string;
  promptChars: number;
  responseChars: number;
  promptPreview: string;
  responsePreview: string;
}

export interface AiJobEvent {
  id: string;
  type: AiJobType;
  label: string;
  status: AiJobStatus;
  startedAt: string;
  finishedAt?: string;
  elapsedMs?: number;
  metadata?: Record<string, unknown>;
  error?: string;
  traces?: AiJobTrace[];
}

export interface AiJobSummary {
  total: number;
  succeeded: number;
  failed: number;
  events: AiJobEvent[];
}

export class AiJobRecorder {
  private nextId = 1;
  private readonly events: AiJobEvent[] = [];

  start(type: AiJobType, label: string, metadata: Record<string, unknown> = {}): string {
    const id = String(this.nextId++);
    this.events.push({ id, type, label, status: "running", startedAt: new Date().toISOString(), metadata });
    return id;
  }

  succeed(id: string | undefined, metadata: Record<string, unknown> = {}): void {
    this.finish(id, "succeeded", metadata);
  }

  fail(id: string | undefined, error: unknown, metadata: Record<string, unknown> = {}): void {
    this.finish(id, "failed", metadata, error instanceof Error ? error.message : String(error));
  }

  trace(id: string | undefined, input: { label?: string; prompt?: string; response?: string }): void {
    if (!id) return;
    const event = this.events.find((item) => item.id === id);
    if (!event) return;
    const prompt = input.prompt ?? "";
    const response = input.response ?? "";
    const trace: AiJobTrace = {
      label: input.label ?? "request",
      promptChars: prompt.length,
      responseChars: response.length,
      promptPreview: tracePreview(prompt),
      responsePreview: tracePreview(response)
    };
    event.traces = [...(event.traces ?? []), trace];
  }

  summary(): AiJobSummary {
    const events = this.events.map((event) => ({
      ...event,
      metadata: event.metadata ? { ...event.metadata } : undefined,
      traces: event.traces?.map((trace) => ({ ...trace }))
    }));
    return {
      total: events.length,
      succeeded: events.filter((event) => event.status === "succeeded").length,
      failed: events.filter((event) => event.status === "failed").length,
      events
    };
  }

  private finish(id: string | undefined, status: "succeeded" | "failed", metadata: Record<string, unknown>, error?: string): void {
    if (!id) return;
    const event = this.events.find((item) => item.id === id);
    if (!event || event.status !== "running") return;
    const finishedAt = new Date().toISOString();
    event.status = status;
    event.finishedAt = finishedAt;
    event.elapsedMs = Math.max(0, Date.parse(finishedAt) - Date.parse(event.startedAt));
    event.metadata = { ...(event.metadata ?? {}), ...metadata };
    if (error) event.error = error;
  }
}

function tracePreview(value: string, maxChars = 600): string {
  return redactSecrets(value)
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, maxChars);
}
