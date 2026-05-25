import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { AiJobRecorder } from "../../src/ai/jobs.js";
import { writeMarkdownReport } from "../../src/reports/markdown.js";

describe("AI job tracing", () => {
  it("records AI job lifecycle events and aggregate counts", () => {
    const recorder = new AiJobRecorder();
    const successId = recorder.start("triage", "custom-rules/js-eval", { tier: "medium" });
    recorder.succeed(successId, { findings: 1 });
    const failureId = recorder.start("audit", "round 1");
    recorder.fail(failureId, new Error("provider timeout"));

    const summary = recorder.summary();

    expect(summary.total).toBe(2);
    expect(summary.succeeded).toBe(1);
    expect(summary.failed).toBe(1);
    expect(summary.events[0]).toEqual(expect.objectContaining({ type: "triage", label: "custom-rules/js-eval", status: "succeeded" }));
    expect(summary.events[1]).toEqual(expect.objectContaining({ type: "audit", label: "round 1", status: "failed", error: "provider timeout" }));
  });

  it("records compact redacted prompt and response traces for a job", () => {
    const recorder = new AiJobRecorder();
    const jobId = recorder.start("triage", "custom-rules/js-eval");

    recorder.trace(jobId, {
      label: "triage",
      prompt: "OPENAI_API_KEY=sk-proj_abcdefghijklmnopqrstuvwxyz",
      response: "{\"ok\":true}"
    });

    const trace = recorder.summary().events[0].traces?.[0];
    expect(trace).toMatchObject({
      label: "triage",
      promptChars: 49,
      responseChars: 11,
      responsePreview: "{\"ok\":true}"
    });
    expect(trace?.promptPreview).toContain("[REDACTED]");
    expect(trace?.promptPreview).not.toContain("sk-proj");
  });

  it("renders AI job summaries in markdown reports", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cg-ai-jobs-"));
    const file = writeMarkdownReport(dir, {
      scan: { id: "1", repo_path: ".", status: "completed" },
      files: [],
      findings: [],
      scannerResults: [],
      aiJobs: {
        total: 2,
        succeeded: 1,
        failed: 1,
        events: [
          { id: "1", type: "triage", label: "one", status: "succeeded", startedAt: "t1", finishedAt: "t2", elapsedMs: 10 },
          { id: "2", type: "audit", label: "two", status: "failed", startedAt: "t3", finishedAt: "t4", elapsedMs: 20, error: "bad json" }
        ]
      }
    });

    const content = fs.readFileSync(file, "utf8");
    expect(content).toContain("AI Jobs");
    expect(content).toContain("- Total jobs: 2");
    expect(content).toContain("| audit | failed | two | 20 | bad json |");
  });
});
