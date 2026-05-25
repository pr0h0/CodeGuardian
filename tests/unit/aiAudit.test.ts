import { describe, expect, it } from "vitest";
import { runExploratoryAudit, runTargetedExploratoryAudit } from "../../src/ai/audit.js";
import { auditResponseJsonSchema, auditResponseJsonSchemaForClasses } from "../../src/ai/schemas.js";
import type { AiCompletionInput, AiProvider } from "../../src/ai/types.js";
import type { IndexedFile } from "../../src/repo/repoIndexer.js";
import type { ScannerResult } from "../../src/scanners/types.js";

function file(path: string, language: string, content: string): IndexedFile {
  return { path, absolutePath: path, language, content, lineCount: content.split(/\r?\n/).length };
}

function scannerResult(overrides: Partial<ScannerResult>): ScannerResult {
  return {
    scanner: "source-patterns",
    ruleId: "source-xxe-unsafe-parser",
    title: "XML parser expands entities for user-controlled XML",
    category: "xxe",
    severity: "high",
    path: "routes/fileUpload.ts",
    startLine: 2,
    endLine: 2,
    message: "libxml.parseXml(data, { noent: true })",
    ...overrides
  };
}

function auditFinding(overrides: Record<string, unknown> = {}) {
  return {
    title: "Command injection",
    category: "command-injection",
    severity: "high",
    confidence: "high",
    status: "suspected",
    path: "src/server.ts",
    startLine: 2,
    endLine: 2,
    source: "req.query.cmd",
    sourceLine: 2,
    sink: "exec",
    sinkLine: 2,
    dataFlow: [{ path: "src/server.ts", line: 2, step: "req.query.cmd -> exec" }],
    missingControl: "argument allowlist",
    exploitPreconditions: ["attacker reaches route"],
    safeRepro: ["send harmless command string"],
    evidence: [{ path: "src/server.ts", line: 2, note: "exec uses request query" }],
    reasoning: "request query reaches exec",
    remediation: "remove shell execution",
    ...overrides
  };
}

class FakeProvider implements AiProvider {
  name = "fake";
  calls: AiCompletionInput[] = [];
  private index = 0;

  constructor(private readonly response: unknown | unknown[]) {}

  async complete(input: AiCompletionInput) {
    this.calls.push({ ...input, messages: input.messages.map((message) => ({ ...message })) });
    const response = Array.isArray(this.response) ? this.response[Math.min(this.index++, this.response.length - 1)] : this.response;
    return { text: typeof response === "string" ? response : JSON.stringify(response), raw: {} };
  }
}

describe("AI exploratory audit", () => {
  it("runs configured vulnerability classes as separate class-scoped audit passes", async () => {
    const provider = new FakeProvider({ summary: "done", requestedFiles: [], toolCalls: [], complete: true, findings: [] });

    await runTargetedExploratoryAudit(
      provider,
      [file("src/server.ts", "typescript", "app.get('/x', (_req, res) => res.send('ok'));")],
      [],
      { maxFiles: 10, maxRounds: 4, maxChars: 50000, vulnerabilityClasses: ["ssrf", "xss"] }
    );

    expect(provider.calls).toHaveLength(3);
    expect(provider.calls.map((call) => (call.jsonSchema as any).name)).toEqual([
      "exploratory_audit_source_map",
      "exploratory_audit_response_ssrf",
      "exploratory_audit_response_xss"
    ]);
  });

  it("uses a targeted default class schedule when no vulnerability classes are configured", async () => {
    const provider = new FakeProvider({ summary: "done", requestedFiles: [], toolCalls: [], complete: true, findings: [] });

    await runTargetedExploratoryAudit(
      provider,
      [file("src/server.ts", "typescript", "app.get('/x', (_req, res) => res.send('ok'));")],
      [],
      { maxFiles: 10, maxRounds: 5, maxChars: 50000 }
    );

    expect(provider.calls.length).toBeGreaterThan(1);
    expect(provider.calls.map((call) => (call.jsonSchema as any).name)).toContain("exploratory_audit_response_auth");
    expect(provider.calls.map((call) => (call.jsonSchema as any).name)).toContain("exploratory_audit_response_ssrf");
  });

  it("runs a source-map pass and feeds source-map notes into class audits", async () => {
    const provider = new FakeProvider([
      {
        summary: "express admin surface",
        globalPriorityFiles: ["src/admin.ts"],
        priorityFilesByClass: { auth: ["src/auth.ts"] },
        notes: ["admin routes need auth review"],
        catalog: {
          sources: [{ name: "req.user", path: "src/admin.ts", line: 1, category: "session", evidence: "custom source" }],
          sinks: [],
          sanitizers: [],
          guards: [{ name: "requireAuth", path: "src/auth.ts", line: 1, category: "auth", evidence: "custom guard" }]
        }
      },
      { summary: "done", requestedFiles: [], toolCalls: [], complete: true, findings: [] }
    ]);
    const artifacts: any[] = [];

    await runTargetedExploratoryAudit(
      provider,
      [
        file("src/admin.ts", "typescript", "app.get('/admin', requireAuth, adminHandler);"),
        file("src/auth.ts", "typescript", "export function requireAuth(req, res, next) { next(); }")
      ],
      [],
      {
        maxFiles: 2,
        maxRounds: 1,
        maxChars: 40000,
        vulnerabilityClasses: ["auth"],
        artifactRecorder: {
          record: (event) => artifacts.push(event)
        }
      }
    );

    expect((provider.calls[0].jsonSchema as any).name).toBe("exploratory_audit_source_map");
    expect(provider.calls[1].messages[0].content).toContain("AI source map");
    expect(provider.calls[1].messages[0].content).toContain("admin routes need auth review");
    expect(provider.calls[1].messages[0].content).toContain("requireAuth");
    expect(provider.calls[1].messages.at(-1)?.content).toContain("src/auth.ts");
    expect(artifacts).toEqual(expect.arrayContaining([
      expect.objectContaining({ kind: "source-map", sourceMap: expect.objectContaining({ catalog: expect.objectContaining({ guards: expect.any(Array) }) }) }),
      expect.objectContaining({ kind: "class-complete", vulnerabilityClass: "auth" })
    ]));
  });

  it("uses deterministic source-pattern seeds as priority files for class-scoped audits", async () => {
    const provider = new FakeProvider([
      { summary: "empty map", globalPriorityFiles: [], priorityFilesByClass: {}, notes: [] },
      { summary: "done", requestedFiles: [], toolCalls: [], complete: true, findings: [] }
    ]);

    await runTargetedExploratoryAudit(
      provider,
      [
        file("src/server.ts", "typescript", "app.get('/health', (_req, res) => res.send('ok'));"),
        file("routes/fileUpload.ts", "typescript", [
          "const data = req.file.buffer.toString();",
          "libxml.parseXml(data, { noent: true });"
        ].join("\n"))
      ],
      [scannerResult({})],
      { maxFiles: 2, maxRounds: 1, maxChars: 40000, vulnerabilityClasses: ["xxe"] }
    );

    expect(provider.calls[0].messages[0].content).toContain("Static scanner seed files");
    expect(provider.calls[0].messages[0].content).toContain("routes/fileUpload.ts");
    expect(provider.calls[1].messages.at(-1)?.content).toContain("routes/fileUpload.ts");
  });

  it("retries invalid source-map JSON before falling back to breadth-first audit", async () => {
    const provider = new FakeProvider([
      "{ \"summary\": \"truncated",
      { summary: "express admin surface", globalPriorityFiles: ["src/admin.ts"], priorityFilesByClass: { auth: ["src/auth.ts"] }, notes: ["retry source map worked"] },
      { summary: "done", requestedFiles: [], toolCalls: [], complete: true, findings: [] }
    ]);

    await runTargetedExploratoryAudit(
      provider,
      [
        file("src/admin.ts", "typescript", "app.get('/admin', requireAuth, adminHandler);"),
        file("src/auth.ts", "typescript", "export function requireAuth(req, res, next) { next(); }")
      ],
      [],
      { maxFiles: 2, maxRounds: 1, maxChars: 40000, vulnerabilityClasses: ["auth"] }
    );

    expect(provider.calls.map((call) => (call.jsonSchema as any).name)).toEqual([
      "exploratory_audit_source_map",
      "exploratory_audit_source_map",
      "exploratory_audit_response_auth"
    ]);
    expect(provider.calls[1].messages[0].content).toContain("Previous source-map response was invalid");
    expect(provider.calls[2].messages[0].content).toContain("retry source map worked");
  });

  it("salvages valid source-map fields when optional catalog items are malformed", async () => {
    const provider = new FakeProvider([
      {
        summary: "express admin surface",
        globalPriorityFiles: ["src/admin.ts"],
        priorityFilesByClass: { auth: ["src/auth.ts"] },
        notes: ["salvaged source map worked"],
        catalog: {
          sources: [{ name: "req.user", path: "src/admin.ts" }],
          sinks: "none",
          sanitizers: [],
          guards: [{ name: "requireAuth", path: "src/auth.ts", line: 1, category: "auth", evidence: "middleware" }]
        }
      },
      { summary: "done", requestedFiles: [], toolCalls: [], complete: true, findings: [] }
    ]);

    await runTargetedExploratoryAudit(
      provider,
      [
        file("src/admin.ts", "typescript", "app.get('/admin', requireAuth, adminHandler);"),
        file("src/auth.ts", "typescript", "export function requireAuth(req, res, next) { next(); }")
      ],
      [],
      { maxFiles: 2, maxRounds: 1, maxChars: 40000, vulnerabilityClasses: ["auth"] }
    );

    expect(provider.calls).toHaveLength(2);
    expect(provider.calls[1].messages[0].content).toContain("salvaged source map worked");
    expect(provider.calls[1].messages[0].content).toContain("requireAuth");
  });

  it("retries empty audit responses instead of accepting a repaired empty object", async () => {
    const provider = new FakeProvider([
      "",
      { summary: "retry produced a usable response", requestedFiles: [], toolCalls: [], complete: true, findings: [] }
    ]);

    await runExploratoryAudit(
      provider,
      [file("src/server.ts", "typescript", "app.get('/x', (_req, res) => res.send('ok'));")],
      [],
      { maxFiles: 1, maxRounds: 1, maxChars: 20000 }
    );

    expect(provider.calls).toHaveLength(2);
    expect(provider.calls[1].messages.at(-1)?.content).toContain("Previous audit response was invalid or empty");
  });

  it("validates AI audit findings in a second pass before returning them", async () => {
    const provider = new FakeProvider([
      {
        summary: "finding",
        requestedFiles: [],
        toolCalls: [],
        complete: true,
        hypotheses: [
          { id: "h1", vulnerabilityClass: "injection", title: "Command injection", path: "src/server.ts", source: "req.query.cmd", sink: "exec", evidence: [{ path: "src/server.ts", line: 2, note: "source reaches sink" }], status: "candidate", reason: "needs validation" }
        ],
        rejectedHypotheses: [
          { id: "r1", title: "Safe redirect", path: "src/server.ts", reason: "local URL only" }
        ],
        findings: [auditFinding()]
      },
      {
        decisions: [
          { findingIndex: 0, verdict: "keep", revisedStatus: "confirmed_true_positive", revisedConfidence: "high", reasons: ["source, sink, and missing control are visible"] }
        ]
      }
    ]);

    const findings = await runExploratoryAudit(
      provider,
      [file("src/server.ts", "typescript", ["app.get('/run', (req, res) => {", "exec(req.query.cmd);", "});"].join("\n"))],
      [],
      { maxFiles: 1, maxRounds: 1, maxChars: 20000, validationPass: true }
    );

    expect(provider.calls).toHaveLength(2);
    expect((provider.calls[1].jsonSchema as any).name).toBe("exploratory_audit_validation");
    expect(findings[0].status).toBe("confirmed_true_positive");
    expect(findings[0].confidence).toBe("high");
    expect(findings[0].reasoning).toContain("AI validation: source, sink, and missing control are visible");
  });

  it("salvages valid findings from a malformed AI audit response with invalid sibling findings", async () => {
    const provider = new FakeProvider([
      {
        summary: "mixed findings",
        requestedFiles: [],
        toolCalls: [],
        complete: true,
        findings: [
          auditFinding(),
          auditFinding({
            title: "Invalid category sibling",
            category: "made-up-category"
          })
        ]
      }
    ]);

    const findings = await runExploratoryAudit(
      provider,
      [file("src/server.ts", "typescript", ["app.get('/run', (req, res) => {", "exec(req.query.cmd);", "});"].join("\n"))],
      [],
      { maxFiles: 1, maxRounds: 1, maxChars: 20000 }
    );

    expect(provider.calls).toHaveLength(1);
    expect(findings).toHaveLength(1);
    expect(findings[0].title).toBe("Command injection");
  });

  it("rejects template-only XSS findings when no route or render call reaches the template", async () => {
    const provider = new FakeProvider([
      {
        summary: "template finding",
        requestedFiles: [],
        toolCalls: [],
        complete: true,
        findings: [
          auditFinding({
            title: "Stored XSS in email template",
            category: "xss",
            path: "backend/views/email.ejs",
            startLine: 1,
            endLine: 1,
            source: "stored html",
            sourceLine: 1,
            sink: "EJS raw output",
            sinkLine: 1,
            dataFlow: [{ path: "backend/views/email.ejs", line: 1, step: "html rendered raw" }],
            evidence: [{ path: "backend/views/email.ejs", line: 1, note: "raw html output" }],
            reasoning: "template renders stored html"
          })
        ]
      }
    ]);

    const findings = await runExploratoryAudit(
      provider,
      [file("backend/views/email.ejs", "ejs", "<%- html %>")],
      [],
      { maxFiles: 1, maxRounds: 1, maxChars: 20000, vulnerabilityClasses: ["xss"] }
    );

    expect(findings).toHaveLength(0);
  });

  it("does not divide maxRounds across configured classes", async () => {
    const provider = new FakeProvider([
      { summary: "map", globalPriorityFiles: ["src/server.ts"], priorityFilesByClass: {}, notes: [] },
      { summary: "round 1", requestedFiles: [], toolCalls: [{ type: "read_file", path: "src/server.ts", startLine: 220, endLine: 220, reason: "next auth slice" }], complete: false, findings: [] },
      { summary: "round 2", requestedFiles: [], toolCalls: [{ type: "read_file", path: "src/server.ts", startLine: 400, endLine: 400, reason: "final auth slice" }], complete: false, findings: [] },
      { summary: "round 3", requestedFiles: [], toolCalls: [], complete: true, findings: [] },
      { summary: "round 1", requestedFiles: [], toolCalls: [{ type: "read_file", path: "src/server.ts", startLine: 220, endLine: 220, reason: "next xss slice" }], complete: false, findings: [] },
      { summary: "round 2", requestedFiles: [], toolCalls: [{ type: "read_file", path: "src/server.ts", startLine: 400, endLine: 400, reason: "final xss slice" }], complete: false, findings: [] },
      { summary: "round 3", requestedFiles: [], toolCalls: [], complete: true, findings: [] }
    ]);
    const content = Array.from({ length: 460 }, (_, index) => index === 0 ? "app.get('/x', handler);" : `const value${index} = ${index};`).join("\n");

    await runTargetedExploratoryAudit(
      provider,
      [file("src/server.ts", "typescript", content)],
      [],
      { maxFiles: 2, maxRounds: 3, maxChars: 80000, vulnerabilityClasses: ["auth", "xss"], maxRequestChars: 18000 }
    );

    expect(provider.calls.map((call) => (call.jsonSchema as any).name)).toEqual([
      "exploratory_audit_source_map",
      "exploratory_audit_response_auth",
      "exploratory_audit_response_auth",
      "exploratory_audit_response_auth",
      "exploratory_audit_response_xss",
      "exploratory_audit_response_xss",
      "exploratory_audit_response_xss"
    ]);
  });

  it("builds class-scoped structured output schemas for focused audits", () => {
    const schema = auditResponseJsonSchemaForClasses(["ssrf"]);
    const categoryEnum = (((schema.schema.properties as any).findings.items.properties.category.enum) ?? []) as string[];
    const baseCategoryEnum = (((auditResponseJsonSchema.schema.properties as any).findings.items.properties.category.enum) ?? []) as string[];

    expect(schema.name).toBe("exploratory_audit_response_ssrf");
    expect(categoryEnum).toEqual(["ssrf"]);
    expect(baseCategoryEnum).toContain("xss");
  });

  it("passes the class-scoped schema to provider calls when vulnerability classes are configured", async () => {
    const provider = new FakeProvider({ summary: "done", requestedFiles: [], toolCalls: [], complete: true, findings: [] });

    await runExploratoryAudit(
      provider,
      [file("src/server.ts", "typescript", "app.get('/x', (_req, res) => res.send('ok'));")],
      [],
      { maxFiles: 1, maxRounds: 1, maxChars: 20000, vulnerabilityClasses: ["ssrf"] }
    );

    const categoryEnum = ((((provider.calls[0].jsonSchema as any).schema.properties as any).findings.items.properties.category.enum) ?? []) as string[];
    expect(categoryEnum).toEqual(["ssrf"]);
  });

  it("uses deterministic initial source targets instead of asking AI to choose files", async () => {
    const provider = new FakeProvider({ summary: "done", requestedFiles: [], complete: true, findings: [] });

    await runExploratoryAudit(
      provider,
      [
        file("src/server.ts", "typescript", [
          "import express from 'express';",
          "const app = express();",
          "app.get('/health', (_req, res) => res.send('ok'));"
        ].join("\n"))
      ],
      [],
      { maxFiles: 3, maxRounds: 1, maxChars: 20000 }
    );

    expect(provider.calls).toHaveLength(1);
    expect(provider.calls[0].messages.at(-1)?.content).toContain("Source pack");
    expect(provider.calls[0].messages.at(-1)?.content).toContain("src/server.ts");
  });

  it("drops findings that are not supported by inspected source", async () => {
    const provider = new FakeProvider({
      summary: "bad finding",
      requestedFiles: [],
      complete: true,
      findings: [
        {
          title: "Invented issue",
          category: "ssrf",
          severity: "high",
          confidence: "high",
          status: "suspected",
          path: "src/not-inspected.ts",
          startLine: 1,
          endLine: 1,
          source: "request parameter",
          sourceLine: 1,
          sink: "fetch",
          sinkLine: 1,
          dataFlow: [{ path: "src/not-inspected.ts", line: 1, step: "param -> fetch" }],
          missingControl: "allowlist",
          exploitPreconditions: ["attacker controls URL"],
          safeRepro: ["inspect route"],
          evidence: [{ path: "src/not-inspected.ts", line: 1, note: "not supplied" }],
          reasoning: "not supported by source pack",
          remediation: "validate URL"
        }
      ]
    });

    const findings = await runExploratoryAudit(
      provider,
      [file("src/server.ts", "typescript", "app.get('/x', (_req, res) => res.send('ok'));")],
      [],
      { maxFiles: 1, maxRounds: 1, maxChars: 20000 }
    );

    expect(findings).toHaveLength(0);
  });

  it("walks local imports breadth-first after entry points", async () => {
    const provider = new FakeProvider([
      { summary: "first", requestedFiles: [], complete: true, findings: [] },
      { summary: "second", requestedFiles: [], complete: true, findings: [] }
    ]);

    await runExploratoryAudit(
      provider,
      [
        file("src/server.ts", "typescript", [
          "import { handler } from './routes/user';",
          "app.get('/user', handler);"
        ].join("\n")),
        file("src/routes/user.ts", "typescript", [
          "import { loadUser } from '../services/user';",
          "export function handler(req, res) { return loadUser(req.query.id); }"
        ].join("\n")),
        file("src/services/user.ts", "typescript", "export function loadUser(id) { return id; }")
      ],
      [],
      { maxFiles: 3, maxRounds: 2, maxChars: 20000 }
    );

    expect(provider.calls).toHaveLength(2);
    expect(provider.calls[0].messages.at(-1)?.content).toContain("src/server.ts");
    expect(provider.calls[0].messages.at(-1)?.content).not.toContain('"path": "src/services/user.ts"');
    expect(provider.calls[1].messages.at(-1)?.content).toContain('"path": "src/services/user.ts"');
  });

  it("resolves tsconfig-style aliases while spreading through imports", async () => {
    const provider = new FakeProvider([
      { summary: "first", requestedFiles: [], complete: true, findings: [] },
      { summary: "second", requestedFiles: [], complete: true, findings: [] }
    ]);

    await runExploratoryAudit(
      provider,
      [
        file("tsconfig.json", "unknown", JSON.stringify({ compilerOptions: { paths: { "@/*": ["src/*"] } } })),
        file("src/server.ts", "typescript", [
          "import { requireAuth } from '@/lib/auth';",
          "app.get('/admin', requireAuth, handler);"
        ].join("\n")),
        file("src/lib/auth.ts", "typescript", "export function requireAuth(req, res, next) { next(); }")
      ],
      [],
      { maxFiles: 2, maxRounds: 2, maxChars: 20000 }
    );

    expect(provider.calls).toHaveLength(2);
    expect(provider.calls[1].messages.at(-1)?.content).toContain('"path": "src/lib/auth.ts"');
  });

  it("sends large files as ordered chunks", async () => {
    const provider = new FakeProvider({ summary: "done", requestedFiles: [], complete: true, findings: [] });
    const content = Array.from({ length: 220 }, (_, index) => index === 0 ? "app.get('/x', handler);" : `const value${index} = ${index};`).join("\n");

    await runExploratoryAudit(
      provider,
      [file("src/server.ts", "typescript", content)],
      [],
      { maxFiles: 1, maxRounds: 1, maxChars: 50000 }
    );

    const prompt = provider.calls[0].messages.at(-1)?.content ?? "";
    expect(prompt).toContain('"chunkIndex": 1');
    expect(prompt).toContain('"chunkIndex": 2');
    expect(prompt).toContain("1: app.get('/x', handler);");
    expect(prompt).toContain("181: const value180 = 180;");
  });

  it("keeps only findings with cited evidence inside inspected chunks", async () => {
    const provider = new FakeProvider({
      summary: "finding",
      requestedFiles: [],
      complete: true,
      findings: [
        {
          title: "Command injection",
          category: "command-injection",
          severity: "high",
          confidence: "high",
          status: "suspected",
          path: "src/server.ts",
          startLine: 2,
          endLine: 2,
          source: "req.query.cmd",
          sourceLine: 2,
          sink: "exec",
          sinkLine: 2,
          dataFlow: [{ path: "src/server.ts", line: 2, step: "req.query.cmd -> exec" }],
          missingControl: "argument allowlist",
          exploitPreconditions: ["attacker reaches route"],
          safeRepro: ["send harmless command string"],
          evidence: [{ path: "src/server.ts", line: 2, note: "exec uses request query" }],
          reasoning: "request query reaches exec",
          remediation: "remove shell execution"
        },
        {
          title: "Invented bottom-half issue",
          category: "ssrf",
          severity: "high",
          confidence: "high",
          status: "suspected",
          path: "src/server.ts",
          startLine: 200,
          endLine: 200,
          source: "req.query.url",
          sourceLine: 200,
          sink: "fetch",
          sinkLine: 200,
          dataFlow: [{ path: "src/server.ts", line: 200, step: "req.query.url -> fetch" }],
          missingControl: "allowlist",
          exploitPreconditions: ["attacker controls url"],
          safeRepro: ["inspect route"],
          evidence: [{ path: "src/server.ts", line: 200, note: "not inspected" }],
          reasoning: "not supported",
          remediation: "validate URL"
        }
      ]
    });

    const findings = await runExploratoryAudit(
      provider,
      [file("src/server.ts", "typescript", ["app.get('/run', (req, res) => {", "exec(req.query.cmd);", "});"].join("\n"))],
      [],
      { maxFiles: 1, maxRounds: 1, maxChars: 20000 }
    );

    expect(findings).toHaveLength(1);
    expect(findings[0].title).toBe("Command injection");
  });

  it("fulfills AI tool calls by searching source and sending matched windows", async () => {
    const provider = new FakeProvider([
      {
        summary: "need sink",
        requestedFiles: [],
        toolCalls: [{ type: "search_symbol", symbol: "dangerousExec", reason: "confirm command sink" }],
        complete: false,
        findings: []
      },
      { summary: "done", requestedFiles: [], toolCalls: [], complete: true, findings: [] }
    ]);

    await runExploratoryAudit(
      provider,
      [
        file("src/server.ts", "typescript", [
          "import { dangerousExec } from './exec';",
          "app.get('/run', (req, res) => dangerousExec(req.query.cmd));"
        ].join("\n")),
        file("src/exec.ts", "typescript", [
          "import { exec } from 'node:child_process';",
          "export function dangerousExec(cmd) { exec(cmd); }"
        ].join("\n"))
      ],
      [],
      { maxFiles: 2, maxRounds: 2, maxChars: 50000 }
    );

    expect(provider.calls).toHaveLength(2);
    expect(provider.calls[1].messages.at(-1)?.content).toContain('"path": "src/exec.ts"');
    expect(provider.calls[1].messages.at(-1)?.content).toContain("dangerousExec");
  });

  it("keeps each audit request under a bounded context budget", async () => {
    const provider = new FakeProvider({ summary: "done", requestedFiles: [], toolCalls: [], complete: true, findings: [] });
    const files = Array.from({ length: 220 }, (_, index) => file(
      `src/routes/route${index}.ts`,
      "typescript",
      [
        "import express from 'express';",
        "const router = express.Router();",
        `router.get('/route-${index}', (req, res) => res.json({ id: req.query.id }));`,
        ...Array.from({ length: 80 }, (__, line) => `export const value${line} = '${"x".repeat(80)}';`)
      ].join("\n")
    ));

    await runExploratoryAudit(
      provider,
      files,
      [],
      { maxFiles: 20, maxRounds: 1, maxChars: 1_000_000 }
    );

    const requestChars = provider.calls[0].system.length + provider.calls[0].messages.reduce((sum, message) => sum + message.content.length, 0);
    expect(requestChars).toBeLessThanOrEqual(60_000);
  });

  it("does not resend prior source packs in later audit rounds", async () => {
    const provider = new FakeProvider([
      { summary: "first", requestedFiles: [], toolCalls: [{ type: "read_file", path: "src/second.ts", startLine: 1, endLine: 1, reason: "read exact line" }], complete: false, findings: [] },
      { summary: "second", requestedFiles: [], toolCalls: [], complete: true, findings: [] }
    ]);

    await runExploratoryAudit(
      provider,
      [
        file("src/server.ts", "typescript", "app.get('/x', handler);"),
        file("src/second.ts", "typescript", "export const second = true;")
      ],
      [],
      { maxFiles: 2, maxRounds: 2, maxChars: 20000 }
    );

    const secondRequest = provider.calls[1].messages.map((message) => message.content).join("\n");
    expect(secondRequest).toContain('"path": "src/second.ts"');
    expect(secondRequest).not.toContain("app.get('/x', handler);");
  });

  it("fulfills read_file tool calls with requested line ranges", async () => {
    const content = [
      "app.get('/start', handler);",
      ...Array.from({ length: 1198 }, (_, index) => `const filler${index} = ${index};`),
      "app.get('/run', (req, res) => {",
      "  exec(req.query.cmd);",
      "});"
    ].join("\n");
    const provider = new FakeProvider([
      { summary: "need range", requestedFiles: [], toolCalls: [{ type: "read_file", path: "src/server.ts", startLine: 1200, endLine: 1201, reason: "inspect exact sink" }], complete: false, findings: [] },
      { summary: "done", requestedFiles: [], toolCalls: [], complete: true, findings: [] }
    ]);

    await runExploratoryAudit(
      provider,
      [file("src/server.ts", "typescript", content)],
      [],
      { maxFiles: 1, maxRounds: 2, maxChars: 20000 }
    );

    const prompt = provider.calls[1].messages.at(-1)?.content ?? "";
    expect(prompt).toContain('"startLine": 1200');
    expect(prompt).toContain('"endLine": 1201');
    expect(prompt).toContain("1200: app.get('/run'");
    expect(prompt).toContain("1201:   exec(req.query.cmd);");
    expect(prompt).not.toContain("1: app.get('/start', handler);");
  });
});
