import { describe, expect, it } from "vitest";
import { runExploratoryAudit } from "../../src/ai/audit.js";
import type { AiCompletionInput, AiProvider } from "../../src/ai/types.js";
import type { IndexedFile } from "../../src/repo/repoIndexer.js";

function file(path: string, language: string, content: string): IndexedFile {
  return { path, absolutePath: path, language, content, lineCount: content.split(/\r?\n/).length };
}

class FakeProvider implements AiProvider {
  name = "fake";
  calls: AiCompletionInput[] = [];
  private index = 0;

  constructor(private readonly response: unknown | unknown[]) {}

  async complete(input: AiCompletionInput) {
    this.calls.push({ ...input, messages: input.messages.map((message) => ({ ...message })) });
    const response = Array.isArray(this.response) ? this.response[Math.min(this.index++, this.response.length - 1)] : this.response;
    return { text: JSON.stringify(response), raw: {} };
  }
}

describe("AI exploratory audit", () => {
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
});
