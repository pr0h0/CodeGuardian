import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { writeHtmlReport } from "../../src/reports/html.js";
import { writeMarkdownReport } from "../../src/reports/markdown.js";
import { writeRuleExport } from "../../src/reports/ruleExport.js";

describe("report", () => {
  it("writes markdown", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cg-"));
    const file = writeMarkdownReport(dir, { scan: { id: "1", repo_path: ".", status: "completed" }, files: [], findings: [], scannerResults: [] });
    expect(fs.existsSync(file)).toBe(true);
  });

  it("renders AI token usage and cost in markdown", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cg-"));
    const file = writeMarkdownReport(dir, {
      scan: { id: "1", repo_path: ".", status: "completed", model: "low:cheap / medium:balanced / high:hard" },
      files: [],
      findings: [],
      scannerResults: [],
      aiBudget: { triagedScannerResults: 2, triageTargetCodeFindings: 1, triageContextChars: 1000, estimatedTriageTokens: 250 },
      aiUsage: [{
        tier: "medium",
        provider: "openrouter",
        model: "balanced",
        requests: 2,
        inputTokens: 1200,
        outputTokens: 300,
        totalTokens: 1500,
        cachedInputTokens: 200,
        cachedInputCostUsd: 0.0002,
        inputCostUsd: 0.001,
        outputCostUsd: 0.002,
        costUsd: 0.003
      }]
    });
    const content = fs.readFileSync(file, "utf8");
    expect(content).toContain("| Tier | Provider | Model | Requests | Input tokens | Cached input tokens | Output tokens | Total tokens | Input cost USD | Cached input cost USD | Output cost USD | Total cost USD |");
    expect(content).toContain("| medium | openrouter | balanced | 2 | 1200 | 200 | 300 | 1500 | 0.001000 | 0.000200 | 0.002000 | 0.003000 |");
  });

  it("escapes html tags in markdown output", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cg-"));
    const file = writeMarkdownReport(dir, {
      scan: { id: "1", repo_path: ".", status: "completed" },
      files: [],
      findings: [{
        title: "<script>alert(1)</script>",
        category: "xss",
        severity: "high",
        confidence: "high",
        status: "confirmed",
        path: "app.ts",
        start_line: 1,
        reasoning: "<img src=x onerror=alert(1)>",
        remediation: "escape < and >",
        evidence_json: "[]"
      }],
      scannerResults: []
    });
    const content = fs.readFileSync(file, "utf8");
    expect(content).toContain("&lt;script&gt;");
    expect(content).not.toContain("<script>");
  });

  it("keeps raw html readable inside fenced evidence snippets", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "cg-repo-"));
    fs.writeFileSync(path.join(root, "view.html"), "<div class=\"x\">Tom & Jerry</div>\n<script>alert(1)</script>\n");
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cg-"));
    const file = writeMarkdownReport(dir, {
      scan: { id: "1", repo_path: root, status: "completed" },
      files: [],
      findings: [{
        title: "Raw HTML example",
        category: "xss",
        severity: "medium",
        confidence: "medium",
        status: "confirmed",
        path: "view.html",
        start_line: 1,
        end_line: 1,
        reasoning: "snippet should be readable",
        remediation: "escape output",
        evidence_json: "[]"
      }],
      scannerResults: []
    });
    const content = fs.readFileSync(file, "utf8");
    expect(content).toContain("<div class=\"x\">Tom & Jerry</div>");
    expect(content).not.toContain("&amp; Jerry");
  });

  it("renders collapsible report sections and finding items", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cg-"));
    const file = writeMarkdownReport(dir, {
      scan: { id: "1", repo_path: ".", status: "completed" },
      files: [],
      findings: [{
        title: "Command injection",
        category: "command-injection",
        severity: "high",
        confidence: "high",
        status: "confirmed",
        path: "app.ts",
        start_line: 1,
        reasoning: "exec receives request input",
        remediation: "avoid shell execution",
        evidence_json: "[]"
      }],
      scannerResults: []
    });
    const content = fs.readFileSync(file, "utf8");
    expect(content).toContain("<details open>");
    expect(content).toContain("<details>");
    expect(content).toContain("<summary><strong>Confirmed Code Findings (1 items)</strong></summary>");
    expect(content).toContain("<summary><strong>1. high Command injection @app.ts:1</strong></summary>");
  });

  it("applies report filters to the main findings view", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cg-"));
    const file = writeMarkdownReport(dir, {
      scan: { id: "1", repo_path: ".", status: "completed" },
      files: [],
      findings: [
        {
          title: "Low confidence XSS",
          category: "xss",
          severity: "medium",
          confidence: "low",
          status: "suspected",
          path: "app.ts",
          start_line: 1,
          reasoning: "weak evidence",
          remediation: "validate output encoding",
          evidence_json: "[]"
        },
        {
          title: "Confirmed SSRF",
          category: "ssrf",
          severity: "high",
          confidence: "high",
          status: "confirmed_true_positive",
          path: "fetch.ts",
          start_line: 2,
          reasoning: "request URL reaches fetch",
          remediation: "allowlist hosts",
          evidence_json: "[]"
        }
      ],
      scannerResults: [],
      projectConfig: {
        reportFilters: {
          minSeverity: "medium",
          minConfidence: "medium",
          guidance: "Drop weak browser-header findings."
        }
      }
    });

    const content = fs.readFileSync(file, "utf8");
    expect(content).toContain("Confirmed SSRF");
    expect(content).not.toContain("Low confidence XSS");
    expect(content).toContain("- Report-filtered findings: 1");
    expect(content).toContain("- Report guidance: Drop weak browser-header findings.");
  });

  it("renders scan strategy metadata", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cg-"));
    const file = writeMarkdownReport(dir, {
      scan: { id: "1", repo_path: ".", status: "completed" },
      files: [],
      findings: [],
      scannerResults: [],
      scanStrategy: {
        focusPaths: ["src/routes/**"],
        avoidPaths: ["tests/**"],
        vulnerabilityClasses: ["injection", "ssrf"],
        rulesOfEngagement: "No destructive requests.",
        reportFilters: { minSeverity: "high", minConfidence: "medium" }
      }
    });

    const content = fs.readFileSync(file, "utf8");
    expect(content).toContain("Scan Strategy");
    expect(content).toContain("- Focus paths: src/routes/**");
    expect(content).toContain("- Avoid paths: tests/**");
    expect(content).toContain("- Vulnerability classes: injection, ssrf");
    expect(content).toContain("- Rules of engagement: configured");
  });

  it("renders static recon and static proof packs", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cg-"));
    const file = writeMarkdownReport(dir, {
      scan: { id: "1", repo_path: ".", status: "completed" },
      files: [],
      findings: [],
      scannerResults: [],
      staticRecon: {
        summary: "1 endpoint, 1 guard, 1 input.",
        endpoints: [{ method: "GET", routePath: "/api/documents/:documentId", path: "src/server.ts", line: 1, objectIdParameters: ["documentId"] }],
        guards: [{ kind: "guard", path: "src/server.ts", line: 1, detail: "requireAuth" }],
        inputVectors: [{ kind: "request-input", path: "src/server.ts", line: 2, detail: "req.params.documentId" }],
        sinks: [{ kind: "database-read", path: "src/server.ts", line: 3, detail: "Document.findById" }],
        boundaries: [],
        invariants: []
      },
      staticProofPacks: [{
        id: "p1",
        title: "Tenant object read lacks ownership guard",
        category: "authz",
        severity: "high",
        confidence: "high",
        status: "confirmed_true_positive",
        location: "src/server.ts:1",
        source: "req.params.documentId",
        sink: "Document.findById",
        evidence: ["Document.findById(req.params.documentId)"],
        missingControl: "No tenant ownership check.",
        exploitPreconditions: ["authenticated user"],
        safeRegressionGuidance: ["Add cross-tenant unit test."],
        confidenceBlockers: ["No runtime validation."],
        runtimeValidated: false
      }]
    });

    const content = fs.readFileSync(file, "utf8");
    expect(content).toContain("Static Recon");
    expect(content).toContain("Endpoint: GET /api/documents/:documentId");
    expect(content).toContain("Static Proof Packs");
    expect(content).toContain("Runtime validated: no - SAST/static evidence only");
    expect(content).toContain("No tenant ownership check.");
  });

  it("exports semgrep-style rules for true positives", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cg-"));
    const file = writeRuleExport(dir, {
      findings: [{
        title: "Command injection",
        category: "command-injection",
        severity: "high",
        confidence: "high",
        status: "confirmed_true_positive",
        path: "app.ts",
        start_line: 10
      }]
    }, "report");

    expect(file).toBeTruthy();
    const content = fs.readFileSync(file!, "utf8");
    expect(content).toContain("rules:");
    expect(content).toContain("codeguardian.command-injection.command-injection");
    expect(content).toContain("exec");
  });

  it("renders additional SAST findings as a table", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cg-"));
    const file = writeMarkdownReport(dir, {
      scan: { id: "1", repo_path: ".", status: "completed" },
      files: [],
      findings: [],
      scannerResults: [{
        scanner: "semgrep",
        rule_id: "javascript.lang.security.audit.detect-eval-with-expression",
        title: "Use of eval",
        category: "code-injection",
        severity: "high",
        path: "src/app.ts",
        start_line: 12,
        message: "eval with dynamic input"
      }]
    });

    const content = fs.readFileSync(file, "utf8");
    expect(content).toContain("| Severity | Rule | Category | Count | Reason | Primary file | Examples |");
    expect(content).toContain("| high | semgrep/javascript.lang.security.audit.detect-eval-with-expression | code-injection | 1 | Use of eval | src/app.ts:12 | src/app.ts:12 |");
  });

  it("renders compliance evidence outside additional SAST findings", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cg-"));
    const file = writeMarkdownReport(dir, {
      scan: { id: "1", repo_path: ".", status: "completed" },
      files: [],
      findings: [],
      scannerResults: [{
        scanner: "compliance",
        rule_id: "compliance-auth-access-control",
        title: "PASS: Access control evidence",
        category: "compliance",
        severity: "info",
        path: "src/auth.ts",
        start_line: 1,
        message: "auth evidence",
        raw_json: JSON.stringify({
          status: "pass",
          frameworks: ["SOC 2", "ISO 27001"],
          controlIds: ["SOC2 CC6.1", "ISO27001 A.5.15"],
          evidence: [{ path: "src/auth.ts", line: 1, note: "requireAuth" }],
          remediation: "document controls"
        })
      }]
    });

    const content = fs.readFileSync(file, "utf8");
    expect(content).toContain("Compliance Evidence");
    expect(content).toContain("| pass | compliance-auth-access-control: Access control evidence | SOC2 CC6.1, ISO27001 A.5.15, SOC 2, ISO 27001 |");
    expect(content).toContain("No additional SAST findings outside promoted code findings.");
  });

  it("renders attack chains outside additional SAST findings", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cg-"));
    const file = writeMarkdownReport(dir, {
      scan: { id: "1", repo_path: ".", status: "completed" },
      files: [],
      findings: [],
      scannerResults: [{
        scanner: "correlation",
        rule_id: "prototype-pollution-to-eta-rce",
        title: "Prototype pollution can enable Eta template RCE",
        category: "rce",
        severity: "critical",
        path: "src/app.ts",
        start_line: 10,
        message: "chain",
        raw_json: JSON.stringify({
          attackChain: {
            kind: "prototype-pollution-rce",
            impact: "Possible remote code execution",
            confidence: "medium",
            steps: ["pollute prototype", "render through eta"],
            validation: ["stub process APIs"]
          },
          evidence: [{ path: "src/app.ts", line: 10, note: "merge(defaults, req.body)" }],
          relatedFindings: [{ scanner: "custom-rules", ruleId: "js-prototype-pollution-unsafe-merge", severity: "high", title: "merge", path: "src/app.ts", startLine: 10 }]
        })
      }]
    });

    const content = fs.readFileSync(file, "utf8");
    expect(content).toContain("Attack Chains");
    expect(content).toContain("Possible remote code execution");
    expect(content).toContain("No additional SAST findings outside promoted code findings.");
  });

  it("writes searchable html report", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cg-"));
    const file = writeHtmlReport(dir, {
      scan: { id: "1", repo_path: ".", status: "completed" },
      files: [{ indexed: 1 }],
      findings: [{
        title: "Command injection",
        category: "command-injection",
        severity: "high",
        confidence: "high",
        status: "likely_true_positive",
        path: "src/app.ts",
        start_line: 12,
        reasoning: "exec receives request input",
        remediation: "avoid shell execution"
      }],
      scannerResults: [{
        scanner: "semgrep",
        rule_id: "eval",
        title: "Use of eval",
        category: "code-injection",
        severity: "medium",
        path: "src/eval.ts",
        start_line: 3
      }],
      aiUsage: [{
        tier: "low",
        provider: "openai",
        model: "cheap",
        requests: 1,
        inputTokens: 100,
        outputTokens: 20,
        totalTokens: 120,
        inputCostUsd: null,
        outputCostUsd: null,
        costUsd: 0.0001
      }]
    });

    const content = fs.readFileSync(file, "utf8");
    expect(file.endsWith(".html")).toBe(true);
    expect(content).toContain("<!doctype html>");
    expect(content).toContain("CodeGuardian Security Report");
    expect(content).toContain("id=\"search\"");
    expect(content).toContain("Command injection");
    expect(content).toContain("Additional SAST Findings");
    expect(content).toContain("AI Usage");
    expect(content).toContain("0.000100");
  });

  it("renders html with sticky header for navigation", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cg-"));
    const file = writeHtmlReport(dir, {
      scan: { id: "1", repo_path: ".", status: "completed" },
      files: [],
      findings: [],
      scannerResults: [{
        scanner: "semgrep",
        rule_id: "eval",
        title: "Use of eval",
        category: "code-injection",
        severity: "medium",
        path: "src/eval.ts",
        start_line: 3
      }]
    });

    const content = fs.readFileSync(file, "utf8");
    expect(content).toMatch(/header\s*\{[^}]*position\s*:\s*sticky/);
    expect(content).not.toMatch(/th\s*\{[^}]*position\s*:/);
    expect(content).not.toMatch(/th\s*\{[^}]*top\s*:/);
  });
});
