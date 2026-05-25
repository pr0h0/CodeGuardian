import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { prepareReportBundle } from "../../src/reports/model.js";
import { writeMarkdownReport } from "../../src/reports/markdown.js";
import type { IndexedFile } from "../../src/repo/repoIndexer.js";

function indexedFile(filePath: string, content: string): IndexedFile {
  return {
    path: filePath,
    absolutePath: `/missing/${filePath}`,
    language: "typescript",
    content,
    lineCount: content.split(/\r?\n/).length
  };
}

describe("report model", () => {
  it("renders prepared source snippets and dependency usage without rereading repository files", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cg-report-model-"));
    const bundle = prepareReportBundle({
      scan: { id: "1", repo_path: "/repo/that/is/not/on/disk", status: "completed" },
      files: [],
      findings: [{
        title: "Command injection",
        category: "command-injection",
        severity: "high",
        confidence: "high",
        status: "confirmed",
        path: "src/app.ts",
        start_line: 2,
        end_line: 2,
        source: "req.query.cmd",
        sink: "exec",
        reasoning: "exec receives request input",
        remediation: "avoid shell execution",
        evidence_json: "[]"
      }],
      scannerResults: [{
        scanner: "trivy",
        rule_id: "CVE-0000-0001",
        title: "eta vulnerable",
        category: "dependency",
        severity: "high",
        path: "package-lock.json",
        message: "vulnerable dependency",
        raw_json: JSON.stringify({ VulnerabilityID: "CVE-0000-0001", PkgName: "eta" })
      }]
    }, [
      indexedFile("src/app.ts", "const cmd = req.query.cmd;\nexec(cmd);\n"),
      indexedFile("src/views.ts", "import eta from 'eta';\neta.render('x', {});\n")
    ]);

    const file = writeMarkdownReport(dir, bundle, [], "report");
    const markdown = fs.readFileSync(file, "utf8");

    expect(markdown).toContain("2 | exec(cmd);");
    expect(markdown).toContain("src/views.ts:1 - import eta from 'eta';");
  });

  it("does not count plain identifiers or strings as dependency usage", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cg-report-model-deps-"));
    const bundle = prepareReportBundle({
      scan: { id: "1", repo_path: "/repo/that/is/not/on/disk", status: "completed" },
      files: [],
      findings: [],
      scannerResults: [
        {
          scanner: "trivy",
          rule_id: "CVE-2025-29927",
          title: "next vulnerable",
          category: "dependency",
          severity: "critical",
          path: "frontend/package-lock.json",
          message: "vulnerable dependency",
          raw_json: JSON.stringify({ VulnerabilityID: "CVE-2025-29927", PkgName: "next" })
        },
        {
          scanner: "trivy",
          rule_id: "CVE-2026-29063",
          title: "immutable vulnerable",
          category: "dependency",
          severity: "high",
          path: "frontend/package-lock.json",
          message: "vulnerable dependency",
          raw_json: JSON.stringify({ VulnerabilityID: "CVE-2026-29063", PkgName: "immutable" })
        },
        {
          scanner: "trivy",
          rule_id: "CVE-2025-27152",
          title: "axios vulnerable",
          category: "dependency",
          severity: "high",
          path: "backend/package-lock.json",
          message: "vulnerable dependency",
          raw_json: JSON.stringify({ VulnerabilityID: "CVE-2025-27152", PkgName: "axios" })
        }
      ]
    }, [
      indexedFile("backend/app.js", "app.use((req, res, next) => {\n  next();\n});\n"),
      indexedFile("frontend/route.ts", "return new Response(null, { headers: { 'Cache-Control': 'public, immutable' } });\n"),
      indexedFile("backend/services/http.ts", "import axios from 'axios';\naxios.get('/health');\n")
    ]);

    const file = writeMarkdownReport(dir, bundle, [], "report");
    const markdown = fs.readFileSync(file, "utf8");

    expect(markdown).toContain("next (CVE-2025-29927)");
    expect(markdown).toContain("immutable (CVE-2026-29063)");
    expect(markdown).toContain("axios (CVE-2025-27152)");
    expect(markdown).not.toContain("backend/app.js:2 - next();");
    expect(markdown).not.toContain("frontend/route.ts:1 - return new Response");
    expect(markdown).toContain("backend/services/http.ts:1 - import axios from 'axios';");
  });
});
