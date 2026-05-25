# Scanner Architecture Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden Codeguardian internals so scans are typed, scoped, reproducible, parser-informed, and usable for real audits.

**Architecture:** Add focused modules around the existing CLI path instead of rewriting the CLI wholesale. Keep scanner adapters stable, but normalize their outputs through a shared scan plan and prepare report/AI metadata before report writing.

**Tech Stack:** TypeScript, Node.js 20, Vitest, better-sqlite3, Commander, Puppeteer, Docker scanner adapters, TypeScript compiler parser.

---

### Task 1: Typed Persistence And Baseline

**Files:**
- Create: `src/db/rows.ts`
- Modify: `src/db/repositories.ts`
- Modify: `src/core/baseline.ts`
- Test: `tests/unit/baseline.test.ts`

- [ ] Write failing tests that baseline comparison uses stored fingerprints when present.
- [ ] Add typed DB row interfaces.
- [ ] Return typed scan bundles and remove persistence-layer `as any` casts.
- [ ] Select `fingerprint` in baseline fallback queries.
- [ ] Run `npm test tests/unit/baseline.test.ts tests/unit/projectConfig.test.ts`.

### Task 2: Shared Scan Plan

**Files:**
- Create: `src/core/scanPlan.ts`
- Modify: `src/core/scanner.ts`
- Test: `tests/unit/scanPlan.test.ts`

- [ ] Write failing tests for changed-file detection, cache upsert, and scanner-result scope filtering.
- [ ] Move changed-file/cache logic out of `runScan`.
- [ ] Filter external scanner results to indexed file paths.
- [ ] Keep deterministic scanner behavior unchanged for local files.
- [ ] Run `npm test tests/unit/scanPlan.test.ts tests/integration/scan.test.ts`.

### Task 3: Parser-Backed Code Intelligence

**Files:**
- Create: `src/repo/codeIntelligence.ts`
- Modify: `src/repo/repoIndexer.ts`
- Modify: `package.json`
- Test: `tests/unit/codeIntelligence.test.ts`

- [ ] Write failing tests for JavaScript/TypeScript imports, exported functions, classes, arrow functions, and Express routes.
- [ ] Add TypeScript compiler parser as runtime dependency.
- [ ] Route repo indexing through `analyzeCode`.
- [ ] Keep regex fallback for non-JS/TS languages.
- [ ] Run `npm test tests/unit/codeIntelligence.test.ts tests/unit/repoParsing.test.ts`.

### Task 4: Prepared Report Model

**Files:**
- Create: `src/reports/model.ts`
- Modify: `src/core/scanner.ts`
- Modify: `src/reports/markdown.ts`
- Test: `tests/unit/reportModel.test.ts`

- [ ] Write failing tests showing snippets and dependency usage can come from prepared model data.
- [ ] Build `prepareReportBundle` from scan bundle and indexed files.
- [ ] Prefer report-model snippets and dependency evidence in Markdown.
- [ ] Preserve filesystem fallback for `codeguardian report <scanId>`.
- [ ] Run `npm test tests/unit/reportModel.test.ts tests/unit/report.test.ts`.

### Task 5: AI Job Tracing

**Files:**
- Create: `src/ai/jobs.ts`
- Modify: `src/core/scanner.ts`
- Modify: `src/ai/triage.ts`
- Modify: `src/ai/audit.ts`
- Modify: `src/reports/markdown.ts`
- Test: `tests/unit/aiJobs.test.ts`

- [ ] Write failing tests for recording AI job start, success, failure, and report rendering.
- [ ] Add `AiJobRecorder`.
- [ ] Thread job recording through triage and exploratory audit without changing provider behavior.
- [ ] Add AI job summary to report bundle.
- [ ] Run `npm test tests/unit/aiJobs.test.ts tests/unit/aiValidation.test.ts tests/unit/aiAudit.test.ts`.

### Task 6: Dynamic Browser Sandbox

**Files:**
- Modify: `src/tools/puppeteerTool.ts`
- Test: `tests/unit/policy.test.ts`

- [ ] Write failing tests for browser subresource allowlist decisions.
- [ ] Export and use a browser request policy helper.
- [ ] Intercept Puppeteer requests and abort non-allowlisted hosts.
- [ ] Close browser in `finally`.
- [ ] Run `npm test tests/unit/policy.test.ts`.

### Task 7: Full Verification And Real Audit Scan

**Files:**
- Modify: `tests/integration/scan.test.ts`

- [ ] Add integration coverage for `runScan` with deterministic local scanners and disabled AI.
- [ ] Run `npm run build`.
- [ ] Run `npm test`.
- [ ] Build the CLI.
- [ ] Run an AI-enabled scan against `/home/pr0h0/Projects/eSmrtovnice` using DeepSeek configuration.
- [ ] Review generated Markdown/JSON/SARIF reports and summarize whether findings are actionable for real auditing.
