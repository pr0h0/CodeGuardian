# Shannon-Inspired Scan Strategy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Shannon-style scan strategy controls to Codeguardian config, AI triage, and reports.

**Architecture:** Extend the existing project config and scan context instead of creating a new orchestration layer. Use the current file walker for path scoping, the triage planner for class filtering, and report-only filtering so persisted findings stay complete.

**Tech Stack:** TypeScript, Node.js 20, zod, minimatch, Vitest.

---

### Task 1: Config Schema And Path Scope

**Files:**
- Modify: `src/config/projectConfig.ts`
- Modify: `src/core/runContext.ts`
- Test: `tests/unit/projectConfig.test.ts`

- [ ] Add failing tests that parse `focusPaths`, `avoidPaths`, `vulnerabilityClasses`, `rulesOfEngagement`, and `reportFilters`.
- [ ] Add failing tests that `createRunContext` maps config focus paths to include globs and merges avoid paths with CLI excludes.
- [ ] Extend the zod schema and exported types.
- [ ] Merge config path strategy into run context options.
- [ ] Run `npm test tests/unit/projectConfig.test.ts`.

### Task 2: AI Strategy Steering

**Files:**
- Modify: `src/core/triagePlanner.ts`
- Modify: `src/core/scanner.ts`
- Modify: `src/ai/audit.ts`
- Test: `tests/unit/triagePlanner.test.ts`
- Test: `tests/unit/aiAudit.test.ts`

- [ ] Add failing tests that class-scoped triage keeps in-scope categories and drops out-of-scope ones.
- [ ] Add failing tests that exploratory audit prompts include strategy instructions.
- [ ] Implement vulnerability-class matching helpers.
- [ ] Thread project strategy instructions into triage and audit AI context.
- [ ] Run `npm test tests/unit/triagePlanner.test.ts tests/unit/aiAudit.test.ts`.

### Task 3: Report Filtering And Metadata

**Files:**
- Create: `src/reports/filters.ts`
- Modify: `src/core/scanner.ts`
- Modify: `src/reports/markdown.ts`
- Test: `tests/unit/report.test.ts`

- [ ] Add failing tests that report filters hide below-threshold findings from the main report.
- [ ] Add failing tests that strategy metadata renders in Markdown.
- [ ] Implement report-only filtering helper.
- [ ] Include scan strategy metadata in the report bundle.
- [ ] Run `npm test tests/unit/report.test.ts`.

### Task 4: Documentation And Verification

**Files:**
- Modify: `README.md`

- [ ] Document the new `.codeguardian.yml` fields.
- [ ] Run `npm run build`.
- [ ] Run `npm test`.
