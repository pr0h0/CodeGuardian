# AI Trust Pipeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement a precision-first AI trust pipeline that reduces duplicate and malformed AI findings while keeping scanner evidence visible.

**Architecture:** Add focused AI trust modules around the existing scanner flow. Triage first asks for a small verdict, validates any full finding before storage, improves dependency reachability in the report model, makes triage memory hash-aware, and adds deterministic plus optional AI dedupe after local exploitability scoring.

**Tech Stack:** TypeScript, Node.js, Zod, Vitest, existing Codeguardian SQLite/report modules.

---

### Task 1: Triage Verdict And No-Fallback Promotion

**Files:**
- Create: `src/ai/verdict.ts`
- Modify: `src/ai/schemas.ts`
- Modify: `src/ai/triage.ts`
- Test: `tests/unit/aiTrust.test.ts`

- [ ] Write tests showing malformed full-finding AI output returns no Code Finding and records `status: "parse_failed"` metadata.
- [ ] Write tests showing a `false_positive` verdict still records a false-positive finding.
- [ ] Add a verdict JSON schema and Zod parser.
- [ ] Run verdict stage before full finding stage.
- [ ] Stop calling `coerceAiFallback()` for active findings.
- [ ] Run `npm test -- tests/unit/aiTrust.test.ts tests/unit/aiValidation.test.ts`.

### Task 2: AI Finding Validator

**Files:**
- Create: `src/ai/findingValidator.ts`
- Modify: `src/ai/triage.ts`
- Modify: `src/ai/audit.ts`
- Test: `tests/unit/aiTrust.test.ts`

- [ ] Write tests rejecting AI findings with missing files, invalid lines, empty evidence, or schema-gap reasoning.
- [ ] Implement `validateAiFindingCandidate()`.
- [ ] Apply the validator before converting AI triage or audit output to stored findings.
- [ ] Run `npm test -- tests/unit/aiTrust.test.ts tests/unit/aiAudit.test.ts`.

### Task 3: Dependency Reachability

**Files:**
- Modify: `src/reports/model.ts`
- Test: `tests/unit/reportModel.test.ts`

- [ ] Write tests that `next()` does not count as usage of package `next`.
- [ ] Write tests that cache-control string `immutable` does not count as usage of `immutable`.
- [ ] Write tests that `import axios from "axios"` and `require("axios")` count as usage.
- [ ] Replace broad word-boundary matching with import/require/subpath import matching.
- [ ] Prefer nested `package.json` and `package-lock.json` matches by path when available.
- [ ] Run `npm test -- tests/unit/reportModel.test.ts`.

### Task 4: Hash-Safe Triage Memory

**Files:**
- Modify: `src/core/scanner.ts`
- Test: `tests/unit/findingState.test.ts` or `tests/unit/aiTrust.test.ts`

- [ ] Write tests showing prior memory applies when fingerprint and file hash match.
- [ ] Write tests showing prior memory does not apply when the cited file hash changed.
- [ ] Include file hash lookup in memory rows.
- [ ] Compare remembered hash to current indexed file hash before applying status.
- [ ] Run the focused memory tests.

### Task 5: Class-Targeted Audit

**Files:**
- Modify: `src/ai/audit.ts`
- Modify: `src/core/scanner.ts`
- Test: `tests/unit/aiAudit.test.ts`

- [ ] Write tests showing audit runs separate class-scoped calls for configured classes.
- [ ] Write tests showing the default schedule uses targeted classes when no config class is supplied.
- [ ] Split total file/round budgets across audit classes.
- [ ] Include audit class metadata in AI job metadata.
- [ ] Run `npm test -- tests/unit/aiAudit.test.ts`.

### Task 6: Dedupe Improvements And AI Clustering

**Files:**
- Create: `src/ai/dedupe.ts`
- Modify: `src/core/findingDeduper.ts`
- Modify: `src/core/semanticDedupe.ts`
- Modify: `src/core/scanner.ts`
- Test: `tests/unit/findingDeduper.test.ts`

- [ ] Write tests collapsing same file/line similar title findings into one representative.
- [ ] Write tests preserving the strongest representative and merging evidence.
- [ ] Write tests for AI duplicate-clustering output on ambiguous groups.
- [ ] Extend deterministic semantic families and same-line grouping.
- [ ] Add optional AI clustering for ambiguous groups only.
- [ ] Run `npm test -- tests/unit/findingDeduper.test.ts`.

### Task 7: Reporting And Metrics

**Files:**
- Modify: `src/ai/jobs.ts`
- Modify: `src/reports/markdown.ts`
- Test: `tests/unit/aiJobs.test.ts`
- Test: `tests/unit/report.test.ts`

- [ ] Write tests rendering AI diagnostics and quality counters.
- [ ] Add quality metadata to AI job summaries.
- [ ] Render parse failures, validator rejections, schema success rate, and dedupe counts.
- [ ] Run `npm test -- tests/unit/aiJobs.test.ts tests/unit/report.test.ts`.

### Task 8: Full Verification

**Files:**
- Modify: `README.md`

- [ ] Document the AI trust pipeline and dependency reachability behavior.
- [ ] Run `npm run build`.
- [ ] Run `npm test`.
- [ ] Run `git diff --check`.
