# SAST Workflow Enhancements Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add resumable offline SAST scans, static proof packs, and static reconnaissance artifacts without enabling DAST behavior.

**Architecture:** Keep `runScan` as the orchestrator, add focused modules for workspace state, static recon, and static proof packs, and thread their artifacts into reports. Resume is best-effort for deterministic stages and strict about workspace compatibility.

**Tech Stack:** TypeScript, Node 20, better-sqlite3, existing report writers, Vitest.

---

## File Structure

- Create `src/core/resume.ts`: workspace naming, fingerprinting, stage snapshot persistence, resume validation, and status summaries.
- Create `src/core/staticProof.ts`: finding-to-proof-pack conversion.
- Create `src/core/staticRecon.ts`: source-only reconnaissance artifact generation.
- Modify `src/core/runContext.ts`: add `workspace` and `resume` CLI options.
- Modify `src/cli.ts`: add scan options plus `status` and `workspaces` commands.
- Modify `src/core/scanner.ts`: use workspace snapshots and attach static artifacts to the report bundle.
- Modify `src/reports/markdown.ts`: render workspace, static recon, and static proof-pack sections.
- Modify `src/reports/html.ts`: expose proof-pack/recon summaries in HTML.
- Modify `src/db/rows.ts`: widen the in-memory bundle type for new report artifacts.
- Test `tests/unit/resume.test.ts`, `tests/unit/staticProof.test.ts`, `tests/unit/staticRecon.test.ts`, and extend `tests/unit/report.test.ts`.

## Tasks

### Task 1: Workspace Resume Core

**Files:**
- Create: `src/core/resume.ts`
- Test: `tests/unit/resume.test.ts`

- [ ] Write tests for stable workspace IDs, snapshot round-trip, status listing, and fingerprint mismatch.
- [ ] Implement `resolveScanWorkspace`, `buildResumeFingerprint`, `writeStageSnapshot`, `readStageSnapshot`, `listScanWorkspaces`, and `summarizeScanWorkspace`.
- [ ] Run `npm test -- tests/unit/resume.test.ts`.

### Task 2: CLI And Context Options

**Files:**
- Modify: `src/core/runContext.ts`
- Modify: `src/cli.ts`

- [ ] Add `workspace?: string` and `resume?: boolean | string` to `CliOptions`.
- [ ] Add `--workspace <name>` and `--resume [workspace]` to scan options.
- [ ] Add `codeguardian status [workspace]` and `codeguardian workspaces` commands.
- [ ] Run `npm run build`.

### Task 3: Scanner Resume Integration

**Files:**
- Modify: `src/core/scanner.ts`
- Test: `tests/integration/runScan.test.ts`

- [ ] Snapshot indexed files after indexing.
- [ ] Snapshot scanner results after scanner normalization, policy, suppression, noise reduction, and fingerprint attachment.
- [ ] Load compatible snapshots when `--resume` is set.
- [ ] Keep AI triage/audit behavior current-run only while recording workspace stages around it.
- [ ] Run deterministic integration scan tests.

### Task 4: Static Proof Packs

**Files:**
- Create: `src/core/staticProof.ts`
- Modify: `src/reports/markdown.ts`
- Modify: `src/reports/html.ts`
- Test: `tests/unit/staticProof.test.ts`
- Test: `tests/unit/report.test.ts`

- [ ] Generate static proof packs from active findings.
- [ ] Include source location, sink/source, evidence summary, missing control, preconditions, safe regression guidance, and confidence blockers.
- [ ] Render proof packs in Markdown and HTML.
- [ ] Run proof/report tests.

### Task 5: Static Recon Artifact

**Files:**
- Create: `src/core/staticRecon.ts`
- Modify: `src/core/scanner.ts`
- Modify: `src/reports/markdown.ts`
- Test: `tests/unit/staticRecon.test.ts`

- [ ] Generate endpoint, guard, input-vector, sink, invariant, and boundary summaries from indexed files and security intelligence.
- [ ] Add the artifact to JSON and Markdown reports.
- [ ] Run recon/report tests.

### Task 6: Full Verification

**Files:**
- No new files.

- [ ] Run `npm run build`.
- [ ] Run `npm test`.
- [ ] Review `git diff --stat` and final report output shape.

