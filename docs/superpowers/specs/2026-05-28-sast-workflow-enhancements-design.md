# SAST Workflow Enhancements Design

## Goal

Improve Codeguardian with Shannon-inspired workflow features while keeping the product firmly SAST/offline: no running target application, no authenticated browser flows, and no live exploitation.

## Scope

This change adds:

- Resumable scan workspaces for repeated or interrupted static scans.
- Static proof packs for high-signal findings.
- Source-only reconnaissance artifacts that summarize attack surface, authorization boundaries, input vectors, and sinks.
- Report sections and JSON artifacts that expose the new SAST evidence.
- CLI lifecycle commands for static scan status and resume.

This change does not add DAST, target URL validation, Playwright agents, authenticated testing, or runtime exploit execution.

## Architecture

`core/resume.ts` owns workspace identity, run fingerprints, stage snapshots, and resume validation. It stores reusable scan artifacts under `.codeguardian/workspaces/<workspace>/` inside the scanned repository so a scan can recover deterministic stages without re-running the whole pipeline.

`core/staticRecon.ts` builds a source-only attack-surface artifact from indexed files, detected routes, security intelligence, scanner seeds, and project config. It produces endpoint, boundary, guard, input-vector, sink, and invariant summaries.

`core/staticProof.ts` converts findings into static proof packs. A proof pack contains cited source locations, source/sink labels, evidence, missing control reasoning, exploit preconditions, safe regression-test guidance, and confidence blockers. It is explicitly not runtime proof.

`core/scanner.ts` remains the orchestrator. It checks a workspace before each resumable stage, writes stage snapshots after successful stages, and includes static recon/proof artifacts in the report bundle.

## Data Flow

1. CLI options create `RunContext`, including optional `workspace` and `resume` settings.
2. A workspace is resolved from explicit CLI input or a deterministic default derived from repository path and scan options.
3. Indexing runs or loads a compatible indexed-file snapshot.
4. Deterministic local/external scanner output runs or loads compatible scanner-result snapshots.
5. AI triage/audit continues to run normally when enabled. The workspace records progress and AI job traces, but it does not replay partial provider calls.
6. Findings are deduped and persisted as today.
7. Static recon and proof-pack artifacts are generated from the final SAST evidence.
8. Reports render the artifacts and workspace metadata.

## Error Handling

A workspace can only resume when repository path, relevant scan options, project config, and indexed file fingerprints match. If they do not match, Codeguardian fails fast with a clear message and instructs the operator to use a new workspace.

Malformed workspace artifacts are ignored only when `--resume` is not requested. When `--resume` is requested, malformed artifacts fail the scan so operators do not unknowingly rely on partial evidence.

## Testing

Tests cover workspace fingerprint stability, stage snapshot read/write, resume mismatch failures, static recon generation, static proof-pack generation, report rendering, and CLI option parsing.

