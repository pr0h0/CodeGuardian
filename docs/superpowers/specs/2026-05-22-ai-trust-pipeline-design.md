# AI Trust Pipeline Design

**Goal:** Reduce noisy AI-promoted findings by making invalid AI output non-authoritative, improving dependency reachability, and deduplicating related findings before reporting.

**Context:** The latest `eSmrtovnice2` AI scan produced many useful scanner signals but also showed weak AI behavior: most triage jobs repaired or fell back, fallback findings reached Code Findings, and dependency reachability matched package names lexically (`next()` and cache-control `immutable`). The scanner already has deterministic scanner-result noise reduction, finding dedupe, AI job tracing, and basic triage memory.

## Design

### Trust-Gated Triage

AI triage becomes two-stage:

1. Verdict stage uses a small schema with `verdict`, `confidence`, `reason`, `requestedFiles`, and `requestedSymbols`.
2. Full finding stage runs only for `true_positive` or strong `needs_context` verdicts.

Malformed full-finding responses do not produce Code Findings. They become AI diagnostics attached to job metadata and the original scanner result remains available in Additional SAST. False-positive verdicts still produce false-positive findings so the report can explain why noisy scanner results were rejected.

### Finding Validation

Before any AI-produced finding is stored, a validator checks that cited files and lines exist, evidence points at real repository locations, reasoning is not a parse/schema fallback, and source/sink/category fields are coherent enough to report. Invalid AI findings are downgraded to diagnostics.

### Dependency Reachability

Dependency usage uses manifest/lockfile and source import evidence, not arbitrary word matching. JavaScript/TypeScript packages are considered used only when imported or required, including scoped packages and subpath imports. Package-lock data is used to report direct vs transitive package paths. Plain identifiers such as `next()` and string values such as `immutable` in cache headers do not count as package usage.

### Audit Targeting

Exploratory audit runs focused passes by vulnerability family: auth/authz, SSRF, path/file IO, XSS/template, and secrets. Each pass uses a class-scoped schema and prompt. Broad audit remains available when no classes are configured, but the default internal schedule uses targeted passes within the configured file/round budget.

### Memory

Triage memory is applied only when the prior finding fingerprint matches and the cited file hash is unchanged. This prevents stale false-positive or true-positive decisions from carrying across code changes.

### Deduplication

Deduplication runs in two layers:

1. Deterministic grouping collapses same file/line/window and semantic family across scanner and AI findings.
2. Optional AI clustering runs only on ambiguous near-duplicate groups. AI returns duplicate groups; deterministic code chooses the canonical representative by severity, status, confidence, exploitability, and evidence quality.

AI clustering never creates findings and cannot override deterministic validation. It can only mark duplicates.

### Metrics

AI job metadata records verdict-stage outcomes, full-stage schema success, repair success, fallback diagnostics, and provider/model quality counters. These metrics can later drive automatic model escalation.

## Acceptance Criteria

- Invalid AI full-finding output does not create active Code Findings.
- Same file/line related scanner findings collapse to one representative with merged evidence and dedupe metadata.
- Dependency reachability rejects lexical false matches for `next()` and `"immutable"`.
- Triage memory does not apply when the cited file hash has changed.
- Targeted audit creates class-scoped audit jobs and respects configured file/round budgets.
- Reports expose AI diagnostics and AI quality counters without hiding scanner evidence.

## Verification

- Unit tests cover trust-gated triage, validator rejection, dependency reachability, hash-safe memory, deterministic dedupe, and AI clustering.
- Full TypeScript build passes.
- Full Vitest suite passes.
