# Scanner Architecture Hardening Design

## Goal

Rework Codeguardian internals so a scan is reproducible, typed at major boundaries, easier to audit, and safer for real repository assessments.

## Scope

This design implements the previously identified rewrite themes in focused slices:

- Typed scan planning and persistence boundaries.
- Shared file scope semantics for local and external scanner results.
- Parser-backed JavaScript/TypeScript code intelligence with regex fallback for other languages.
- Prepared report model data so reports do not have to rediscover source snippets and dependency reachability.
- Explicit AI job traces for triage and exploratory audit.
- Browser dynamic-test sandboxing through request interception.
- Full-scan integration coverage for deterministic behavior.

The implementation does not replace Semgrep, Gitleaks, Trivy, OSV, or Bearer. It normalizes their outputs against a shared scan plan.

## Architecture

`runScan` remains the CLI-facing orchestrator, but the heavy responsibilities move into small units:

- `core/scanPlan.ts` builds the scan scope from indexed files, computes changed files, stores cache metadata, and filters scanner results to the scope.
- `repo/codeIntelligence.ts` provides one interface for imports, symbols, and routes. JavaScript and TypeScript use the TypeScript compiler parser; other languages keep the existing regex extractors.
- `db/rows.ts` gives typed row shapes for scans, files, scanner results, findings, approvals, and scanner runs.
- `reports/model.ts` prepares source snippets and dependency reachability once from the scan bundle.
- `ai/jobs.ts` records AI job lifecycle events and summary data without changing provider APIs.
- `tools/puppeteerTool.ts` blocks browser requests to non-allowlisted hosts and always closes the browser.

## Data Flow

1. CLI options and project config create a `RunContext`.
2. Repository indexing produces `IndexedFile[]` and DB file/chunk/symbol/route rows through `codeIntelligence`.
3. `buildScanPlan` creates a file-scope set and changed-file set.
4. Local scanners run against the scan plan local file list.
5. External scanners still execute in Docker, but their normalized results are filtered against the scan plan so report semantics match includes/excludes.
6. Policy and suppressions are applied.
7. AI triage/audit records job events while producing findings.
8. Findings and scanner results are persisted through typed repository functions.
9. `prepareReportBundle` enriches the bundle for report rendering.

## Error Handling

External scanner failures remain warnings unless parsing produces structured results. Browser testing rejects disallowed navigation and subresource requests. AI job tracing records failures in the report bundle even when deterministic fallbacks are used.

## Testing

Tests cover scan-plan scope filtering, baseline fingerprint use, parser-backed JS/TS extraction, report-model-prepared snippets, browser request blocking policy, and a deterministic full `runScan` integration path with mocked Docker scanners.
