# Shannon-Inspired Scan Strategy Design

## Goal

Add operator-controlled scan strategy knobs from Shannon that fit Codeguardian's deterministic scanner architecture without importing Shannon's Temporal agent pipeline.

## Scope

This change adds project-config fields for:

- `focusPaths`: repository-relative globs to prioritize and limit indexed source paths.
- `avoidPaths`: repository-relative globs to exclude from indexing and local scanner scope.
- `vulnerabilityClasses`: focused vulnerability classes for AI triage and exploratory audit steering.
- `rulesOfEngagement`: free-form defensive engagement rules included in AI context.
- `reportFilters`: minimum severity/confidence thresholds plus optional guidance for report rendering.

The scanner still runs deterministic local and Docker scanners as before. The new strategy controls which files are indexed, which scanner results are promoted into AI validation, what context the exploratory audit sees, and which findings appear in generated reports.

## Architecture

`config/projectConfig.ts` owns the new schema fields and class matching helpers. `runContext.ts` merges `focusPaths` and `avoidPaths` into the existing include/exclude pipeline so existing file-walker semantics remain the source of truth.

`core/triagePlanner.ts` filters AI triage candidates by vulnerability class. `core/scanner.ts` appends scan strategy instructions to AI context and records scan strategy metadata in the report bundle. A small report filter module applies report-only filtering after findings are persisted, so the database still keeps full evidence for audit/review.

## Data Flow

1. `loadProjectConfig` reads `.codeguardian.yml` or `.codeguardian.json`.
2. `createRunContext` maps `focusPaths` to include globs and merges `avoidPaths` with CLI excludes.
3. Repository indexing, scan planning, local scanners, and external scanner scope filtering work on the focused indexed file set.
4. AI triage candidate selection skips out-of-class results when `vulnerabilityClasses` is configured.
5. AI triage and exploratory audit prompts receive vulnerability-class scope, rules of engagement, and report guidance.
6. Report output receives a filtered findings view plus scan strategy metadata.

## Error Handling

Invalid class names, severities, and confidences fail project-config validation. Empty or omitted fields keep current behavior. Report guidance is treated as context, not executable logic.

## Testing

Tests cover config parsing and path-scope merging, class-based triage filtering, AI prompt steering, and report filtering/metadata rendering.
