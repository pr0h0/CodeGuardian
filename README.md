# codeguardian

`codeguardian` is Docker-first local CLI for security-first code scanning. It indexes a repository, stores structured memory in SQLite, runs deterministic scanners, builds small context packs, optionally asks an LLM to triage evidence, and writes Markdown, JSON, and SARIF reports.

It does not do autonomous exploitation, remote crawling, nmap scans, unrestricted shell execution, or send whole repositories to an LLM.

## Safety Model

- Default dynamic targets are `localhost` and `127.0.0.1`.
- POST/PUT/PATCH/DELETE and non-allowlisted targets create approvals instead of running.
- External scanners run through Docker-only execution.
- Secrets, Authorization headers, cookies, JWTs, private keys, and `.env`-style values are redacted.
- Missing Docker/runtime scanner failures for Semgrep, Gitleaks, Trivy, OSV-Scanner, or Bearer produce warnings, not scan failure.

## Install

```bash
npm install
npm run build
npm link
```

## Docker

```bash
docker build -t codeguardian .
docker run --rm -v "$PWD":/workspace codeguardian scan /workspace --no-ai
docker compose run --rm codeguardian scan /workspace --no-ai
```

## Local Usage

```bash
codeguardian tools .
codeguardian doctor . --pull
codeguardian index ./some-repo
codeguardian scan ./some-repo --no-ai --format all
codeguardian scan ./some-repo --ai --provider openai --model gpt-4.1-mini
codeguardian scan ./some-repo --ai --max-ai-findings 50
codeguardian scan ./some-repo --ai --max-ai-findings 150 --ai-triage-target 40
codeguardian scan ./some-repo --ai --max-ai-audit-files 80 --max-ai-audit-rounds 10
codeguardian scan ./some-repo --baseline latest
codeguardian scan ./some-repo --profile cli --incremental
codeguardian report <scanId>
```

AI mode has two passes:

- Scanner-result triage: sends compact context packs for high-signal scanner findings. AI mode keeps triaging additional SAST results in batches until it reaches the active code-finding target or the `--max-ai-findings` cap. True positives move into Code Findings; false positives move into AI False Positives and disappear from Additional SAST.
- Exploratory source audit: sends a repository manifest first, lets the AI request source files by path, then sends bounded source packs so it can look for vulnerabilities missed by scanners. This is controlled by `--no-ai-audit`, `--max-ai-audit-files`, `--max-ai-audit-rounds`, and `--max-ai-audit-chars`.
- Static source-pattern seeds: before AI triage, Codeguardian also runs lightweight source-aware checks for patterns that regex-only SAST often misses, including unsafe XML entity parsing, archive entry writes, NoSQL `$where` concatenation, redirect variables, filename/MIME upload validation, and sensitive routes without obvious inline guards. These are general seeds for AI/developer validation, not app-specific challenge rules.

Before an AI scan starts, Codeguardian preflights the low, medium, and high model tiers with tiny structured requests so missing credentials, bad models, schema incompatibility, and billing blocks fail early. AI provider errors are classified as authentication, billing, rate-limit, server, invalid-request, or unknown; authentication/configuration and invalid-request failures fail fast, while billing/rate-limit/server failures are retried once. Spending-cap or billing-limit text returned as a normal model response is treated as a billing failure. AI job metadata in reports includes compact redacted prompt/response traces for preflight, triage, critic, repair, and audit calls.

Reports default to timestamped files such as `codeguardian-report/report-APP-YYYY-MM-DD-HHMMSS.md`, `.json`, and `.sarif`.

Reports include baseline diff, top-fix-first ordering, grouped low-signal noise, dependency reachability hints, CWE/OWASP metadata where known, and suppressions.
Correlation checks connect related signals, such as prototype pollution plus vulnerable Eta template engine dependency RCE, reachable vulnerable dependencies, or spoofable Host / proxy headers used to gate admin routes across Express/Next, Flask/Django, Laravel/PHP, Rails/Ruby, Spring/Java, ASP.NET, and Go HTTP handlers.

Suppress findings with `.codeguardianignore` or inline comments:

```text
# .codeguardianignore
generated/
fixtures/unsafe-example.php

# codeguardian-disable-next-line php-eval -- trusted local fixture
```

## Environment

Copy `.env.example` to `.env`.

OpenAI:

```env
AI_PROVIDER=openai
OPENAI_API_KEY=...
OPENAI_MODEL=gpt-4.1-mini
```

Anthropic:

```env
AI_PROVIDER=anthropic
ANTHROPIC_API_KEY=...
ANTHROPIC_MODEL=claude-3-5-haiku-latest
```

DeepSeek:

```env
AI_PROVIDER=deepseek
DEEPSEEK_API_KEY=...
AI_LOW_MODEL=deepseek-v4-flash
AI_MEDIUM_MODEL=deepseek-chat
AI_HIGH_MODEL=deepseek-v4-pro
DEEPSEEK_BASE_URL=https://api.deepseek.com
```

AI triage routes straightforward medium-severity scanner findings to the low tier, most high-signal findings to the medium tier, and only complex critical/high candidates such as correlation chains, authz, SSRF, RCE, path traversal, and command injection to the high tier. Each tier uses `AI_LOW_MODEL`, `AI_MEDIUM_MODEL`, or `AI_HIGH_MODEL` when set, otherwise it falls back to `AI_MODEL`. Reports include per-tier/per-model request count, input tokens, cached input tokens, output tokens, total tokens, and USD cost. When the provider response omits cost fields, Codeguardian estimates cost from checked-in per-1M-token pricing for known OpenAI, Anthropic, and DeepSeek models; cached input pricing is used only when cached token counts are present.

OpenRouter:

```env
AI_PROVIDER=openrouter
OPENROUTER_API_KEY=...
OPENROUTER_MODEL=openai/gpt-4.1-mini
OPENROUTER_BASE_URL=https://openrouter.ai/api/v1
```

## Dynamic Testing

```bash
codeguardian test-web --target http://localhost:3000
codeguardian test-web --target http://dev.local:3000 --allow-host dev.local
codeguardian approve <approvalId>
codeguardian reject <approvalId>
codeguardian test-web --target http://dev.local:3000 --allow-host dev.local --run-approved
```

If `--target` is omitted, `test-web` uses `CODEGUARDIAN_DEFAULT_TARGET`. Set `CODEGUARDIAN_REQUIRE_APPROVAL=false` only for trusted local targets.

## Custom Rules

Edit `rules/custom/dangerous-patterns.json`. Rules use JavaScript regular expressions and produce structured scanner results with file and line evidence. Bundled rules include JavaScript prototype pollution candidates such as unsafe object merges, dynamic user-controlled property assignment, and direct `__proto__`/`constructor.prototype` mutation.

## Project Config

Create `.codeguardian.yml` or `.codeguardian.json` in the scanned repo:

```yaml
profile: rails
disabledRules:
  - quality/large-file
severityOverrides:
  custom-rules/debug-endpoint: low
focusPaths:
  - src/routes/**
  - app/controllers/**
avoidPaths:
  - tests/**
vulnerabilityClasses:
  - injection
  - authz
  - ssrf
rulesOfEngagement: "No destructive testing against shared environments."
reportFilters:
  minSeverity: medium
  minConfidence: medium
  guidance: "Drop missing-header-only findings."
failOn: high
maxAdditionalSastFindings: 100
maxAiFindings: 150
aiTriageTargetCodeFindings: 40
aiLowModel: deepseek-v4-flash
aiMediumModel: deepseek-chat
aiHighModel: deepseek-v4-pro
aiCritic: true
incremental: true
```

Profiles: `all`, `web`, `cli`, `php`, `ruby`, `rails`, `laravel`, `node`, `python`.

Scan strategy fields are optional. `focusPaths` limits indexed source paths when no `--include` CLI glob is supplied, while `avoidPaths` is merged with CLI `--exclude` globs. Config preflight fails when a configured `focusPaths` or `avoidPaths` glob matches no repository file or directory, catching typos before the scan starts. `vulnerabilityClasses` steers AI triage/audit toward `injection`, `xss`, `auth`, `authz`, `ssrf`, `exposure`, `validation`, `dependency`, `crypto`, `misconfig`, `xxe`, and `business-logic`; exploratory audit also narrows its structured output schema to the configured classes. `rulesOfEngagement` and `reportFilters.guidance` are included in AI context; report severity/confidence thresholds filter generated report findings without deleting stored scan evidence.

## AI Instructions

Add `AI_INSTRUCTIONS.md`, `AGENT.md`, `AGENTS.md`, or `.codeguardian/AI_INSTRUCTIONS.md` to the scanned repository to teach AI triage local invariants and known false positives.

Example:

```md
- Shopify shopDomain comes from authenticated Shopify session context.
- Do not report SSRF for post-auth shopDomain usage unless arbitrary host input bypasses Shopify validation.
- Test fixtures and local development secrets are not production findings.
```

See `AI_INSTRUCTIONS.example.md`.

## Supported Scanners

- Semgrep CE
- Gitleaks
- Trivy
- OSV-Scanner
- Bearer
- Built-in custom dangerous pattern scanner
- Built-in taint-lite source-to-sink scanner
- Built-in framework/config posture checks
- Built-in SOC 2 / ISO 27001 compliance evidence checks
- Built-in chained-risk correlation checks
- Lightweight quality checks

Built-in language support is strongest for JS/TS, PHP, Ruby/Rails, Python, and common CLI entrypoints. Docker scanners add broader multi-language coverage.

## Compliance Evidence

Compliance checks are best-effort evidence mapping, not certification. Reports include a Compliance Evidence section with `pass`, `fail`, or `unknown` rows for selected SOC 2 and ISO 27001 controls: access control, session cookie protection, security logging, secret management, change management, vulnerability management, and cryptography/transport protection. `unknown` means the scanner did not find enough indexed source/config evidence to make a claim.

## Limitations

Tree-sitter is not required in this MVP; symbol extraction uses robust generic regex patterns and line-window chunking. Docker install scripts for external scanners depend on upstream network availability during image build. AI triage only runs when valid provider configuration is supplied; deterministic reports work without API keys.
