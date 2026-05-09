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
codeguardian index ./some-repo
codeguardian scan ./some-repo --no-ai --format all
codeguardian scan ./some-repo --ai --provider openai --model gpt-4.1-mini
codeguardian scan ./some-repo --ai --max-ai-findings 50
codeguardian scan ./some-repo --ai --max-ai-audit-files 80 --max-ai-audit-rounds 10
codeguardian report <scanId>
```

AI mode has two passes:

- Scanner-result triage: sends compact context packs for high-signal scanner findings.
- Exploratory source audit: sends a repository manifest first, lets the AI request source files by path, then sends bounded source packs so it can look for vulnerabilities missed by scanners. This is controlled by `--no-ai-audit`, `--max-ai-audit-files`, `--max-ai-audit-rounds`, and `--max-ai-audit-chars`.

Reports default to `codeguardian-report/report.md`, `report.json`, and `report.sarif`.

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
DEEPSEEK_MODEL=deepseek-chat
DEEPSEEK_BASE_URL=https://api.deepseek.com
```

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

## Custom Rules

Edit `rules/custom/dangerous-patterns.json`. Rules use JavaScript regular expressions and produce structured scanner results with file and line evidence.

## Supported Scanners

- Semgrep CE
- Gitleaks
- Trivy
- OSV-Scanner
- Bearer
- Built-in custom dangerous pattern scanner
- Lightweight quality checks

## Limitations

Tree-sitter is not required in this MVP; symbol extraction uses robust generic regex patterns and line-window chunking. Docker install scripts for external scanners depend on upstream network availability during image build. AI triage only runs when valid provider configuration is supplied; deterministic reports work without API keys.
