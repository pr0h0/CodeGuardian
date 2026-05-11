# CodeGuardian AI Instructions

Use this file in the repository being scanned as `AI_INSTRUCTIONS.md`, `AGENT.md`, or `.codeguardian/AI_INSTRUCTIONS.md`.

## Known Safe Patterns

- Shopify `shopDomain` values come from Shopify-authenticated app/session context after OAuth/session validation.
- Do not report SSRF for post-auth Shopify `shopDomain` usage unless code shows attacker-controlled arbitrary host input bypassing Shopify validation or allowlists.
- Local development certificates, sample fixtures, and documented test secrets are not production secret findings unless they are referenced by production paths.

## Security Invariants

- State-changing routes require authenticated sessions unless a file explicitly documents public access.
- Webhook handlers validate Shopify HMAC before trusting request payloads.

## Report Guidance

- Prefer `false_positive` for scanner findings that conflict with these invariants and lack contradicting code evidence.
- If unsure, use `needs_dynamic_test` rather than confirmed.
