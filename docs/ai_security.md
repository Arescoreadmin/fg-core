# AI Route Security Enablement

AI is fail-closed by default.

## Required toggles

- `FG_AI_DISABLED=false` (set true to force `503 AI_DISABLED` on all AI routes).
- Tenant active config must contain `{"ai_enabled": true}`.
- Caller must use scoped API key with `ai:query` and key-bound tenant.

## Abuse prevention guards

- Idempotency replay guard supports `Idempotency-Key` and `X-Idempotency-Key`.
  - Cache key scope: `(tenant_id, actor_id, idempotency_key)`.
  - Cache payload includes `request_hash` and response payload/hash.
  - Reuse of the same idempotency key with a different request hash is rejected with
    `409 AI_IDEMPOTENCY_MISMATCH` and only safe error fields (+ trace_id correlation) are returned.
  - TTL: `FG_AI_IDEMPOTENCY_TTL_SECONDS` (default 600, clamped 300-900).
- Tenant rate-limit guard: `FG_AI_RATE_LIMIT_PER_MIN` (default 30).
- Tenant token budget guard:
  - `FG_AI_BUDGET_TOKENS_PER_HOUR` (default 60000)
  - `FG_AI_BUDGET_TOKENS_PER_DAY` (default 500000)
- Guard backend:
  - `FG_AI_GUARDS_BACKEND=redis` (recommended) with `FG_REDIS_URL`
  - `FG_AI_GUARDS_BACKEND=memory` for dev/test only.

### Dev-only guard fail-open escape hatch

- `FG_AI_GUARD_FAIL_OPEN_FOR_DEV=1` is honored only in non-prod/non-staging environments.
- When used, the service emits a **critical** security event
  `ai_guard_fail_open_dev_override` to make the exception obvious.
- In prod/staging, guard backend issues remain fail-closed (`AI_GUARD_UNAVAILABLE`) and an explicit `ai_guard_fail_open_rejected` security event is emitted if the override is attempted.
- `AI_GUARD_UNAVAILABLE` includes only safe correlation details (`trace_id`, `request_fingerprint`).

## PII/sensitive redaction coverage

The redaction pass scans input and output for:

- emails
- phones
- SSN patterns
- payment card-like numbers
- IPv4 addresses
- JWT-like strings
- Bearer token substrings
- `Authorization:` / `X-Api-Key:` / `api_key=`-like substrings
- `sk_`/`rk_`/`pk_` key prefixes and long hex key-like strings
- basic street-address heuristics

### Important limitations

- Not guaranteed to detect names or all free-form identifiers.
- Heuristic matching can under- or over-redact.
- This is defense-in-depth, not a legal/compliance classifier.

## RAG seam and injection guardrails

- `FG_RAG_ENABLED=true` enables retrieval provider invocation.
- Retrieval chunks are untrusted evidence and cannot override system policy.
- Evidence is quoted and prefixed (`EVIDENCE:`), never treated as directives.
- Required chunk metadata contract:
  `source_id`, `doc_id`, `chunk_id`, `chunk_hash`, `score`, `created_at`, `text`.

## LLM provider resiliency

- Circuit breaker around provider calls.
- Retry semantics:
  - retryable + no breaker trip: `429`.
  - retryable + breaker-counted: `408`, `409`, `425`, `5xx`, and network failures.
  - terminal: other `4xx` and malformed responses.
- Total request budget enforced via timeout + max retries.

## Audit logging (no raw content)

Each request emits structured metadata without raw prompt/output:

- tenant_id, actor_id, scopes
- `request_fingerprint` (deterministic HMAC for request correlation)
- `trace_id` (attempt-level unique HMAC-derived value)
- provider, model, max_tokens, temperature
- request_hash, response_hash
- status, error_code, policy_state
- schema_validation_failed
- pii_redaction_applied/counts (input + output)
- latency_ms
