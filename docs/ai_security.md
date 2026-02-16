# AI Route Security Controls

`POST /ai/query` is fail-closed by default.

## Enablement
- Global kill switch: `FG_AI_DISABLED=true` returns `503` with code `AI_DISABLED`.
- Tenant toggle table: `tenant_ai_config.ai_enabled` (default `false`) must be `true` for the bound tenant.
- Control-plane only: no tenant-facing route mutates `tenant_ai_config`; updates must flow through admin/control-plane paths with audit logging.
- Required scope: `ai:query`.
- Required key-bound tenant context.
- Error envelope is deterministic for all failures: `{ "error_code": "...", "trace_id": "...", "detail": null }`.
- Model allowlist is enforced via `FG_AI_MODEL_ALLOWLIST`; disallowed model config fails closed with `AI_MODEL_NOT_ALLOWED`.

## Input / context hard caps
- Query payload is capped (`MAX_QUERY_BYTES`), otherwise `AI_BAD_REQUEST`.
- Retrieved context is capped by chunk count + byte budget, even when future RAG providers are enabled.
- Response payload is capped; oversized/invalid outputs fail closed as `AI_SCHEMA_INVALID`.

## Tenant throttles
- Per-tenant requests/minute limiter (`FG_AI_RPM`, or tenant override `tenant_ai_config.rpm_limit`).
- Per-tenant daily token budget (`FG_AI_DAILY_TOKEN_BUDGET`, or tenant override `tenant_ai_config.daily_token_budget`).
- Stable throttle errors: `AI_RATE_LIMITED`, `AI_BUDGET_EXCEEDED`.
- Quota windows are UTC-based; daily budgets reset at UTC midnight.
- No carry-forward policy: unused daily token budget does not roll over to the next UTC day.

## Cold-path circuit breaker
- Provider error spikes trigger temporary degraded mode and fail-closed `AI_DEGRADED`.
- Controls: `FG_AI_CB_ERROR_THRESHOLD`, `FG_AI_CB_WINDOW_S`, `FG_AI_CB_DEGRADED_S`.
- Open-transition log cooldown: `FG_AI_CB_OPEN_LOG_COOLDOWN_S` (prevents log spam during flapping while counters still increment).
- Breaker scope is process-local (not shared across tenants/processes today).
- Breaker transitions are emitted as structured logs (open / half-open trial / closed).

### Retry/reaction classification (single source of truth)
- `OpenAILLMClient.RETRYABLE_HTTP_STATUS`: statuses safe to retry (`408`, `409`, `425`, `429`).
- `OpenAILLMClient.BREAKER_TRIP_HTTP_STATUS`: retryable statuses that should also trip breaker (`408`, `425`).
- Deterministic/non-retryable 4xx (e.g., `400`, `401`, `403`) do **not** trip breaker.
- This intentionally allows retryable-but-not-breaker-worthy statuses (e.g., `429`) to avoid false degraded mode under normal throttling.

#### Explicit status rationale
- `408 Request Timeout`: retryable **and** breaker-trip (indicates upstream/network instability).
- `429 Too Many Requests`: retryable, **not** breaker-trip (expected throttling can happen under normal load).
- `500 Internal Server Error`: breaker-trip (generic upstream failure).
- `502 Bad Gateway`: breaker-trip (upstream dependency/proxy failure).
- `503 Service Unavailable`: breaker-trip (explicit upstream unavailability).
- `504 Gateway Timeout`: breaker-trip (upstream timeout path).

## PII / secret protections
- Request content is sanitized before model use.
- Response content is sanitized again before returning.
- Emails, phones, SSNs, payment-card-like data, API-key-like strings, addresses, IPs, JWTs, bearer tokens, and Authorization/X-Api-Key header values are redacted.

## Audit
Every AI request emits a structured audit record with:
- tenant/actor/scope context and trace id
- model params (`model`, `max_tokens`, `temperature`)
- SHA-256 hashes of sanitized request/response payloads
- status (`ok`, `blocked`, `pii_redacted`, `schema_failed`, `disabled`)
- breaker summary state (`closed`, `open`, `half_open`) to simplify timeline correlation

`/health` and `/health/ready` also expose:
- `ai_breaker_state`
- `ai_breaker_log_cooldown_seconds`
- `ai_breaker_metrics` (`open_count`, `half_open_trials`, `close_count`)

Raw prompt/context/model output are never logged.

## RAG seam
Retrieval is behind `FG_RAG_ENABLED` and a tenant-bound `RetrievalProvider` contract. Default provider is `NullRetrievalProvider` and returns no chunks. Providers must enforce `tenant_id`; untrusted chunks are sanitized before prompt construction.
