# Enterprise AI Console

## Device enable/disable

- Devices are identified by `fg_device_id` cookie (or `x-fg-device-id`) and registered tenant-scoped in `ai_device_registry`.
- First sighting is fail-closed: unknown devices are inserted with `enabled=false`.
- Enable/disable endpoints:
  - `POST /admin/devices/{device_id}/enable`
  - `POST /admin/devices/{device_id}/disable`
  - `POST /ui/devices/{device_id}/enable`
  - `POST /ui/devices/{device_id}/disable`
- All state toggles emit audit events (`admin_action`) with actor, tenant, previous/new state, reason, and ticket.

## Tenant experience/theme configuration

Contracts live under `contracts/ai/`:

- `experiences/*.json`
- `policies/*.json`
- `themes/*.json`
- schemas in `contracts/ai/schema/*.schema.json`

`/ui/ai/experience` resolves tenant-bound experience + policy + theme references.
In `prod/staging`, missing/invalid contracts fail closed.

## Token quotas and metering

`/ui/ai/chat` writes usage rows to `ai_token_usage` with:

- tenant_id, device_id, persona, provider, model
- prompt/completion/total token counts
- estimation mode (`estimated` when provider usage is unavailable)
- request/policy/experience hashes

Quota enforcement is policy-driven:

- `tenant_max_tokens_per_day`
- `device_max_tokens_per_day`

Exceeded quota returns deterministic deny codes:

- `AI_QUOTA_TENANT_EXCEEDED`
- `AI_QUOTA_DEVICE_EXCEEDED`

## Adding a new provider

1. Add provider id to policy `allowed_providers`.
2. Add adapter in the AI gateway router (`api/ui_ai_console.py`) and preserve fail-closed behavior for unknown providers.
3. Keep provider credentials server-side only; browser calls gateway routes only.
4. Emit provider/model routing decision in audit details.


## Request signature hook (future non-browser device support)

`POST /ui/ai/chat` accepts optional headers now: `X-FG-TS`, `X-FG-NONCE`, `X-FG-SIG`.

- Disabled by default (`FG_AI_DEVICE_SIGNATURE_ENABLED=0`).
- When enabled, missing/invalid signature is denied with deterministic error codes.
- Signing material: `tenant_id|device_id|ts|nonce|request_hash` (HMAC-SHA256 using `FG_AI_DEVICE_SIG_SECRET`).

This preserves current browser flow while providing a fail-closed contract for future signed device traffic.


## Atomic quota enforcement

Quota accounting uses an atomic upsert/increment row per scope/day (`ai_quota_daily`) to avoid race conditions under concurrent requests.

- scope `tenant:<tenant_id>` for tenant cap
- scope `device:<tenant_id>:<device_id>` for device cap

If an increment would exceed the limit, the request fails closed with deterministic quota error codes.


If metering mode is uncertain (`unknown`) on an allow-path response, the gateway fails closed with `AI_METERING_UNCERTAIN` and logs the attempt.


Quota charging metadata is emitted as `quota_charge_mode` (`precharge` or `precharge_refunded`) in audit/usage metadata.

Quota day is UTC and pinned to request start time (requests spanning midnight are charged to the start day).
