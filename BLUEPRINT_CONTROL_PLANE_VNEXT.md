# FrostGate Control Plane + Console — Blueprint vNext (Audit Search/Export Hardening Edition)

## 0) Non‑Negotiables

- Core decides. Admin‑gateway and console are observers/configurators only.
- `FROSTGATE_CONTROL_PLANE_STAGED_…`
- No default secrets in prod. CI can generate ephemerals, prod cannot.
- Tenant scoping is enforced server‑side in core and gateway (defense in depth).
- Contract‑first: OpenAPI + schema snapshots are the contract, drift is a failing build.

## 1) Capability Ledger (Stage Map)

Stage **C4 (Audit Viewer + Export + Evidence Surfacing)** is expanded into:

- **C4a: Audit Search API (admin‑gateway)**
  - `GET /admin/audit/search` (filters: tenant_id, action, actor, status, time range; pagination)
  - Tenant scoping enforced in gateway regardless of client filter
  - Strict response schema stable via contract snapshots

- **C4b: Audit Export API (admin‑gateway)**
  - `POST /admin/audit/export` streaming CSV/JSON
  - Hard tenant scoping (export cannot escape tenant boundary)
  - Optional redaction (IP/UA) controlled by env

- **C4c: Console Audit UI**
  - Search table + filters
  - Export button (csv/json)
  - Highlights panel (recent failures, canary trip events)

## 2) Data Contracts (Audit Event Model)

AuditEvent (core canonical)

Minimum fields:

- `id` (uuid or monotonic id)
- `ts` (RFC3339)
- `tenant_id`
- `actor` (user/service id)
- `action` (string enum‑ish)
- `status` (`success|deny|error`)
- `resource_type`, `resource_id` (optional but recommended)
- `request_id`
- `ip`, `user_agent` (optional, redactable)
- `meta` (json dict, must be schema‑stable for core “known keys”)

### Redaction rule

If `FG_AUDIT_REDACT=true`, then:

- `ip` => `null/omitted`
- `user_agent` => `null/omitted`
- Exports must match the same behavior

## 3) Admin‑Gateway API Contract (authoritative surface)

### 3.1 `GET /admin/audit/search`

Query params

- `tenant_id` (optional input, but gateway clamps to allowed tenant)
- `action` (optional)
- `actor` (optional)
- `status` (optional)
- `from_ts`, `to_ts` (optional)
- `cursor` or `page + page_size` (choose one scheme and freeze it)

Response

- `items: AuditEvent[]`
- `next_cursor` (if cursor‑based)
- `page_info` (if page‑based)

Hard rules

- Gateway computes `effective_tenant_id` (shows up in logs).
- If client asks for unauthorized tenant: `403` with stable message.
- Pagination must be deterministic:
  - stable sort: `(ts desc, id desc)` or equivalent.

### 3.2 `POST /admin/audit/export`

Request

- `format: "csv"|"json"`
- same filters as search
- `fields` optional allowlist (optional, but nice for “enterprise” upsell)

Response

- Streaming
- Header `Content-Disposition: attachment; filename=...`
- Redaction applied if enabled

Hard rules

- Export must use same tenant clamp as search.
- Export must not load all records into memory.
- CSV escaping correct, JSON is newline‑delimited JSON (NDJSON) preferred for streaming.

## 4) Core Integration (single source of audit truth)

Option A (recommended): Admin‑gateway proxies to core audit API

- Core exposes internal‑only audit endpoints.
- Admin‑gateway is policy/scoping layer + UX semantics.

Option B: Admin‑gateway queries audit store directly

- Only allowed if core already exposes the store with safe query semantics OR you treat gateway as a read replica client.

Guardrail: even if gateway queries directly, it must still use core’s tenant authorization model (shared library or signed claim), not “gateway guessed it.”

## 5) Console Blueprint (Audit UI)

Pages

- `/audit`

Filter bar

- tenant selector (if multi‑tenant), action, actor, status, date range

Results table

- time, actor, action, status, request_id, resource, redaction‑aware IP/UA columns

Export dropdown

- CSV/JSON

Highlights panel

- Recent failures (deny/error count)
- Canary trip events (action prefix or explicit flag)

UX guardrails

- Debounce search
- Cursor pagination, not offset
- Export should reflect current filters

## 6) Guardrails (what prevents “works on my laptop” theater)

### 6.1 Contract Guardrails

- `contracts/admin/openapi.json` drift gate remains mandatory.
- Add/maintain audit schema snapshot tests:
  - audit event shape stable
  - pagination shape stable
  - export response headers stable

### 6.2 Security Guardrails

- Tenant clamp is mandatory:
  - search + export cannot accept tenant_id as truth
- Redaction is enforced end‑to‑end:
  - search response
  - export output
  - logs do not leak raw IP/UA when redaction enabled (or at least do not include them in structured audit payload logs)

### 6.3 Performance Guardrails

- Export is streaming (no giant list in memory).
- Search uses bounded page size and indexed sort keys.

### 6.4 CI Guardrails

All lanes must pass:

- `make fg-fast`
- `make fg-contract`
- `make ci-admin`
- `make ci-console`
- docker compose validation lane

If a lane depends on env vars:

- CI must generate ephemerals and assert presence before running.
- Prod must fail‑closed if secrets missing.

## 7) Tests (minimum suite required for “real”)

Gateway tests

- tenant scoping
- export includes only tenant records
- search returns only tenant records even if filter tries other tenant
- redaction
  - with `FG_AUDIT_REDACT=true`, IP/UA absent in both search + export
- pagination stability
  - demonstrate stable ordering and cursor correctness across inserts
- contract schema
  - OpenAPI snapshot includes both endpoints + schemas

Core tests

- audit query returns stable sort order
- audit storage fields consistent with contract

Console tests

- audit page renders
- export triggers correct API call with filters

## 8) Monetization hooks (because “audit export” is secretly a pricing feature)

- Gate export formats:
  - CSV export = paid tier
  - NDJSON export = enterprise
- Gate retention window:
  - default retention X days, extended for paid plans (ties to M‑GOV module later)

`FROSTGATE_MODULE_CATALOG_HIGH_R…`

Evidence bundle surfacing becomes “compliance tier.”

## Repo Documentation Artifacts to Add/Update (authoritative list)

Create these as repo “truth anchors” (one place, not five):

- `BLUEPRINT_CONTROL_PLANE_VNEXT.md` (this blueprint)
- `contracts/admin/openapi.json` updated with audit routes
- `contracts/admin/schemas.py` (schema helpers)
- `admin_gateway/tests/test_audit_endpoints.py` (tenant + redaction + pagination + export streaming)
- `console/app/audit/page.tsx` (UI)
- CI gates in Makefile/workflows for:
  - contract drift
  - admin lane
  - console lane
  - docker‑compose validation
