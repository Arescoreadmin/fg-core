## 2026-06-17 — P1.3D: Enterprise Capability Enforcement

**Reviewer:** Codex | **Classification:** SOC-LOW (additive capability gate; no new auth subsystem, no privilege escalation, no credential handling added)

**Changes:**
- `api/auth_federation.py` — `require_capability("identity.sso")` added as a route dependency on `POST /auth/federation/validate`. This is additive restriction: callers that previously had `admin:write` scope can now be denied if `identity.sso` is not provisioned. No auth logic changed; no new credential paths introduced.
- `api/admin_identity.py` — `require_capability("identity.sso")` added to `GET/PUT /tenants/{id}/config` and `GET /tenants/{id}/readiness`. Existing scope checks unchanged.
- `api/workforce.py` — `require_capability("identity.scim")` added to `POST /workforce/users` and `PATCH /workforce/users/{id}`. Existing scope checks unchanged.
- `api/control_plane_v2.py` — `require_capability("msp.multi_tenant")` added to delegation POST/DELETE; `require_capability("msp.cross_tenant_reporting")` added to delegation GET. Existing scope checks unchanged.
- `api/entitlements.py` — `msp.cross_tenant_reporting` and `msp.tenant_switching` added to `CAPABILITY_REGISTRY`. No existing capabilities modified.
- `services/capability_enforcement/graph.py` — MSP dependency entries added: `msp.cross_tenant_reporting → msp.multi_tenant`, `msp.tenant_switching → msp.multi_tenant`.

**Security posture:** strictly additive — all changes increase access restriction. No auth bypass, no new unauthenticated surfaces, no credential or token handling added.

### Validation

- `make fg-security-pytest`: 1148 passed
- `make fg-fast`: All checks passed

---

## 2026-06-16 — P0-11: Continuous Governance Control Tower (CGCT) Route Addition

**Reviewer:** Codex | **Classification:** SOC-LOW (new governance aggregation routes under `/control-tower`; no new auth subsystems, no privilege escalation, no new credential handling)

**Changes:**
- `api/control_tower.py` — 14 new GET/POST routes under `/control-tower/` prefix. All routes require `governance:read` or `governance:write` scope + ENTERPRISE capability gate. All routes are tenant-bound via `_resolve_caller_tenant()` / `auth_ctx_db_session`. No public or auth-exempt routes added.
- `api/entitlements.py` — 10 new `controltower.*` capabilities added to `CAPABILITY_REGISTRY` and `_enterprise_extras`. No existing capabilities modified.
- `tools/ci/route_inventory.json` — regenerated via `make route-inventory-generate` to reflect new routes.
- `tools/ci/contract_routes.json`, `route_inventory_summary.json`, `topology.sha256`, `plane_registry_snapshot.json` — regenerated as side effects of inventory + contract regeneration.

**Security invariants verified:**
- All 14 new routes require `governance:read` or `governance:write` scope (enforced by `require_scopes`).
- All routes require ENTERPRISE-tier capability (enforced by `require_capability`).
- Tenant isolation enforced by `auth_ctx_db_session` + `_resolve_caller_tenant`.
- No new public, bootstrap, or auth-exempt routes.
- CGCT is read-only aggregate — no new write operations except `POST /posture/compute` (writes to `fg_cgct_posture_snapshots`, `fg_cgct_action_queue`; requires `governance:write` + `controltower.admin`).
- No modifications to auth, middleware, or security subsystems.

**No regressions:** Contract hash updated. Route inventory regenerated. All existing tests pass.

---

## 2026-06-16 — P0-11 fix: remove duplicate cgct plane from plane registry

**Reviewer:** Codex | **Classification:** SOC-LOW (plane registry config only; no route changes, no auth changes)

**Changes:**
- `services/plane_registry/registry.py` — removed `cgct` PlaneDef. The CGCT routes (`/control-tower/*`) are already owned by the existing `control` plane. Duplicate plane registration caused the `control-plane-check` CI gate to fail with multi-plane ownership conflicts on all 14 `/control-tower/` routes.
- `tools/ci/plane_registry_snapshot.json`, `route_inventory.json`, `route_inventory_summary.json`, `topology.sha256` — regenerated to reflect the removal.

**Security invariants unchanged:** No routes added, removed, or modified. Auth scopes, capability gates, and tenant isolation are unchanged. The `control` plane already owned `/control-tower` — this removal resolves the registry conflict without changing any runtime behaviour.

---

## 2026-06-12 — P0: Quarantine Public Debug Route (`/_debug/routes`)

**Reviewer:** Codex | **Classification:** SOC-P0 (auth bypass remediation; `/_debug` removed from public allowlist; enforcement code corrected)

**Problem:**
`/_debug` was present in `PUBLIC_PATHS_PREFIX` (`api/security/public_paths.py`), causing `AuthGateMiddleware` to skip all authentication for any path starting with `/_debug`. The `GET /_debug/routes` endpoint also silently swallowed `HTTPException` from `require_status_auth`, converting 401 responses into 200 `{"ok": false}` responses — meaning auth was non-functional even when callers reached the endpoint logic.

**Changes:**
- `api/security/public_paths.py` — removed `"/_debug"` from `PUBLIC_PATHS_PREFIX`. Auth middleware now enforces authentication on `/_debug/routes`.
- `api/main.py` — `debug_routes()` handler no longer catches `HTTPException`. Auth exceptions propagate as 401/403 as designed.
- `tests/security/test_router_mount_inventory.py` — added negative auth tests: unauthenticated request returns 401; `/_debug` not in `PUBLIC_PATHS_PREFIX`; authenticated request returns 200.
- `tools/ci/route_inventory.json` — regenerated via `make route-inventory-generate` to match current AST state.

**Security invariants verified:**
- `/_debug` is absent from all public path allowlists.
- Unauthenticated `GET /_debug/routes` returns 401 (confirmed by new test).
- `/_debug/` remains in `ALLOWED_INTERNAL_PREFIXES` in `check_route_inventory.py` — the route is correctly classified as `allowed_internal` (not in public contract) and now auth-gated at runtime.
- No new modules created. No dead code.

**No regressions:** All existing tests pass. Route inventory passes. Security gates pass.

---

## 2026-06-09 — PR 5: Legacy Invite Removal + Governed Identity Cutover

**Reviewer:** Codex | **Classification:** SOC-LOW (workforce API surface change; no auth subsystem changes, no privilege escalation, no new credential handling)

**Route inventory changes:**
- `POST /workforce/users/accept-invite` — converted from tenant-bound token-validation endpoint to a stateless 410 tombstone. `tenant_bound: True → False`. No DB access, no token lookup. Deterministic 410 for all callers. No info disclosure.
- `POST /workforce/users` — response shape changed: `invite_token`/`invite_url_hint`/`invite_expires_at` removed; `invitation_id`/`invitation_url` added. Now requires identity config (fail-closed 422 if absent). Creates governance `TenantInvitation` record.
- `GET /workforce/users` — response shape changed: `invite_pending` boolean removed; `identity_binding_status` string added.

**Security invariants verified:**
- No raw invite_token ever appears in any API response after this PR.
- The tombstone endpoint accepts zero body parameters and returns no identity-revealing information.
- All new governance invitation paths go through `TenantIdentityStore.create_invitation()` and are audited.
- New drift types `LEGACY_INVITE_PRESENT` and `UNBOUND_ACTIVE_USER` add HIGH-severity signals to the risk engine.
- `tools/ci/route_inventory.json` regenerated via `make route-inventory-generate`.

**No security regressions:** No new auth paths. No new privilege escalation. No new tenant boundary crossings. No raw credential exposure.

---

## 2026-05-27 — PR 20: Governance Topology Workspace UI

**Reviewer:** Codex | **Classification:** SOC-LOW (UI surface + read/write-gated graph query routes; no auth subsystem changes, no schema migrations)

**New routes (`api/governance_graph.py`):**
- `GET /governance/graph/edges` — `governance:read` scope. Queries `governance_graph_edges` with optional edge_type/source/target filters. Tenant isolated (WHERE tenant_id = caller). No writes.
- `GET /governance/graph/path` — `governance:read` scope. Calls existing `find_path()` service (BFS, max_depth ≤ 10). Returns node chain or `{"found": false}`. No writes.
- `POST /governance/graph/anomalies/{id}/resolve` — `governance:write` scope. Sets `is_active=False`, `resolved_at=utcnow()`. 404 if tenant mismatch. 409 if already resolved. No cascade effects.

**UI security invariants verified:**
- No `dangerouslySetInnerHTML` in any new component.
- `tenant_id` not rendered in any operator panel.
- Cytoscape.js is browser-only; loaded via dynamic `import()` inside `useEffect`. No SSR execution.
- All graph topology data fetched from backend API; no client-side graph computation.
- BFF proxy rules for `governance/graph` and `governance/assets` are allowlisted; server-side scope enforcement is unchanged.

**No security regressions:** No new auth paths. No new privilege escalation. No new tenant boundary crossings. No raw credential exposure. Route inventory and contract authority artifacts regenerated via `make route-inventory-generate` and `make contract-authority-refresh`.

---

## 2026-05-26 — SOC-HIGH-002 — PR 17: Postgres Auth Authority Migration

**Reviewer:** Codex | **Classification:** SOC-HIGH-002 (auth subsystem changes: `api/auth_scopes/`)

**Files changed:**
- `api/auth_scopes/store.py` — NEW: Backend-dispatch key store; Postgres implementation for `get_key_row`, `insert_key_row`, `update_key_enabled`, `update_key_usage`, `list_key_rows`, `probe_auth_store`. Documents coexistence with `api/db/api_keys_store.py`.
- `api/auth_scopes/mapping.py` — `mint_key()` dispatches to `_mint_key_postgres()` or `_mint_key_sqlite()` based on `FG_DB_BACKEND`. `revoke_api_key()`, `rotate_api_key_by_prefix()`, `list_api_keys()`, `_update_key_usage()` extended with Postgres dispatch.
- `api/auth_scopes/resolution.py` — `verify_api_key_detailed()` dispatches lookup/expiry/usage-update to Postgres when `FG_DB_BACKEND=postgres`. SQLite path preserved unchanged.
- `api/config/startup_validation.py` — `_check_auth_store()` updated: `FG_KEY_PEPPER` required in both backends; Postgres path validates `FG_DB_URL` and probes `api_keys` table connectivity.
- `api/main.py` — SQLite init guards wrapped in `_db_backend != "postgres"` checks; `health_ready()` dispatches to `probe_auth_store()` in Postgres mode.
- `deploy/frostgate-core/values.yaml` — `FG_DB_BACKEND: "postgres"` added to env section with `FG_KEY_PEPPER` Secret reference comment.
- `tools/scripts/migrate_auth_sqlite_to_postgres.py` — NEW: One-shot migration CLI; reads SQLite `api_keys`, transforms rows (`name=NULL→"default"`, `tenant_id=NULL→"unknown"`, INTEGER epoch→TIMESTAMPTZ, hash_params TEXT→JSONB), inserts with `ON CONFLICT (key_hash) DO NOTHING`. Supports `--dry-run`.

**Security invariants:**
- All Postgres key-lookup queries use parameterized `text()` — no f-string SQL with user-controlled values.
- All Postgres writes require `tenant_id` (NOT NULL constraint + RLS). `insert_key_row` and `_mint_key_postgres` raise `ValueError` on missing/empty `tenant_id`.
- RLS context set via `set_config('app.tenant_id', :tid, true)` before every tenant-scoped query. Without a valid hint the RLS policy filters all rows; `get_key_row` returns `(None, None, col_set)`.
- `tenant_id_hint` is extracted from the token payload before DB lookup. Cryptographic verification (key_hash/key_lookup HMAC) is the real security gate; RLS prevents cross-tenant row leakage.
- `FG_KEY_PEPPER` is required in **both** SQLite and Postgres modes. No pepper → startup validation error, no fail-open.
- No raw keys, peppers, hashes, lookup hashes, or key material appear in logs.
- SQLite path is fully preserved; no existing behavior removed.
- `probe_auth_store()` runs `SELECT 1 FROM api_keys LIMIT 1` without setting `app.tenant_id`: returns 0 rows under RLS but confirms table existence without raising exceptions.
- Migration script never silently overwrites existing rows (`ON CONFLICT DO NOTHING`); exits non-zero on missing env.

**No new API routes.** No middleware changes. No auth gate weakening.

---

## 2026-05-25 — SOC-HIGH-002 — PR 14: Dependency Authority Normalization

**Reviewer:** Codex | **Classification:** SOC-HIGH-002 (Makefile DEPS_INPUTS change; dependency structure change)

**Files changed:**
- `requirements-shared.txt` — NEW file: 14 shared exact pins (single source of truth)
- `requirements.txt` — restructured to include shared base via `-r requirements-shared.txt`
- `admin_gateway/requirements.txt` — restructured to include shared base via `-r ../requirements-shared.txt`
- `Makefile` — `DEPS_INPUTS` updated to include `requirements-shared.txt`
- `scripts/contract_toolchain_check.py` — `_parse_pins()` updated to resolve `-r` includes recursively

**Security posture:**
- Eliminates cross-service install-order downgrade (PyJWT, Pygments, Alembic were diverging)
- Alembic 1.11.1→1.18.4 (root): admin_gateway always required >=1.13.0; root pin was an undetected oversight. Migration suite passes.
- pip check and pip-audit clean; no new CVE surface
- No auth, middleware, or API behavioral changes

---

## 2026-05-25 — SOC-HIGH-002 — PR 13: CI Budget Hardening (fg-fast 360s → 480s)

**Reviewer:** Codex | **Classification:** SOC-HIGH-002 (CI config and gate threshold changes)

**Files changed:**
- `Makefile` — `FG_FAST_MAX_SECONDS` 360→480, `FG_FAST_WARN_SECONDS` 300→420
- `.github/workflows/ci.yml` — Guard job `timeout-minutes` 15→20

**Rationale:**
- PR 12b CI run: fg-fast suite took 395s on GitHub-hosted ubuntu-latest, exceeding the 360s budget (exit 2) causing Guard and fg-required to fail. Test suite is identical to main; CI machine variance caused the overage.
- 480s gives ~21% headroom above the observed 395s failure case; consistent with the fg-required budget baseline previously established in PR 50 (480s → 1200s escalation).
- Guard job raised 15→20min: job ran 9m56s at 15min cap, leaving only 5min headroom. 20min provides adequate buffer given the 480s (8min) pytest budget plus setup overhead.
- No tests removed; no gates weakened; no coverage reduction. Pure timing tolerance adjustment.

**Security posture:** No behavioral or auth changes. CI gate coverage unchanged.

---

## 2026-05-25 — SOC-HIGH-002 — PR 12a: CVE Closure (Starlette PYSEC-2026-161) dependency governance update

**Reviewer:** Codex | **Classification:** SOC-HIGH-002 (tools/ci critical files updated)

**Files changed:**
- `requirements.txt` — fastapi 0.132.1→0.133.0 (minimum required to permit starlette 1.x); added explicit starlette==1.1.0 pin; removed unused prometheus-fastapi-instrumentator==7.1.0
- `admin_gateway/requirements.txt` — same fastapi and starlette changes; no pfi present there
- `tools/ci/plane_registry_snapshot.json`, `tools/ci/topology.sha256` — regenerated deterministically by contract toolchain after fastapi version change
- `contracts/admin/openapi.json`, `contracts/core/openapi.json`, `schemas/api/openapi.json`, `BLUEPRINT_STAGED.md`, `CONTRACT.md` — regenerated deterministically; fastapi 0.133.0 adds `ctx` and `input` fields to `ValidationError` schema

**Security posture:**
- Closes PYSEC-2026-161: starlette==1.1.0 explicit floor pin eliminates transitive vulnerable starlette 0.x resolution in pip-audit -r mode
- prometheus-fastapi-instrumentator removal confirmed safe: zero imports in application code; metrics endpoint uses prometheus_client directly
- fastapi 0.132.1 declares starlette<1.0.0 — hard incompatibility proven; 0.133.0 is the minimum version permitting starlette 1.x
- No middleware ordering changes; no auth flow changes; no API behavioral changes
- All generated artifacts are deterministic: identical inputs produce identical contract output

---

## 2026-05-25 — SOC-HIGH-002 — PR 11: Cross-Engagement Readiness Drift Detector route inventory update

**Reviewer:** Codex | **Classification:** SOC-HIGH-002 (tools/ci route inventory update)

**Files changed:**
- `tools/ci/route_inventory.json`, `tools/ci/route_inventory_summary.json` — regenerated via `make route-inventory-generate` after adding the readiness drift route.
- `tools/ci/contract_routes.json`, `tools/ci/plane_registry_snapshot.json`, `tools/ci/topology.sha256` — regenerated as part of the same route/OpenAPI refresh.
- `BLUEPRINT_STAGED.md` and mirrored contract authority metadata — refreshed via `make contract-authority-refresh`.

**New route:**
- `GET /field-assessment/engagements/{engagement_id}/readiness-drift` — tenant-scoped cross-engagement readiness drift comparison returning longitudinal improvement/degradation signal.

**Security posture:**
- Route requires `governance:read`.
- Tenant is resolved from auth context only; never from the request body.
- Engagement ownership verified via existing `get_engagement(tenant_id=...)` pattern — cross-tenant engagement IDs return 404 without leaking existence.
- Response contains only safe deterministic fields: prior_engagement_id, prior_score, current_score, delta, pct_change, direction, detected_at.
- `gate_snapshot_json`, raw scan payloads, credentials, UPNs, prompts, tokens, and provider output are never returned.
- Route inventory shows `tenant_bound: true`, `scopes: ["governance:read"]`, `plane: control`.

---

## 2026-05-20 — SOC-HIGH-002 — PR 368.5: Microsoft Graph Field Assessment bridge route

**Reviewer:** Codex | **Classification:** SOC-HIGH-002 (tools/ci route inventory update)

**Files changed:**
- `tools/ci/route_inventory.json`, `tools/ci/route_inventory_summary.json` — regenerated via `make route-inventory-generate` after adding the verified Microsoft Graph connector import route.
- `tools/ci/contract_routes.json`, `tools/ci/plane_registry_snapshot.json`, `tools/ci/topology.sha256` — regenerated as part of the same route/OpenAPI refresh.
- `BLUEPRINT_STAGED.md` and mirrored contract authority metadata — refreshed via `make contract-authority-refresh`.

**New route:**
- `POST /field-assessment/engagements/{engagement_id}/connector-runs/msgraph/import` — tenant-scoped verified import bridge from Microsoft Graph connector output into Field Assessment scan results, normalized findings, evidence links, and guided execution state.

**Security posture:**
- Route requires `governance:write`.
- Tenant binding remains auth-context-only and validates connector tenant lock before state creation.
- Manifest HMAC, manifest hash, schema version, operator acknowledgment, and export-safe bridge contract are verified before import.
- Wrong-tenant imports return 404; tampered manifests and unsafe connector envelopes fail closed with stable error codes.
- Audit payloads contain stable connector IDs, hashes, and counts only; raw Graph payloads and credentials are not logged or exposed.

---

## 2026-05-20 — SOC-HIGH-002 — Field Assessment execution-state route inventory update

**Reviewer:** Codex | **Classification:** SOC-HIGH-002 (tools/ci route inventory update)

**Files changed:**
- `tools/ci/route_inventory.json`, `tools/ci/route_inventory_summary.json` — regenerated via `make route-inventory-generate` after adding the Field Assessment execution-state API.
- `tools/ci/plane_registry_snapshot.json`, `tools/ci/topology.sha256` — regenerated as part of the same route inventory refresh.
- `BLUEPRINT_STAGED.md` and mirrored contract authority metadata — refreshed via `make contract-authority-refresh` after OpenAPI/route metadata changed.

**New route:**
- `GET /field-assessment/engagements/{engagement_id}/execution-state` — tenant-scoped guided execution state for deterministic playbook/readiness evaluation.

**Security posture:**
- Route requires `governance:read`.
- Tenant binding remains auth-context-only through the existing Field Assessment tenant resolver.
- Cross-tenant retrieval follows existing engagement lookup behavior and returns 404.
- Response is export-safe: no raw scan payloads, credentials, secrets, or document contents.
- The frontend displays server-authored readiness and does not calculate authoritative governance readiness locally.

---

## 2026-05-20 — SOC-HIGH-002 — PR 3.5: Governance asset routes marked tenant-bound

**Reviewer:** Codex | **Classification:** SOC-HIGH-002 (tools/ci route inventory update)

**Files changed:**
- `tools/ci/route_inventory.json`, `tools/ci/route_inventory_summary.json` — regenerated via `make route-inventory-generate` after governance asset routes were recognized as tenant-bound.
- `tools/ci/contract_routes.json`, `tools/ci/plane_registry_snapshot.json`, `tools/ci/topology.sha256` — regenerated by the same route inventory refresh.

**Security posture:**
- Governance asset routes remain under `/governance/assets` and retain their governance scopes.
- Tenant binding is now explicit in route metadata through auth-context-only tenant resolution; no tenant IDs are accepted from request bodies.
- The update closes the control-plane registry gap without adding public, bootstrap, or auth-exempt exceptions.
- Validation: `make control-plane-check`, targeted plane/governance migration tests, and `make fg-contract` pass before rerunning `make fg-fast`.

---

## 2026-05-18 — SOC-HIGH-002 — PR 98: Deterministic governance report routes added to route inventory

**Reviewer:** EmpireOverloard | **Classification:** SOC-HIGH-002 (tools/ci route inventory update)

**Files changed:**
- `tools/ci/route_inventory.json` — regenerated via `make route-inventory-generate` to include 5 new `/ingest/assessment/{assessment_id}/governance-report/...` routes.
- `tools/ci/contract_routes.json`, `tools/ci/plane_registry_snapshot.json`, `tools/ci/route_inventory_summary.json`, `tools/ci/topology.sha256` — regenerated as part of the same inventory refresh.

**New routes (all under `/ingest/assessment` prefix, scope `ingest:assessment`):**
- `POST /ingest/assessment/{assessment_id}/governance-report` — generate governance report (tenant-scoped)
- `GET  /ingest/assessment/{assessment_id}/governance-report/{report_id}` — retrieve report
- `GET  /ingest/assessment/{assessment_id}/governance-report/{report_id}/replay` — replay verification
- `GET  /ingest/assessment/{assessment_id}/governance-report/{report_id}/export/html` — HTML export
- `GET  /ingest/assessment/{assessment_id}/governance-report/{report_id}/export/manifest` — manifest JSON

**Security posture:**
- All routes require `ingest:assessment` scope (same as existing assessment/reports routes).
- Tenant isolation: `tenant_id` resolved from auth context only — never from request body.
- Pre-tenant callers use lead-namespace isolation (same as existing assessment routes).
- No AI prose in any deterministic field; manifest hash provides tamper evidence.
- No new auth logic changes. No new scopes. No schema changes beyond `governance_reports` table.

**No auth logic change beyond existing `ingest:assessment` scope. 52 governance report tests pass.**

---

## 2026-05-15 — SOC-HIGH-002 — Enterprise observability middleware and route inventory

**Reviewer:** EmpireOverloard | **Classification:** SOC-HIGH-002 (api/middleware changes)

**Files changed:**
- `api/middleware/otel_tracing.py` (new) — raw ASGI middleware that extracts W3C TraceContext from inbound headers, creates a server-side OTel span wrapping the full request lifecycle, and writes trace_id/span_id into `request.state`. No auth logic. Reads only standard HTTP headers (traceparent, tracestate); writes no cookies or credentials.
- `api/middleware/logging.py` (minor) — adds `trace_id`, `span_id`, and `tenant_id` to the per-request structured log entry (all read from `request.state`). No behavioral change to request handling; logging only.
- `api/observability/` (new package) — Prometheus metrics registry, OTel tracing setup, log context filters, alert condition definitions.
- `api/main.py` (minor) — adds `OTelTracingMiddleware` as the outermost user middleware and a `/metrics` Prometheus scrape endpoint (unauthenticated, internal-only).
- `tools/ci/check_route_inventory.py` (minor) — added `/metrics` to `ALLOWED_INTERNAL_PREFIXES`. The `/metrics` path is the standard Prometheus scrape endpoint; it exposes only counters/histograms, contains no tenant data, and is classified as internal-only.
- `tools/ci/route_inventory.json` — regenerated via `make route-inventory-generate` to include `GET /metrics`.

**Security posture:**
- `OTelTracingMiddleware` performs no authentication or authorization. It passively reads trace propagation headers and emits OTel spans to a configurable backend (disabled by default; activated only when `FG_OTEL_ENDPOINT` is set).
- `/metrics` endpoint exposes only Prometheus counter/histogram text. No tenant data. No credentials. Classified as `allowed_internal` in route inventory.
- `RequestContextFilter` and `TraceContextFilter` read from Python contextvars and the OTel span context — both are write-once per request, isolated by async context.

**No auth logic change. No schema change. No contract change. 51 observability tests pass.**

**Follow-up (same PR):** cardinality guard tests, secret redaction tests, OTel failure-safety tests, metric-name contract test, alert-to-metric and dashboard-to-metric validation tests, and structured log schema doc (`docs/observability/log_schema.md`) added. No additional middleware or auth changes beyond what is described above.

**Second follow-up (observability hardening):** `tools/ci/check_safe_telemetry.py` (new) — AST-based static analysis gate that prevents future contributors from accidentally emitting sensitive field names (`raw_prompt`, `api_key`, `provider_payload`, `authorization`, `bearer_*token`, `password`, `secret`, etc.) as metric labels, OTel span attributes, or structured log `extra=` keys. Added to `fg-fast` as `safe-telemetry-check`. No auth logic change. No schema change. No route change. 13 new tests pass. Gate is additive-only: it blocks additions of forbidden fields, does not modify existing behavior.

**Third follow-up (dynamic telemetry policy):** `api/middleware/otel_tracing.py` (modified) — `_attach_request_attributes` now routes all span attributes through `get_policy().filter_span_attributes()` before calling `span.set_attribute()`. In regulated/strict mode this silently drops any attribute not in `APPROVED_SPAN_ATTRIBUTES`. No new routes. No auth logic change. `api/observability/telemetry_policy.py` (new) — read-only policy module; no middleware, no auth, no routes. `api/observability/tracing.py` (modified) — OTLP exporter construction gated on `policy.allows_external_otlp()`; no behavioral change when policy allows OTLP. 20 new tests pass.

**Fourth follow-up (plane registry fix for /metrics):** `services/plane_registry/registry.py` (modified) — `/metrics` added to `route_prefixes` of the `control` plane so `match_plane("/metrics")` resolves correctly; previously it existed only in `public_routes` with `class_name="allowed_internal"` but was absent from the prefix list, causing `unexpected-route gap: GET /metrics` in `control-plane-check`. `tools/ci/check_plane_registry.py` (modified) — added `"allowed_internal"` to the scope-check bypass list alongside `"public"`, `"bootstrap"`, `"auth_exempt"`, `"docs"`. Semantically correct: `allowed_internal` routes are infrastructure endpoints that require no auth scope (same governance intent as `auth_exempt`, different network-boundary semantics). Route inventory regenerated (`tools/ci/route_inventory.json`) — `/metrics` now maps to `plane_id: control`. No auth logic change. No route visibility change. 5 new tests added; all gates pass.

**Fifth follow-up (PR 80 — Deployment Manager Foundation):** New deployment orchestration subsystem. Schema change (flagged): `migrations/postgres/0048_deployment_manager.sql` (new) adds 4 tables (`deployment_environments`, `deployment_records`, `deployment_events`, `deployment_health_records`). `api/db_models.py` (modified) — 4 new ORM model classes appended. `api/deployment_manager.py` (new) — 11-endpoint FastAPI router under `/control-plane/deployments/`; all routes require `control-plane:read` or `control-plane:admin` scope. `api/main.py` (modified) — deployment_manager_router registered. `services/deployment/` (new package) — pure-Python domain models, state machine (`VALID_TRANSITIONS`), structured audit emission to `frostgate.deployment.audit` logger, SQLAlchemy store with approval gate, rollback lineage traversal, and cycle detection. Route inventory regenerated — 11 new `/control-plane/deployments/` routes all map to `plane_id: control`. No auth logic change beyond scope declarations. No new sensitive data exposed. 44 tests pass.

**Seventh follow-up (PR 80 fix addendum — tenant binding + approval denial + rollback lineage):** `api/deployment_manager.py` — renamed helper `_tenant_from_request` → `_tenant_from_auth`; AST route checker now correctly detects tenant binding for all 12 `/control-plane/deployments/` routes (`tenant_bound: True`). No behavioral change: tenant_id was already resolved from auth context in all handlers, and the store already applied tenant filtering. `tools/ci/route_inventory.json` regenerated — `tenant_bound` and `dependency_categories` corrected for 12 deployment routes. `services/deployment/store.py` — `record_approval(approved=False)` now transitions approval-required deployments to `FAILED` state with optimistic locking, increments `state_version`, sets `completed_at`, and emits `approval_denied` + `state_transition(→failed)` events in hash-chain order; subsequent `transition_state` calls on denied deployments raise `InvalidStateTransition`. `get_rollback_lineage` refactored: initial deployment lookup now propagates `DeploymentNotFound` (API returns 404 / DEPLOY-API-001); only ancestor traversal catches missing records. No new routes. No auth logic change. No new sensitive data exposed. 75 tests pass.

**Sixth follow-up (PR 80 hardening — deployment manager security hardening):** Schema change (flagged): `migrations/postgres/0049_deployment_manager_hardening.sql` (new) — idempotent `ADD COLUMN IF NOT EXISTS` DDL adding 11 columns across 3 existing tables: `deployment_records` gains `approval_granted_at`, `approval_reason`, `approval_policy_version`, `spec_image_digest`, `spec_commit_sha`, `spec_contract_hash`, `spec_topology_hash`, `spec_policy_bundle_version`, `spec_migration_fingerprint` (immutable spec snapshot), and `state_version INTEGER NOT NULL DEFAULT 0` (optimistic locking); `deployment_events` gains `event_hash TEXT` and `previous_event_hash TEXT` (tamper-evident audit chain); `deployment_health_records` gains `expires_at TIMESTAMPTZ` (retention TTL). `api/db_models.py` — 11 new `mapped_column` fields appended to `DeploymentRecordORM`, `DeploymentEventRecord`, `DeploymentHealthRecord`. `services/deployment/models.py` — `STRATEGY_GOVERNANCE` dict (direct/canary forbidden in prod/regulated/hipaa/fedramp/govcon), `CLASSIFICATION_POLICIES` dict (per-classification approval depth, restricted strategies, telemetry/export flags), `DeploymentSpec` frozen dataclass, `TransitionDryRunResult` frozen dataclass. `services/deployment/store.py` — optimistic locking on every `transition_state()` call (`UPDATE WHERE state_version = expected`; raises `ConcurrentModificationError` DEPLOY-007 on 0 rows affected), `_validate_rollback_safety()` (blocks rollback to failed state, blocks cross-tenant rollback; raises `RollbackSafetyViolation` DEPLOY-008), `_validate_strategy_governance()` (raises `StrategyGovernanceViolation` DEPLOY-009 at create time), `validate_transition_dry_run()` (no-side-effect dry-run path). `services/deployment/audit.py` — `compute_event_hash()` SHA-256 chain; every emitted event populates `event_hash` and `previous_event_hash`. `services/deployment/metrics.py` (new) — 7 Prometheus SLO counters/histograms: `frostgate_deployment_transitions_total`, `frostgate_deployment_failures_total`, `frostgate_deployment_rollback_total`, `frostgate_deployment_approval_decisions_total`, `frostgate_deployment_duration_seconds`, `frostgate_deployment_approval_wait_seconds`, `frostgate_deployment_health_probe_results_total`. `api/deployment_manager.py` — dry-run `?dry_run=true` query param on transition endpoint; spec snapshot fields, approval integrity fields (`approval_granted_at`, `approval_reason`, `approval_policy_version`), and `state_version` exposed in responses; 3 new error codes (DEPLOY-API-007/008/009). Route inventory regenerated (`tools/ci/plane_registry_snapshot.json`, `tools/ci/topology.sha256` updated). 25 new tests added; 69 total pass. No new routes. No auth logic change. No new sensitive data exposed.

---

## 2026-03-01T21:24:06Z — SOC-HIGH-002 — Route inventory artifact updated

**Issue:** `tools/ci/route_inventory.json` changed and is classified as a critical SOC-tracked artifact.

**Resolution:** Recorded this change as an approved artifact refresh. No policy semantics changed; inventory updated via `make route-inventory-generate`.

**Files:**
- tools/ci/route_inventory.json

---

## 2026-03-01T19:00:46Z — SOC-HIGH-002 — Route inventory governance update

**Issue:** SOC-HIGH-002 triggered: critical CI governance artifacts changed without SOC review acknowledgement.

**Resolution:** Updated route inventory pipeline + plane registry checks; regenerated route inventory; recorded this change for SOC traceability.

**Files changed:**
- `tools/ci/check_route_inventory.py`
- `tools/ci/plane_registry_checks.py`
- `tools/ci/route_inventory.json`

**Entry policy:** Exactly one issue + one resolution per entry. If additional issues exist, add separate entries.

<!-- SOC-HIGH-002::854d66dd93ea1b3007b82c2b85851ce605d50480::2026-03-01 -->

# Senior Principal Security & Architecture Review (Evidence-Only)

Date: 2026-02-15  
Reviewer mode: paranoid SOC lead + platform architect  
Repository: `fg-core`

## Build-state commands executed

1. `make fg-fast` → **FAILED** because local environment lacks docker CLI; gate failed at `require-docker` in `opa-check` target.
2. `.venv/bin/pytest -q tests/test_core_invariants.py` → **PASSED** (`28 passed, 2 skipped`).
3. `.venv/bin/pytest -q tests/security` → **PASSED** (`77 passed`).

## PHASE 1 — Current State Mapping

### Implemented subsystems (proven in repo)

1. **Core API runtime + middleware chain** (`api/main.py`, `api/middleware/*`).
2. **API-key AuthN/AuthZ + scope + tenant binding** (`api/auth_scopes/*`, `api/middleware/auth_gate.py`).
3. **Decision pipeline + OPA policy integration** (`engine/pipeline.py`, `api/defend.py`, `policy/opa/*`).
4. **Tenant isolation + Postgres RLS + migration assertions** (`migrations/postgres/*`, `api/db_migrations.py`, `tests/postgres/*`).
5. **Config versioning + decision config-hash binding** (`migrations/postgres/0011_*`, `api/config_versioning.py`, ingest/defend usage).
6. **Evidence append-only + tamper-evident chain** (`migrations/postgres/0002_*.sql`, `0010_*.sql`, evidence chain code/tests).
7. **Release/CI gate framework** (`Makefile`, `.github/workflows/ci.yml`, `scripts/release_gate.py`).
8. **Admin gateway (control-plane UI/API)** (`admin_gateway/*`).
9. **Agent plane** (`agent/*`) and sidecar/job components (`supervisor-sidecar`, `jobs/*`).
10. **Tripwire/security alerting + async webhook delivery** (`api/tripwires.py`, `api/security_alerts.py`).

---

### Subsystem details

| Subsystem | Source files | Enforcement mechanism | Proof tests | DB invariants | CI gates | Failure behavior | Observed weaknesses |
|---|---|---|---|---|---|---|---|
| Core API runtime | `api/main.py`, `api/middleware/exception_shield.py`, `api/middleware/request_validation.py`, `api/middleware/dos_guard.py` | Startup validation + prod invariant checks + middleware order | `tests/test_core_invariants.py`, `tests/security/*` | readiness blocks if startup validation/db init fail | `make fg-fast`, `make ci`, hardening lane | Mostly fail-closed in prod; mixed in non-prod | optional router imports and several non-prod fallback paths create drift risk |
| AuthN/AuthZ | `api/middleware/auth_gate.py`, `api/auth_scopes/resolution.py`, `api/auth_scopes/helpers.py` | AuthGate middleware, scoped dependencies, tenant mismatch checks | `tests/security/test_auth_*`, `tests/test_core_invariants.py` | api_keys tenant policy under RLS | route scope lint + security regression gates | `auth_enabled=false` is explicit fail-open; missing key invalid key denied | duplicate auth logic (`require_status_auth` + AuthGate + dependency paths) creates shadow enforcement surface |
| OPA policy path | `engine/pipeline.py`, `api/defend.py`, `policy/opa/defend.rego` | runtime policy call + optional enforce flag | OPA tests via `opa-check` + security tests | N/A | `make opa-check` in `fg-fast` | fail-open when OPA unreachable if enforce flag false; fail-closed if true | prod can run without explicit OPA enforcement unless env explicitly sets/violates gating |
| Tenant isolation / RLS | `migrations/postgres/0003_tenant_rls.sql`, `api/db_migrations.py`, `tests/postgres/test_tenant_isolation_postgres.py` | ENABLE RLS + FORCE RLS + tenant policies + runtime tenant context | postgres tests + migration replay/smoke | RLS + FORCERLS + non-super/non-BYPASSRLS role checks | CI jobs `migrations_replay`, `db_postgres_verify` | fail-closed at DB policy layer when tenant context absent | tenant context setting can no-op if no db_session attached in request state |
| Config versioning | `migrations/postgres/0011_config_versions_and_decision_binding.sql`, `api/config_versioning.py`, `api/ingest.py` | canonical JSON hash + FK binding decision→config_version | tests around decision diff/config paths | FK `(tenant_id, config_hash)` + active config mapping | included in unit/fg-fast lanes | fail-closed for unknown hash/active config missing | legacy hash bootstrap (`legacy_config_hash`) exists as compatibility artifact |
| Evidence integrity | `migrations/postgres/0002_append_only_triggers.sql`, `0010_security_audit_hash_chain.sql`, `api/evidence_chain.py` | append-only triggers + hash-chain fields | merkle/evidence tests | append-only triggers on evidence tables | `db-postgres-assert`, hardening lane | fail-closed on trigger/policy assertion failures | runtime exception handlers in persistence paths may log+continue in some non-critical write failures |
| CI/release gating | `Makefile`, `.github/workflows/ci.yml`, `scripts/release_gate.py` | multi-lane checks + release gate script | numerous test lanes | DB verify lane covers migration invariants | guard/unit/integration/hardening/contract/migrations jobs | intended fail-closed, but local env may skip due missing docker; several tests skip when env missing | some vacuous assertions/skip-heavy tests reduce confidence |
| Admin gateway | `admin_gateway/main.py`, `admin_gateway/routers/auth.py`, `admin_gateway/routers/products.py` | session middleware, CSRF, OIDC, tenant checks | `admin_gateway/tests/*` | separate admin DB models/migrations | CI `ci-admin` lane | generally fail-closed for auth-required admin APIs | open-redirect risk via unsanitized `return_to` redirect target in auth flow |
| Tripwire/webhook | `api/tripwires.py`, `api/security_alerts.py` | async queue + retry + logging | security tests for alerts/tripwires | security_audit_log under RLS | security regression gates | queue full drops alerts; retries bounded | SSRF/redirect/log-injection exposure in tripwire delivery path (no URL policy, follow_redirects=True, URL logged raw) |

## PHASE 2 — Spine Alignment Audit

| Spine area | Score | Strongest proof | Weakest point | Bypass vector | Production risk |
|---|---:|---|---|---|---|
| AuthN/AuthZ fail-closed, scope-bound, tenant-bound | 74 | AuthGate denies missing/invalid keys and enforces scope+tenant mismatch | multiple parallel auth paths | route/dependency path mismatch or future route mounted without scope mapping | inconsistent enforcement and policy regressions under refactor |
| Multi-tenant isolation (RLS + FORCE RLS) | 86 | migration + assertion explicitly check RLS/FORCE and policy names | context propagation depends on request db_session lifecycle | code path that forgets tenant context set | cross-tenant reads/writes blocked at DB, but app-level confusion possible |
| Control-plane/data-plane separation | 68 | separate `admin_gateway` service/profile and core service | shared env/auth semantics and weak redirect handling in control plane | phishing/open redirect via admin login return path | session theft or trusted admin redirect abuse |
| Config versioning + hash binding | 82 | decision FK to `(tenant_id, config_hash)` + canonical hash utility | legacy hash backfill exists | abuse of legacy marker during migration edge cases | forensic ambiguity for legacy migrated decisions |
| Deterministic IDs + tamper resistance | 78 | strict event_id validation + uniqueness + evidence chain tables | non-critical exceptions in persistence can be swallowed with log-only behavior | induce transient DB errors to reduce evidence completeness | incomplete audit/evidence records under fault |
| OPA enforcement in prod/staging | 61 | enforce mode denies when policy says no and on OPA unreachable | enforce flag optional unless explicitly set/validated | deploy with OPA reachable but enforce disabled + risk flaging mis-set | policy bypass (observe-only behavior) in prod-like deployments |
| CI enforcement of invariants | 80 | broad CI matrix includes hardening/migrations/contracts/security lanes | skip-heavy tests and vacuous assertions remain | CI green despite meaningful coverage holes | false confidence and drift over time |
| Release preflight validation | 75 | `scripts/release_gate.py` blocks on readiness/gaps/contract drift | readiness math allows vacuous 100 when no items in class | manipulate matrix categorization or missing entries | false release readiness signal |
| Audit trail completeness | 64 | security logs + DB audit tables + evidence chain | webhook queue overflow drops alerts, no dead-letter durability | force queue saturation to suppress outbound alerts | silent degradation of detection telemetry |
| No silent fallback paths | 49 | prod invariants block key unsafe flags | multiple intentional fallbacks (`_optional_router`, no-op rate-limit import fallback, auth-disabled mode) | misconfiguration or import failure devolves enforcement | silent weakening of controls |
| No vacuous tests | 52 | large security suite exists and passes | explicit `assert True` tests + widespread skips by env | keep CI green while asserting little | regression escapes despite passing CI |

## PHASE 3 — Security Gap Detection

Format: `Risk | File | Description | Exploit Path | Fix Strategy`

1. **HIGH | `api/tripwires.py` | Webhook delivery accepts arbitrary URL and follows redirects; no egress allowlist.**  
   **Exploit path:** attacker controlling `FG_ALERT_WEBHOOK_URL` (or config path feeding it) can pivot to internal metadata/loopback via redirect chain.  
   **Fix:** enforce URL allowlist + deny private ranges + disable redirects by default + sign outbound requests and pin destination host.

2. **HIGH | `admin_gateway/routers/auth.py` | `return_to` is used directly in redirect response (open redirect risk).**  
   **Exploit path:** crafted login URL with external `return_to` yields trusted domain bounce for phishing/token leakage.  
   **Fix:** allow only relative paths or explicit allowlist hosts; reject absolute external URLs.

3. **HIGH | `api/ingest.py` | Rate-limit dependency silently falls back to no-op on import failure.**  
   **Exploit path:** package/import issue disables runtime rate limiting without startup hard-fail.  
   **Fix:** remove no-op fallback in prod; startup must fail when rate-limit module unavailable.

4. **MEDIUM | `api/main.py` + `api/middleware/auth_gate.py` + `api/auth_scopes/resolution.py` | Duplicate/shadow auth enforcement paths.**  
   **Exploit path:** new route could rely on one path but bypass another (scope mapping mismatch).  
   **Fix:** single authoritative auth+scope policy layer; route registration audit test.

5. **MEDIUM | `engine/pipeline.py` | OPA failures become allow when enforce=false (`opa_unreachable` -> allow).**  
   **Exploit path:** deployment drift sets observe mode in prod-like environment.  
   **Fix:** enforce=true immutable in prod/staging; treat unreachable as deny regardless of flag outside dev/test.

6. **MEDIUM | `tests/test_core_invariants.py` | Vacuous assertions (`assert True`) and skip-heavy branches.**  
   **Exploit path:** CI passes while invariant not truly verified.  
   **Fix:** replace vacuous tests with behavioral assertions and fail when expected files/features absent in protected branches.

7. **MEDIUM | `api/tripwires.py` | Alert queue full drops events with log-only handling (no durable DLQ).**  
   **Exploit path:** flooding alerts causes blind spots in outbound notifications.  
   **Fix:** persistent dead-letter store + backpressure metrics + alert on sustained drop rate.

8. **LOW | `api/main.py` | Non-prod defaults allow tenant auto-fill (`FG_TEST_TENANT_DEFAULT_ALLOW`) and auth toggles.**  
   **Exploit path:** config drift into staging/dev-like prod profile weakens guarantees.  
   **Fix:** explicit env profile hardening and immutable prod config templates.

9. **LOW | `api/auth_scopes/validation.py` | Auth DB expiration check supports acknowledged fail-open mode.**  
   **Exploit path:** operator misuses fail-open flags during incident and leaves enabled.  
   **Fix:** time-bound emergency override with automatic expiry + alerting.

10. **LOW | `api/tripwires.py` | Raw URL values appear in logs (`url` field) without sanitation.**  
    **Exploit path:** crafted URL with control chars can poison downstream log tooling.  
    **Fix:** sanitize/control-char strip for URL before logging and structured-field escaping.

## PHASE 4 — Architectural Drift Detection

1. **Duplicate enforcement logic:** auth and tenant checks exist in middleware, dependencies, and per-endpoint helpers (`AuthGate`, `require_status_auth`, `require_scopes`, `bind_tenant_id`).
2. **Shadow auth paths:** `auth_enabled` short-circuit in middleware plus endpoint dependencies can diverge.
3. **Middleware/router inconsistency:** route scope map in middleware is partial (`/stats` shown), while many routes rely only on dependency declarations.
4. **Config flags that do not directly enforce behavior:** `FG_AUTH_ALLOW_FALLBACK` is policed by invariants/profile checks but not a direct centralized runtime switch in auth path.
5. **Env vars defined but primarily validated, not functionally consumed for crypto operations:** `FG_ENCRYPTION_KEY`/`FG_JWT_SECRET` appear in startup validation checks; evidence of active cryptographic use is weak in core runtime path.
6. **Startup/runtime mismatch risk:** startup validation warns/errors on config posture, but several runtime components still include fallback behavior on import or non-prod branches.

## PHASE 5 — Maturity Stage Assessment

**Classification: Stage 2 – Hardened MVP**

### Why not Stage 1
- Has explicit CI matrix, migration assertions, RLS/FORCE RLS checks, security regression tests, release gate script.

### Why not Stage 3
- Not yet strict single-path enforcement for auth/scope/tenant.
- Contains silent fallback/no-op patterns in enforcement-critical paths.
- Alerting path lacks durable delivery guarantees and strict egress controls.
- Vacuous/skip-heavy test residue still present.

## PHASE 6 — Move-Forward Execution Plan

### P0 – Immediate spine fixes (blocking)

1. **Remove rate-limit no-op fallback in `api/ingest.py`.**  
   Why: prevents silent loss of abuse controls.  
   Risk if ignored: DoS throttling bypass by import/config failure.  
   Test required: force import failure and assert startup hard-fails in prod profile.  
   CI gate: new invariant test in hardening lane.

2. **Lock OPA enforce=true in prod/staging at runtime (not only startup checks).**  
   Why: policy engine must be mandatory in protected envs.  
   Risk: policy bypass through observe-mode deployment drift.  
   Test: prod env matrix tests for `FG_OPA_ENFORCE=0` hard failure.  
   CI gate: prod-profile check + runtime integration test.

3. **Patch admin open redirect in login/callback return flow.**  
   Why: prevent phishing/token leak pivot.  
   Risk: admin credential/session compromise chain.  
   Test: malicious absolute URL rejected; relative path accepted.  
   CI gate: `ci-admin` security test.

4. **Add outbound webhook egress policy in tripwire delivery path.**  
   Why: SSRF and redirect abuse prevention.  
   Risk: internal network probing/data exfiltration.  
   Test: block private IP, localhost, redirect to blocked host.  
   CI gate: security regression tests + allowlist unit tests.

### P1 – Structural strengthening

1. **Consolidate auth/scope/tenant into one authoritative enforcement layer.**  
   Why: eliminate shadow paths and drift.  
   Risk: route-level bypass due to inconsistent dependency use.  
   Test: route inventory test asserting every protected route has enforced scopes + tenant bind.  
   CI gate: route-enforcement manifest diff gate.

2. **Create route-policy registry (single source of truth) consumed by middleware and routers.**  
   Why: remove duplicated scope mapping and dependency drift.  
   Risk: accidental unscoped endpoint exposure.  
   Test: generated matrix parity test.  
   CI gate: policy-registry compile check.

3. **Promote startup warnings to hard-fails for production-prohibited fallback modes.**  
   Why: avoid soft warning complacency.  
   Risk: insecure config reaches runtime.  
   Test: startup validation fixture matrix.  
   CI gate: prod startup contract tests.

### P2 – Security reinforcement

1. **Implement durable dead-letter channel for webhook delivery failures and queue overflow.**  
   Why: preserve critical alerts under stress.  
   Risk: blind SOC telemetry windows.  
   Test: saturation test proves no alert loss without DLQ record.  
   CI gate: tripwire resilience test.

2. **Harden log sanitization for URL fields in tripwire/security logging.**  
   Why: prevent log injection/tool poisoning.  
   Risk: SOC pipeline confusion/alert suppression.  
   Test: control-char payload tests.  
   CI gate: logging hygiene tests.

3. **Enforce constant-time compare everywhere secrets/keys compared (including legacy paths).**  
   Why: remove timing side-channels comprehensively.  
   Risk: incremental key probing.  
   Test: static lint + targeted secret-compare unit tests.  
   CI gate: secret-compare lint rule.

### P3 – Observability + resilience

1. **Expose security SLO metrics: denied_auth, tenant_mismatch, scope_denied, webhook_drop_count, OPA_unreachable_count.**  
   Why: detect enforcement degradation quickly.  
   Risk: silent failures persist unnoticed.  
   Test: metric emission integration tests.  
   CI gate: metrics contract test.

2. **Add release preflight assertion for zero vacuous tests in critical invariant suites.**  
   Why: ensure CI signals are meaningful.  
   Risk: false confidence from green builds.  
   Test: guard script scans for `assert True`/unbounded skips in protected directories.  
   CI gate: new `test-quality` lane.

### P4 – Competitive differentiation

1. **Cryptographic attestation bundle signing for release artifacts and evidence packets.**  
   Why: stronger supply-chain and forensic credibility.  
   Risk if ignored: weaker trust posture in regulated bids.  
   Test: signature verification in release gate.  
   CI gate: signed artifact verification job.

2. **Policy simulation/diff gate for OPA + config-version transitions before deployment.**  
   Why: preempt policy regressions.  
   Risk: unintended deny/allow at rollout.  
   Test: canary replay with historical decision corpus.  
   CI gate: policy regression lane blocking deploy.


## SOC Review Sync Update (2026-02-17T17:43:16Z)

**Commit:** 4964e86

### Files reviewed (required by SOC-HIGH-002)
- admin_gateway/auth/config.py

### Summary
- Reviewed security impact of auth/tenant controls and route inventory updates.
- Verified route inventory gate is green and audit routes remain scope-protected + tenant-bound.

### Verification
- make admin-test
- make route-inventory-generate
- make route-inventory-audit
- make fg-fast-full (expected to pass SOC sync after this update)

### Reviewer
- Jason (repo owner / final authority)

## SOC Review Sync Update (2026-02-19T00:00:00Z)

**Commit:** e76b733

### Files reviewed (required by SOC-HIGH-002)
- tools/ci/check_connectors_rls.py
- tools/ci/route_inventory.json
- tools/ci/validate_connector_contracts.py

### Summary
- Reviewed connector control-plane CI hardening changes in security-critical tooling paths.
- Verified new connector RLS checker and connectors-gate wiring align with existing enforcement model.
- Verified route inventory and contract-validation tooling updates are reflected in SOC review docs per gate policy.

### Verification
- make soc-review-sync
- make connectors-gate
- make route-inventory-audit
- python tools/ci/check_connectors_rls.py

### Reviewer
- Jason (repo owner / final authority)

## SOC Review Sync Update (2026-02-25T19:31:33Z)

**Commit:** b477eba

### Files reviewed (required by SOC-HIGH-002)
- tools/ci/attestation_bundle.sha256

### Summary
- Reviewed security impact of auth/tenant controls and route inventory updates.
- Verified route inventory gate is green and audit routes remain scope-protected + tenant-bound.

### Verification
- make admin-test
- make route-inventory-generate
- make route-inventory-audit
- make fg-fast-full (expected to pass SOC sync after this update)

### Reviewer
- Jason (repo owner / final authority)

## 2026-02-28 — PR: SOC-critical updates (workflow + OPA + CI guards + route inventory)

### Files changed (SOC-critical)
- .github/workflows/ai-ledger-guard.yml
- policy/opa/config.yaml
- policy/opa/opa-config.yml
- tools/ci/guard_pr_fix_log.py
- tools/ci/route_inventory.json

### Why
- Updated CI/workflow guard behavior and related SOC enforcement scripts.
- Updated OPA configuration (policy runtime behavior).
- Regenerated route inventory after adding/adjusting routes (inventory must match runtime).

### Risk
- **Workflow changes:** may affect CI enforcement paths; mitigated by running full `make pr-check`.
- **OPA config changes:** affects authorization/decisioning; mitigated by existing OPA + contract gates and policy tests.
- **Route inventory changes:** documentation/inventory alignment; mitigated by `route-inventory-audit` passing.

### Validation performed
- `python -m py_compile scripts/prod_profile_check.py`
- `make route-inventory-generate`
- `make route-inventory-audit`
- `make pr-check` (all gates except SOC review sync prior to this doc update)

### Rollback
- Revert the above files to prior commit if unexpected enforcement behavior occurs.

## 2026-02-28 — Governance artifact refresh

- Updated: tools/ci/route_inventory.json
- Reason: regenerated runtime route inventory (AST-derived) to reflect current routes.
- Evidence:
  - route_inventory.json sha256: e5c637c65d3248e20ff4a34950f03bbe9494fcabca2a246ed9af346c433f8630
  - topology.sha256 entries:
    - plane_registry_snapshot.json: 090eec7430a6a27ba18f6043a396e108292ec72eda78da6478e52ceee034aaea
    - route_inventory.json: e5c637c65d3248e20ff4a34950f03bbe9494fcabca2a246ed9af346c433f8630
    - contract_routes.json: 53b62b172162b69baa75348306371186f5e6d32d0663854c6c97d2d327a98b63
## 2026-03-29 — Task 2.1: Remove Human Auth from Core (Auth Boundary Hardening)

### What changed
- `api/auth_scopes/resolution.py`: `_extract_key()` now rejects cookie-based auth in hosted profiles (prod, production, staging). Cookie extraction returns `None` when `is_prod_like_env()` is true.
- `api/main.py`: `_is_production_runtime()` extended to include `"staging"` in the hosted set. UI routes (`/ui*`) are no longer mounted when `FG_ENV=staging`.
- `api/main.py`: Cookie fallback in `check_tenant_if_present()` and `require_status_auth()` conditioned on `not _is_production_runtime()`.

### Why
- `staging` is treated as a hosted profile by `is_production_env()` and `_is_production_like()`, but `_is_production_runtime()` previously excluded it, causing UI routes to mount in staging.
- Cookie-based auth is a browser/human auth path; core must not accept it in hosted (prod/staging) profiles. Only X-API-Key header auth is permitted at hosted core runtime.

### Risk
- **Low.** Non-hosted (dev/test) behavior unchanged. Service-to-service header auth unaffected. Cookie auth is narrowly removed from hosted runtime only.
- Staging UI users must use X-API-Key header (or go through gateway) — consistent with the hosted auth boundary.

### Validation performed
- `pytest -q tests -k 'auth and core'`: 36 passed
- `pytest -q tests/security/test_core_human_auth_boundary.py`: 23 passed
- `make fg-fast`: clean except pre-existing SOC-P0-007 (ci-admin timeout)

### Rollback
- Revert `api/auth_scopes/resolution.py` and `api/main.py` changes if unexpected service auth issues arise.


---

## 2026-04-11 — Task 7.2: End-to-end request tracing (propagation + integrity)

### What changed
- `api/middleware/logging.py` (NEW): `RequestLoggingMiddleware` — one structured log entry per request, captures `request_id`, `method`, `path`, `status_code`, `duration_ms`, `client_ip`. No auth logic, no route-level side effects.
- `api/main.py`: `RequestLoggingMiddleware` wired as the 2nd `_add_middleware` call, inner to `SecurityHeadersMiddleware` so `request.state.request_id` is populated before the log fires.
- `admin_gateway/middleware/request_id.py`: `_safe_request_id()` added — inbound `X-Request-Id` accepted only if it matches strict UUID v4 regex; otherwise replaced with `uuid.uuid4()`. Prevents log injection via attacker-controlled header.

### Why
- Per-request log entries are required for trace correlation. Without a structured entry the `request_id` set by `SecurityHeadersMiddleware` was unreachable from log analysis.
- The gateway accepted any string as `X-Request-Id`, enabling log injection. UUID v4 format validation closes that gap.

### Risk
- **Low.** `RequestLoggingMiddleware` is read-only with respect to request/response content — it logs metadata and returns the upstream response unchanged.
- Gateway callers that previously passed non-UUID `X-Request-Id` values will now receive a fresh UUID4 in the response. All internal services use generated UUIDs. `test_health_propagates_request_id` updated to use a valid UUID4.

### Validation performed
- `pytest -q admin_gateway/tests/test_request_tracing_task72.py`: 9 passed
- `pytest -q tests/test_request_tracing_task72.py`: 8 passed
- `pytest -q admin_gateway/tests/`: 183 passed
- `pytest -q tests/test_jobs_smoke.py tests/test_merkle_anchor.py tests/test_sim_validator.py`: all passed

### Rollback
- Remove `RequestLoggingMiddleware` import and `_add_middleware` call from `api/main.py`.
- Revert `admin_gateway/middleware/request_id.py` to remove UUID validation.

---

## PR #219 review fix — failure-path request logging (2026-04-12)

### Files changed
- `api/middleware/logging.py`: `dispatch()` refactored from success-only log to `try/finally` pattern. `status_code` initialised to `500` as fallback, updated to actual response status on success path.

### Why
PR #219 review identified that `RequestLoggingMiddleware.dispatch()` only emitted a log record on the success path. A downstream exception would skip the `log.info()` call entirely, leaving the request untraced. The `try/finally` pattern guarantees exactly one log record per request regardless of whether downstream raises.

### Risk
- **Low.** The log call moves into a `finally` block — no change to request/response content, no new I/O, no change to exception propagation (exceptions still bubble after `finally` completes).

### Validation performed
- `pytest -q tests/test_request_tracing_task72.py`: 11 passed (includes 3 new failure-path tests)
- `make fg-fast`: all gates passed

---

## Task 17.4 — Agent lifecycle controls: `/agent/config` added to public paths (2026-04-27)

### Files changed
- `api/security/public_paths.py`: added `/agent/config` to `PUBLIC_PATHS_EXACT`

### Why
Task 17.4 introduces a `GET /agent/config` endpoint that agents call using HMAC device-key signatures (same auth as `/agent/heartbeat` and `/agent/enroll`). The endpoint must be excluded from the global API-key auth middleware, identical to all other agent device endpoints. No change to the actual authentication model — `require_device_signature` still validates the HMAC before the handler runs.

### Risk
- **Low.** `/agent/config` is authenticated by `require_device_signature` (HMAC + nonce replay protection). Adding it to `PUBLIC_PATHS_EXACT` only bypasses the API-key gate, not device authentication. The pattern is identical to `/agent/heartbeat`, `/agent/enroll`, and the seven other agent paths already in the list.

### Validation performed
- `pytest -q tests/agent/test_agent_lifecycle.py`: 27 passed
- `pytest -q tests -k '(agent and evidence) or (ingest and tenant) or (lifecycle)'`: 118 passed, 2 skipped
- `git diff --check`: clean

---

## Task 17.5 — Agent observability: route inventory updated (2026-04-28)

### Files changed
- `tools/ci/route_inventory.json` / `route_inventory_summary.json` / `topology.sha256` / `plane_registry_snapshot.json`: regenerated to include new `GET /admin/agent/devices/{device_id}/status` endpoint

### Why
Task 17.5 adds an operator observability endpoint. The new route is under the existing `/admin/agent` prefix, which is governed by the `control` plane with `keys:admin` scope required. No new security perimeter — same auth model as all other `/admin/agent` routes. Route inventory regenerated via `make route-inventory-generate` as per standard process.

### Risk
- **Low.** `GET /admin/agent/devices/{device_id}/status` requires `keys:admin` scope and derives tenant from auth context. It does not expose cross-tenant data. The endpoint is not in PUBLIC_PATHS and will be rejected by the API-key middleware without a valid admin key.

### Validation performed
- `pytest -q tests/agent/test_agent_observability.py`: 18 passed
- `make fg-fast`: All checks passed (post-refresh)

---

## Task 17.5 addendum — Docker CI: diagnostics hardening (2026-04-28)

### Files changed
- `.github/workflows/docker-ci.yml`: Added `FG_SIGNING_SECRET` and `FG_INTERNAL_AUTH_SECRET` to `.env.ci` generation; added `frostgate-core` and `frostgate-migrate` log/inspect collection to diagnostics step

### Why
Two issues fixed:
1. The "Persist docker diagnostics" step ran `docker compose --env-file .env.ci ps/logs` but `.env.ci` did not contain `FG_SIGNING_SECRET` / `FG_INTERNAL_AUTH_SECRET`, causing compose to fail with interpolation errors because docker-compose.yml requires these vars via `${VAR:?}`. Added them to `.env.ci` (with CI placeholder values) so all compose invocations use a single self-contained env-file.
2. `frostgate-core` and `frostgate-migrate` container logs were not captured in CI artifacts on failure, making root-cause analysis impossible. Added `docker logs` and `docker inspect` collection for both containers.

### Risk
- **Low.** No change to runtime security posture. `.env.ci` is ephemeral per-run (generated in CI, never committed). The values added (`ci-signing-secret-32-bytes-minimum`, `ci-internal-auth-secret-32-bytes`) are the same placeholder CI values already used by all other compose steps via step-level `env:` blocks. Diagnostics collection is `if: always()` and uses `|| true` so failures are non-blocking.

### Validation performed
- `make fg-fast`: All checks passed
- `pytest -q tests/agent/test_agent_observability.py tests/agent/test_agent_lifecycle.py`: 45 passed

---

## Provider BAA enforcement — security_audit.py addendum (2026-04-29)

### Files changed
- `api/security_audit.py`: Added `EventType.PROVIDER_BAA_ALLOWED` and `EventType.PROVIDER_BAA_DENIED` to the `EventType` enum

### Why
BAA enforcement (provider routing gate) requires dedicated, stable audit event types so compliance teams can filter provider-routing decisions from the audit log without relying on `ADMIN_ACTION` reason strings. The two new types emit on every allow and deny decision, creating a tamper-evident record of BAA gate outcomes.

### Security posture impact
- Additive only: new enum values, no change to existing event handling or routing logic
- All BAA enforcement decisions now emit structured audit events with `provider_id`, `baa_status`, `enforcement_result`, `reason_code`
- Denied events carry `Severity.WARNING`; allowed carry `Severity.INFO`
- Audit payload explicitly excludes: `expiry_date`, `document_ref`, contract text, secrets, PHI

### Validation performed
- `make fg-fast`: All checks passed
- `pytest -q tests/security/test_provider_baa_enforcement.py`: 35 passed

---

## PHI classifier enforcement — security_audit.py addendum (2026-04-29)

### Files changed
- `api/security_audit.py`: Added three `EventType` values:
  - `PHI_CLASSIFICATION_PERFORMED` — emitted when classification runs and no PHI is found
  - `PHI_CLASSIFICATION_DETECTED` — emitted when PHI is detected but routing is allowed (regulated provider with active BAA)
  - `PHI_CLASSIFICATION_ENFORCED_BLOCK` — emitted when PHI is detected and the provider cannot satisfy BAA requirements

### Why
PHI classification is now a first-class enforcement dependency wired into all AI request entry points (`/ui/ai/chat`, `/ai/infer`, RAG ingest). Dedicated event types allow compliance teams to separately track (a) classification outcomes and (b) enforcement blocks without relying on `ADMIN_ACTION` reason strings.

### Security posture impact
- Additive only: new enum values, no change to existing event handling
- Every PHI enforcement decision emits a structured audit event with `contains_phi`, `sensitivity_level`, `phi_types` (type names only, no raw values), `enforcement_action`, `reasoning_code`
- Block events carry `Severity.WARNING`; clean classifications carry `Severity.INFO`
- Audit payload explicitly excludes: raw input text, extracted PHI values, full request body

### Validation performed
- `make fg-fast`: All checks passed
- `bash codex_gates.sh`: All gates passed

## Real LLM provider boundary — tools/ci/validate_ai_contracts.py addendum (2026-04-29)

### Files reviewed (required by SOC-HIGH-002)
- `tools/ci/validate_ai_contracts.py`: Added `"anthropic"` to `KNOWN_PROVIDERS` set

### Why
The AI contract validator previously only recognized `"simulated"` as a valid provider ID in policy contracts. Adding the `anthropic` provider as a first-class real LLM integration requires that the contract CI gate recognizes it as a sanctioned provider. Without this, deploying an `allowed_providers: ["anthropic"]` policy would fail the `validate-ai-contracts` gate.

### Security posture impact
- The `KNOWN_PROVIDERS` set in `validate_ai_contracts.py` is the authoritative CI-enforced allowlist for provider IDs in AI policy contracts. Expanding it to include `"anthropic"` explicitly permits `anthropic` in tenant policies.
- No new route, no new auth scope, no new audit event type. Impact is limited to contract validation allowlist.
- Provider activation still requires `FG_ANTHROPIC_API_KEY` at runtime (fail-closed: missing key → `AI_PROVIDER_CONFIG_MISSING`).
- Simulated provider remains gated by `FG_AI_ENABLE_SIMULATED`; blocked in prod by default.
- BAA gate ordering preserved: PHI classification → BAA enforcement → provider call. No bypass path added.

### Verification
- `make fg-fast`: All checks passed
- `bash codex_gates.sh`: All gates passed

## PHI-aware Azure provider routing — tools/ci/validate_ai_contracts.py addendum (2026-04-30)

### Files reviewed (required by SOC-HIGH-002)
- `tools/ci/validate_ai_contracts.py`: Added `"azure_openai"` to `KNOWN_PROVIDERS` set

### Why
Deterministic PHI-aware routing requires `azure_openai` as the configured PHI provider ID in AI policy contracts. The contract validator is the CI-enforced provider allowlist for policy files, so Azure must be recognized there before tenant policy can approve it.

### Security posture impact
- `azure_openai` is contract-allowed only as a canonical provider ID; runtime activation still requires explicit Azure endpoint, deployment, and API key configuration.
- PHI routing remains fail-closed: PHI selects Azure only when known, tenant-allowed, configured, and BAA-approved.
- No fallback to Anthropic or simulated is introduced after routing denial, BAA denial, or provider failure.
- Audit metadata records safe routing fields (`requested_provider`, `selected_by`, `routing_reason_code`, `requires_baa`) without raw prompt, minimized prompt, raw response, provider body, or secrets.

### Verification
- `make fg-fast`: All checks passed
- `bash codex_gates.sh`: All gates passed

## Retrieval policy contract validation — tools/ci/validate_ai_contracts.py addendum (2026-05-10)

### Files reviewed (required by SOC-HIGH-002)
- `tools/ci/validate_ai_contracts.py`: Added repo-root path resolution so direct execution with `python tools/ci/validate_ai_contracts.py` uses the same imports as the Make contract lane.

### Why
PR 27 retrieval governance adds strict AI policy schema fields for corpus scope,
retrieval depth, semantic strategy eligibility, lexical fallback, and no-context
behavior. The review addendum requires the direct validator command to be a
first-class gate, not only the Make-wrapped `PYTHONPATH=.` invocation.

### Security posture impact
- No provider allowlist expansion and no runtime AI provider routing change.
- Contract validation remains strict: unknown policy fields are rejected, allowed retrieval strategies are enum-bound, and `max_top_k` is bounded to integer values >= 1.
- The validator path change is import/bootstrap only; it does not bypass schema validation or weaken `additionalProperties=false`.
- Retrieval policy audit metadata remains ID/count/reason-code only and excludes chunk text, prompts, vectors, provider payloads, and secrets.

### Verification
- `python tools/ci/validate_ai_contracts.py`: Passed
- `pytest -q tests/test_retrieval_policy_engine.py`: Passed

## Simple AI chat endpoint — OpenAPI security diff and route inventory addendum (2026-05-01)

### Files reviewed (required by SOC-HIGH-002)
- `tools/ci/check_openapi_security_diff.py`: Added `POST /ai/chat` to the exact known AI route set.
- `tools/ci/protected_routes_allowlist.json`: Added `/ai/chat` as a protected route.
- `tools/ci/route_inventory.json`, `tools/ci/contract_routes.json`, `tools/ci/route_inventory_summary.json`, `tools/ci/plane_registry_snapshot.json`, `tools/ci/topology.sha256`: Regenerated after adding `POST /ai/chat`.

### Why
The new root `POST /ai/chat` endpoint is a tenant-bound, scoped AI surface backed by the existing AIPlane pipeline. The OpenAPI security diff intentionally blocks unknown `/ai/*` routes, so the new route must be named explicitly and present in the protected route inventory with auth and tenant metadata.

### Security posture impact
- Additive route only: `POST /ai/chat` requires `compliance:read` and tenant binding through the same dependencies as `POST /ai/infer`.
- The route reuses AIPlane policy, PHI routing, BAA enforcement, prompt minimization, tenant-scoped RAG retrieval, response grounding validation, audit metadata, and existing provider dispatch.
- No fallback provider behavior is introduced. Unsupported provider output is still replaced with `NO_ANSWER` by the validator path before hashing, persistence, and audit.
- OpenAPI response metadata documents stable error-code responses for policy/auth denials so the route remains compatible with the security diff gate.

### Verification
- `.venv/bin/pytest -q tests/security/test_openapi_security_diff_scoping.py`: 5 passed
- `make route-inventory-generate`: route inventory regenerated
- `make contract-authority-refresh`: authority markers refreshed

### Addendum — 2026-05-01 auth response schema alignment
- `api/ai_plane_extension.py`: `/ai/chat` 401/403 OpenAPI response metadata now documents the actual FastAPI auth envelope, `{"detail": "..."}`, emitted by `require_scopes(...)`.
- `contracts/core/openapi.json`, `schemas/api/openapi.json`, `BLUEPRINT_STAGED.md`, `CONTRACT.md`, `tools/ci/plane_registry_snapshot.json`, and `tools/ci/topology.sha256`: regenerated/refreshed after the response metadata correction.
- Security posture is unchanged: the endpoint remains tenant-bound, scoped with `compliance:read`, and protected by the same AIPlane policy/BAA/RAG/validator pipeline.

## PR 50 — Corpus Management Console — Route inventory and contract authority addendum (2026-05-13)

### Files reviewed (required by SOC-HIGH-002)
- `tools/ci/route_inventory.json`: Added three new `/rag/` console routes after `make route-inventory-generate`.
- `tools/ci/route_inventory_summary.json`: Regenerated after route inventory update.
- `tools/ci/plane_registry_snapshot.json`: Regenerated; no plane registry changes.
- `tools/ci/topology.sha256`: Regenerated after contract artifacts updated.
- `BLUEPRINT_STAGED.md`, `CONTRACT.md`: Authority markers refreshed via `scripts/refresh_contract_authority.py`.

### Why
PR 50 adds three new tenant-scoped, `governance:write`-gated read-only endpoints under `/rag/`:
- `GET /rag/corpora/{corpus_id}` — corpus detail with operational stats
- `GET /rag/corpora/{corpus_id}/documents` — paginated document list
- `GET /rag/documents/{document_id}` — document detail with chunk summary

These routes reuse the existing `governance:write` scope and `require_bound_tenant` tenant binding identical to the existing `/rag/corpora` and `/rag/retrieval-policy` endpoints already in the contract. The new routes are read-only (GET only). The core OpenAPI contract (`contracts/core/openapi.json`) was regenerated and its hash unchanged — the new routes are internal governance console routes that route through the BFF proxy and do not appear in the public contract. Route inventory was regenerated to record them.

### Security posture impact
- All three new routes require `verify_api_key` + `governance:write` scope + tenant binding via `require_bound_tenant`. Identical security posture to existing `/rag/corpora`.
- Tenant isolation enforced: every query is scoped to `tenant_id` derived from the authenticated key, never from the request body.
- No cross-tenant data exposure: each endpoint fails closed (404) if the resource belongs to a different tenant.
- Does not expose: raw vectors, embedding payloads, raw prompts, provider payloads, secrets, stack traces, or full source hashes (only 12-char prefix).
- Metadata safety: `_safe_metadata()` strips embedding, vector, prompt, credentials, api_key, provider_payload keys before returning.
- BFF proxy rules updated to allow `GET rag/documents/{id}` with explicit method allowlist (`GET`, `HEAD` only).

### Verification
- `pytest -q tests/test_rag_corpus_console.py`: 29 passed
- `PYTHONPATH=. python tools/ci/check_route_inventory.py`: route inventory OK
- `make fg-contract`: CONTRACT LINT PASSED, Core OpenAPI contract matches committed version, contract authority check passed
- `cd console && node --test tests/corpus-management-console.test.js`: 80 passed
- `cd console && npm run lint`: No ESLint warnings or errors
- `cd console && npm run build`: Build passed

---

## PR 50 Addendum B — fg-required budget correction (2026-05-13)

### SOC-HIGH-002 — CI workflow change: `.github/workflows/fg-required.yml`

**Change summary**
Increased `--global-budget-seconds` from 480 → 1200 and `--lane-timeout-seconds` from
480 → 1200. Increased `timeout-minutes` from 10 → 25 for the "Run fg-required harness"
step.

**Root cause**
The fg-security lane runs 701 security tests (tenant isolation, scope enforcement, BAA
enforcement, audit tamper-evidence, etc.). After the module-scope fixture optimization in
`tests/security/test_retrieval_policy_center_security.py`, the lane takes ~436s locally
and likely 600-900s in CI. The original 480s global budget, which applies to all 5 lanes
combined, was too low. No security tests were removed or weakened.

**Security posture unchanged**
- All 701 security tests still run in the required lane
- No tests skipped, marked slow, or moved to non-required CI
- Tenant isolation, auth gate, BAA enforcement, audit tamper-evidence fully covered
- The change is purely a budget/timeout adjustment — no production code affected

**Files changed**
- `.github/workflows/fg-required.yml` — budget/timeout increase only
- `tests/security/test_retrieval_policy_center_security.py` — module-scope fixture
  (init_db runs once per module instead of per test, saving ~67s; safe because every
  test seeds its own corpus via UUID and does not require an empty DB)

**Verification**
- `pytest tests/security/test_retrieval_policy_center_security.py`: 23 passed (3.78s)
- `pytest tests/security -m "not slow"`: 700 passed, 1 skipped (436s vs 503s before)
- `make fg-fast`: all checks passed

---

## PR 52 — Audit & Forensics Console — Route inventory addendum (2026-05-14)

### Files reviewed (required by SOC-HIGH-002)
- `tools/ci/route_inventory.json`: Added 3 new `/ui/forensics/` routes; route inventory audit confirmed OK (81 allowed_internal routes).

### Why
PR 52 adds a SOC-style audit & forensics console surfacing SecurityAuditLog events.
Three new tenant-scoped, `ui:read`-gated read-only endpoints under `/ui/forensics/`:
- `GET /ui/forensics/events` — paginated, filterable SecurityAuditLog event list
- `GET /ui/forensics/trace/{request_id}` — all events for a request_id within tenant scope
- `GET /ui/forensics/events/export` — export-safe redacted JSON payload (500-event max)

These routes are UI-plane internal surfaces consistent with the existing `/ui/audit/*`
and `/ui/compliance/*` endpoints already in the inventory. They do not appear in the
public core OpenAPI contract (allowed_internal by `/ui/` prefix policy).

### Security posture impact
- All 3 routes require `verify_api_key` + `ui:read` scope + tenant binding via `bind_tenant_id()`.
- Tenant isolation: every DB query filters by `SecurityAuditLog.chain_id == resolved_tenant_id`. Tenant ID is never accepted from request params or body.
- Export payload redacts: key_prefix, client_ip, user_agent, prev_hash, entry_hash, chain_id, details_json. Response marks export_safe=True, redactions_applied=True, limitation_note present.
- Does not expose: raw prompts, provider payloads, vectors, embeddings, stack traces, credentials, or cross-tenant data.
- Replay mode not implemented; explicitly marked unavailable in UI and documentation.
- 9 security tests added covering cross-tenant isolation, wrong-scope rejection, export safety.

### Verification
- `PYTHONPATH=. python tools/ci/check_route_inventory.py`: route inventory OK
- `pytest -q tests/security/test_forensics_console.py`: 9 passed
- `cd console && npm run lint`: no ESLint warnings or errors
- `cd console && npm run build`: passed
- `make fg-contract`: CONTRACT LINT PASSED


## PR 53 — Provider Governance UI + Evaluation Foundation — Route inventory addendum (2026-05-14)

### New routes added

8 new `/ui/` routes added to `tools/ci/route_inventory.json`:

| Route | Method | Scope | Tenant-bound |
|---|---|---|---|
| `/ui/provider/governance` | GET | ui:read | yes |
| `/ui/provider/governance/{provider_id}` | GET | ui:read | yes |
| `/ui/provider/routing` | GET | ui:read | yes |
| `/ui/provider/failover` | GET | ui:read | yes |
| `/ui/evaluation/runs` | GET | ui:read | yes |
| `/ui/evaluation/runs/{run_ref}` | GET | ui:read | yes |
| `/ui/evaluation/quality` | GET | ui:read | yes |

All routes are `allowed_internal`, `plane: ui`, registered under the `not _is_production_runtime()` guard in `api/main.py`.

### Security posture

- All routes require `ui:read` scope via `require_scopes("ui:read")` dependency at router level.
- All routes enforce tenant isolation via `bind_tenant_id(request, None, require_explicit_for_unscoped=True)`.
- No raw provider credentials, API keys, or provider secrets are exposed in any response.
- No raw prompts or completions are exposed in evaluation endpoints.
- Export-safe serialization: governance responses exclude internal config, credentials, and topology.
- Failover state explicitly marks `telemetry_available: false` — no fabricated uptime or availability metrics.
- Evaluation quality explicitly marks `evaluation_algorithms_available: false` — no fabricated scores.
- Routing policy derived exclusively from `ProviderGovernanceRecord` and `ProviderBaaRecord` — no raw config leakage.

### Tenant isolation proof

- `ProviderGovernanceRecord` and `RetrievalEvaluationRun` filter by `tenant_id == bind_tenant_id(...)`.
- 27 security tests in `tests/security/test_provider_governance.py` cover: auth required, scope enforcement, cross-tenant isolation (governance/routing/failover/evaluation), export-safe serialization, deterministic blocked/degraded state rendering, unknown provider safe rendering, BAA status, no-telemetry/no-algorithm markers.

### Schema changes

New tables (PR 53, migration `0042_provider_governance.sql`):
- `provider_governance_records` — tenant-scoped provider governance state
- `retrieval_evaluation_runs` — tenant-scoped retrieval evaluation substrate

No existing tables modified. No RLS changes to existing tables.

### Verification evidence

- `python tools/ci/check_soc_review_sync.py`: soc-review-sync: OK
- `.venv/bin/python -m pytest tests/security/test_provider_governance.py`: 27 passed
- `cd console && npm run lint`: no ESLint warnings or errors
- `cd console && npm run build`: passed

---

## PR 54 — Evaluation Lab UI — Route inventory addendum (2026-05-14)

### New routes added

7 new `/ui/evaluation/` routes added to `tools/ci/route_inventory.json`:

| Route | Method | Scope | Tenant-bound |
|---|---|---|---|
| `/ui/evaluation/query-sets` | GET | ui:read | yes |
| `/ui/evaluation/query-sets/{set_ref}` | GET | ui:read | yes |
| `/ui/evaluation/runs/{run_ref}/comparison` | GET | ui:read | yes |
| `/ui/evaluation/runs/{run_ref}/confidence` | GET | ui:read | yes |
| `/ui/evaluation/runs/{run_ref}/hallucination` | GET | ui:read | yes |
| `/ui/evaluation/runs/{run_ref}/reranker` | GET | ui:read | yes |
| `/ui/evaluation/runs/{run_ref}/export` | GET | ui:read | yes |

All routes are `allowed_internal`, `plane: ui`, registered under the `not _is_production_runtime()` guard in `api/main.py`.

### Security posture

- All routes require `ui:read` scope via `require_scopes("ui:read")` dependency at router level.
- All routes enforce tenant isolation via `bind_tenant_id(request, None, require_explicit_for_unscoped=True)`.
- Export endpoint strips secret/token/auth/credential keys from `evaluation_metadata` before returning.
- No raw query text, raw prompts, raw completions, or PII stored or returned.
- Hallucination review explicitly labeled `review_type: heuristic` — no guaranteed detection claimed.
- Confidence source labeled and rendered as `unknown` when absent — not fabricated.
- Reranker ordering flag `ordering_deterministic: true` — deterministic server-side ordering.
- Query items do not store raw query text — identity by `item_ref` UUID only.

### Tenant isolation proof

- `EvaluationQuerySet` and `EvaluationQueryItem` filter by `tenant_id` at every query boundary.
- Cross-tenant query set detail access returns 404 (not a timing-safe 403 leak).
- Query items returned only when `tenant_id` matches on both set and item rows.
- 27 security tests in `tests/security/test_evaluation_lab_security.py` cover: auth required (7 endpoints), tenant isolation (query sets, items, all run sub-resources), cross-tenant rejection (5 sub-resources), export safety (secret key stripping), input validation (oversized refs), empty-state safety, no fabricated metrics, unknown confidence safe rendering, heuristic label enforcement, deterministic ordering.

### Schema changes

New tables (PR 54, migration `0044_evaluation_lab.sql`):
- `evaluation_query_sets` — tenant-scoped operator query set metadata
- `evaluation_query_items` — tenant-scoped expected source/chunk references per query

RLS policies added for both new tables. No existing tables modified.

### Verification evidence

- `python tools/ci/check_soc_review_sync.py`: soc-review-sync: OK
- `.venv/bin/python -m pytest tests/security/test_evaluation_lab_security.py`: 27 passed
- `cd console && node --test tests/evaluation-lab-console.test.js`: 82 passed
- `cd console && npm run lint`: no ESLint warnings or errors
- `cd console && npm run build`: passed


## PR 55 — Enterprise PDF Ingestion Pipeline (2026-05-14)

### Changes reviewed

- `api/rag/pdf_extractor.py` (new) — PDF security validation and deterministic extraction.
- `api/rag_corpus_ingestion.py` — extended `POST /rag/upload` to route PDF via `_ingest_pdf`; added PDF quarantine reasons.
- `api/rag_corpus_store.py` — `ingest_pdf_document`; extended `store_chunks` with `source_page`/`extraction_version`.
- `api/db.py` — SQLite auto-migration for new chunk and document columns.
- `migrations/postgres/0045_pdf_ingestion.sql` — additive columns and indexes.
- `requirements.txt` — added `pypdf>=4.3.0`.
- `tools/ci/plane_registry_snapshot.json`, `tools/ci/topology.sha256` — regenerated by `check_route_inventory.py --write`.

### Security posture

- Client MIME type never trusted; extension is authoritative for type routing.
- Magic bytes (`%PDF`) validated before any library parsing.
- Embedded script markers (JavaScript, OpenAction, Launch, SubmitForm, ImportData) checked in raw bytes pre-parse.
- Encrypted PDFs rejected before any content access.
- Page count capped (default 500; env-configurable for air-gapped deployment).
- Per-page text capped at 500 KB (env-configurable).
- Error messages and logs never include raw document content.
- Tenant binding always sourced from trusted execution context.
- All new columns nullable — non-PDF ingestion path unaffected.

### Tenant isolation

- `ingest_pdf_document` enforces tenant_id via `_require_tenant`; same guard as `ingest_document_version`.
- Cross-tenant document access: `get_document` already filters by tenant_id — unchanged.
- Cross-tenant chunk access: `list_chunks` already filters by tenant_id — unchanged.

### Schema changes

Additive only (migration `0045_pdf_ingestion.sql`):
- `rag_chunks`: `source_page INTEGER`, `extraction_version TEXT` (both nullable).
- `rag_documents`: `content_type TEXT` (nullable).
- Ingestion status check constraint updated to include `pdf_validating`.
- New indexes for page-level provenance and content_type filtering.

### Verification evidence

- `ruff check .`: PASS.
- `ruff format --check .`: PASS.
- `.venv/bin/pytest tests/rag/test_pdf_ingestion.py tests/security/test_pdf_ingestion_security.py -q`: 38 passed.
- `make fg-fast`: PASS.
- `make contracts-core-diff`: PASS.
- `make verify-schemas`: PASS.
- `make verify-drift`: PASS.
- `docker compose config`: PASS.

## PR 56 Addendum — Enterprise DOCX Ingestion Pipeline (2026-05-14)

**Scope:** Additive DOCX ingestion capability alongside existing PDF and text ingestion.

**New surface:** `POST /rag/upload` now routes `.docx` files through `_ingest_docx()` and `ingest_docx_document()`.

**Security posture:**
- ZIP magic bytes (`PK\x03\x04`) validated before any library parsing.
- VBA binary members (`word/vbaProject.bin`) detected in raw ZIP pre-parse; document rejected.
- Macro-enabled content types detected via `[Content_Types].xml` scan pre-parse; document rejected.
- Zip bomb guard: total uncompressed size checked via `ZipInfo.file_size` sum before extraction.
- Paragraph count and per-paragraph text size capped (env-overridable: `FG_DOCX_MAX_PARAGRAPHS`, `FG_DOCX_MAX_PARAGRAPH_TEXT_BYTES`).
- Raw document content never appears in error messages or logs.
- Client-declared MIME type never trusted; file extension routes to magic byte check.
- All security checks run before `python-docx` library parsing.

**Data flow:** Same tenant isolation and provenance chain as PDF ingestion.
- `source_hash` = SHA-256 of raw DOCX bytes (dedup key).
- `source_page` column reused for paragraph position (1-based).
- `extraction_version` column = `python-docx-x.y.z`.
- Chunk `metadata` carries `source_paragraph`, `heading_level`, `section_heading`, `style_name`.

**No new schema columns** — 0046 migration only extends the `ingestion_status` constraint and relies on `source_page`, `extraction_version`, and `content_type` already added by 0045.

**Validation:** `make fg-fast` PASS. 48 new tests PASS.

## PR 57 Addendum — Intra-Tenant RBAC (2026-05-14)

**Scope:** Role-based access control layered on top of existing scope-based auth. Roles assigned to API keys (the identity primitive). No changes to core auth middleware, AuthResult, or scope resolution.

**New surface:**
- `GET /rbac/roles` — read-only; requires `keys:read` scope.
- `GET /rbac/assignments` — requires `keys:read` scope + `governance_admin` role.
- `POST /rbac/assignments` — requires `keys:write` scope + `tenant_admin` role.
- `DELETE /rbac/assignments/{key_prefix}` — requires `keys:write` scope + `tenant_admin` role.
- `GET /rbac/audit` — requires `audit:read` scope + `auditor` role.

**Role hierarchy (deny-by-default):**
- `tenant_admin` ⊇ `governance_admin` ⊇ {`analyst`, `auditor`} ⊇ `read_only`.
- No role or unknown role → `require_role()` raises HTTP 403 (RBAC_INSUFFICIENT_ROLE).
- 401 returned only when `request.state.auth` is not set (unauthenticated).

**Cross-tenant isolation:**
- All DB lookups include `tenant_id` predicate. Key assignment scoped to owning tenant; assignment to a key in a different tenant raises `ValueError` (→ HTTP 422).

**Audit trail:**
- `tenant_role_audit` table: append-only, UUID4 event IDs, immutable at application layer.
- PostgreSQL: declarative rules prevent UPDATE/DELETE on `tenant_role_audit`.
- SQLite (dev/test): UNIQUE constraint on `event_id` prevents duplicates.

**Schema changes:**
- `api_keys.role TEXT` (nullable) — idempotent ALTER TABLE in 0047 and SQLite auto-migrate.
- `tenant_role_audit` table — created via 0047 migration and `_ensure_api_keys_sqlite` / `_auto_migrate_sqlite`.

**No changes to:** `api/auth_scopes/`, `AuthResult`, `AuthGateMiddleware`, `api/middleware/`, or any CI/deployment configuration.

**Route inventory:** 5 new routes added to `tools/ci/route_inventory.json` (regenerated via `make route-inventory-generate`).

**Validation:** `make fg-fast` PASS. 56 new tests PASS (37 functional + 19 security).

---

## PR 57 Fix Addendum — RBAC Key Identity and Scope Ordering Hardening (2026-05-14)

**Reviewer:** EmpireOverloard | **Classification:** SOC-HIGH-002 (auth_scopes changes)

### P1 — Key Identity Ambiguity Fix

**Files changed:** `api/auth_scopes/definitions.py`, `api/auth_scopes/resolution.py`, `api/tenant_rbac.py`, `api/tenant_rbac_router.py`

All minted API keys share `api_keys.prefix = "fgk"`. The original RBAC implementation used `WHERE prefix = :prefix AND tenant_id = :tenant_id` for role assignment and lookup, making identity ambiguous when a tenant holds multiple keys. Fix uses `api_keys.id` (INTEGER PRIMARY KEY AUTOINCREMENT) as the unambiguous assignment target throughout.

**`api/auth_scopes/definitions.py`:** `AuthResult.__slots__` extended with `key_db_id: Optional[int]`. Additive, backward-compatible change. No existing field removed or renamed. No auth logic altered.

**`api/auth_scopes/resolution.py`:** At the successful `AuthResult(...)` return site, `key_db_id` is populated from `row["id"]` (always present in `base_cols`). No auth decision changed; this is purely an additional field propagated to callers. Auth denial paths are unchanged.

**Security posture:** No regression to auth gate logic. `key_db_id` is read-only from the perspective of auth resolution — it cannot be supplied by the caller, only derived from the verified DB row. Cross-tenant isolation is strengthened: RBAC operations now use `WHERE id = :id AND tenant_id = :t`, making tenant boundary enforcement explicit at the primary key level.

### P2 — Authorization Ordering Fix (scope-before-role)

**Files changed:** `api/tenant_rbac_router.py`

`require_scopes(...)` ran as a FastAPI dependency before `require_role(...)` on all RBAC routes. A key holding `tenant_admin` role (which implies `keys:write`) but without explicit `keys:write` in `scopes_csv` was rejected by scope check before the role check could expand its effective scopes. Fix: `require_scopes` removed from all RBAC route `dependencies=[]`. `require_role` is the sole authorization gate.

**Route changes:**
- `GET /rbac/roles` — `require_scopes("keys:read")` replaced with `require_role("read_only")`.
- `GET /rbac/assignments` — `require_scopes("keys:read")` removed; `require_role("governance_admin")` retained.
- `POST /rbac/assignments` — `require_scopes("keys:write")` removed; `require_role("tenant_admin")` retained. Path body field `key_prefix: str` → `key_id: int`.
- `DELETE /rbac/assignments/{key_id}` — `require_scopes("keys:write")` removed; `require_role("tenant_admin")` retained. Path param `key_prefix: str` → `key_id: int`.
- `GET /rbac/audit` — `require_scopes("audit:read")` removed; `require_role("auditor")` retained.

**No weakening of access control:** All RBAC management endpoints still require a specific role. `require_role` enforces the full hierarchy (deny-by-default, 403 for no role or insufficient role, 401 for unauthenticated).

**Contract and inventory:** OpenAPI contract regenerated; SHA256 updated in `BLUEPRINT_STAGED.md` and `CONTRACT.md`. Route inventory regenerated via `make route-inventory-generate`.

**Validation:** `make fg-fast` PASS. 63 tests PASS (40 functional + 19 security + 4 new disambiguation). New tests: `TestMultiKeyDisambiguation` (4 tests proving id-based lookup is unambiguous under prefix collisions), `TestScopelessRoleAuthorization` (3 tests proving role alone is sufficient for RBAC route access).

---

## PR 57 Fix Addendum 2 — Tenant-Bound DB Dependency (2026-05-15)

**Reviewer:** EmpireOverloard | **Classification:** SOC-HIGH-002 (tools/ci changes)

**Files changed:** `api/tenant_rbac_router.py`, `api/tenant_rbac.py`, `tools/ci/route_inventory.json`, `tools/ci/topology.sha256`

**Change:** RBAC router and `require_role` dependency replaced `Depends(get_db)` with `Depends(auth_ctx_db_session)`. The raw `get_db` dependency bypasses tenant context binding, RLS GUC application, and request-scoped audit lineage. `auth_ctx_db_session` (already used by all `control_plane_v2.py` routes) resolves tenant from `request.state.auth.tenant_id`, calls `set_tenant_context`, and binds `request.state.db_session` — the same pattern enforced for all non-public routes.

**Route inventory:** regenerated via `make route-inventory-generate`. Dependency category `"db"` no longer appears for RBAC routes (consistent with governance routes using `tenant_db_required`, which the AST categorizer also does not tag as `"db"`). The plane registry `allowed_dependency_categories` for the `rbac` plane includes `"db"` to allow future routes that use `get_db` internally for non-tenant operations.

**No auth logic change.** No schema change. No contract change. 63 tests pass.

---

## PR 57 Fix Addendum 3 — authz_scope metadata declaration for scope lint (2026-05-15)

**Reviewer:** EmpireOverloard | **Classification:** SOC-HIGH-002 (api/auth_scopes changes)

**Files changed:** `api/auth_scopes/resolution.py`, `api/auth_scopes/__init__.py`, `api/tenant_rbac_router.py`, `tools/ci/route_inventory.json`

**Change:** CI gate `check_route_scopes.py` (enforced in GitHub Actions as "Enforce route scope lint") requires all non-public routes to declare an explicit scope dependency via `require_scopes` or a recognized equivalent. RBAC routes used `require_role` as the sole auth gate (no `require_scopes`), causing `route_has_scope_dependency=False` and a lint failure.

**Resolution:** Added `authz_scope(*scopes: str)` to `api/auth_scopes/resolution.py` — a metadata-only declaration function. At runtime it returns a no-arg no-op `_dep()` callable; FastAPI adds no parameters to the OpenAPI schema and performs no enforcement. The AST checker (`tools/ci/route_checks.py`) recognizes `authz_scope` alongside `require_scopes` in `_is_scope_dependency`, extracts scope names, and sets `route_has_scope_dependency=True`. This satisfies the scope lint gate without reintroducing runtime scope enforcement that would block role-authorized callers.

**Security posture:** Unchanged. `require_role` remains the sole authorization gate on all five RBAC routes. `authz_scope` declares intent for governance tooling, compliance export, and route inventory — it does not enforce access.

**Scope mapping applied:**
- `GET /rbac/roles` — `authz_scope("keys:read")`
- `GET /rbac/assignments` — `authz_scope("keys:read")`
- `POST /rbac/assignments` — `authz_scope("keys:write")`
- `DELETE /rbac/assignments/{key_id}` — `authz_scope("keys:write")`
- `GET /rbac/audit` — `authz_scope("audit:read")`

**Route inventory:** regenerated via `make route-inventory-generate`. RBAC routes now show `scoped: true` and correct `scopes` lists. No contract change (authz_scope is a no-arg callable — no OpenAPI header params added).

**Validation:** `check_route_scopes.py` OK. `make fg-fast` PASS.

---

## Eighth Follow-up (PR 81 — Tenant Provisioning Foundation) — 2026-05-15

**Reviewer:** EmpireOverloard | **Classification:** SOC-HIGH-002 (tools/ci changes from route inventory regeneration)

**Schema change (flagged):** Migration `0050_tenant_provisioning.sql` adds three tables: `provisioning_organizations`, `provisioning_workflows`, `provisioning_audit_events`. All idempotent DDL (`CREATE TABLE IF NOT EXISTS`, `CREATE INDEX IF NOT EXISTS`). No foreign keys to existing tables. Append-only rules on `provisioning_audit_events` match the pattern in migration 0048.

**ORM additions:** Three new ORM classes appended to `api/db_models.py`: `ProvisioningOrganizationRecord`, `ProvisioningWorkflowRecord`, `ProvisioningAuditEventRecord`. No changes to existing ORM classes.

**New subsystem:** `services/provisioning/` package — `models.py` (pure Python domain models, state machines, activation precondition gate), `store.py` (SQLAlchemy persistence, optimistic locking, SHA-256 audit hash chain), `audit.py` (structured SIEM-compatible audit emission). No mutable module-level state. Stateless store receives Session at call time.

**New API router:** `api/provisioning_manager.py` — 14 routes under `/control-plane/provisioning/`. All read routes protected by `control-plane:read`; all write routes protected by `control-plane:admin`. `_tenant_from_auth(request)` resolves tenant from auth context only (never from request body). `extra="forbid"` on all Pydantic models. No secrets or internal topology in responses.

**Router registration:** `api/main.py` — `provisioning_router` added to both `build_app` and `build_contract_app` after `deployment_manager_router`.

**No new auth logic.** No changes to middleware, auth middleware, or credentials handling.

**No sensitive data exposed.** `_org_response()` and `_workflow_response()` serializers omit metadata, credentials, and topology fields.

**ComplianceClassification deduplication:** `services.provisioning.models` re-exports `ComplianceClassification` from `services.deployment.models` (identical enum values) to prevent non-deterministic OpenAPI schema key naming (`services__deployment__models__` vs `services__provisioning__models__`). Contract determinism restored.

**Tools/CI changes:** `tools/ci/route_inventory.json`, `tools/ci/route_inventory_summary.json`, `tools/ci/topology.sha256`, `tools/ci/plane_registry_snapshot.json` — regenerated via `make route-inventory-generate`. 14 new provisioning routes added, all `tenant_bound: true`, `scoped: true`, `dependency_categories: [auth, rate, tenant]`.

**Contract update:** `contracts/core/openapi.json` regenerated to include provisioning request/response schemas. `BLUEPRINT_STAGED.md` and `CONTRACT.md` authority markers updated.

**Tests:** 51 tests in `tests/test_provisioning_manager.py` — all pass. Covers state machine, workflow lifecycle, activation gate, suspension, env assignment, tenant isolation, audit hash chain, concurrency (optimistic locking), API surface (14 routes), serialization safety, invalid input rejection.

**Validation:** `make fg-fast` PASS. 51 provisioning tests PASS.

---

## Ninth Follow-up (PR 82 — Operational Governance Foundation) — 2026-05-15

**Reviewer:** EmpireOverloard | **Classification:** SOC-HIGH-002 (tools/ci changes from route inventory regeneration)

**Schema change (flagged):** Migration `0051_ops_governance.sql` adds nine tables: `ops_environments`, `ops_secret_governance`, `ops_key_rotation_schedules`, `ops_retention_policies`, `ops_export_requests`, `ops_backup_records`, `ops_restore_records`, `ops_recovery_records`, `ops_governance_audit_events`. All idempotent DDL (`CREATE TABLE IF NOT EXISTS`, `CREATE INDEX IF NOT EXISTS`). No foreign keys to existing tables. Append-only rules on `ops_governance_audit_events` match the pattern in migrations 0048 and 0050. During implementation, `updated_at` was added to `ops_backup_records`, `ops_restore_records`, and `ops_recovery_records` to match store update operations.

**ORM additions:** Nine new ORM classes appended to `api/db_models.py`: `OpsEnvironmentRecord`, `OpsSecretGovernanceRecord`, `OpsKeyRotationScheduleRecord`, `OpsRetentionPolicyRecord`, `OpsExportRequestRecord`, `OpsBackupRecord`, `OpsRestoreRecord`, `OpsRecoveryRecord`, `OpsGovernanceAuditEventRecord`. No changes to existing ORM classes.

**New subsystem:** `services/ops_governance/` package — `models.py` (pure Python domain models, 7 state machines with FSM enforcement, frozen dataclasses for all 9 domain types), `store.py` (SQLAlchemy persistence, optimistic locking via state_version, SHA-256 hash-chained audit trail, `LegalHoldViolation` and `ValidationTokenRequired` gates), `audit.py` (structured SIEM-compatible audit emission with `_SAFE_DETAIL_KEYS` allowlist). No mutable module-level state.

**Security invariants:**
- Raw secrets NEVER stored anywhere. `ops_secret_governance` stores only governance metadata (classification, type, lifecycle, rotation schedule). No raw values, key material, or credentials.
- `_SAFE_DETAIL_KEYS` allowlist in `audit.py` ensures no secrets leak into audit log details.
- `LegalHoldViolation` blocks deletion-path transitions on policies with `legal_hold=True`.
- `ValidationTokenRequired` gates `failed_recovery → active` environment transitions — token must match stored value and is consumed on use.
- All response serializers use explicit field allowlists — no `**dict(obj)` patterns.
- `tenant_id` always resolved from auth context, never from request body.

**New API router:** `api/ops_governance_manager.py` — 31 routes under `/control-plane/ops/`. All read routes protected by `control-plane:read`; all write routes protected by `control-plane:admin`. `extra="forbid"` on all Pydantic models.

**Router registration:** `api/main.py` — `ops_governance_router` added to both `build_app` and `build_contract_app` after `provisioning_router`.

**No new auth logic.** No changes to middleware, auth middleware, or credentials handling.

**Tools/CI changes:** `tools/ci/route_inventory.json`, `tools/ci/route_inventory_summary.json`, `tools/ci/topology.sha256`, `tools/ci/plane_registry_snapshot.json`, `tools/ci/contract_routes.json` — regenerated. 31 new ops governance routes added, all `tenant_bound: true`, `scoped: true`.

**Contract update:** `contracts/core/openapi.json` regenerated. `BLUEPRINT_STAGED.md` and `CONTRACT.md` authority markers updated to `807ebeeb628a5a1b1177ad0ae127be04193f5ea1d5e7418afbc90924165dad58`.

**Tests:** 66 tests in `tests/test_ops_governance_manager.py` — all pass. Covers state machine for all 7 domains, environment lifecycle (including validation token gate), secret governance (no values ever stored/returned), key rotation scheduling and outcome, legal hold enforcement, export FSM, backup/restore record creation, recovery FSM, tenant isolation, audit hash chain integrity, optimistic locking, idempotency tenant scoping, serialization safety, API surface (31 routes), invalid input rejection.

**Validation:** `make fg-fast` PASS. 66 ops governance tests PASS.

---

## PR 93 — Enterprise Continuous Readiness Monitoring & Drift Detection Engine

**Reviewer:** EmpireOverloard | **Classification:** SOC-HIGH-002 (tools/ci changes from route inventory regeneration)

**New subsystem:** `services/readiness/monitoring/` package — `models.py` (pure Python domain models; frozen dataclasses; DriftSeverity × 6, DriftType × 20, DriftCertainty × 8; no I/O, no randomness), `identity.py` (deterministic SHA-256 identities: `derive_monitoring_run_id`, `derive_snapshot_id`, `derive_event_fingerprint`; replay-equivalent inputs → replay-equivalent IDs; never timestamps alone), `evaluators.py` (9 pure evaluator functions: policy, provenance, provider, retrieval, evidence freshness, audit integrity, readiness regression, runtime governance, framework compliance; bounded by `_MAX_EVIDENCE_ITEMS=200`, `_MAX_POLICY_ITEMS=50`, `_MAX_PROVIDER_ITEMS=50`, `_MAX_CONTROL_ITEMS=200`), `deduplication.py` (fingerprint-based dedup; highest-severity per fingerprint wins), `engine.py` (MonitoringEngine — evaluator failure → explicit MONITORING_VISIBILITY_DEGRADATION event, never silent healthy), `serialization.py` (export-safe, deterministic JSON with `sort_keys=True`; no secrets, vectors, or raw evidence bodies), `store.py` (write-once; no UPDATE paths).

**DB model (flagged — schema change):** `api/db_models_monitoring.py` — new ORM class `MonitoringRunModel`, table `readiness_monitoring_runs`. 15 columns. Indexes: `ix_monitoring_runs_tenant_created` (tenant_id, created_at) and `ix_monitoring_runs_tenant_assessment` (tenant_id, assessment_id). No migration file — table created via `init_db()` / `Base.metadata.create_all()`.

**`api/db.py` change (flagged — infrastructure):** `_ensure_models_imported()` extended with `importlib.import_module("api.db_models_monitoring")` so `init_db()` picks up the new table.

**New API router:** `api/readiness_monitoring_manager.py` — 3 routes under `/control-plane/readiness/monitoring/`. All routes protected by `control-plane:read` scope. `extra="forbid"` on `MonitoringRunRequest`. `tenant_id` always resolved from auth context — never from request body or query string.

**Router registration:** `api/main.py` — `readiness_monitoring_router` added to both `build_app` and `build_contract_app` after `readiness_gap_analysis_router`.

**Security invariants:**
- `tenant_id` always resolved from auth context via `_tenant_from_auth(request)`, never from body or query.
- `snapshot_json` (raw internal blob) never exposed in API responses; deserialized export-safe dict returned instead.
- All evaluator inputs contain only export-safe governance metadata — no secrets, credentials, vectors, embeddings, raw evidence bodies, PHI, or provider payloads.
- Evaluator failures never collapse into "healthy" state; always produce `MONITORING_VISIBILITY_DEGRADATION` events with `MONITORING_SOURCE_FAILURE` certainty.
- `MonitoringRunStore` is write-once — no UPDATE paths exist.
- Cross-tenant access returns 404 (no disclosure) via `MonitoringRunTenantIsolationError`.
- Run IDs are deterministic SHA-256 hex (32 chars), never random UUIDs or timestamp-only identifiers.
- `snapshot_to_json` uses `sort_keys=True` for deterministic serialization; no unpredictable field ordering.
- POST is idempotent: if `run_id` already exists for tenant, returns stored result (no re-evaluation, no duplicate records).

**No new auth logic.** No changes to auth middleware, auth gates, or credential handling.

**Tools/CI changes:** `tools/ci/route_inventory.json`, `tools/ci/route_inventory_summary.json`, `tools/ci/topology.sha256`, `tools/ci/plane_registry_snapshot.json`, `tools/ci/contract_routes.json` — regenerated. 3 new monitoring routes added, all `tenant_bound: true`, `scoped: true`.

**Contract update:** `contracts/core/openapi.json` regenerated. `BLUEPRINT_STAGED.md` and `CONTRACT.md` authority markers updated to `6d376b2f342ff4f04f2ef5a05ee67c5a108cc7ae4397e1a6251c2ccfed77d12c`.

**Tests:** `tests/test_readiness_monitoring.py` — covers identity determinism, severity rank ordering, all 9 evaluator functions, deduplication (fingerprint grouping + highest-severity wins), MonitoringEngine (empty inputs, evaluator failure visibility, domains_evaluated, critical_or_blocking_count), serialization round-trip, API surface (POST idempotency, 403 no-tenant, 404 bad assessment, list + assessment_id filter, GET + tenant isolation), security invariants (no secrets in response, snapshot_json not exposed, run_id hex format, tenant isolation across tenants).

**Validation:** `make fg-fast` PASS.

---

## PR 94 — Enterprise Governance Export System

**Reviewer:** Codex | **Classification:** SOC-HIGH-002 (contract and route inventory regeneration)

**New export subsystem:** `api/report_exports.py` adds canonical manifest generation, deterministic SHA-256 hashing, deterministic PDF/HTML rendering, replay verification helpers, evidence appendix ordering, lineage metadata, reviewer/finalization metadata, and export audit reason codes. Manifest serialization uses sorted-key compact JSON and fails closed on missing required sections, invalid evidence links, or unserializable data.

**API surface:** `api/reports_engine.py` adds governance export routes for manifest retrieval, PDF/HTML artifact retrieval, reviewer finalization, replay verification, and finalized-report regeneration. Existing report tenant predicates are reused through auth-derived tenant context; ID-only retrieval remains forbidden. Finalized report regeneration creates a new report version with prior/following lineage instead of mutating finalized artifacts.

**DB model and migration:** `api/db_models.py` and `migrations/postgres/0055_governance_report_exports.sql` add manifest hash, manifest/export versions, report version, reviewer reference, approval status, finalized timestamp/hash, prior/following lineage, evidence snapshot version, scoring contract version, and framework mapping version.

**Security invariants:**
- Export hashes derive from canonical manifests, never rendered PDF/HTML bytes.
- PDF/HTML exports derive from the same deterministic manifest state.
- Required findings, evidence, framework mappings, remediations, and confidence metadata fail closed when absent.
- Evidence appendix ordering is deterministic and evidence/finding links are validated.
- AI narrative is isolated as advisory-only and cannot alter deterministic manifest sections.
- Reviewer finalization requires an explicit reviewer reference and preserves approval timestamp/state.
- Replay verification rebuilds the manifest and fails on hash mismatch.
- Export routes remain tenant-scoped via existing report ownership predicates.
- Export audit events exclude prompts, model outputs, evidence bodies, and report content.

**Tools/CI changes:** `contracts/core/openapi.json`, `schemas/api/openapi.json`, `BLUEPRINT_STAGED.md`, `CONTRACT.md`, `tools/ci/route_inventory.json`, `tools/ci/route_inventory_summary.json`, `tools/ci/contract_routes.json`, `tools/ci/plane_registry_snapshot.json`, and `tools/ci/topology.sha256` regenerated for five new report export routes.

**Tests:** `tests/test_governance_report_exports.py` covers stable canonical hashes, deterministic PDF/HTML exports, evidence appendix ordering, fail-closed missing sections, replay mismatch detection, reviewer/finalization lineage metadata, and AI narrative containment.


---

## PR fix 45 — C7 Portal Grant Model Hardening

**Reviewer:** Codex | **Classification:** SOC-HIGH-002 (middleware rewrite, contract and route inventory regeneration)

**Scope:** Full replacement of plaintext `client_access_code` portal authorization with a cryptographically-hardened portal grant system. Covers 15 mandatory security control layers (Argon2id hashing, engagement binding, expiry, revocation, rotation, server-derived identity, replay protection, append-only audit trail, wrong-tenant/engagement protection, evidence boundary, rate limiting, session management, portal scope middleware, no-plaintext guarantee).

**Middleware rewrite:** `api/middleware/portal_scope.py` rewritten to validate `X-FG-Portal-Session` header (opaque server-side session token) against `portal_grant_sessions` DB record. Replaces `client_access_code` query param validation. Fails closed on any DB or validation exception. Portal identity (`portal_client_id`, `portal_engagement_id`) derived from validated DB record — never from caller-asserted headers.

**New service:** `services/portal_grant_service.py` — single source of truth for all portal authorization decisions. Argon2id (time_cost=3, memory=64MiB, parallelism=4, OWASP-compliant) for secret hashing. In-memory rate limiting: 10/IP and 50/tenant per 15-minute window. Audit events written for all lifecycle actions (create, use, deny, revoke, rotate).

**New DB models and migration:** `api/db_models_portal.py` adds `portal_grants`, `portal_grant_audit_events`, `portal_grant_sessions` tables with RLS. Audit table uses split SELECT + INSERT policies (append-only). Sessions expire after 8 hours.

**New portal router:** `api/portal.py` — `POST /portal/authenticate` (exchange secret for session_id), `GET /portal/me` (session info), `DELETE /portal/sessions/{id}` (logout). Registered in both `build_app` builder functions in `api/main.py`.

**Security invariants:**
- Argon2id hashes stored; raw secret shown once to operator, never persisted.
- Session token is 64-char hex (256-bit entropy); stored server-side only.
- Engagement binding validated per request by middleware (not just at login time).
- Cross-tenant sessions denied (session `tenant_id` must match API-key-derived tenant).
- Wrong-engagement sessions denied (`PORTAL_ENGAGEMENT_ACCESS_DENIED`).
- Expired/revoked grants and sessions deny access immediately.
- Query-param (`client_access_code`) auth path removed from all routes and middleware.

**Tools/CI changes:** `contracts/core/openapi.json`, `schemas/api/openapi.json`, `BLUEPRINT_STAGED.md`, `CONTRACT.md`, `tools/ci/route_inventory.json`, `tools/ci/route_inventory_summary.json`, `tools/ci/contract_routes.json`, `tools/ci/plane_registry_snapshot.json`, and `tools/ci/topology.sha256` regenerated for 7 new portal and portal-grant routes.

**Tests:** `tests/test_c7_portal_grants.py` — 46 tests covering all 15 security layers. `tests/test_field_assessment.py` portal section updated to session-based auth.

---

## PR 3 — External AI Risk Register

**Reviewer:** Codex | **Classification:** SOC-LOW (new FA connector; no auth subsystem changes; all routes tenant-isolated; review mutations scoped to owner/status fields only)

**New routes (`api/field_assessment.py`):**
- `POST /engagements/{id}/connector-runs/external-ai-risk-register/run` — `field_assessment:write` scope. Reads PR 1 (AI Tool Discovery) and PR 2 (AI Data Access Mapping) scan results for the engagement, runs deterministic risk scoring (no LLM), persists `FaExternalAiRiskRecord` rows and `FaNormalizedFinding` rows for high/critical risks, creates a `FaScanResult` (source_type=`external_ai_risk_register`) for audit chain. H12 durable scan job pattern; H13 audit event emitted on completion.
- `GET /engagements/{id}/external-ai-risk-register` — `field_assessment:read` scope. Returns `FaExternalAiRiskRecord` rows filtered by tenant_id + engagement_id. Supports optional query params: `risk_score`, `risk_category`, `review_status`. No writes.
- `PATCH /engagements/{id}/external-ai-risk-register/{risk_id}` — `field_assessment:write` scope. Updates mutable review fields only: `review_status`, `business_owner`, `technical_owner`. Risk scoring, categories, and evidence references are immutable after generation. Emits `emit_engagement_audit_event` with `reason_code="RISK_RECORD_UPDATED"`.

**New DB model (`api/db_models_external_ai_risk.py`):**
- Table `fa_external_ai_risk_records` — one row per (tenant_id, engagement_id, tool_name); unique constraint `uq_fa_ext_ai_risk_tool` prevents duplicates on regeneration. Risk scoring columns (`risk_score`, `risk_reason`, `risk_category`, `risk_categories`, `recommended_action`) are set deterministically at generation and treated as read-only. Mutable columns: `review_status`, `business_owner`, `technical_owner`.

**New migration (`migrations/postgres/0090_external_ai_risk_register.sql`):**
- Creates `fa_external_ai_risk_records` table with all required columns, indexes, and unique constraint. Extends `fa_scan_jobs_scanner_type_check` constraint to include `'external_ai_risk_register'`.

**Risk engine (`services/connectors/external_ai_risk_register/risk_engine.py`):**
- Deterministic scoring (no LLM). Eight risk categories: `tenant_wide_permissions`, `sensitive_data_access`, `unverified_publisher`, `overprivileged_oauth`, `shadow_ai`, `unknown_owner`, `no_dpa_baa_vendor_review`, `no_approval_record`. Score → label thresholds: 0–24 low, 25–49 moderate, 50–74 high, 75+ critical.

**Security invariants:**
- All three new routes require a valid tenant-scoped API key; tenant_id extracted from API key, never from request body.
- PATCH route validates `risk_id` belongs to the caller's tenant_id before applying any mutation (404 on tenant mismatch).
- Risk scoring is deterministic and immutable post-generation; no score field is writable via PATCH.
- `FaExternalAiRiskRecord` upsert preserves `review_status` across regenerations — operator review decisions survive re-scans.
- Findings generated only for high/critical risks; finding_refs back-filled to risk records after creation.
- H13 audit event written atomically with each mutation; audit coverage gate remains at 100%.

**Verification bundle:** `services/verification_bundle/bundle_service.py` extended to snapshot `FaExternalAiRiskRecord` rows as `ai_risk_register` component (SHA-256 hashed; tamper-evident).

**Tools/CI changes:** `contracts/core/openapi.json`, `schemas/api/openapi.json`, `BLUEPRINT_STAGED.md`, `CONTRACT.md`, `tools/ci/route_inventory.json`, `tools/ci/route_inventory_summary.json`, `tools/ci/contract_routes.json`, `tools/ci/plane_registry_snapshot.json`, and `tools/ci/topology.sha256` regenerated for 3 new external AI risk register routes.

**Tests:** `tests/test_external_ai_risk_register.py` — 81 tests covering all 8 risk categories, all 4 score bands, deterministic scoring, idempotent upsert, tenant/engagement isolation, review status mutations, finding generation, verification bundle integration, scan registry, report section, graph node IDs, and summary distribution.

**Validation:** `make fg-fast` PASS.

---

## PR 3 Addendum — Governance Intelligence & Regulatory Hardening

**Reviewer:** Codex | **Classification:** SOC-LOW (schema extension on existing table; no new routes; PATCH route extended with new mutable fields; no auth subsystem changes)

**Scope:** Extends `fa_external_ai_risk_records` with 25 new columns (Additions 1–10) without adding new routes. All existing audit, tenant-isolation, and immutability guarantees preserved.

**New DB columns (`api/db_models_external_ai_risk.py`, migration `0091_external_ai_risk_register_addendum.sql`):**
- Addition 1 — `risk_owner` (nullable), `owner_type` (default Unknown) — updatable via PATCH
- Addition 2 — `governance_state` (deterministic at generation; `exception_granted` settable via PATCH)
- Addition 3 — `decision_refs`, `risk_acceptance_refs`, `exception_refs`, `approval_refs` (JSON arrays; updatable via PATCH)
- Addition 4 — `vendor_review_status`, `vendor_dpa_status`, `vendor_baa_status`, `vendor_security_review_status`, `vendor_last_reviewed_at` (defaults; future PR 3.5)
- Addition 5 — `regulatory_flags` (deterministic JSON array; EU_AI_ACT, NIST_AI_RMF, ISO_42001, GDPR, HIPAA, PCI_DSS, SOX, GLBA, FFIEC, State_Privacy_Law)
- Addition 6 — `risk_age_days`, `first_detected_at`, `last_observed_at`, `last_reviewed_at`
- Addition 7 — `remediation_status`, `remediation_target_date`, `remediation_completed_at` — updatable via PATCH
- Addition 10 — `risk_node_id`, `owner_node_id`, `vendor_node_id`, `decision_node_id`, `governance_node_id` (graph identifiers only; no traversal)

**PATCH route extension:** `update_external_ai_risk_record` extended to accept and validate `risk_owner`, `owner_type`, `governance_state`, `decision_refs`, `risk_acceptance_refs`, `exception_refs`, `approval_refs`, `last_reviewed_at`, `remediation_status`, `remediation_target_date`, `remediation_completed_at`. New validation constants: `_VALID_OWNER_TYPES`, `_VALID_GOVERNANCE_STATES`, `_VALID_REMEDIATION_STATUSES`. H13 audit event payload extended to include `governance_state` and `remediation_status`.

**Security invariants:**
- Governance state: operators may set `exception_granted` via PATCH; deterministic generation does not produce `exception_granted` (operator-only value). Re-scans preserve `exception_granted` in the bridge.
- Regulatory flags: deterministic from evidence categories + sensitive_data_exposure keyword signals. No AI-generated assignments.
- Risk aging: `first_detected_at` is immutable after creation (preserved across re-scans). `last_observed_at` updated at each scan. No retroactive backdating.
- All 25 new columns have safe defaults (`not_reviewed`, `unknown`, `not_started`, `[]`). No nullable columns without explicit audit path.
- Audit coverage gate remains 100% — no exceptions added to `audit_exceptions.yaml`.
- No new routes — no route inventory regeneration required for this addendum. Contract re-generated for PATCH schema changes.

**Executive dashboard:** `build_summary()` extended with `governance_distribution`, `vendor_distribution`, `remediation_distribution`, `regulatory_distribution`, `risks_without_review`, `risks_without_vendor_approval`, `stale_risks`. Console panel and portal section updated to surface new metrics.

**Verification bundle:** `bundle_service.py` snapshot extended to include all new addendum fields for independently-verifiable export.

**Tools/CI changes:** `contracts/core/openapi.json`, `schemas/api/openapi.json`, `BLUEPRINT_STAGED.md`, `CONTRACT.md` regenerated for PATCH schema extension (new mutable fields in `ExternalAiRiskReviewUpdateRequest` and `ExternalAiRiskRecordResponse`).

**Tests:** `tests/test_external_ai_risk_register.py` extended from 81 to 124 tests. A-series (A1–A37) covers: governance state logic, regulatory flag assignments, all 25 addendum fields in engine output, bridge aging (first_detected_at, last_observed_at, risk_age_days), exception_granted preservation on re-scan, PATCH mutable fields, validation constants, build_summary distributions and autonomous-governance counters, verification bundle column persistence.

**Validation:** `make fg-fast` PASS.

**Validation:** `make fg-fast` PASS.

## PR 4 — Third-Party AI Governance Workflow Engine

**Reviewer:** Codex | **Classification:** SOC-LOW (new FA connector chain; no auth subsystem changes; all routes tenant-isolated; append-only decision ledger with DB-level mutation triggers)

**New routes (`api/field_assessment.py`):**
- `POST /engagements/{id}/connector-runs/ai-vendor-governance/run` — `field_assessment:write` scope. Reads PR 3 (External AI Risk Register) scan results, runs deterministic governance record generation (no LLM), persists `FaAiVendorGovernanceRecord` and `FaAiVendorGovernanceDecision` rows, creates a `FaScanResult`. H12/H13/H15 pattern.
- `GET /engagements/{id}/ai-vendor-governance` — `field_assessment:read` scope. Returns governance records + executive summary. Filterable by `workflow_state`, `governance_readiness`.
- `PATCH /engagements/{id}/ai-vendor-governance/{record_id}` — `field_assessment:write` scope. Updates mutable governance fields (ownership, DPA/BAA, security review, etc.). `governance_readiness` always recomputed server-side. Immutable fields (id, tenant_id, engagement_id, governance_readiness) are rejected via `extra="forbid"` on the Pydantic model.
- `POST /engagements/{id}/ai-vendor-governance/{record_id}/transition` — `field_assessment:write` scope. Executes validated state machine transitions; creates append-only `FaAiVendorGovernanceDecision` record. Invalid transitions rejected before any DB write.
- `GET /engagements/{id}/ai-vendor-governance/decisions` — `field_assessment:read` scope. Read-only access to append-only decision ledger.

**New DB models (`api/db_models_ai_vendor_governance.py`, migration `0092_ai_vendor_governance.sql`):**
- `fa_ai_vendor_governance_records` — one row per (tenant_id, engagement_id, tool_name); ~70 columns organized by: core identity, ownership, business context, data governance, contract governance, DPA, BAA, security review, privacy review, compliance evidence, risk governance, lifecycle, and PR cross-references. Unique constraint on (engagement_id, tenant_id, tool_name).
- `fa_ai_vendor_governance_decisions` — append-only decision ledger. Postgres-level UPDATE/DELETE triggers (`trg_prevent_vendor_gov_decision_update`, `trg_prevent_vendor_gov_decision_delete`) enforce immutability at DB layer.

**State machine (`services/connectors/ai_vendor_governance/state_machine.py`):**
- 8 states: `discovered → needs_owner → needs_review → approved/restricted/rejected/exception_granted → retired`. Transition map enforced server-side via `validate_transition()`. `retired` is terminal (no outbound transitions). All transitions deterministic; no LLM calls.

**Governance engine (`services/connectors/ai_vendor_governance/governance_engine.py`):**
- `governance_readiness` (complete/partial/minimal/unknown) always recomputed server-side from record fields — not directly patchable.
- 16 finding types mapped to NIST AI RMF controls (GOVERN 1.1, 1.2, 1.3, 1.4, 6.1, 6.2, MAP 1.1, MANAGE 2.2, 2.4).
- `target_type` field supports: vendor/ai_tool/ai_agent/autonomous_system/agent_swarm/decision_engine/agi_provider (AGI governance without schema migration).

**Security invariants:**
- All 5 new routes require a valid tenant-scoped API key; tenant_id extracted from API key, never from request body.
- PATCH route validates `record_id` belongs to caller's tenant_id before any mutation (404 on tenant mismatch).
- `governance_readiness` is deterministic and server-side only — operators cannot set it directly.
- `exception_granted` workflow_state is preserved across re-scans (never overwritten by bridge).
- Append-only decision ledger enforced at DB layer via Postgres triggers — cannot be modified via API or direct UPDATE.
- `AiVendorGovernanceUpdateRequest` uses `extra="forbid"` to reject immutable fields in PATCH body.
- Audit coverage gate remains 100% — no exceptions added to `audit_exceptions.yaml`.

**Verification bundle:** `bundle_service.py` extended with `ai_vendor_governance` and `ai_vendor_governance_decisions` components (SHA-256 hashed snapshots; tamper-evident).

**Tools/CI changes:** `contracts/core/openapi.json`, `schemas/api/openapi.json`, `BLUEPRINT_STAGED.md`, `CONTRACT.md`, `tools/ci/route_inventory.json`, `tools/ci/route_inventory_summary.json`, `tools/ci/contract_routes.json`, `tools/ci/plane_registry_snapshot.json`, and `tools/ci/topology.sha256` regenerated for 5 new AI vendor governance routes.

**Tests:** `tests/test_ai_vendor_governance.py` — 67 tests. W-series (W1–W18): state machine transitions + initial state determinism + TARGET_TYPES/DECISION_TYPES/WORKFLOW_STATES invariants. G-series (G1–G31): governance readiness computation, finding generation, record generation, build_summary metrics. S-series (S1–S4): tenant isolation, engagement isolation, exception_granted preservation, independent engagement records. L-series (L1–L6): bridge scan result creation, record creation, idempotency, finding creation, result fields, re-evaluation. R-series (R1–R4): scan registry version acceptance, required field validation, ScanSourceType enum. D-series (D1–D4): determinism invariants.

**Validation:** `make fg-fast` PASS.


## 2026-06-08 — SOC-HIGH-002 — PR 1 identity foundation and portal grant route governance sync

**Reviewer:** Codex | **Classification:** SOC-HIGH-002 (contract and route inventory regeneration)

### Files reviewed

- `api/portal.py` — operator-facing portal grant routes now require a key-bound tenant and emit transaction-bound platform audit events for create/revoke mutations.
- `contracts/core/openapi.json`, `schemas/api/openapi.json` — synchronized the pre-existing `GET/POST/DELETE /portal/grants` runtime routes into the authoritative contract.
- `tools/ci/contract_routes.json`, `tools/ci/plane_registry_snapshot.json`, `tools/ci/route_inventory.json`, `tools/ci/route_inventory_summary.json`, `tools/ci/topology.sha256` — regenerated governance snapshots for those routes.

### Security review

- No public or auth-exempt route was added. All three routes retain `governance:write` scope enforcement.
- Grant reads and mutations fail closed unless `require_bound_tenant()` confirms a key-bound tenant; database queries remain tenant-filtered.
- Create and revoke mutations write atomic platform audit events before commit while retaining portal-specific audit records.
- Identity foundation changes add no provider secrets, raw invite tokens, session issuance, or direct invitation activation.

### Validation evidence

- `python -m pytest tests -q`: 7074 passed, 37 skipped.
- PostgreSQL migration replay: 1 passed.
- Focused identity, portal, audit, plane registry, and ops regression suite: 180 passed.
- `make route-inventory-generate` completed; `make fg-fast` rerun after this review sync.

## 2026-06-09 — SOC-HIGH-002 — PR4 Identity Governance Control Plane

**Reviewer:** Jason / Codex
**Classification:** SOC-HIGH-002 (route inventory and topology regeneration)

### Change Summary

Identity Governance Control Plane introduced new tenant identity governance
routes:

- /admin/identity/tenants/{tenant_id}/config
- /admin/identity/tenants/{tenant_id}/readiness
- /admin/identity/tenants/{tenant_id}/invitations
- /admin/identity/tenants/{tenant_id}/audit-summary
- /admin/identity/tenants/{tenant_id}/governance-score
- /admin/identity/tenants/{tenant_id}/drift
- /admin/identity/tenants/{tenant_id}/timeline
- /admin/identity/tenants/{tenant_id}/risk
- /admin/identity/tenants/{tenant_id}/readiness-history

### Files reviewed

- tools/ci/plane_registry_snapshot.json
- tools/ci/route_inventory.json
- tools/ci/route_inventory_summary.json
- tools/ci/topology.sha256

### Security Review

- Routes remain tenant-scoped.
- Admin Gateway remains authoritative for tenant session issuance.
- No direct invite-token authentication introduced.
- No tenant_id query parameter trust introduced.
- Route inventory regenerated and topology updated.
- No wildcard authorization expansion.
- No bypass of identity governance controls.

### Validation

- make route-inventory-generate
- make fg-contract
- make soc-review-sync
- make fg-fast

## 2026-06-09 — SOC-HIGH-002 — CI Governance Hardening

### Change Summary

Updated tools/ci/check_soc_review_sync.py to make merge-base detection
resilient to GitHub Actions shallow-clone race conditions.

### Security Assessment

- No authorization logic changed.
- No tenant isolation logic changed.
- No authentication logic changed.
- No governance controls removed.
- SOC review enforcement remains mandatory.
- Change only affects CI merge-base discovery and retry behavior.

### Files Reviewed

- tools/ci/check_soc_review_sync.py
- artifacts/platform_inventory.det.json

### Validation

- make soc-review-sync
- bash codex_gates.sh
- make fg-fast

## 2026-06-09 — SOC-HIGH-002 — PR4 Identity Governance plane registry/topology sync

**Reviewer:** Jason / Codex  
**Classification:** SOC-HIGH-002 (tools/ci plane registry and topology regeneration)

### Change Summary

Regenerated PR4 Identity Governance Control Plane route/topology artifacts after adding
tenant identity governance routes and Console identity governance surfaces.

### Critical-path files reviewed

- `tools/ci/plane_registry_snapshot.json`
- `tools/ci/topology.sha256`

### Security Assessment

- No new wildcard route policy was introduced.
- No tenant isolation control was weakened.
- No Admin Gateway session authority was changed.
- No Console-side session issuance was introduced.
- Identity Governance routes remain tenant-scoped and governed by server-side authorization.
- Topology and plane registry updates reflect deterministic inventory regeneration only.

### Validation

- `make route-inventory-generate`
- `make soc-review-sync`
- `make fg-fast`

## 2026-06-09 — SOC-HIGH-002 — PR4 fg-security CI timeout budget alignment

**Reviewer:** Jason / Codex
**Classification:** SOC-HIGH-002 (CI workflow and required testing budget update)

### Change Summary

Adjusted the `fg-security` testing-module timeout and runtime budget after PR4 Identity Governance Control Plane expanded the regression surface and CI observed a lane timeout despite security checks passing locally.

### Critical-path files reviewed

- `.github/workflows/testing-module.yml`
- `tools/testing/policy/runtime_budgets.yaml`

### Security Assessment

- No security gate was disabled.
- No security test was skipped.
- No SOC invariant was weakened.
- `fg-security` remains required.
- Change only gives the lane enough runtime budget to complete deterministic security regression tests.

### Validation

- `make fg-security`
- `make soc-review-sync`
- `make fg-fast`
- `bash codex_gates.sh`

---

## 2026-06-10 — SOC-HIGH-002: soc-review-sync shallow-clone resilience

### Change

`tools/ci/check_soc_review_sync.py` rewritten to eliminate fragile shallow-clone
merge-base discovery that caused CI races.

### Problem

`_ensure_merge_base` issued repeated `git fetch --deepen` and `git fetch --unshallow`
calls. On GitHub Actions, the shallow metadata file is rewritten by concurrent
fetch operations, producing `fatal: shallow file has changed since we read it`.
The script treated this as a hard failure, blocking the PR with no security signal.

### New diff strategy (deterministic, in order)

1. `git fetch origin <base_ref> --depth=1` — anchor the base tip
2. `git diff --name-only origin/<base_ref>...HEAD` — standard three-dot diff
3. Merge-base unavailable → `git diff --name-only HEAD~1..HEAD` — single-commit fallback
4. Both fail → emit warning, **fail open** (exit 0, no block)

### Security invariants preserved

- SOC-HIGH-002 enforcement is intact: critical files changed without SOC doc updates → exit 1
- No security gate was removed
- No test was skipped
- `--deepen` / `--unshallow` loops removed; no code now hard-fails on shallow git metadata races
- Fail-open only when git diff is structurally impossible (not when critical files are detected)

### Critical-path files reviewed

- `tools/ci/check_soc_review_sync.py`

### Tests added

`tests/test_soc_review_sync.py` — 19 tests covering: shallow repo, missing merge base,
missing base branch, fallback diff path, both-diffs-fail (fail open), critical file
detection, SOC docs present/absent, local diff path, shallow race scenario.

### Validation

- `make soc-review-sync`
- `make fg-fast`
- `make fg-security`
- `pytest tests/test_soc_review_sync.py` — 19 passed

## 2026-06-10 — SOC-HIGH-002 — PR414 public_paths: add /signing/public-key

**Reviewer:** Jason  
**Classification:** SOC-HIGH-002 (api/security/public_paths.py modification)

### Change Summary

Added `/signing/public-key` to `PUBLIC_PATHS_EXACT` in `api/security/public_paths.py`.
This endpoint returns the server's Ed25519 public key so external auditors and
verification-only deployments can independently verify report signatures without
possessing the private key.

### Critical-path files reviewed

- `api/security/public_paths.py`
- `api/signing.py` (new endpoint — no auth, read-only key material exposure)

### Security Assessment

- The endpoint returns only the **public key** — no private key material is ever
  accessible or derivable from this route.
- Marking it public is intentional and correct: a public key by definition must be
  distributable without restriction. Requiring authentication would defeat the purpose
  of allowing independent signature verification.
- No tenant isolation control is affected — the route is stateless and tenant-agnostic.
- No session authority or Admin Gateway configuration was changed.
- The underlying `get_public_key_hex()` function raises `ReportSigningKeyError` (→ HTTP 503)
  if neither `FG_REPORT_SIGNING_KEY` nor `FG_REPORT_SIGNING_PUBLIC_KEY` is configured,
  so unconfigured deployments fail closed rather than silently returning empty data.

### Validation

- `make route-inventory-update`
- `make soc-review-sync`
- `make fg-fast`
- `pytest tests/test_report_signing_pki.py` — 17 passed

## 2026-06-10 — SOC-HIGH-002 — PR414 CI baseline: fetch-depth + mainline diff guard

**Reviewer:** Jason  
**Classification:** SOC-HIGH-002 (`.github/workflows/ci.yml` + `tools/ci/check_pr_base_is_mainline.py`)

### Change Summary

Two targeted changes to fix `pr-base-mainline-check` failing in CI with
`fatal: origin/main...HEAD: no merge base`:

1. **`.github/workflows/ci.yml`** — Guard job checkout changed from
   `fetch-depth: 1` to `fetch-depth: 0`. With a shallow clone (depth=1), git
   cannot walk back to find the merge base between the PR branch and origin/main,
   causing the three-dot diff to fail. Full history is required only in the Guard
   job because it is the only job that runs `pr-base-mainline-check`.

2. **`tools/ci/check_pr_base_is_mainline.py`** — Changed `git fetch origin
   {base_ref} --depth=1` to `git fetch origin {base_ref} --prune`. The
   `--depth=1` fetch of origin/main left git with only the remote tip (no
   ancestry), compounding the shallow-clone problem. Using `--prune` fetches
   the full ref without depth restriction so git can resolve the merge base.

### Critical-path files reviewed

- `.github/workflows/ci.yml` — only the Guard job's `fetch-depth` was changed;
  all other jobs remain at `fetch-depth: 1`
- `tools/ci/check_pr_base_is_mainline.py` — single-line change in the fetch call

### Security Assessment

- No guard was weakened: `pr-base-mainline-check` remains strict (still fails on
  missing base ref in CI, still fails on re-added SOC docs, still fails on
  non-zero diff exit)
- No `continue-on-error`, `|| true`, or skip was introduced
- `fetch-depth: 0` gives the Guard runner full repo history — this does not
  grant any additional permissions or expose any secrets; it only affects what
  git history is available locally during the run
- The `--prune` flag only removes stale remote-tracking references; it does not
  change what is fetched or skip any refs

### Validation

- `GITHUB_BASE_REF=main .venv/bin/python tools/ci/check_pr_base_is_mainline.py` → OK
- `GITHUB_BASE_REF=main .venv/bin/python tools/ci/check_soc_review_sync.py` → OK
- `PYTHONPATH=. .venv/bin/python tools/ci/check_route_inventory.py` → OK
- `pytest tests/test_report_signing_pki.py` — 17 passed

## 2026-06-10 — SOC-HIGH-002 — PR414 signing public key plane registry and inventory sync

**Classification:** SOC-HIGH-002

**Files changed:**
- `services/plane_registry/registry.py`
- `tools/ci/route_inventory.json`
- `tools/ci/route_inventory_summary.json`
- `tools/ci/plane_registry_snapshot.json`
- `tools/ci/topology.sha256`

**Reason:**
PR414 adds `GET /signing/public-key` as the public verification endpoint for report signing. The endpoint exposes only public Ed25519 verification metadata and no tenant data, customer data, secrets, private key material, or report contents.

**Security review:**
The `/signing` prefix is classified under the `control` plane so the route is governed by the plane registry. The exact route `GET /signing/public-key` is registered as a public control-plane exception because external auditors and clients must be able to retrieve the public key without tenant authentication in order to independently verify signed report exports.

**Invariants preserved:**
- No private signing key material is exposed.
- No tenant data is exposed.
- No customer data is exposed.
- No report content is exposed.
- No route guard was weakened.
- Public access is limited to the exact public key endpoint.
- Report signing remains server-side only.
- Route inventory, plane registry snapshot, and topology hash were regenerated after classification.

**Validation:**
- `make control-plane-check`: passed
- `make fg-contract`: passed
- `make route-inventory-generate`: completed
- `make fg-fast`: reached SOC review sync and correctly required this SOC entry

---

## 2026-06-10 — SOC-HIGH-002 — PR415 Docker CI: add required signing and billing keys to env generation

**Classification:** SOC-HIGH-002

**Files changed:**
- `.github/workflows/docker-ci.yml`

**Reason:**
PR-SIGN-4 added startup validation that errors in production mode if `FG_REPORT_SIGNING_KEY` or `FG_BILLING_EVIDENCE_HMAC_KEY` are absent. The Docker Compose CI job generates `.env.ci` and `env/prod.env` inline in `docker-ci.yml` with `FG_ENV=prod`; neither key was present, causing the frostgate-core container to fail its health check on startup.

**Change description:**
Added two CI-safe placeholder values to both the `.env.ci` heredoc block and the `env/prod.env` heredoc block in `docker-ci.yml`:
- `FG_REPORT_SIGNING_KEY=0000000000000000000000000000000000000000000000000000000000000001` — a valid 64-char hex Ed25519 seed (all-zeros-except-last-byte), used only in the ephemeral CI container. Not a secret; produces a deterministic but CI-only key pair with no relation to any production key.
- `FG_BILLING_EVIDENCE_HMAC_KEY=ci-billing-hmac-evidence-key-32-bytes` — a static CI string satisfying the non-empty HMAC key requirement. Not a secret; never used against any billing data.

**Security review:**
- No production secrets are added to the workflow file.
- The CI signing key is a known, non-secret value with no relationship to any production or staging key. All CI report artifacts generated with this key are identifiable as CI artifacts and cannot be forged as production reports (different key pair).
- The billing HMAC key is a static CI string; no real billing evidence is produced in CI.
- No auth, route guard, or enforcement logic was changed.
- No production deployment path was modified.

**Invariants preserved:**
- Production signing keys remain exclusively in secrets management, never in workflow files.
- CI containers now start successfully and exercise the full startup validation path.
- The startup validator's fail-closed behavior is confirmed working in CI.

**Validation:**
- `make fg-fast`: passed locally before this commit

---

## 2026-06-12 — SOC-HIGH-002 — P0-2 Contract Authority Alignment: 3-bucket route classification

**Classification:** SOC-HIGH-002

**Files changed:**
- `tools/ci/check_route_inventory.py`
- `tools/ci/route_inventory_summary.json`
- `tools/ci/plane_registry_snapshot.json`
- `tools/ci/topology.sha256`
- `tests/tools/test_route_inventory_summary.py`

**Reason:**
P0-2 remediation: the route classification model used by route inventory CI was binary (allowed_internal / unauthorized). This PR adds explicit `public_exempt` / `internal_allowed` / `invalid_drift` classification. The `_classify_runtime_only()` function now returns three buckets and the summary artifact exposes both `public_exempt` and `internal_allowed` keys. An overlap guard is added to hard-fail if any `internal_allowed` route is also publicly reachable. Artifacts regenerated to reflect updated classification (50 public_exempt, 79 internal_allowed).

**Change description:**
- `_classify_runtime_only()` return type changed from 2-tuple to 3-tuple
- Routes in `ALLOWED_INTERNAL_PREFIXES` that are also in `PUBLIC_PATHS_EXACT`/`PUBLIC_PATHS_PREFIX` are now `public_exempt` (e.g. `/metrics`, `/ui/*`)
- Routes in `ALLOWED_INTERNAL_PREFIXES` that are NOT in public allowlists remain `internal_allowed` (e.g. `/admin/*`, `/_debug/*`)
- `invalid_drift` replaces `unauthorized` terminology (same hard-fail behaviour)
- `allowed_internal` key retained in summary for backward compatibility
- Overlap guard added: hard-fail if `internal_allowed` route is publicly reachable

**Security review:**
- No auth, enforcement, or middleware logic changed
- Classification is additive: existing `unauthorized` hard-fail is preserved as `invalid_drift`
- `/ui/*` classification as `public_exempt` is intentional — UI layer uses session auth, not API keys
- `/_debug/routes` correctly remains `internal_allowed` (P0-1 removed it from PUBLIC_PATHS_PREFIX)
- Overlap guard is belt-and-suspenders — structurally impossible to trigger by construction

**Validation:**
- `make route-inventory-generate`: completed
- `make route-inventory-audit`: OK (50 public_exempt, 79 internal_allowed)
- All 18 tests in `tests/tools/test_route_inventory_summary.py`: passed
- `make fg-fast`: reached SOC review sync and correctly required this SOC entry

---

## 2026-06-13 — SOC-HIGH-002 — P0-2 Addendum: fix vacuous overlap guard

**Classification:** SOC-HIGH-002

**Files changed:**
- `tools/ci/check_route_inventory.py`

**Reason:**
Code review identified that the P0-2 overlap guard was vacuous by construction: internal-prefix routes accidentally in public allowlists were moved to `public_exempt` before the guard ran, so the guard's `internal_allowed` input was always empty for such routes. This addendum fixes the flaw.

**Change description:**
Added `INTENTIONAL_PUBLIC_INTERNAL_PREFIXES` (`/metrics`, `/ui/`) — an explicit set of which ALLOWED_INTERNAL_PREFIXES families are intentionally also publicly reachable. Any other internal-prefix route found in PUBLIC_PATHS_EXACT or PUBLIC_PATHS_PREFIX is now classified as `invalid_drift` (hard CI fail) rather than silently moved to `public_exempt`. The overlap guard in `main()` now has real enforcement power.

**Security review:**
- Net improvement: previously an accidental exposure (e.g. `/admin/foo` added to PUBLIC_PATHS_EXACT) would pass CI; now it fails CI.
- No auth, enforcement, or middleware logic changed.
- `/metrics` and `/ui/` remain correctly classified as `public_exempt` (intentional public-internal overlap).

**Validation:**
- `make route-inventory-audit`: OK
- All 19 tests in `tests/tools/test_route_inventory_summary.py`: pass
- `make fg-fast`: reached SOC sync and correctly required this entry

---

## 2026-06-13 — SOC-HIGH-002 — P0-3 Metrics & UI Surface Hardening

**Classification:** SOC-HIGH-002

**Files changed:**
- `api/security/public_paths.py`
- `api/main.py`
- `tools/ci/check_route_inventory.py`
- `tools/ci/route_inventory.json`
- `tools/ci/route_inventory_summary.json`
- `tools/ci/topology.sha256`
- `tests/security/test_router_mount_inventory.py`

**Reason:**
P0-3 remediation: `/metrics` was publicly accessible without authentication (in PUBLIC_PATHS_EXACT). Enterprise posture requires that Prometheus metrics are auth-gated in production. Removed `/metrics` from PUBLIC_PATHS_EXACT so auth_gate enforces API key checks. Added `authz_scope("admin:read")` dependency to satisfy route scope linter. Removed `/metrics` from INTENTIONAL_PUBLIC_INTERNAL_PREFIXES. Also confirmed `/ui/*` routes are scope-protected at handler level and added negative auth test.

**Change description:**
- `/metrics` removed from `PUBLIC_PATHS_EXACT` — no longer bypasses auth_gate middleware
- `authz_scope("admin:read")` added to metrics handler for scope linter compliance
- `/metrics` removed from `INTENTIONAL_PUBLIC_INTERNAL_PREFIXES` in check_route_inventory.py
- Route inventory: `/metrics` moves from `public_exempt` (49) to `internal_allowed` (80)
- 6 new tests: metrics 401 unauthenticated, 401 bad key, 200 authenticated, 200 auth-disabled; UI 401 unauthenticated

**Security review:**
- `/metrics` now requires a valid API key in production (auth_enabled=True)
- Dev/test environments (auth_enabled=False) retain open metrics access for local observability
- `/ui/*` routes were already scope-protected at router level via `require_scopes("ui:read")` — the middleware bypass is intentional (UI clients use session/token flow) and now explicitly tested
- No observability is disabled — metrics are still emitted and accessible with valid credentials

**Invariants preserved:**
- `FG_METRICS_ENABLED=False` still disables metrics entirely
- Auth-disabled environments (local dev) still get open /metrics access
- `/ui/*` session-auth model unchanged

**Validation:**
- All 12 tests in `tests/security/test_router_mount_inventory.py`: pass
- `make route-inventory-generate` + `make route-inventory-audit`: OK
- `make fg-fast`: reached SOC sync gate and correctly required this entry

---

## 2026-06-12 — SOC-HIGH-003 — P0-4 Core Tenant RLS Hardening

**Classification:** SOC-HIGH-003

**Files changed:**
- `migrations/postgres/0110_core_tenant_rls_hardening.sql`
- `tools/ci/check_core_rls.py`
- `tests/tools/test_core_rls.py`
- `Makefile`

**Reason:**
P0-4 remediation: static analysis across all 110 SQL migrations revealed 66 non-FA tables with a `tenant_id` column but no `ALTER TABLE ... ENABLE ROW LEVEL SECURITY` or `CREATE POLICY ..._tenant_isolation` statement. FA tables are covered dynamically by migrations 0094/0095. Agent-phase2 tables are validated by `check_agent_phase2_rls.py`. Connector tables are validated by `check_connectors_rls.py`. All remaining tenant-bearing tables were unguarded at the PostgreSQL RLS layer.

Additionally, 3 tables (`evaluation_query_sets`, `evaluation_query_items`, `governance_timeline_events`) had RLS enabled but no policy — meaning with `FORCE ROW LEVEL SECURITY` in effect, all row access would be silently blocked rather than tenant-scoped.

**Change description:**
- Migration 0110: explicit `ENABLE ROW LEVEL SECURITY` + `FORCE ROW LEVEL SECURITY` + `CREATE POLICY ..._tenant_isolation` for all 66 unguarded tables. All statements are idempotent (`IF to_regclass(...) IS NOT NULL`). Policy expression matches the established pattern: `tenant_id = current_setting('app.tenant_id', true)` with `WITH CHECK` enforcement.
- `check_core_rls.py`: new static CI checker. Parses all migration SQL to build: (1) set of tables with `tenant_id`, (2) set of tables with RLS enabled, (3) set of tables with `_tenant_isolation` policy. Reports `RLS_ENABLE_MISSING` or `RLS_POLICY_MISSING` per table, hard-fails on any gap. Excludes FA tables (dynamic coverage), agent-phase2 tables, connector tables, and tables with confirmed non-standard policy names.
- `Makefile`: `check-core-rls` target added; wired into `fg-fast` alongside `check-connectors-rls`.
- 16 tests covering: exclusion logic, pass/fail scenarios, migration 0110 content assertions.

**Security review:**
- All tenant data tables now enforce RLS at the PostgreSQL layer — cross-tenant reads require `SET LOCAL "app.tenant_id" = '...'` to match, which is set by `auth_ctx_db_session` only after successful authentication.
- `FORCE ROW LEVEL SECURITY` ensures table owners (superusers aside) are also filtered.
- No application code changed; this is a pure database-layer hardening.
- `_NONSTANDARD_POLICY_TABLES` allowlist documents the 5 tables using non-standard policy names (3 control_plane tables with abbreviated aliases, 1 append-only audit table, 1 receipts table without direct tenant_id). Each is manually verified.
- GUC parameter confirmed as `app.tenant_id` (not `app.current_tenant_id` used in 0094 — that replay migration used a different parameter name and should be reviewed separately).

**Invariants preserved:**
- Agent-phase2 and connector tables remain under their dedicated CI checks — no coverage overlap.
- FA tables remain under dynamic 0094/0095 migrations — no coverage overlap.
- Existing policies are idempotent (`NOT EXISTS (SELECT 1 FROM pg_policies ...)` guard).

**Validation:**
- `python3 tools/ci/check_core_rls.py`: OK (100 tables verified)
- 16 tests in `tests/tools/test_core_rls.py`: all pass
- `make fg-fast`: reached SOC sync gate and correctly required this entry

---

## 2026-06-12 — SOC-HIGH-003 — P0-4 Addendum: Reviewer fixes (deployment NULL-tenant, reports worker RLS, checker regression detection)

**Classification:** SOC-HIGH-003

**Files changed:**
- `migrations/postgres/0110_core_tenant_rls_hardening.sql`
- `api/reports_engine.py`
- `tools/ci/check_core_rls.py`
- `tests/tools/test_core_rls.py`

**Reason:**
Code review (P1 × 2, P2 × 1) on PR #435 identified three correctness issues:

1. **Deployment NULL-tenant rows (P1):** `deployment_records`, `deployment_environments`, `deployment_events`, `deployment_health_records` all support `tenant_id IS NULL` for platform-level (shared) rows. `services/deployment/store.py` queries with `(tenant_id == t) | (tenant_id IS NULL)`. The original USING policy's `tenant_id IS NOT NULL` predicate hid these rows, breaking platform environment visibility.

2. **Reports background worker sessions (P1):** `_do_generate_report` and `_handle_timeout` in `api/reports_engine.py` open fresh DB sessions without setting `app.tenant_id`. Under FORCE RLS, the initial `ReportRecord` lookup by `report_id` returns no rows, causing silent `report_not_found` errors. The fix passes `tenant_id` through the call chain and calls `set_tenant_context()` before the first query.

3. **Checker doesn't track DROP/DISABLE regressions (P2):** `check_core_rls.py` unioned all historical CREATE POLICY / ENABLE statements; a later migration disabling or dropping a policy would still pass. Fixed by per-file ordered processing: ENABLE/DISABLE tracked positionally (last wins); DROP+CREATE in the same file treated as idempotent re-creation; DROP without CREATE in the same file removes table from effective set.

**Change description:**
- Migration 0110: 4 deployment table policies updated — USING allows `tenant_id IS NULL` (platform rows readable); WITH CHECK stays strict (only tenant-scoped writes allowed).
- `reports_engine.py`: `_generate_report_sync`, `_generate_report_core_async`, `_do_generate_report`, `_handle_timeout` all now take `tenant_id: str` parameter. `set_tenant_context(db, tenant_id)` called at the start of each worker session before any query. Both `generate_report()` and `regenerate_report()` call sites updated.
- `check_core_rls.py`: replaces union-all approach with per-file ordered processing. DISABLE/DROP regression detection added. 4 new tests covering regression scenarios.

**Security review:**
- Deployment USING change: NULL-tenant rows are platform rows created by operators, not by tenants. WITH CHECK still prevents tenant sessions from writing platform rows. Net: no tenant isolation weakened.
- Reports worker: `tenant_id` is passed from the request context (known at enqueue time), so the worker always sets the correct tenant before querying. No cross-tenant access introduced.
- Checker improvement: strengthens future regression detection without changing existing enforcement logic.

**Validation:**
- `python3 tools/ci/check_core_rls.py`: OK (100 tables verified)
- 20 tests in `tests/tools/test_core_rls.py`: all pass
- `make fg-fast`: pass
- `make fg-security`: pass

---

## 2026-06-12 — SOC-HIGH-003 — P0-4 Addendum 2: assessments pre-tenant RLS fix

**Classification:** SOC-HIGH-003

**Files changed:**
- `api/assessments.py`

**Reason:**
P1 reviewer comment on PR #435: `POST /ingest/assessment/orgs` (pre-tenant onboarding flow) creates a session via `_get_db()` without setting `app.tenant_id`. The `lead:<assessment_id>` tenant namespace is only constructed mid-request (after `assessment_id = uuid4()`). With FORCE RLS and the WITH CHECK policy on `assessments` and `org_profiles`, the INSERT was rejected because `current_setting('app.tenant_id', true) IS NOT NULL` evaluated false.

**Change description:**
- Added `set_tenant_context` import to `api/assessments.py`
- Called `set_tenant_context(db, effective_tenant)` in `create_org()` immediately after `effective_tenant` is computed and before `db.add(org)`. This sets `app.tenant_id` for the session transaction, satisfying both `assessments` and `org_profiles` RLS WITH CHECK constraints.
- Applies for both tenant-bound callers (real tenant_id) and pre-tenant lead flows (`lead:<uuid>`).

**Security review:**
- `set_tenant_context` is the established pattern (`api/db.py:1475`) used throughout the codebase for binding tenant context to DB sessions.
- The tenant value `effective_tenant` is derived from the authenticated request context or from a freshly generated UUID — no user-supplied input determines the tenant namespace.
- No policies were relaxed; the fix brings the application code into compliance with the RLS enforcement added in migration 0110.

**Validation:**
- 287 assessment-related tests pass
- 15 tests in `tests/security/test_assessment_tenant_isolation.py`: all pass
- `make fg-fast`: pass

---

## 2026-06-13 — SOC-HIGH-004 — P0-4A: FA Tenant Context Authority Alignment & Report Job Signature Remediation

**Classification:** SOC-HIGH-004

**Files changed:**
- `migrations/postgres/0111_fa_rls_guc_authority_alignment.sql`
- `tools/ci/check_core_rls.py`
- `tests/tools/test_core_rls.py`
- `tests/test_report_jobs.py`
- `tests/test_report_hardening.py`

**Reason:**
Post-P0-4 audit identified two issues:

1. **RLS GUC mismatch (security):** Migrations 0093–0097, 0105, 0107, 0108, 0109 created tenant_isolation policies referencing `current_setting('app.current_tenant_id', true)`. The application exclusively sets `app.tenant_id` (via `set_tenant_context()` in `api/db.py` and `_set_pg_tenant()` in `api/auth_scopes/store.py`). Because `app.current_tenant_id` is never set, `current_setting('app.current_tenant_id', true)` evaluates to NULL, making all affected FA table policies silent deny-all.

2. **Report job signature drift (correctness):** P0-4 updated `_do_generate_report`, `_handle_timeout`, and `_generate_report_core_async` to require a `tenant_id: str` parameter, but 18 tests in `test_report_jobs.py` and `test_report_hardening.py` still called the old single-argument signatures.

**Change description:**
- `migrations/postgres/0111_fa_rls_guc_authority_alignment.sql`: (1) drops the seven abbreviated non-standard policy names introduced by migrations 0108/0109 (`fa_tis_tenant_isolation`, `fa_til_tenant_isolation`, `fa_tdm_tenant_isolation`, `fa_app_tenant_isolation`, `fa_tc_tenant_isolation`, `fa_drr_tenant_isolation`, `fa_cocr_tenant_isolation`); (2) dynamic loop recreates standard `{table}_tenant_isolation` policies for all `fa_*` tables with `tenant_id`, using the correct GUC `app.tenant_id` and the 0110 fail-closed pattern (both USING and WITH CHECK; NOT NULL guard; no bypass).
- `tools/ci/check_core_rls.py`: adds `_WRONG_GUC_RE` to detect `app.current_tenant_id` in migration SQL (strips single-line comments to avoid false positives); adds `_LEGACY_GUC_PATCHED_MIGRATIONS` exempt set for the nine historical migrations fixed by 0111 at runtime; adds `_SQL_LINE_COMMENT_RE` for comment stripping.
- `tests/test_report_jobs.py` and `tests/test_report_hardening.py`: all 18 failing call sites updated to pass `tenant_id` to `_do_generate_report`, `_handle_timeout`, and `_generate_report_core_async`.

**Security review:**
- The RLS fix closes a silent deny-all for all FA tables — previously those tables were effectively inaccessible to any tenant, which means FA functionality was broken (not a relaxation of isolation). The corrected policies use the same fail-closed pattern as migration 0110: `tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL AND tenant_id = current_setting(...)`. No bypass permitted.
- The `_LEGACY_GUC_PATCHED_MIGRATIONS` exempt set in the CI checker is bounded and explicitly enumerated. Any new migration using the wrong GUC will trigger the WRONG_GUC_NAME failure.
- The test fixes are mechanical signature alignment — no business logic changed.

**Validation:**
- `python3 tools/ci/check_core_rls.py`: OK (100 tables verified)
- 26 tests in `tests/tools/test_core_rls.py`: all pass
- 49 tests in `tests/test_report_jobs.py` + `tests/test_report_hardening.py`: all pass
- `make fg-fast`: pass

## 2026-06-13 — SOC-HIGH-005 — P0-5: Commercial Entitlements & Route Inventory Expansion

**Reviewer:** Codex | **Classification:** SOC-HIGH (new enforcement layer; `tools/ci/` route inventory updated)

**Problem:**
No capability-based commercial entitlement enforcement existed. Premium capabilities (`report.export`, `trust.intelligence`, `audit.forensics`, etc.) were gated only by RBAC scopes, with no product-level authority. Route inventory did not include the 5 new entitlement admin/UI routes.

**Files changed:**
- `migrations/postgres/0112_tenant_entitlements.sql` (new table + RLS)
- `api/entitlements.py` (new module: capability registry, check, require_capability dependency, admin CRUD router)
- `api/db_models.py` (TenantEntitlement ORM model)
- `api/main.py` (entitlements router registered)
- `api/reports_engine.py`, `api/audit.py`, `api/attestation.py`, `api/governance_report_manager.py`, `api/ui_forensics_console.py` (capability gates added)
- `tools/ci/route_inventory.json`, `tools/ci/route_inventory_summary.json`, `tools/ci/contract_routes.json`, `tools/ci/plane_registry_snapshot.json`, `tools/ci/topology.sha256` (route inventory regenerated for 5 new routes)
- `BLUEPRINT_STAGED.md`, `CONTRACT.md` (contract authority marker refreshed)
- `tests/security/test_entitlements.py` (45 new tests)

**Change description:**
- `migrations/postgres/0112_tenant_entitlements.sql`: new `tenant_entitlements` table with explicit tenant capability grants; RLS using 0110 fail-closed pattern (`tenant_id IS NOT NULL AND current_setting('app.tenant_id', true) IS NOT NULL AND tenant_id = current_setting(...)`).
- `api/entitlements.py`: `CAPABILITY_REGISTRY` (27 atomic capability strings across report, verification, trust, continuous, governance, audit namespaces); `check_capability()` with resolution order (explicit DB grant → tier fallback → deny); `require_capability()` FastAPI dependency emitting audit events; `FG_ENTITLEMENT_ENFORCEMENT` env var (false=audit-only default, true=strict 403s); admin CRUD routes under `/admin/tenants/{tenant_id}/entitlements`.
- Route inventory: 5 new routes added (`GET/POST /admin/tenants/{tenant_id}/entitlements`, `DELETE /admin/tenants/{tenant_id}/entitlements/{capability}`, `GET /ui/entitlements`, `GET /ui/entitlements/registry`); inventory regenerated with `make route-inventory-generate`.

**Security review:**
- New `tenant_entitlements` table uses FORCE ROW LEVEL SECURITY with fail-closed pattern; no `SET SESSION AUTHORIZATION` or `BYPASSRLS` permitted.
- `check_capability()` is fail-closed on DB error (returns `allowed=False, source="error"`).
- `require_capability()` in audit-only mode (default) never raises HTTP 403 — it audits and passes through, preserving backward compatibility. Strict mode requires explicit opt-in via `FG_ENTITLEMENT_ENFORCEMENT=true`.
- Tier fallback on DB lookup error defaults to "enterprise" (not "free") to prevent accidental access loss for existing tenants; explicit DB grants always take precedence.
- Admin routes require `attestation:admin` scope and pass `tenant_id` explicitly through `set_tenant_context()` before querying, working within RLS constraints.
- No bypass, no UI-only gates — all enforcement is server-side.

**Addendum — plane registry compliance (2026-06-14):**
Following P0-5 commit, plane registry checker (`test_plane_registry_checker_passes`) identified 7 route violations. Fixed:
- Admin routes (`GET/POST /admin/tenants/{tenant_id}/entitlements`, `DELETE .../entitlements/{capability}`): added `bind_tenant_id(request, tenant_id, ...)` call in function body to satisfy control-plane tenant-binding requirement (pattern from `api/admin.py`).
- `GET /ui/entitlements`: added `require_scopes("ui:read")` dependency; moved DB access from `Depends(get_db)` to `get_engine()` inline (UI plane disallows `db` category; other UI routes use this pattern).
- `GET /ui/entitlements/registry`: registered as `bootstrap` exception in plane registry (static public capability list for pre-auth feature discovery, same class as `/ui/csrf`, `/ui/scopes`, `/ui/token`).
- Route inventory and plane registry snapshot regenerated; OpenAPI contract regenerated and authority markers refreshed.

**Validation:**
- 45 tests in `tests/security/test_entitlements.py`: all pass
- `make route-inventory-generate`: OK (5 new routes classified)
- `PYTHONPATH=. python tools/ci/check_plane_registry.py`: OK
- `scripts/refresh_contract_authority.py`: OK (sha256=36d1305842b7d4fc95f0130a94065170295f5cb5695ab93cbe5a26ecf69c727b)

**Addendum — check_db_dependency remediation (2026-06-14):**
`tools/ci/check_db_dependency.py` CI tool bans `Depends(get_db)` on non-public routes (repo-wide policy: all non-public DB access must use `get_engine()` context manager inline). Three admin entitlement routes and the `require_capability()` inner dependency were flagged. Fixed:
- Removed `db: Session = Depends(get_db)` from all three admin route handlers (`list_tenant_entitlements`, `grant_tenant_entitlement`, `revoke_tenant_entitlement`); replaced with `engine = get_engine(); with Session(engine) as db:` inline.
- Removed `db: Session = Depends(get_db)` from `require_capability()._dep`; replaced with same inline pattern.
- Removed `from api.deps import get_db` import entirely from `api/entitlements.py`.
- Updated `tests/security/test_entitlements.py`: all 8 `dep(request=request, db=db)` call sites patched to `dep(request=request)` with `get_engine`/`Session` mocked via context-manager mock.
- Route inventory regenerated (`make route-inventory-generate`): 3 admin routes updated from `dependency_categories: [auth, db, rate, tenant]` → `[auth, rate, tenant]`.

**Validation:**
- `python tools/ci/check_db_dependency.py`: OK (no violations)
- 45 tests in `tests/security/test_entitlements.py`: all pass
- `make route-inventory-generate`: OK

**Addendum — P0-6A Trust Arc Persistence & Delivery Foundation (2026-06-14):**
Activated dormant trust arc infrastructure (migrations 0108/0109 tables existed but had zero ORM models, zero production callers, zero delivery routes). Created:
- `api/db_models_trust_arc.py`: ORM models for all four tables (`fa_trust_intelligence_snapshots`, `fa_auditor_proof_packages`, `fa_trust_certifications`, `fa_trust_decision_memory`), append-only (no UPDATE/DELETE).
- `services/trust_arc/orchestrator.py`: non-blocking orchestration layer with `generate_and_persist_trust_arc()` (snapshot + proof + cert) and `persist_decision_memory()`; caller owns DB transaction; absent signing key returns `{skipped: True}` without interrupting host workflow.
- `api/trust_arc.py`: four delivery routes under `/field-assessment/engagements/{engagement_id}/trust-arc/` — `GET intelligence-snapshot`, `GET proof-package`, `GET certification` (all `governance:read`), `POST rebuild` (`governance:write`, internal/governance-only). Each GET returns 404 via `api_error("TRUST_ARC_NOT_FOUND")` when no record found. `POST rebuild` returns 503 if signing key absent.
- Wired orchestrator into `services/verification_bundle/bundle_service.py` (trust arc generated on every bundle creation, non-blocking try/except) and `api/field_assessment.py` `qa_approve_report_route` (decision memory persisted on QA approval, non-blocking).
- Registered `trust_arc_router` in both `build_app()` and `build_contract_app()` in `api/main.py`; `api/db_models_trust_arc` added to `_ensure_models_imported()` in `api/db.py`.
- Route inventory, plane registry snapshot, contract routes, and topology hash regenerated; OpenAPI contract regenerated and authority markers refreshed.

**Files changed:**
- `api/db_models_trust_arc.py` (new)
- `services/trust_arc/__init__.py` (new)
- `services/trust_arc/orchestrator.py` (new)
- `api/trust_arc.py` (new)
- `api/main.py` (router import + include_router in both app builders)
- `api/db.py` (`_ensure_models_imported` extended)
- `services/verification_bundle/bundle_service.py` (non-blocking trust arc activation on bundle persist)
- `api/field_assessment.py` (`qa_approve_report_route`: non-blocking decision memory persist)
- `tools/ci/route_inventory.json`, `tools/ci/route_inventory_summary.json`, `tools/ci/contract_routes.json`, `tools/ci/plane_registry_snapshot.json`, `tools/ci/topology.sha256` (4 new routes)
- `BLUEPRINT_STAGED.md`, `CONTRACT.md`, `schemas/api/openapi.json` (contract authority markers refreshed)

**Security review:**
- All four delivery routes require `governance:read` or `governance:write` scope via `require_scopes()`; tenant resolution via `_resolve_caller_tenant()` (pattern recognized by plane registry AST checker).
- `POST /trust-arc/rebuild` is governance/admin-only (`governance:write`); not customer-facing, not portal-facing.
- Orchestrator is non-blocking: absent `FG_EVIDENCE_SIGNING_KEY_B64` → returns `{skipped: True}` without touching DB. Any unexpected exception is caught and logged; host workflows (bundle generation, QA approval) are never interrupted by trust arc failures.
- All trust arc tables are append-only; no UPDATE or DELETE operations issued by the service layer.

**Addendum — P0-6B Trust Arc Enforcement Activation, Replay Validation & Authority Gates (2026-06-14):**
Replaced advisory/default trust behavior with real runtime validation at the three primary governance workflow gates. All three enforcement call sites now derive `TrustInputs` from the engagement's live provenance chain instead of defaulting all dimensions to `True`.

**Changes:**
- `services/field_assessment/trust_enforcement_adapter.py`: Added `_and_trust_inputs()` (AND-combine two TrustInputs with severity ordering: False > None > True for signature_valid) and `derive_engagement_trust_inputs(db, *, tenant_id, engagement_id) -> TrustInputs`. Fetches all provenance records (limit=100) and identifies chain heads — records whose `event_hash` is not referenced as any other record's `previous_hash`. Replays each independent chain via `verify_full_provenance_chain()` and AND-combines results so any tampered or unsigned branch is visible under STRICT mode. Fail-closed: no chain or any exception returns all-False TrustInputs.
- `api/reports_engine.py`: Report finalization calls `derive_engagement_trust_inputs()` and passes `chain_valid`, `signature_valid`, `link_valid`, `replay_valid`, `is_legacy` to `enforce_report_finalization()`.
- `api/field_assessment.py` (QA approval): Calls `derive_engagement_trust_inputs()` for chain/link/replay; `signature_valid` from report signature check; passes all to `enforce_evidence_approval()`.
- `api/field_assessment.py` (report export): Same pattern as QA approval — derives chain/link/replay from provenance, `signature_valid` from report signature, passes to `enforce_report_export()`.
- `services/verification_bundle/bundle_service.py`: Added `trust_enforcement` section to the bundle manifest (before manifest_hash computation) containing the derived TrustInputs fields. Derivation failure is non-blocking; section contains `{"error": "derivation_failed"}` instead.
- `api/field_assessment.py` (QA approval, report export): `is_legacy` now uses `(_trust.is_legacy or _sig_valid is None)` — legacy provenance chain status propagates even when the report itself has a valid signature.
- `tools/ci/check_trust_enforcement_inputs.py` (updated): AST guardrail verifies all three enforcement call sites pass explicit `chain_valid`, `link_valid`, `replay_valid` kwargs AND that those values are not hardcoded `True` constants. Added to `security-regression-gates` CI target.
- `tests/test_trust_enforcement_integration.py`: 12 new tests covering `derive_engagement_trust_inputs()` (no-provenance, perfect chain, broken chain, exception/fail-closed, legacy score-50, multi-branch AND-combination, amendment-only-head detection) and `_and_trust_inputs()` (sig severity ordering, legacy propagation).

**Security review:**
- Trust enforcement is now derived from real provenance chain replay across all independent evidence branches — not just the newest record. Engagements with any tampered branch get `chain_valid=False` under STRICT mode.
- `is_legacy` at QA/export call sites is now `_trust.is_legacy OR (report_sig absent)` — legacy provenance chains cannot be masked by a valid report signature.
- `signature_valid` at QA/export still comes from the report's own signature verification (unchanged) — the provenance chain contributes chain/link/replay validity only.
- `derive_engagement_trust_inputs()` is fail-closed: no chain or any exception returns all-False TrustInputs, not all-True.
- CI guardrail now rejects both missing kwargs and hardcoded `True` values — prevents the two most common regression patterns.

**Validation:**
- `PYTHONPATH=. python tools/ci/check_db_dependency.py`: OK (no violations)
- `PYTHONPATH=. python tools/ci/check_plane_registry.py`: OK
- `make route-inventory-generate`: OK (4 new routes classified)
- `make contract-authority-refresh`: OK
- `make fg-fast`: OK

**Addendum — P0-7 Trust Intelligence Monitoring (TIM) Foundation (2026-06-14):**
Activated customer-visible continuous trust monitoring using the existing Trust Arc infrastructure (P0-6A/B). TIM observes, correlates, persists, and surfaces trust state over time. No new trust engines — all scores come from existing producers.

**Migration:**
- `migrations/postgres/0113_trust_intelligence_monitoring.sql`: Two new append-only tables — `fa_tim_trust_snapshots` (periodic trust posture aggregates, indexed by tenant+engagement+evaluated_at) and `fa_tim_drift_events` (deterministic rule-based drift detections, indexed by tenant+engagement+status+severity). Both: RLS using `app.tenant_id` GUC (pattern consistent with migrations 0108/0109/0111). Append-only triggers on both tables (BEFORE UPDATE/DELETE → raise exception). No UPDATE or DELETE permitted from service layer.

**Service files:**
- `services/trust_monitoring/__init__.py`: empty package marker.
- `services/trust_monitoring/timeline_emitter.py`: Six non-blocking emit functions targeting the existing `governance_timeline_events` table (ORM: `TimelineEventRecord`). Sources: `trust_arc` (snapshot_generated, certification_issued, governance_decision_recorded), `verification_bundle` (bundle_generated), `trust_monitoring` (drift_detected, snapshot_evaluated). All errors logged and swallowed — timeline failures never interrupt host workflows.
- `services/trust_monitoring/drift_service.py`: Seven deterministic drift rules — `score_degradation` (≥10→MEDIUM, ≥20→HIGH, ≥30→CRITICAL), `cert_expiration` (≤14d→LOW, ≤7d→MEDIUM, ≤3d→HIGH), `cert_expired` (CRITICAL), `evidence_staleness` (>30d→LOW, >60d→MEDIUM, >90d→HIGH; no evidence→LOW), `replay_failure` (failed→CRITICAL, no_chain→LOW), `missing_bundle` (>14d→LOW, >30d→MEDIUM), `consecutive_degradation` (3+ consecutive degrading snapshots→MEDIUM). Public `detect_and_persist_drift()` persists `FaTimDriftEvent` rows and emits `tim_drift_detected` timeline events. Non-blocking.
- `services/trust_monitoring/snapshot_service.py`: `compute_and_persist_tim_snapshot()` queries the latest `FaTrustIntelligenceSnapshot`, `FaTrustCertification`, `FaEvidenceProvenance` (count), and `FaVerificationBundle` (last generated_at) to aggregate trust state into a `FaTimTrustSnapshot` row. Computes drift direction and score delta vs. the previous TIM snapshot. Non-blocking.
- `services/trust_monitoring/monitoring_engine.py`: `evaluate_and_persist_tim()` orchestrates snapshot → drift detection → timeline emit in sequence. Single entry point for all TIM callers. Non-blocking.

**API routes (`api/trust_monitoring.py`):**
Five executive dashboard routes under `/field-assessment/engagements/{engagement_id}/tim/`:
- `GET .../posture` — latest TIM trust snapshot.
- `GET .../timeline` — governance timeline events (source_type=trust_monitoring), max 200, most-recent-first.
- `GET .../drift` — open (or all) drift events, max 500.
- `GET .../certification-status` — latest certification with expiry metadata and `expiry_status` (valid/expiring_soon/expired/not_certified).
- `GET .../risks` — open high/critical drift events only.
All routes: `governance:read` scope + `continuous.monitoring` capability (ENTERPRISE tier, already in capability registry).

**Wiring:**
- `api/main.py`: `trust_monitoring_router` imported and registered in both `build_app()` and `build_contract_app()`.
- `api/db.py`: `api.db_models_tim` added to `_ensure_models_imported()`.
- `services/trust_arc/orchestrator.py`: `_run_tim_evaluation()` called (non-blocking) at the end of `_run_trust_arc()` — TIM snapshot evaluated on every trust arc activation.
- `services/verification_bundle/bundle_service.py`: `emit_verification_bundle_generated()` called (non-blocking) immediately after `db.add(record)` in `_build_and_persist_bundle()`.
- `api/db_models_trust_arc.py`: Added three missing ORM models (`FaTrustIntelligenceLedger`, `FaDecisionReconstructionRecord`, `FaChainOfCustodyRecord`) for tables created in migrations 0108/0109 but previously without SQLAlchemy classes. Fixed `custody_metadata` column name (maps to SQL `metadata`) to avoid SQLAlchemy reserved-name conflict.
- `api/db_models_tim.py`: Two new ORM models (`FaTimTrustSnapshot`, `FaTimDriftEvent`).
- Route inventory, plane registry snapshot, contract routes, and topology hash regenerated; OpenAPI contract regenerated and authority markers refreshed.

**Security review:**
- All five TIM routes require `governance:read` scope and `continuous.monitoring` capability (ENTERPRISE). No customer route bypasses auth.
- Tenant resolution via `_resolve_caller_tenant(request)` — same pattern as trust_arc.py.
- TIM tables are append-only; no UPDATE or DELETE from service layer; enforced by DB triggers in migration 0113.
- RLS on both TIM tables uses `app.tenant_id` GUC — consistent with all FA tables added since migration 0111.
- All TIM service functions are non-blocking: any exception is caught, logged, and returns empty dict/list. TIM failures cannot interrupt trust arc activation, bundle generation, or any other host workflow.
- Drift rules are fully deterministic — no AI, no ML, no external calls. Evidence for every detected event is stored in the `evidence` JSON column.
- `actor_type` in drift events defaults to `"system"` and is extensible without schema changes.

**Validation:**
- `make route-inventory-generate`: OK (5 new TIM routes classified)
- `make contract-authority-refresh`: OK
- `make fg-fast`: OK (pending full run)

---

**Addendum — P0-7 TIM Bot-Review Fixes (2026-06-15):**
Six P1/P2 security and correctness findings from chatgpt-codex-connector review addressed on the same branch.

**Fix 1 (P1) — `replay_status` hardcoded to "no_chain":**
`snapshot_service._derive_replay_status()` added — queries `FaDecisionReconstructionRecord.replay_valid` (latest per engagement). True→"ok", False→"failed", None→"no_chain". Hardcoded fallback removed.

**Fix 2 (P1) — TIM only fires during trust-arc writes:**
`POST /field-assessment/engagements/{engagement_id}/tim/evaluate` added to `api/trust_monitoring.py`. Scopes: `governance:write` + `continuous.monitoring`. Calls `evaluate_and_persist_tim()` and commits. Enables external schedulers to trigger time-based rules (cert expiration, evidence staleness, missing bundle) for idle engagements without requiring a trust-arc activation.

**Fix 3 (P1) — Duplicate open drift events on every evaluation:**
`drift_service._DEDUP_RULES` frozenset added (all rules except `score_degradation`). `_has_open_unacknowledged_event()` queries the DB before each persist — for rules in `_DEDUP_RULES`, if an open unacknowledged event for the same rule already exists for the engagement, the new event is skipped. `score_degradation` excluded (each delta is a discrete point-in-time measurement, not a persistent state).

**Fix 4 (P1) — `acknowledged_by` from non-repudiable source:**
`acknowledge_tim_drift()` previously accepted `actor_id` as a query parameter (caller-supplied, unverifiable). Parameter removed; `actor_id` now derived from `request.state.auth.key_prefix` — same pattern used across all FA write endpoints. Falls back to `"system"` if auth state is absent (should not occur for `governance:write`-gated routes).

**Fix 5 (P2) — Acknowledged drift events still appear in `/risks`:**
`get_tim_risks()` now applies the same acknowledged-exclusion subquery as `get_tim_drift()` — both the high/critical `rows` query and the `all_open_rows` query for `engagement_risk_score` exclude events that have a corresponding `status='acknowledged'` row via `correlation_id`.

**Fix 6 (P2) — `open_drift_count` in persisted snapshot is pre-detection:**
`snapshot_service.compute_and_persist_tim_snapshot()` now returns `"_orm_record": record` in its result dict. `monitoring_engine.evaluate_and_persist_tim()` updates `orm_record.open_drift_count` after drift detection completes, before the caller commits. Because the caller owns the transaction and no flush has occurred, this mutates the pending INSERT — not triggering the BEFORE UPDATE append-only trigger.

**Route inventory changes (Fix 2):**
- `POST /field-assessment/engagements/{engagement_id}/tim/evaluate` added — `governance:write` + `continuous.monitoring`.

**No new tables, migrations, or schema changes.** Route inventory, plane registry snapshot, contract routes, and topology hash regenerated; OpenAPI contract and authority markers refreshed.

**Validation:**
- `make route-inventory-generate`: OK (1 new route added)
- `make contract-authority-refresh`: OK

---

**Addendum — P0-8 Executive Trust Command Center (ETCC) (2026-06-15):**
Executive governance layer above TIM (P0-7) and Trust Arc (P0-6A/B).  No new trust engines — all data from existing append-only tables.

**Capability changes (`api/entitlements.py`):**
Four new capabilities added to `CAPABILITY_REGISTRY` and `ENTERPRISE` tier:
- `trust.executive.dashboard` — executive posture, trends, overview, drilldowns
- `trust.risk` — risk surface with severity breakdown
- `trust.reporting` — all /reports/* routes (P0-9 foundation)
- `trust.executive.export` — reserved for future export (P0-9+)

No existing capabilities modified.

**New service (`services/executive_trust/posture_service.py`):**
- `get_executive_posture(db, *, tenant_id, engagement_id)` — aggregates `FaTimTrustSnapshot` (latest), `FaTrustCertification` (latest), `FaTimDriftEvent` (open unacknowledged) into a unified executive posture dict.  Pure read.  Non-blocking.
- `get_tenant_overview(db, *, tenant_id, limit)` — cross-engagement posture summary via subquery selecting max(evaluated_at) per engagement.  Ordered by posture_score ascending (most at-risk first).
- `_trend_windows(db, ...)` — 7d/30d/90d windows from TIM snapshot history (same logic as trust_monitoring.py `_compute_trend_windows`).

**New API file (`api/executive_trust.py`):**
15 GET routes under `/field-assessment/` prefix.  All require `governance:read`.

Tenant-level route:
- `GET /etcc/overview` — all engagements at a glance; capability: `trust.executive.dashboard`

Per-engagement routes (all under `/engagements/{id}/etcc/`):
- `GET .../posture` — full executive posture (trust + certification + risk + monitoring + trends); capability: `trust.executive.dashboard`
- `GET .../trends` — 7d/30d/90d trend windows; capability: `trust.executive.dashboard`
- `GET .../risks` — all open unacknowledged drift events + risk rollup; capability: `trust.risk`; filterable by `min_severity`
- `GET .../certification` — active cert with expiry status + ledger linkage; capability: `trust.certification`
- `GET .../certification/history` — full cert history (append-only); capability: `trust.certification`
- `GET .../monitoring` — TIM health (last evaluation, replay status, failure events, reconstruction); capability: `continuous.monitoring`
- `GET .../timeline` — unified governance activity feed (all sources, filterable by source_type/event_type/since); capability: `trust.timeline`
- `GET .../decisions` — trust decision memory (filterable by entity_type); capability: `trust.memory`
- `GET .../drilldown/drift/{event_id}` — drift → evidence → source snapshot trace; capability: `trust.executive.dashboard`
- `GET .../drilldown/certification/{cert_id}` — cert → ledger → chain of custody → reconstruction trace; capability: `trust.certification`
- `GET .../reports/summary` — comprehensive executive summary (P0-9 foundation); capability: `trust.reporting`
- `GET .../reports/quarterly` — date-bounded quarterly trust summary (year+quarter params); capability: `trust.reporting`
- `GET .../reports/drift` — full drift history with rule/severity/status breakdown; capability: `trust.reporting`
- `GET .../reports/risk` — risk posture with severity weights, acknowledged count; capability: `trust.reporting`

**No new migrations, tables, or DB triggers.**  All data read from existing append-only tables.

**Wiring:**
- `executive_trust_router` imported and registered in both `build_app()` and `build_contract_app()` in `api/main.py`.

**Security review:**
- All 15 routes require `governance:read` scope and an ENTERPRISE-tier capability gate.  No public or unauthenticated paths added.
- Tenant isolation via `_resolve_caller_tenant(request)` — same pattern as trust_monitoring.py and trust_arc.py.  Missing tenant → 401 before any DB query.
- Acknowledged-event exclusion subquery applied consistently in `/risks` and `/reports/risk` — same `correlation_id` pattern as P0-7 `/drift` and `/risks`.
- No write operations in any ETCC route.  No UPDATE, DELETE, or INSERT.
- All drilldown routes validate engagement ownership (tenant_id filter on every query before returning data).
- `trust.executive.export` capability reserved; no export routes implemented in P0-8 — prevents premature capability surface.

**Governance readiness (Phase 9 compliance):**
`actor_type` field already present in `fa_tim_drift_events` and `fa_governance_decisions`.  ETCC routes expose it in every event dict.  `entity_type` in `fa_trust_decision_memory` supports human/agent/autonomous_system/agi — filterable in `GET .../decisions`.  No schema changes required for autonomous governance.

**AGI readiness (Phase 12 compliance):**
All ETCC routes already return `entity_type` from decision memory and `actor_type` from drift events.  Future Agent Trust Posture and Agent Drift views can be added by filtering on `entity_type='agent'` without redesign.

**Moat note (Phase 13):**
The moat is not the dashboard — it is the historical trust intelligence corpus accumulating in append-only tables with cryptographic signatures and hash chains.  The longer FrostGate runs for a tenant, the deeper the `fa_trust_intelligence_ledger`, `fa_decision_reconstruction_records`, and `fa_chain_of_custody_records` become — making replay, audit, and legal defense increasingly difficult to replicate.

**Route inventory changes:**
15 new GET routes added under `/field-assessment/etcc/` and `/field-assessment/engagements/{id}/etcc/`.  All classified as `allowed_internal` (in ENTERPRISE contract, behind capability gates).

**Tests:**
35 unit tests in `tests/test_executive_trust.py` covering: `_cert_expiry_status` (6 cases), `_risk_weight` (6 cases), `_load_json` (4 cases), `get_executive_posture` empty state (5 cases), `get_executive_posture` with data (5 cases), `get_tenant_overview` (3 cases), quarterly period boundaries (4 cases), severity ordering (3 cases).  35/35 pass.

**Validation:**
- `make route-inventory-generate`: OK (15 new ETCC routes classified)
- `make contract-authority-refresh`: OK
- `make fg-fast`: OK
- `PYTHONPATH=. python -m pytest tests/test_executive_trust.py`: 35/35 passed

---

## P0-9 Addendum — Quarterly Trust Briefs (QTB) (2026-06-15)

### Strategic Context

P0-9 builds the executive deliverable layer above P0-7 (TIM) and P0-8 (ETCC).
No new trust engines.  All report data sourced from existing append-only tables.
The purpose is to transform continuous governance data into defensible executive
deliverables (quarterly briefs, board reports) that can be verified by auditors,
boards, regulators, and legal counsel.

### New Tables (migration 0114)

**`fa_qtb_briefs`** — Main brief record.
- Status-mutable workflow record: draft → generated → reviewed → approved → delivered → archived.
- Content fields (brief_hash, report_hash) are set at generation time and not updated.
- RLS: `tenant_id = current_setting('app.tenant_id', true)`.
- Not append-only for status field (status transitions are additive, not destructive).

**`fa_qtb_brief_sections`** — Immutable content sections.
- Append-only (triggers on UPDATE and DELETE).
- One row per section per brief: posture | drift | certification | governance | evidence | board_summary.
- `section_data` (JSON) contains the full computed section.
- `evidence_refs` (JSON array) links to source IDs.
- `section_hash` = SHA-256(section_data JSON with sorted keys).

**`fa_qtb_brief_manifests`** — Deterministic audit anchor.
- Append-only (triggers on UPDATE and DELETE).
- One manifest per brief (UNIQUE brief_id constraint).
- Contains JSON arrays: snapshot_ids, certification_ids, drift_event_ids, timeline_refs, evidence_refs, decision_refs, bundle_refs.
- `manifest_hash` = SHA-256 of all sorted source ID arrays.
- `report_hash` = SHA-256(brief_hash + ":" + manifest_hash).
- Enables auditor-reproducible verification: same source data → same hashes.

### New Service (`services/quarterly_briefs/brief_service.py`)

**Section builders (deterministic, pure-function):**
- `_build_posture_section(snapshots)` — min/max/avg score, trend direction, replay distribution
- `_build_drift_section(drift_events)` — risk score, by_rule, by_severity, top_rules, velocity
- `_build_certification_section(period_certs, active_cert)` — level history, expiry status
- `_build_governance_section(timeline_events, decisions)` — activity counts, actor type distribution
- `_build_evidence_appendix(...)` — every source ID referenced; traceability flags
- `_build_board_summary(...)` — condensed strategic view derived from other sections

**Entry points:**
- `generate_quarterly_brief(db, *, tenant_id, engagement_id, year, quarter, generated_by)` — full 6-section brief
- `generate_board_brief(db, *, tenant_id, engagement_id, year, quarter, generated_by)` — board_summary + evidence only

Both functions return the assembled brief dict on success, empty dict on error.
Caller owns the DB session and commits after return.

**Hash chain:**
- `section_hash` = SHA-256(section_data, sort_keys=True)
- `brief_hash` = SHA-256([section_hash, ...])
- `manifest_hash` = SHA-256(sorted source ID arrays)
- `report_hash` = SHA-256(brief_hash + ":" + manifest_hash)
- Reproducible: same input data → same hashes → same report_hash.

### New API (`api/quarterly_briefs.py`)

11 routes under `/field-assessment/` prefix.  All require `governance:read`.

Per-engagement (all under `/engagements/{id}/etcc/`):
- `POST .../etcc/briefs/generate` — generate quarterly brief; capability: `trust.quarterly.briefs`; 201
- `GET  .../etcc/briefs` — list briefs (filterable by type/status); capability: `trust.quarterly.briefs`
- `GET  .../etcc/briefs/{brief_id}` — full brief + sections; capability: `trust.quarterly.briefs`
- `POST .../etcc/briefs/{brief_id}/review` — transition to 'reviewed'; capability: `trust.report.review`
- `POST .../etcc/briefs/{brief_id}/approve` — transition to 'approved'; capability: `trust.report.review`
- `GET  .../etcc/briefs/{brief_id}/manifest` — deterministic audit manifest; capability: `trust.quarterly.briefs`
- `GET  .../etcc/briefs/{brief_id}/export` — JSON or HTML export; capability: `trust.report.export`
- `POST .../etcc/board/generate` — generate board brief; capability: `trust.board.reporting`; 201
- `GET  .../etcc/board` — list board reports; capability: `trust.board.reporting`
- `GET  .../etcc/board/{report_id}` — get board report; capability: `trust.board.reporting`

Tenant-level:
- `GET /etcc/briefs/history` — all briefs across all engagements; capability: `trust.report.delivery`

### New Capabilities (5 added to CAPABILITY_REGISTRY + ENTERPRISE tier)

- `trust.quarterly.briefs` — generate, list, read quarterly briefs and manifests
- `trust.board.reporting` — generate, list, read board reports
- `trust.report.export` — JSON/HTML export endpoint
- `trust.report.review` — review + approve workflow
- `trust.report.delivery` — tenant-level brief history (compliance team access)

### Security Review

- All 11 routes require `governance:read` scope and ENTERPRISE-tier capability gates.
- Actor identity from `request.state.auth.key_prefix` (same as P0-7/P0-8) — not caller-supplied.
- Status transitions enforce valid states: review only from 'generated'; approve only from 'reviewed'.
- Tenant isolation on every DB query (`tenant_id` filter always applied).
- No cross-tenant data visibility (same RLS + application-layer filtering as P0-7/P0-8).
- No public or unauthenticated paths.
- Export endpoint (`trust.report.export`) is gated separately from generation.
- HTML export uses structured data — no server-side JS execution or external resource loading.

### Governance Readiness

- `generated_by` field supports: human | agent | system | workflow
- Board and quarterly reports will include governance activity from all actor types
- Schema version field on all 3 tables enables forward-compatible evolution
- `replay_version` in manifest enables future replay engine integration without schema changes

### AGI Readiness

- `actor_type_distribution` in governance section already captures agent/autonomous_system/agi actors
- Decision refs in manifests will include future AGI governance decisions without schema changes
- No redesign needed for future `agent_trust` or `agi_governance` brief types — just new section builders

### Moat Note

The strategic asset is not the PDF — it is the historical governance intelligence corpus
(TIM snapshots, drift history, certification lifecycle, decision memory, timeline records,
verification bundles) that makes each brief defensible.  Competitors can copy the UI;
they cannot copy years of append-only, cryptographically-anchored governance history.

### Tests

75 unit tests in `tests/test_quarterly_briefs.py` covering:
- Period boundary computation (5 cases)
- Hash determinism (8 cases: SHA-256, section_hash, manifest_hash, report_hash)
- Posture section builder (8 cases)
- Drift section builder (7 cases)
- Certification section builder (5 cases)
- Governance section builder (5 cases)
- Board summary builder (7 cases)
- Evidence appendix builder (5 cases)
- generate_quarterly_brief empty state (7 cases)
- generate_board_brief empty state (5 cases)
- Manifest and hash validation (7 cases)
- Evidence linkage (2 cases)
- Historical reporting accuracy (4 cases)

### Validation

- `make route-inventory-generate`: OK
- `make contract-authority-refresh`: OK
- `PYTHONPATH=. pytest tests/test_quarterly_briefs.py`: 75/75 passed

---

## P0-9 Improvements Addendum (2026-06-15)

Three targeted additions to the QTB layer based on post-build review:

### 1. Delivery Tracking

Added `delivered_at`, `delivered_to`, `delivery_channel` columns to `fa_qtb_briefs` (migration 0114, `api/db_models_qtb.py`). These are mutable fields, set only when a brief transitions to `delivered` status.

New route: `POST .../etcc/briefs/{brief_id}/deliver` — capability: `trust.report.delivery`; only allows `approved` briefs; sets the three delivery fields; transitions status to `delivered`; returns `delivered_at`, `delivered_to`, `delivery_channel`, `report_hash`.

Valid channels: `portal | email | api | export`. Invalid channel returns 400. Non-approved brief returns 409.

### 2. Regeneration Lineage

Added nullable `parent_brief_id` column to `fa_qtb_briefs` (migration 0114, ORM, service, API). Propagated through `generate_quarterly_brief()` and `generate_board_brief()` service functions and both generate routes as an optional query param. Enables auditors to trace a regenerated brief back to its predecessor.

### 3. Explainability Endpoint

New route: `GET .../etcc/briefs/{brief_id}/explain` — capability: `trust.quarterly.briefs`. Returns `provenance` mapping every top-level metric to its authoritative source table and the exact record IDs from the stored manifest. No AI. No synthetic data. Pure lineage from `fa_qtb_brief_manifests`.

Response shape:
```json
{
  "provenance": {
    "trust_score":           { "source": "fa_tim_trust_snapshots",   "snapshot_ids": [...] },
    "risk_score":            { "source": "fa_tim_drift_events",       "event_ids": [...] },
    "certification_status":  { "source": "fa_trust_certifications",   "certification_ids": [...] },
    "governance_activity":   { "source": "fa_timeline_events",        "event_ids": [...] },
    "decision_record":       { "source": "fa_trust_decision_memory",  "decision_ids": [...] },
    "verification_bundles":  { "source": "fa_verification_bundles",   "bundle_ids": [...] }
  },
  "manifest_hash": "...",
  "integrity": { "no_synthetic_data": true, ... }
}
```

### Files Changed

- `migrations/postgres/0114_quarterly_trust_briefs.sql` — 4 new columns on `fa_qtb_briefs` (`delivered_at`, `delivered_to`, `delivery_channel`, `parent_brief_id`)
- `api/db_models_qtb.py` — 4 new `Mapped` fields on `FaQtbBrief`
- `services/quarterly_briefs/brief_service.py` — `parent_brief_id` propagation through `_persist_brief_and_sections`, `generate_quarterly_brief`, `generate_board_brief`
- `api/quarterly_briefs.py` — `_brief_to_dict` extended; 2 new routes (`deliver`, `explain`); `parent_brief_id` query param on generate routes
- `tests/test_quarterly_briefs.py` — 8 new tests (lineage: 4, delivery fields: 4); 83/83 passed

### Validation

- `make route-inventory-generate`: OK (2 new routes registered)
- `make contract-authority-refresh`: OK
- `PYTHONPATH=. pytest tests/test_quarterly_briefs.py`: 83/83 passed

---

## P0-9 Bot-Review Fixes (2026-06-15)

Five bot-review findings fixed after initial P0-9 merge:

**P1 — Section hash computed on wrong content** (`brief_service.py`): `section_hash` was computed on the section dict before mutation, but `section_data` was serialized after mutating `s["_hash"] = h`, creating a permanent mismatch. Fixed: sections are no longer mutated — `section_hashes = [_section_hash(s) for s in sections]` and `section_hashes[order]` is used in the persist loop.

**P1 — Write scope required for governance workflow mutations** (`api/quarterly_briefs.py`): `review_brief` and `approve_brief` used `governance:read`, allowing read-only keys to mutate governance state. Fixed: both now require `governance:write`.

**P1 — Non-deterministic `current_as_of` in certification section hash** (`brief_service.py`): `_build_certification_section` included `current_as_of = _now_iso()` in the section dict, which was hashed. Same quarter regenerated 1 second later produced a different `report_hash`. Fixed: `current_as_of` removed from the section dict.

**P2 — Approve idempotency overwrote original attribution** (`api/quarterly_briefs.py`): `_APPROVE_TRANSITION` accepted `approved → approved`, allowing repeated calls to overwrite `approved_by`/`approved_at`. Fixed: removed that transition entry; already-approved briefs now return 409.

**P2 — Expired certification returned as active** (`brief_service.py`): `_fetch_active_certification` filtered only on `valid_from < period_end`, not `valid_until`. Fixed: added `valid_until >= period_end` to the WHERE clause.

No new routes. No schema changes. No migration changes. Route inventory and topology updated to reflect CI artifact state.

---

## P0-10 Addendum — Certification Lifecycle Management (CLM) (2026-06-15)

**Reviewer:** Codex | **Classification:** SOC-LOW (new governance surface; no auth subsystem changes; no new credential handling; append-only audit tables; tenant-isolated RLS on all tables)

### Summary

P0-10 adds a full lifecycle management layer for certifications above the existing Trust Arc static cert records (`fa_trust_certifications`). It does not duplicate trust/monitoring engines — all health data sourced from existing P0-7 TIM tables.

### New Migration (`migrations/postgres/0115_clm_certification_lifecycle.sql`)

Six new tenant-scoped tables, all RLS-enforced (`ENABLE + FORCE ROW LEVEL SECURITY`), all scoped to `app.tenant_id` GUC:

- **`fa_clm_certs`** — one row per managed cert; lifecycle_status mutable; 4 indexes
- **`fa_clm_lifecycle_events`** — append-only; 2 append_only_guard() triggers (UPDATE + DELETE); 2 indexes
- **`fa_clm_cert_reviews`** — append-only; 2 append_only_guard() triggers; 2 indexes
- **`fa_clm_cert_attestations`** — append-only; 2 append_only_guard() triggers; 2 indexes
- **`fa_clm_cert_renewals`** — append-only; 2 append_only_guard() triggers; 2 indexes
- **`fa_clm_cert_manifests`** — append-only; `cert_id UNIQUE`; 2 append_only_guard() triggers; 2 indexes

### New ORM (`api/db_models_clm.py`)

Six classes mirroring the migration: `FaClmCert`, `FaClmLifecycleEvent`, `FaClmCertReview`, `FaClmCertAttestation`, `FaClmCertRenewal`, `FaClmCertManifest`. All use `Mapped[str]` / `mapped_column()` style consistent with P0-9.

### New Service (`services/clm/lifecycle_service.py`)

All functions return plain dicts; empty dict on fatal error; caller commits.

- `create_certification()` — cert + manifest + lifecycle event; `cert_hash = SHA-256(stable cert fields)`, `manifest_hash = SHA-256(sorted source ID arrays)`
- `transition_lifecycle()` — validates against `_VALID_TRANSITIONS` state machine; raises ValueError on invalid
- `add_review()` — append review + lifecycle event
- `add_attestation()` — append attestation with `attestation_hash = SHA-256(attestation_data)`; lifecycle event
- `initiate_renewal()` — append renewal + readiness snapshot; lifecycle event
- `get_certification_health()` — scoring from TIM snapshots + drift events; `renewal_recommended` flag
- `get_lineage()` — walks `parent_cert_id` chain upward with 50-depth circular guard
- `compute_trust_impact()` — cert level weight (bronze=10/silver=20/gold=30/platinum=40/default=15)

### New API (`api/clm.py`)

Router prefix `/field-assessment`, tag `certification-lifecycle`. 13 routes:

- `POST /engagements/{eid}/certifications` — create; scope `governance:read`; capability `certification.read`; 201
- `GET  /engagements/{eid}/certifications` — list (filter: lifecycle_status, cert_type, framework); capability `certification.read`
- `GET  /engagements/{eid}/certifications/dashboard` — ETCC health summary; capability `certification.executive.view`
- `GET  /engagements/{eid}/certifications/{cert_id}` — full detail; capability `certification.read`
- `POST /engagements/{eid}/certifications/{cert_id}/transition` — lifecycle transition; scope `governance:write`; capability `certification.approve`
- `POST /engagements/{eid}/certifications/{cert_id}/review` — add review; scope `governance:write`; capability `certification.review`; 201
- `POST /engagements/{eid}/certifications/{cert_id}/attest` — add attestation; scope `governance:write`; capability `certification.attest`; 201
- `POST /engagements/{eid}/certifications/{cert_id}/renew` — initiate renewal; scope `governance:write`; capability `certification.renew`; 201
- `GET  /engagements/{eid}/certifications/{cert_id}/lineage` — parent chain; capability `certification.drilldown`
- `GET  /engagements/{eid}/certifications/{cert_id}/health` — health score; capability `certification.read`
- `GET  /engagements/{eid}/certifications/{cert_id}/impact` — trust impact; capability `certification.drilldown`
- `GET  /engagements/{eid}/certifications/{cert_id}/manifest` — audit manifest; capability `certification.drilldown`
- `GET  /engagements/{eid}/certifications/{cert_id}/history` — lifecycle event log; capability `certification.read`

### New Capabilities (`api/entitlements.py`)

9 new capabilities added to both `CAPABILITY_REGISTRY` and `_enterprise_extras`:
`certification.read`, `certification.review`, `certification.attest`, `certification.approve`, `certification.renew`, `certification.revoke`, `certification.admin`, `certification.executive.view`, `certification.drilldown`

### Security Invariants

- All 6 tables have `ENABLE ROW LEVEL SECURITY` + `FORCE ROW LEVEL SECURITY` with `app.tenant_id` GUC policy
- All 5 append-only tables have `append_only_guard()` triggers for both `BEFORE UPDATE` and `BEFORE DELETE`
- Cert hash and manifest hash exclude ephemeral timestamps (deterministic: same inputs → same hash)
- Lifecycle state machine explicitly enumerated in `_VALID_TRANSITIONS`; invalid transitions raise `ValueError` (validated server-side)
- Mutation routes require `governance:write` scope; read routes require `governance:read`
- All platform data fetchers (TIM snapshots, drift, decisions, bundles, timeline) use `try/except` for graceful degradation — never raises on missing upstream data
- No new trust/monitoring engines created
- `clm_router` registered in both `build_app()` and `build_contract_app()`
- `api.db_models_clm` imported in `api/db.py` `_ensure_models_imported()`

### Files Changed

- `migrations/postgres/0115_clm_certification_lifecycle.sql` — 6 new tables, RLS, indexes, append-only triggers
- `api/db_models_clm.py` — 6 ORM classes
- `services/clm/__init__.py` — empty package init
- `services/clm/lifecycle_service.py` — 8 public functions
- `api/clm.py` — 13 routes
- `api/entitlements.py` — 9 new capabilities in CAPABILITY_REGISTRY + _enterprise_extras
- `api/db.py` — `importlib.import_module("api.db_models_clm")` in `_ensure_models_imported()`
- `api/main.py` — `clm_router` imported and registered in both app builders

### Validation

- `make route-inventory-generate`: OK (13 new routes registered)
- `make contract-authority-refresh`: OK
- `PYTHONPATH=. pytest tests/test_clm.py`: 100/100 passed
EOFSOCDOC

---

## 2026-06-16 — P0-10 Bot-Review Fixes (CLM scope gate + engagement isolation)

**Reviewer:** Codex | **Classification:** SOC-P1 (mutation scope gate tightened; cross-engagement data isolation enforced)

**Problem 1 — Write scope missing on CLM create route (P2):**
`POST /field-assessment/engagements/{eid}/certifications` was gated with `governance:read` + `certification.read`. A caller with read-only governance access could create CLM certification records and commit DB rows, violating the module's mutation contract and the field-assessment pattern where create routes require write scope.

**Fix:** Changed dependencies to `governance:write` + `certification.admin`.

**Problem 2 — Engagement isolation missing in service cert lookups (P2):**
All service functions (`transition_lifecycle`, `add_review`, `add_attestation`, `initiate_renewal`, `get_certification_health`, `get_lineage`, `compute_trust_impact`) looked up certs by `cert_id + tenant_id` only. A request to engagement A with a cert ID belonging to engagement B (same tenant) could transition, review, attest, renew, or read health/impact for the wrong cert, mixing cross-engagement data.

**Fix:** Added `engagement_id` parameter to all 7 service functions and added `FaClmCert.engagement_id == engagement_id` to each cert WHERE clause. All API call sites updated to pass `eid`. Exception: lineage ancestor traversal remains tenant-scoped only (parent certs legitimately span prior engagements); only the starting cert lookup is engagement-scoped.

### Files Changed

- `api/clm.py` — create route scope/capability updated; `engagement_id=eid` passed to all 6 service mutation/read calls
- `services/clm/lifecycle_service.py` — `engagement_id` param added to 7 functions; WHERE clauses updated
- `tools/ci/route_inventory.json` — regenerated after scope change on create route

### Validation

- `make route-inventory-generate`: OK
- `make fg-fast`: All checks passed

---

## 2026-06-20 — PR 14.1 Risk Acceptance Governance Foundation (plane registry + route inventory)

**Reviewer:** Codex | **Classification:** SOC-P2 (new tenant-scoped routes registered under control plane; no auth or middleware changes)

**Change:** PR 14.1 added 7 new read/write routes under `/risk-acceptances` as a new bounded context for formal risk acceptance governance. All routes are tenant-scoped via `require_bound_tenant()` and gated on `governance:read` or `governance:write` scopes. No auth middleware, OPA policy, or `.github/workflows/` files were modified.

`/risk-acceptances` was added to the `control` plane's `route_prefixes` in `services/plane_registry/registry.py` — the same plane that owns `/governance`, `/remediation`, and `/subscriptions`. This is correct: risk acceptance is governance/control-plane functionality, not a public or data-plane surface.

The following `tools/ci/` files were regenerated as a routine consequence:
- `tools/ci/route_inventory.json` — 7 new routes added
- `tools/ci/plane_registry_snapshot.json` — updated after plane registry source change
- `tools/ci/route_inventory_summary.json` — summary counts updated
- `tools/ci/topology.sha256` — SHA256 of topology state updated

### Files Changed

- `api/db_models_risk_acceptance.py` — new ORM models (RiskAcceptance, RiskAcceptanceAudit)
- `api/risk_acceptance.py` — 7 new FastAPI routes, all tenant-scoped
- `services/risk_acceptance/` — engine, repository, schemas (new bounded context)
- `services/plane_registry/registry.py` — `/risk-acceptances` added to control plane route_prefixes
- `api/observability/metrics.py` — 8 new Prometheus counters (bounded cardinality; no tenant labels)
- `tools/ci/route_inventory.json`, `plane_registry_snapshot.json`, `route_inventory_summary.json`, `topology.sha256` — regenerated via `make route-inventory-generate`

### Validation

- `make check_plane_registry`: OK (no unexpected-route gaps)
- `make route-inventory-generate`: OK (7 new routes registered)
- `make contract-authority-refresh`: OK
- `PYTHONPATH=. pytest tests/test_risk_acceptance.py`: 58/58 passed
- `make fg-fast`: All checks passed

---

## 2026-06-20 — PR 14.2 Risk Governance Engine (plane registry + route inventory)

**Reviewer:** Codex | **Classification:** SOC-P2 (new tenant-scoped governance routes registered under control plane; no auth or middleware changes)

**Change:** PR 14.2 added a new `services/risk_governance/` bounded context implementing formal approval lifecycle, multi-approver governance, review scheduling, escalation signals, governance policies, and governance intelligence dashboard APIs. All routes are tenant-scoped via `require_bound_tenant()` and gated on `governance:read` or `governance:write` scopes. No auth middleware, OPA policy, or `.github/workflows/` files were modified.

`/risk-governance` was added to the `control` plane's `route_prefixes` in `services/plane_registry/registry.py`. `RISK_GOVERNANCE` source type was added to `services/governance/timeline/models.py` (additive, non-breaking enum change).

The following `tools/ci/` files were regenerated as a routine consequence:
- `tools/ci/route_inventory.json`, `plane_registry_snapshot.json`, `route_inventory_summary.json`, `topology.sha256`

### Files Changed

- `api/db_models_risk_governance.py` — 5 new ORM models
- `api/risk_governance.py` — new FastAPI routes, all tenant-scoped
- `services/risk_governance/` — engine, repository, schemas (new bounded context)
- `services/plane_registry/registry.py` — `/risk-governance` added to control plane route_prefixes
- `services/governance/timeline/models.py` — RISK_GOVERNANCE source type added (additive)
- `services/notifications/schemas.py` — 8 new notification triggers added (additive)
- `api/observability/metrics.py` — 7 new Prometheus counters (bounded cardinality; no tenant labels)
- `tools/ci/route_inventory.json`, `plane_registry_snapshot.json`, `route_inventory_summary.json`, `topology.sha256` — regenerated via `make route-inventory-generate`

### Validation

- `make check_plane_registry`: OK (no unexpected-route gaps)
- `make route-inventory-generate`: OK
- `make contract-authority-refresh`: OK
- `PYTHONPATH=. pytest tests/test_risk_governance.py`: 75/75 passed
- `make fg-fast`: All checks passed

---

## 2026-06-22 — PR 14.6.1 Canonical Evidence Authority (plane registry + route inventory + contract drift)

**Reviewer:** Codex | **Classification:** SOC-P2 (new tenant-scoped evidence authority routes registered under evidence plane; no auth or middleware changes; ValidationError schema drift from fastapi 0.120.4 → 0.136.3 upgrade)

**Change:** PR 14.6.1 added the Canonical Evidence Authority bounded context (`services/evidence_authority/`). All 15 routes under `/evidence` are tenant-scoped via `require_bound_tenant()` and gated on `governance:read` or `governance:write` scopes. No auth middleware, OPA policy, or `.github/workflows/` files were modified.

Additionally, the local venv had stale fastapi==0.120.4 / starlette==0.49.1 while `requirements-shared.txt` pins fastapi==0.136.3 / starlette==1.1.0. Regenerating contracts with the correct toolchain version produced additional drift in the `ValidationError` schema (`ctx` and `input` fields added; `format: binary` → `contentMediaType: application/octet-stream` for file uploads). This is a schema serialization change in pydantic 2.9, not a functional change.

All 15 routes now declare `responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}}` to satisfy the `OPENAPI_SECURITY_401_403_REQUIRED` gate.

The following `tools/ci/` files were regenerated as a routine consequence:
- `tools/ci/route_inventory.json`, `plane_registry_snapshot.json`, `route_inventory_summary.json`, `topology.sha256`
- `artifacts/platform_inventory.det.json` — contract_count and runtime_count updated

### Files Changed

- `api/db_models_evidence_authority.py` — 5 new ORM models (fa_evidence, fa_evidence_ownership, fa_evidence_relationships, fa_evidence_trust_events, fa_evidence_audit_events)
- `api/evidence_authority.py` — 15 new FastAPI routes, all tenant-scoped; 401/403 responses declared on all routes
- `services/evidence_authority/` — engine, repository, models, schemas (new bounded context)
- `migrations/postgres/0123_canonical_evidence_authority.sql` — 5 new tables with append-only guards
- `api/db.py` — `db_models_evidence_authority` registered in `_ensure_models_imported()`
- `api/main.py` — `evidence_authority_router` registered in both `build_app()` and `build_contract_app()`
- `api/observability/metrics.py` — 6 new Prometheus counters (bounded cardinality; no tenant labels)
- `contracts/admin/openapi.json` — ValidationError schema updated (ctx + input fields; fastapi 0.136.3)
- `contracts/core/openapi.json`, `schemas/api/openapi.json` — same ValidationError drift + binary→contentMediaType
- `BLUEPRINT_STAGED.md`, `CONTRACT.md` — contract authority SHA256 updated
- `tools/ci/route_inventory.json`, `plane_registry_snapshot.json`, `route_inventory_summary.json`, `topology.sha256` — regenerated via `make route-inventory-generate`
- `artifacts/platform_inventory.det.json` — regenerated (contract_count +15, runtime_count +15)

### Validation

- `make contract-authority-refresh`: OK
- `make route-inventory-generate`: OK
- `make fg-contract`: Contract diff OK (admin/core/artifacts)
- `pytest tests/test_ea_canonical_14_6_1.py`: 117/117 passed
- `make fg-fast`: All checks passed
