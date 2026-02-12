# FrostGate Core Dashboard — Repo Reality Map & Architecture (Contract-Driven)

Verified against: `97fe8ca`

Date: 2026-02-12

## A) Repo Reality Map

### Method used
- Authoritative contract: `contracts/core/openapi.json`.
- Route implementation discovery: FastAPI route decorators in `api/**` + `api/main.py` router registration.
- Auth/tenant enforcement discovery: `api/auth_scopes/resolution.py`, `api/deps.py`, `api/db.py`, and per-route dependencies.
- RLS verification: Postgres migrations under `migrations/postgres/`.
- Route test mapping: `tests/**` and `tests/security/**` references.
- Note: test mapping is best-effort; confirm with `rg` before treating as authoritative.

### Contract routes → implementation/auth/tenant/RLS/tests

| Method | Route | Implementation | Auth enforcement | Tenant binding | RLS interaction | Tests (mapped by name; verify) |
|---|---|---|---|---|---|---|
| GET | `/_debug/routes` | `api/main.py::debug_routes` | `require_status_auth(request)` inside handler | none | none | `tests/test_auth_gate_regression.py` (indirect auth gate), `tests/test_main_integrity.py` |
| GET | `/decisions` | `api/decisions.py::list_decisions` | `Depends(require_scopes("decisions:read"))` | `Depends(tenant_db_required)` + `request.state.tenant_id` | Query filters by tenant; PG can also enforce via RLS session context | `tests/test_tenant_binding.py`, `tests/test_auth_tenants.py`, `tests/test_e2e_http_local.py` |
| GET | `/decisions/{decision_id}` | `api/decisions.py::get_decision` | `Depends(require_scopes("decisions:read"))` | `Depends(tenant_db_required)` + explicit tenant mismatch check | Tenant row ownership check + optional PG RLS | `tests/test_tenant_binding.py`, `tests/security/test_decision_immutability.py` |
| POST | `/defend` | `api/defend.py::defend` | Router deps: `require_scopes("defend:write")` + `rate_limit_guard` | `bind_tenant_id(...)` in handler | Writes tenant_id to decisions/artifacts; PG RLS applies when context set | `tests/test_defend_endpoint.py`, `tests/test_decision_pipeline_unified.py`, `tests/test_tenant_binding.py` |
| GET | `/feed/live` | `api/feed.py::feed_live` | Router deps: `require_scopes("feed:read")` + `rate_limit_guard` | `Depends(tenant_db_required)` + enforced request tenant | Query tenant filtered; PG RLS compatible | `tests/test_feed_live_filters.py`, `tests/test_feed_live_presentation_contract.py` |
| GET | `/feed/stream` | `api/feed.py::feed_stream` | Router deps: `require_scopes("feed:read")` + `rate_limit_guard` | `Depends(tenant_db_required)` + enforced request tenant | Stream payload assembled from tenant-filtered rows | `tests/test_contract_feed.py`, `tests/test_feed_live_filters.py` |
| HEAD | `/feed/stream` | `api/feed.py::feed_stream_head` | same router deps as above | same as above | same as above | `tests/test_contract_feed.py` |
| GET | `/forensics/audit_trail/{event_id}` | `api/forensics.py::audit_trail` | `require_scopes("forensics:read")` + enabled guard | `Depends(tenant_db_required)` + tenant-filtered query | Tenant-filtered read + PG RLS path | `tests/security/test_forensics_contract.py`, `tests/security/test_forensics_leakage.py` |
| GET | `/forensics/chain/verify` | `api/forensics.py::chain_verify` | `require_scopes("forensics:verify")` + enabled guard | `Depends(tenant_db_required)` | Calls `verify_chain_for_tenant(... tenant_id=...)` | `tests/security/test_chain_verification_detects_tamper.py`, `tests/security/test_forensics_contract.py` |
| GET | `/forensics/snapshot/{event_id}` | `api/forensics.py::snapshot` | `require_scopes("forensics:read")` + enabled guard | `Depends(tenant_db_required)` + tenant-filtered query | Tenant-filtered read + PG RLS path | `tests/security/test_forensics_contract.py`, `tests/security/test_forensics_leakage.py` |
| GET | `/governance/changes` | `api/governance.py::list_changes` | Router deps: `verify_api_key` + `require_scopes("governance:write")` | none (uses `get_db`) | No tenant predicate in handler; RLS only effective if DB context exists (not set here) | `tests/test_governance_approval_flow.py` |
| POST | `/governance/changes` | `api/governance.py::create_change` | same as above | none | same as above | `tests/test_governance_approval_flow.py` |
| POST | `/governance/changes/{change_id}/approve` | `api/governance.py::approve_change` | same as above | none | same as above | `tests/test_governance_approval_flow.py` |
| GET | `/health` | `api/main.py::health` | auth gate marks as public path | none | none | `tests/test_integration_smoke.py`, `tests/test_main_integrity.py` |
| GET | `/health/detailed` | `api/main.py::health_detailed` | `Depends(require_status_auth)` | none | none | `tests/test_auth.py` (status auth behaviors), `tests/test_integration_smoke.py` |
| GET | `/health/live` | `api/main.py::health_live` | auth gate public path | none | none | `tests/test_integration_smoke.py` |
| GET | `/health/ready` | `api/main.py::health_ready` | auth gate public path | none | none | `tests/test_integration_smoke.py`, `tests/security/test_startup_validation.py` |
| GET | `/keys` | `api/keys.py::get_keys` | Router deps: `require_scopes("keys:admin")` | `bind_tenant_id(...)` in handler | Key listing bound by tenant argument where applicable; PG RLS optional | `tests/test_key_lifecycle.py`, `tests/security/test_keys_admin_tenant_scope.py` |
| POST | `/keys` | `api/keys.py::create_key` | Router deps: `require_scopes("keys:admin")` | `bind_tenant_id(...)` in handler | tenant_id associated at create time; PG RLS optional | `tests/test_key_lifecycle.py`, `tests/security/test_keys_admin_tenant_scope.py` |
| POST | `/keys/revoke` | `api/keys.py::revoke_key` | Router deps: `require_scopes("keys:admin")` | `bind_tenant_id(...)` in handler | tenant-bounded revoke path | `tests/test_key_lifecycle.py` |
| POST | `/keys/rotate` | `api/keys.py::rotate_key` | Router deps: `require_scopes("keys:admin")` | `bind_tenant_id(...)` in handler | tenant-bounded rotate path | `tests/test_key_lifecycle.py`, `tests/security/test_key_hashing_kdf.py` |
| DELETE | `/keys/{prefix}` | `api/keys.py::delete_key` | Router deps: `require_scopes("keys:admin")` | delegates to revoke with `bind_tenant_id` | tenant-bounded revoke path | `tests/test_key_lifecycle.py` |
| GET | `/missions` | `api/mission_envelope.py::list_missions` | none in router | none | not DB-backed (default/file-backed) | `tests/test_mission_envelope_contract.py` |
| GET | `/missions/{mission_id}` | `api/mission_envelope.py::get_mission` | none | none | not DB-backed | `tests/test_mission_envelope_contract.py` |
| GET | `/missions/{mission_id}/status` | `api/mission_envelope.py::mission_status` | none | none | not DB-backed | `tests/test_mission_envelope_contract.py` |
| GET | `/rings/isolation` | `api/ring_router.py::check_isolation` | none | none | not DB-backed | `tests/test_ring_router_contract.py` |
| GET | `/rings/policies` | `api/ring_router.py::list_policies` | none | none | not DB-backed | `tests/test_ring_router_contract.py` |
| POST | `/rings/route` | `api/ring_router.py::route_request` | none | none | not DB-backed | `tests/test_ring_router_contract.py` |
| POST | `/roe/evaluate` | `api/roe_engine.py::evaluate_roe` | none | none | not DB-backed | `tests/test_roe_gating_contract.py` |
| GET | `/roe/policy` | `api/roe_engine.py::get_policy` | none | none | not DB-backed | `tests/test_roe_gating_contract.py` |
| GET | `/stats` | `api/stats.py::get_stats` | Router deps: `require_scopes("stats:read")` | `Depends(tenant_db_required)` + request tenant | Query filtered by tenant + PG RLS support | `tests/security/test_stats_tenant_filter.py`, `tests/test_stats_contract_adapter.py` |
| GET | `/stats/debug` | `api/main.py::stats_debug` | `Depends(require_status_auth)` | none | none | `tests/test_main_integrity.py` |
| GET | `/stats/summary` | `api/stats.py::get_stats_summary` | Router deps: `require_scopes("stats:read")` | `Depends(tenant_db_required)` + request tenant | Query filtered by tenant + PG RLS support | `tests/security/test_stats_tenant_filter.py`, `tests/test_stats_contract_adapter.py` |
| GET | `/status` | `api/main.py::status` | `Depends(require_status_auth)` | optional tenant header checked by status auth helper | none | `tests/test_auth.py` |
| POST | `/v1/defend` | `api/defend.py::defend` (mounted with `/v1` prefix) | same as `/defend` | same as `/defend` | same as `/defend` | `tests/test_defend_endpoint.py`, `tests/test_e2e_http_local.py` |
| GET | `/v1/status` | `api/main.py::v1_status` | `Depends(require_status_auth)` | optional tenant header checked by status auth helper | none | `tests/test_auth.py` |

### Tenant-scoped endpoints (implemented)
- Tenant-scoped (explicit): `/defend`, `/decisions*`, `/feed/*`, `/forensics/*`, `/stats*`, `/keys*`.
- Not tenant-scoped by implementation: `/governance/*`, `/missions*`, `/rings*`, `/roe/*`, `/health*`, `/status*`, `/_debug/routes`.

### Endpoints that produce artifacts
- `/defend` emits decision evidence artifacts (`emit_decision_evidence`) and chain fields.
- `/forensics/snapshot/{event_id}` and `/forensics/audit_trail/{event_id}` return forensic evidence views.
- `/forensics/chain/verify` returns chain verification results.

### Endpoints that affect decisions
- `/defend` and `/v1/defend` are decision-producing control-plane actions.
- `/roe/evaluate` performs policy/ROE gating evaluation (advisory computation route).

### Endpoints related to governance/compliance
- `/governance/*`.
- `/forensics/*`.
- `/rings/*`, `/missions*`, `/roe/*` (compliance/control support functions).

### Auth enforcement confirmation
- Scope enforcement is dependency-based (`require_scopes`) in router/route dependencies.
- API key validation is in `require_api_key_always`/`verify_api_key_detailed`.
- Middleware `AuthGateMiddleware` classifies paths as public/protected and stamps headers, but does **not** itself validate keys.

### Tenant binding confirmation
- Tenant binding is performed by `bind_tenant_id`.
- DB session tenant context for Postgres is set via `_apply_tenant_context` calling `set_tenant_context(session, tenant_id)`.
- `tenant_db_required` centralizes tenant binding + request state + DB session exposure.

### RLS confirmation
- RLS enabled and forced on `decisions`, `decision_evidence_artifacts`, `api_keys`, and `security_audit_log`.
- Policies use `current_setting('app.tenant_id', true)` and strict tenant equality.

### WebSocket confirmation
- No websocket endpoints found in `api/**`, `admin_gateway/**`, or `contracts/core/openapi.json`.

### Gaps between contract and implementation (observed)
1. **Governance endpoints are not tenant-bound** in handler dependencies (`get_db` instead of `tenant_db_required`) and do not explicitly set tenant context. If governance tables become tenantized, this is a security gap.
2. **Mission/Ring/ROE endpoints currently do not declare per-route `require_scopes` dependencies in their routers**. Confirm whether `AuthGateMiddleware` classifies these as protected paths in deployment configuration.
3. **`AuthGateMiddleware` is non-enforcing by design** (header stamping only). Endpoint-level dependencies are the real gate; if a route forgets dependencies, middleware will not block it.
4. **Potential classification mismatch for `/forensics/audit_trail`**: public-path string in `main.py` uses `/forensics/audit-trail` (hyphen) while route is `/forensics/audit_trail` (underscore). Scope dependencies still enforce access, but normalize to avoid relying on route-level correctness.

---

## B) Dashboard Architecture

Design is strictly based on currently implemented contract routes.

### 1) Overview domain
- **Endpoints**:
  - `GET /stats/summary` (risk/trend/headline)
  - `GET /health/ready` + `GET /health/live` (service health)
  - `GET /forensics/chain/verify` (verification status)
  - `GET /feed/live?limit=1` (latest event context)
- **Expected JSON schema**:
  - from OpenAPI component schemas for `StatsSummaryResponse`, health payloads, forensics verify payload.
- **Scopes**: `stats:read`, `forensics:verify`, `feed:read`.
- **Tenant behavior**: tenant required for stats/forensics/feed.
- **Indexes needed**:
  - `decisions(tenant_id, created_at desc)`
  - `decisions(tenant_id, threat_level, created_at desc)`
  - `decisions(tenant_id, event_type, created_at desc)`
- **Tests required**:
  - 401/403 scope tests per widget endpoint.
  - tenant mismatch and unknown-tenant rejection.
  - empty-state behavior for new tenant.

### 2) Tenants domain
- **Existing contract support**: partial.
  - Active tenant indicator from current auth token + request context.
  - Isolation confirmation can be inferred from successful tenant-scoped queries and `/rings/isolation` (not same thing as data isolation).
- **Tenant list (admin-only)**: **unknown in core OpenAPI**; likely served by `admin_gateway` instead of core.
- **Scopes**:
  - core: none for tenant list (missing in core contract).
  - admin gateway endpoints likely require admin scopes/session auth.
- **Backend action**:
  - For core-only dashboard, use session tenant indicator only.
  - If tenant list is required, integrate admin_gateway APIs (outside core contract).

### 3) Decisions domain
- **Endpoints**:
  - `GET /decisions` with `limit`, `offset`, `event_type`, `threat_level`.
  - `GET /decisions/{decision_id}` for detail.
- **Schema**: `DecisionsPage`, `DecisionOut` from route response models.
- **Scopes**: `decisions:read`.
- **Tenant behavior**: required; enforced by `tenant_db_required` + handler checks.
- **Indexes needed**:
  - `decisions(tenant_id, created_at desc, id desc)`
  - `decisions(tenant_id, event_type, created_at desc)`
  - `decisions(tenant_id, threat_level, created_at desc)`
- **Tests required**:
  - pagination contract tests (offset/limit).
  - server-side filtering assertions.
  - cross-tenant access denied.

### 4) Evidence / Forensics domain
- **Endpoints**:
  - `GET /forensics/snapshot/{event_id}`
  - `GET /forensics/audit_trail/{event_id}`
  - `GET /forensics/chain/verify`
- **Artifact list / download endpoint**:
  - **unknown in core OpenAPI** for generic artifact listing/download.
  - There are UI-specific packet endpoints in `api/ui_dashboards.py`, but not part of core contract route set.
- **Scopes**: `forensics:read`, `forensics:verify`.
- **Tenant behavior**: required and bound.
- **Indexes needed**:
  - `decisions(tenant_id, event_id, id desc)`
  - `decision_evidence_artifacts(tenant_id, event_id, created_at desc)`
- **Tests required**:
  - not-found behavior for cross-tenant probes.
  - tamper detection for chain verification.

### 5) Keys domain
- **Endpoints**:
  - `GET /keys`
  - `POST /keys`
  - `POST /keys/revoke`
  - `POST /keys/rotate`
  - `DELETE /keys/{prefix}`
- **Schema**: `ListKeysResponse`, `CreateKeyResponse`, `RotateKeyResponse`, etc.
- **Scopes**: `keys:admin` (current contract implementation).
- **Tenant behavior**: bound via `bind_tenant_id`.
- **Indexes needed**:
  - `api_keys(prefix)` unique/lookup
  - `api_keys(tenant_id, enabled, last_used_at desc)`
  - `api_keys(key_lookup)`
- **Tests required**:
  - scope enforcement + tenant-scoped key operations.
  - rotation/revoke lifecycle and audit emissions.

### 6) Drift / Alignment domain
- **Current contract support**: no direct drift endpoint in core OpenAPI routes.
- **Available sources**:
  - CI/tooling outputs: `tools/align_score.py`, `tools/drift_check.py`, ledger docs.
- **Design recommendation**:
  - Read-only dashboard panel backed by precomputed artifacts published by CI.
  - If API endpoint is required, add new contract-driven read endpoint under strict scopes.

---

## C) Required Backend Changes (minimum set for requested dashboard)

Only list changes strictly necessary to satisfy requested MVP domains without inventing parallel logic.

1. **Tenant list endpoint (admin-only)**
   - Status: **unknown in core contract**.
   - Option A (preferred): consume from `admin_gateway` existing admin APIs.
   - Option B (core extension): add `GET /tenants` with `admin:read`, tenant-neutral admin context, and explicit no-cross-tenant leakage tests.

2. **Artifact list + download in core contract**
   - Status: missing from core OpenAPI route set.
   - Add endpoints (if dashboard must be core-only):
     - `GET /forensics/artifacts` (tenant-scoped list)
     - `GET /forensics/artifacts/{artifact_id}/download` (tenant-scoped fetch)
   - Must include: `forensics:read`, tenant binding via `tenant_db_required`, RLS-safe queries, and integration tests.

3. **Governance tenant model decision**
   - Current state: governance routes are global and non-tenant-bound.
   - Target state: governance will be tenant-scoped (Option B); current implementation must be updated to align.
   - Implementation direction: refactor governance routes to `tenant_db_required`, add `tenant_id` column where needed, enforce RLS policy, and add tenant-isolation tests.

4. **Optional aggregate endpoint for Overview**
   - Can be deferred by composing existing endpoints client-side.
   - If added, must be contract-defined and read-only with strict scopes.

---

## D) UI Structure (no code, architecture only)

### Proposed folder structure
- `console/app/dashboard/layout.tsx`
- `console/app/dashboard/page.tsx` (Overview)
- `console/app/dashboard/decisions/page.tsx`
- `console/app/dashboard/forensics/page.tsx`
- `console/app/dashboard/keys/page.tsx`
- `console/app/dashboard/alignment/page.tsx`
- `console/lib/coreApi.ts` (contract-bound client wrappers)
- `console/lib/errors.ts` (401/403/tenant mismatch mapping)
- `console/components/status/AlignmentCard.tsx`
- `console/components/tables/DecisionsTable.tsx`
- `console/components/common/TenantBadge.tsx`

### Route map
- `/dashboard` → Overview
- `/dashboard/tenants` → tenant/session/isolation view
- `/dashboard/decisions` → filterable paged decision list
- `/dashboard/forensics` → snapshots/audit/chain verify/artifacts
- `/dashboard/keys` → key lifecycle
- `/dashboard/alignment` → drift/alignment status

### Component tree (example)
- `DashboardShell`
  - `TopNav`
    - `TenantBadge`
    - `ScopeBadge`
  - `OverviewPage`
    - `AlignmentCard`
    - `GateStatusCard`
    - `DriftStatusCard`
    - `SystemHealthCard`
    - `RecentDecisionsCard`
    - `EvidenceHashCard`
  - `DecisionsPage`
    - `DecisionFilters`
    - `DecisionsTable` (server-side pagination)
    - `DecisionDetailDrawer`
  - `ForensicsPage`
    - `ForensicsSearch`
    - `SnapshotPanel`
    - `AuditTrailPanel`
    - `ChainVerifyPanel`
    - `ArtifactsTable` (if endpoint exists)

### API client abstraction rules
- Every method maps 1:1 to an OpenAPI route.
- Tenant context only via headers/query explicitly required by contract.
- Unified error mapping:
  - 401 → `AUTH_REQUIRED`
  - 403 → `SCOPE_OR_TENANT_DENIED`
  - 400 + `Tenant mismatch`/`tenant_id required` → `TENANT_CONTEXT_ERROR`
- No direct DB logic; no synthetic endpoints.

### Example decisions table behavior
- Query params: `limit`, `offset`, `event_type`, `threat_level`, `tenant_id` (if required by caller flow).
- Server-side pagination only.
- Columns: `event_id`, `tenant_id`, `action` (derived from decision diff if available), `severity`, `timestamp`.

### Example alignment status card behavior
- Source hierarchy:
  1) contract-backed endpoint if available.
  2) CI artifact JSON served via static/object storage endpoint.
- Show:
  - gate pass/fail
  - missing blueprint IDs count
  - drift status
  - last evaluation timestamp/hash

---

## E) Test Plan

### Contract and auth tests
- Route-level scope tests for every dashboard-consumed route.
- 401/403 matrix for missing key, bad key, insufficient scope.

### Tenant isolation tests
- Per route, assert:
  - scoped tenant sees only own data.
  - cross-tenant ids return 403/404 according to contract.
  - unscoped key without explicit tenant is rejected where required.

### RLS tests (Postgres)
- Ensure `set_tenant_context` is applied by dependencies.
- Attempt cross-tenant SQL access and assert blocked by policy.
- Validate migrations keep `FORCE ROW LEVEL SECURITY`.

### Dashboard integration tests
- Decisions pagination/filter integration test.
- Forensics verification workflow test.
- Key rotation indicator data test.
- Tenant switching smoke test (no 500s, no stale tenant leaks).

### Gates
- Required backend validation gates (if backend changes are introduced):
  - `make fg-fast`
  - `make db-postgres-verify`

---

## F) Step-by-step execution checklist (ordered by dependency)

1. Freeze contract baseline (`contracts/core/openapi.json`) and enumerate consumed routes.
2. Confirm auth + tenant binding for consumed routes; document unsupported requirements as `unknown`.
3. Decide tenancy model for Governance (global vs tenantized) and codify in contract/docs.
4. Decide tenant-list source (admin_gateway vs new core endpoint).
5. Decide artifact list/download source (existing UI API vs new core contract endpoint).
6. If new endpoints are required, update OpenAPI first, then implement + scopes + tenant binding + tests.
7. Run backend gates: `make fg-fast` and `make db-postgres-verify`.
8. Implement UI API client wrappers strictly from contract routes.
9. Implement Overview and Decisions first (highest confidence existing APIs).
10. Implement Forensics and Keys pages using existing scoped routes.
11. Add tenant-switching, 401/403, and empty-state handling with error boundaries.
12. Add alignment/drift panel from contract route or CI artifact source.
13. Run full test suite and smoke checks; ensure no console errors and no 500s on tenant switch.
14. Produce release notes linking routes, scopes, and tenant isolation evidence.


## How to verify this document

```bash
# verify route list
python -c "import json; print([p for p in json.load(open('contracts/core/openapi.json'))['paths'].keys()])"

# verify fastapi decorators
rg "router\.(get|post|delete|head)\(" -n api

# verify tenant binding usage
rg "tenant_db_required|bind_tenant_id|request\.state\.tenant_id" -n api

# verify governance tenant gap
rg "api/governance.py" -n api && rg "tenant_db_required" -n api/governance.py
```
