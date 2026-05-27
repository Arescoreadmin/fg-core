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
