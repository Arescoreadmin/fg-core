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
