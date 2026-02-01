# FrostGate Core — 7-Day Hardening Plan

**Date**: 2026-01-31
**Goal**: 90% Production-Ready in 7 Days
**Approach**: Harden, Unify, Test, Make Operations Boring

---

## SECTION 1: CORE INVENTORY TABLE

| Component | Files | Entrypoints | Invariants | Maturity (0-5) | Risks | Test Coverage |
|-----------|-------|-------------|------------|----------------|-------|---------------|
| **Auth/AuthZ** | `api/auth_scopes.py`, `api/auth.py`, `api/middleware/auth_gate.py` | `verify_api_key_detailed()`, `bind_tenant_id()`, `require_scopes()` | Single source of truth, constant-time compare, fail-closed | 4 | Global key bypass in non-prod, staging treated as prod-ish | `test_auth.py`, `test_auth_contract.py`, `test_auth_gate_regression.py` (GOOD) |
| **Tenant Isolation** | `api/auth_scopes.py:bind_tenant_id()`, `api/decisions.py`, `api/ingest.py` | `bind_tenant_id()` enforced at each endpoint | No cross-tenant reads/writes | 4 | `unknown` tenant bucket exists, unscoped keys have fallback | `test_auth_tenants.py`, `test_admin_audit_tenant_binding.py` (GOOD) |
| **Decision Pipeline** | `api/defend.py`, `api/ingest.py`, `engine/evaluate.py`, `engine/roe.py` | `/defend POST`, `/ingest POST` | Deterministic, observable, doctrine-gated | 3 | **DUAL PATHS**: `defend.evaluate()` vs `engine.evaluate()` | `test_defend_endpoint.py`, `test_roe_gating_contract.py` (PARTIAL) |
| **Governance** | `api/governance.py` | `/governance/changes`, `/governance/changes/{id}/approve` | Persistent, authenticated, auditable | 3 | Approvals not validated against key scope, no rollback | `test_governance_approval_flow.py` (PARTIAL) |
| **Persistence** | `api/db.py`, `api/db_models.py` | `init_db()`, `get_db()` | Schema migrations, integrity constraints | 4 | SQLite in prod warning only, no DB-level RLS | `test_db_path_contract.py`, `test_db_fallback.py` (GOOD) |
| **Rate Limiting** | `api/ratelimit.py` | `rate_limit_guard()` | Token bucket, fail-closed default | 4 | Memory backend in prod, bypass keys not audited | `test_security_hardening.py` (PARTIAL) |
| **Config Validation** | `api/config/startup_validation.py` | `validate_startup_config()` | Fail-fast on unsafe config | 3 | `fail_on_error=False` by default, warnings don't crash | `test_main_integrity.py` (PARTIAL) |
| **Observability** | `api/health.py`, logging throughout | `/health`, `/health/ready`, `/health/detailed` | Probes reflect real dependencies | 3 | `/health/ready` doesn't check Redis/NATS | Smoke tests only |
| **Eventing/NATS** | `api/ingest_bus.py` | `IngestBus.publish()` | Tenant in subject hierarchy | 2 | Not mandatory path, can be skipped | `test_ingest_bus.py` (BASIC) |
| **Admin Gateway** | `admin_gateway/` | OIDC flow, session management | CSRF, HttpOnly cookies, tenant validation | 4 | Dev bypass exists, must be blocked in prod | `ci-admin` lane (GOOD) |

---

## SECTION 2: CORE INVARIANT SPEC

Each invariant MUST be:
- Enforced in code
- Tested in CI
- Observable in production (logs/metrics)

### INV-001: No Unauthenticated Access to Protected Routes
- **Enforcement**: `api/middleware/auth_gate.py:dispatch()`, `api/auth_scopes.py:verify_api_key_detailed()`
- **Bypass Today**: `FG_AUTH_ENABLED=0` disables ALL auth
- **Test**: `tests/test_auth_gate_regression.py::test_protected_routes_require_auth`
- **Metric/Log**: `frostgate.security` logger with `auth_event` type, success=false

### INV-002: No Cross-Tenant Reads/Writes
- **Enforcement**: `api/auth_scopes.py:bind_tenant_id()` at every endpoint
- **Bypass Today**: Unscoped keys can specify any tenant via header; `unknown` bucket accepted
- **Test**: `tests/test_auth_tenants.py::test_cross_tenant_blocked`
- **Metric/Log**: `frostgate.security` logger with `tenant_mismatch` reason

### INV-003: Fail-Closed on Auth/Tenant Check Failures
- **Enforcement**: `_check_db_expiration()` returns True (deny) on error; `rate_limit_guard()` raises 503
- **Bypass Today**: `FG_AUTH_DB_FAIL_OPEN=true`, `FG_RL_FAIL_OPEN=true` env vars
- **Test**: `tests/test_security_hardening.py::test_fail_closed_*`
- **Metric/Log**: `SECURITY:` prefix in logs when fail-open triggered

### INV-004: Single Decision Enforcement Path
- **Enforcement**: CURRENTLY VIOLATED - `defend.py:evaluate()` and `engine/evaluate.py:evaluate()` are separate
- **Bypass Today**: Two code paths exist with different rule logic
- **Test**: MISSING - need `test_decision_pipeline_unified.py`
- **Metric/Log**: Need `decision_path` label on metrics

### INV-005: Governance Changes Are Authenticated, Persisted, Auditable
- **Enforcement**: `api/governance.py` router has `Depends(verify_api_key)`
- **Bypass Today**: No scope check (any key can create/approve), approvals not validated against required roles
- **Test**: `tests/test_governance_approval_flow.py` (partial)
- **Metric/Log**: `governance.create_change`, `governance.approve_change` logs exist

### INV-006: Config Validated at Startup; Unsafe Configs Crash Fast
- **Enforcement**: `api/config/startup_validation.py:validate_startup_config()`
- **Bypass Today**: `fail_on_error=False` by default, so production can start with warnings
- **Test**: MISSING - need `test_startup_fail_fast.py`
- **Metric/Log**: `_security_log.error()` on validation failure

### INV-007: Health/Readiness Probes Reflect Real Dependencies
- **Enforcement**: `/health/ready` checks DB only
- **Bypass Today**: Redis, NATS, policy engine not checked
- **Test**: MISSING - need `test_health_probes_comprehensive.py`
- **Metric/Log**: `health_check` endpoint returns dependency status

---

## SECTION 3: TOP 20 WEAKNESSES (RANKED)

### P0: Critical / Security

| # | Issue | Impact | Exploit Scenario | Root Cause | Fix | Cost | Verification |
|---|-------|--------|------------------|------------|-----|------|--------------|
| 1 | **DUAL DECISION PATHS** | Security, Correctness | Different threat levels from `/defend` vs `/ingest` for same event | `defend.py` has inline `evaluate()`, `ingest.py` imports `engine.evaluate()` | Consolidate to single `engine/evaluate.py` module | M | Test: same input produces same output via both endpoints |
| 2 | **Unknown Tenant Bucket** | Security | Data written to `tenant_id=unknown` is orphaned, queryable | `bind_tenant_id()` returns `"unknown"` when unscoped key has no tenant | Reject `unknown` at write paths, require explicit tenant | S | Test: `unknown` tenant rejected with 400 |
| 3 | **Governance No Scope Check** | Security | Any valid API key can approve policy changes | Router uses `verify_api_key` not `require_scopes` | Add `require_scopes("governance:write")` | S | Test: key without scope gets 403 |
| 4 | **Fail-Open Env Vars Exist** | Security | Operator sets `FG_RL_FAIL_OPEN=true`, Redis down = no rate limit | Feature flag for fail-open exists | Log CRITICAL + require explicit acknowledgment, add metric | S | Test: fail-open emits specific log/metric |
| 5 | **Global Key Bypass in Non-Prod** | Security | `FG_API_KEY` env var bypasses all scope checks | Legacy compatibility | Remove in staging, only allow in `dev`/`test` | S | Test: staging rejects FG_API_KEY |
| 6 | **Dev Bypass in Admin Gateway** | Security | `FG_DEV_AUTH_BYPASS=true` creates full admin session | Dev convenience | Hard-block if FG_ENV contains `stag`/`prod` | S | Test: staging throws on bypass attempt |

### P1: Correctness / Data Integrity

| # | Issue | Impact | Exploit Scenario | Root Cause | Fix | Cost | Verification |
|---|-------|--------|------------------|------------|-----|------|--------------|
| 7 | **Startup Validation Doesn't Crash** | Operability | Production starts with insecure config | `fail_on_error=False` default | Change default to `True` for `is_production` | S | Test: prod env with bad config fails startup |
| 8 | **Readiness Probe Incomplete** | Operability | Pod marked ready but Redis/NATS down | Only DB checked | Add Redis + NATS connectivity checks | M | Test: `/health/ready` returns unhealthy when Redis down |
| 9 | **No Governance Rollback** | Correctness | Deployed bad policy can't be undone | `deployed_at` set but no revert | Add `rollback` status and endpoint | M | Test: POST `/governance/changes/{id}/rollback` |
| 10 | **Decision Diff Not Required** | Correctness | Decision changes undetected | `decision_diff_json` nullable, silently fails | Make mandatory for high-severity decisions | S | Test: high threat requires diff |

### P2: Operability / Scale

| # | Issue | Impact | Exploit Scenario | Root Cause | Fix | Cost | Verification |
|---|-------|--------|------------------|------------|-----|------|--------------|
| 11 | **Memory Rate Limiter in Prod** | Scale | Distributed deployment = no rate limiting | `FG_RL_BACKEND=memory` allowed | Warn/block memory backend in prod | S | CI: prod-profile-check fails on memory backend |
| 12 | **No Request ID in All Logs** | Operability | Can't trace requests across services | Inconsistent `request_id` propagation | Add middleware to inject/propagate | M | Test: all log entries have request_id |
| 13 | **Tenant ID Missing from Some Logs** | Operability | Can't filter logs by tenant | Some code paths don't log tenant | Audit all log calls, add tenant | M | Grep: no log call without tenant context |
| 14 | **No Metrics for Key Auth Events** | Operability | Can't dashboard auth failures | Only logs exist | Add Prometheus counters | M | Test: metrics endpoint has auth_* counters |
| 15 | **SQLite in Production Warning Only** | Operability | Operator uses SQLite in prod unknowingly | Warning doesn't crash | Error in production, block startup | S | Test: prod + SQLite fails startup |

### P3: Code Quality / Maintainability

| # | Issue | Impact | Exploit Scenario | Root Cause | Fix | Cost | Verification |
|---|-------|--------|------------------|------------|-----|------|--------------|
| 16 | **Duplicate TieD Computation** | Maintainability | Doctrine logic in `defend.py:_apply_doctrine()` and `engine/roe.py` | Copy-paste evolution | Single source in `engine/` | M | Test: remove defend.py doctrine code |
| 17 | **Inconsistent JSON Column Handling** | Maintainability | Some use JSON column, some TEXT | Schema evolution | Standardize on JSON type | S | Migration script |
| 18 | **No Index on decisions.tenant_id** | Scale | Slow tenant-scoped queries | Index missing | Add index in migration | S | Migration + verify EXPLAIN |
| 19 | **Auth Module Has Too Many Helpers** | Maintainability | 1000+ line file | Organic growth | Split into auth/core.py, auth/keys.py, auth/tenant.py | M | Refactor, no behavior change |
| 20 | **Test Fixtures Use Default Secrets** | Security | Leaked fixture could be valid key | Test convenience | Generate random keys per test run | S | CI: assert no hardcoded keys |

---

## SECTION 4: 7-DAY HARDENING PLAN

### DAY 1: UNIFY DECISION PIPELINE (No Split Brains)

**Goal**: Single enforcement path for all decisions

**Tasks**:
1. Consolidate `defend.py:evaluate()` → use `engine/evaluate.py`
2. Move `defend.py:_apply_doctrine()` → `engine/doctrine.py`
3. Ensure `/defend` and `/ingest` produce identical results for same input
4. Add test proving no bypass path remains

**Files Modified**:
- `engine/evaluate.py` (enhance to be single source)
- `engine/doctrine.py` (new file, extracted from defend.py)
- `api/defend.py` (remove inline evaluate, import from engine)
- `tests/test_decision_pipeline_unified.py` (new)

**Acceptance**:
- [ ] `pytest tests/test_decision_pipeline_unified.py` passes
- [ ] Same payload to `/defend` and `/ingest` → same `threat_level`
- [ ] `grep -r "def evaluate" api/` returns 0 results (only in engine/)

---

### DAY 2: TENANT INVARIANT ENFORCEMENT (Make It Hard to Screw Up)

**Goal**: Unscoped queries are impossible or loudly fail

**Tasks**:
1. Reject `unknown` tenant at write paths (ingest, defend, governance)
2. Add `require_explicit_tenant=True` default for write operations
3. Add `tenant_required` decorator/helper for endpoints
4. Add regression tests for ID enumeration and mismatch
5. Add DB-level CHECK constraint (SQLite/Postgres compatible)

**Files Modified**:
- `api/auth_scopes.py` (stricter bind_tenant_id defaults)
- `api/ingest.py`, `api/defend.py` (reject unknown)
- `tests/test_tenant_invariant.py` (new)
- `api/db_models.py` (add CHECK constraint)

**Acceptance**:
- [ ] `POST /ingest` with `tenant_id=unknown` → 400
- [ ] `POST /defend` without tenant header (unscoped key) → 400
- [ ] `GET /decisions?tenant_id=other` with scoped key → 403
- [ ] DB rejects INSERT with tenant_id='unknown' or NULL

---

### DAY 3: AUTH/AUTHZ HARDENING + CONFIG FAIL-FAST

**Goal**: No bypass flags, no ambiguous env behavior

**Tasks**:
1. Block `FG_API_KEY` global bypass in staging/prod
2. Block dev bypass if FG_ENV contains `stag` or `prod`
3. Add `require_scopes("governance:write")` to governance router
4. Change startup validation `fail_on_error=True` for production
5. SQLite in production = startup failure (not warning)

**Files Modified**:
- `api/auth_scopes.py` (block global key in staging)
- `admin_gateway/auth/dev_bypass.py` (stricter prod check)
- `api/governance.py` (add scope requirement)
- `api/config/startup_validation.py` (fail_on_error default)
- `api/main.py` (call validation with fail_on_error=is_production)
- `tests/test_auth_hardening.py` (new)

**Acceptance**:
- [ ] FG_ENV=staging + FG_API_KEY auth → 401
- [ ] FG_ENV=staging + FG_DEV_AUTH_BYPASS → crash on startup
- [ ] Governance without `governance:write` scope → 403
- [ ] FG_ENV=prod + insecure config → startup crash

---

### DAY 4: GOVERNANCE CHANGE CONTROL END-TO-END

**Goal**: Governance is real, not a formality

**Tasks**:
1. Validate approver against `requires_approval_from` roles
2. Add rollback mechanism (status=rolled_back, original config restored)
3. Add audit log for all governance operations
4. Add approval scope validation (approver must have governance:approve)

**Files Modified**:
- `api/governance.py` (approval validation, rollback endpoint)
- `api/db_models.py` (add rolled_back status, rollback_reason)
- `tests/test_governance_complete.py` (new)

**Acceptance**:
- [ ] Approval by unauthorized user → 403
- [ ] `POST /governance/changes/{id}/rollback` works
- [ ] All governance operations create SecurityAuditLog entries
- [ ] Double-approval prevented

---

### DAY 5: FAIL-OPEN ELIMINATION + ABUSE CONTROLS

**Goal**: Default deny on failures; controlled overrides only

**Tasks**:
1. Add CRITICAL log + metric when fail-open triggered
2. Require explicit `FG_RL_FAIL_OPEN_ACKNOWLEDGED=true` for fail-open
3. Add chaos tests (simulate DB down, Redis down)
4. Rate limiter bypass keys must be audited

**Files Modified**:
- `api/ratelimit.py` (acknowledged flag, metrics)
- `api/auth_scopes.py` (fail-open acknowledgment)
- `tests/test_chaos_resilience.py` (new)
- `tests/test_fail_open_audit.py` (new)

**Acceptance**:
- [ ] Redis down + FG_RL_FAIL_OPEN=true without acknowledgment → 503
- [ ] Fail-open triggered → `fail_open_triggered_total` metric incremented
- [ ] Bypass key used → security audit log entry created
- [ ] DB down → auth fails closed (401)

---

### DAY 6: OBSERVABILITY + OPERABILITY (3AM Ready)

**Goal**: Debug incidents fast

**Tasks**:
1. Add request_id to all log entries via middleware
2. Add tenant_id to all security-relevant logs
3. Add Redis + NATS to `/health/ready` probe
4. Add Prometheus metrics for auth events, rate limits, tenant mismatches
5. Document "core health" runbook

**Files Modified**:
- `api/middleware/request_id.py` (new)
- `api/health.py` (add Redis/NATS checks)
- `api/auth_scopes.py` (add metrics)
- `api/ratelimit.py` (add metrics)
- `docs/RUNBOOK_CORE_HEALTH.md` (new)

**Acceptance**:
- [ ] Every log line has `request_id` field
- [ ] `/health/ready` returns unhealthy when Redis down
- [ ] `/metrics` has `auth_success_total`, `auth_failure_total`, `rate_limit_total`
- [ ] Runbook covers: auth failures, rate limit bypass, tenant mismatch

---

### DAY 7: BATTLE TEST WEEKEND (Break It On Purpose)

**Goal**: Prove resilience

**Tasks**:
1. Create stress test harness
2. Run chaos scenarios:
   - 10× normal request rate
   - Random tenant IDs
   - Random invalid keys
   - DB down simulation
   - Redis down simulation
3. Document findings and remaining risks

**Files Modified**:
- `tests/stress/run_stress.py` (new)
- `tests/stress/chaos_scenarios.py` (new)
- `docs/STRESS_TEST_REPORT.md` (new)

**Acceptance**:
- [ ] System handles 10× load without crash
- [ ] All chaos scenarios produce correct error responses
- [ ] No data corruption
- [ ] Remaining risks documented and prioritized

---

## SECTION 5: CLAIMS VERIFICATION

Claims from docs/README, CONTRACT.md vs Code Reality:

| Claim | Source | Verified | Evidence |
|-------|--------|----------|----------|
| "Deterministic: same input → same output" | CONTRACT.md | PARTIAL | `/defend` and `/ingest` use different evaluate() |
| "Safe-by-default: disruptive actions gated" | CONTRACT.md | YES | doctrine.py caps block_ip mitigations |
| "API key via X-API-Key header only" | CONTRACT.md | YES | Query params explicitly rejected in code |
| "401 for missing/invalid key" | CONTRACT.md | YES | auth_gate.py returns 401 |
| "Rate limit on /defend" | CONTRACT.md | YES | rate_limit_guard dependency |
| "Fail-soft: non-critical may degrade" | CONTRACT.md | YES | decision_diff is best-effort |
| "DecisionRecord persistence" | CONTRACT.md | YES | defend.py calls _persist_decision_best_effort |
| "tenant_id required for /decisions" | CONTRACT.md | YES | bind_tenant_id with require_explicit=True |

**UNKNOWN = RISK**:
- Merkle chain tamper detection: Code exists but no automated verification test
- NATS message ordering: No guarantee documented or tested
- Session expiration enforcement: Claimed 8h TTL but not tested

---

## SECTION 6: CI GATES (Must Run on Every PR)

```yaml
# .github/workflows/ci.yml additions

- name: Startup Fail-Fast Test
  run: make test-startup-fail-fast

- name: Tenant Isolation Test
  run: make test-tenant-isolation

- name: Decision Pipeline Unity Test
  run: make test-decision-unified

- name: Auth Hardening Test
  run: make test-auth-hardening

- name: Governance Complete Test
  run: make test-governance-complete

- name: Chaos Resilience Test
  run: make test-chaos
```

---

## SECTION 7: DEFINITION OF DONE (90% Complete)

- [ ] **INV-001**: All protected routes require auth (0 exceptions)
- [ ] **INV-002**: Cross-tenant queries return 403 (tested)
- [ ] **INV-003**: All fail-open triggers emit CRITICAL log + metric
- [ ] **INV-004**: Single evaluate() path for all decisions
- [ ] **INV-005**: Governance requires scope, has rollback
- [ ] **INV-006**: Production startup fails on unsafe config
- [ ] **INV-007**: Readiness probe checks DB + Redis + NATS
- [ ] All P0 issues fixed
- [ ] All P1 issues fixed or have documented waivers
- [ ] 80%+ test coverage on core modules
- [ ] Stress test passes at 10× load
- [ ] Runbook exists for top 5 incident types
- [ ] No Production-blocking gaps in GAP_MATRIX.md

---

## APPENDIX: PATCH PROPOSALS

### Patch 1: Unified Decision Pipeline (Day 1)

```python
# engine/evaluate.py - SINGLE SOURCE OF TRUTH
def evaluate(event: dict) -> dict:
    """
    SINGLE evaluation path for all decision endpoints.

    Args:
        event: Dict with tenant_id, source, event_type, payload

    Returns:
        Dict with threat_level, rules_triggered, mitigations, score, etc.
    """
    # ... implementation
```

### Patch 2: Reject Unknown Tenant (Day 2)

```python
# api/auth_scopes.py
def bind_tenant_id(..., reject_unknown: bool = True) -> str:
    ...
    if reject_unknown and tenant_id == "unknown":
        raise HTTPException(400, "tenant_id 'unknown' not allowed for write operations")
```

### Patch 3: Governance Scope Requirement (Day 3)

```python
# api/governance.py
router = APIRouter(
    prefix="/governance",
    dependencies=[
        Depends(verify_api_key),
        Depends(require_scopes("governance:write")),  # NEW
    ],
)
```

See detailed patches in subsequent commits.

---

*Document generated: 2026-01-31*
*Author: Hardening Audit Bot*
