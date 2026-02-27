# Security Audit — fg-core — 2026-02-27

Auditor role: Hostile Staff Security Engineer + Systems Architect
Branch audited: `claude/setup-security-docs-b1VLZ` (HEAD as of 2026-02-27)
Scope: Full repository

---

### 0) Audit Verdict

**FAIL**

Cross-tenant data leak via unauthenticated compliance routes (G-001).
Cross-tenant read via fail-open RLS policy (G-002).
Rate-limit bypass via untrusted proxy headers (G-003).
RLS missing entirely on AI governance tables (G-005).
These constitute active exploitable paths. Merge to main is blocked.

---

### 1) Critical Findings (BLOCKERS)

---

#### C-001 — `/missions`, `/rings`, `/roe` routes are fully unauthenticated

**Impact:** Any unauthenticated internet caller can read mission envelopes
(classification level, allowed mitigations, budget caps, blast-radius caps),
ring isolation policies (encryption requirements, retention policy, cross-ring
query controls), and invoke ROE evaluation with arbitrary inputs.

**Exploit path:**
```
curl http://prod/missions
curl http://prod/rings/route -d '{"classification":"TOPSECRET"}'
curl http://prod/roe/evaluate -d '{"persona":"admin","mitigations":[]}'
```
No API key required. Returns 200 with full policy data.

**Exact files/functions:**
- `api/security/public_paths.py` lines 32–38: `/missions`, `/rings`, `/roe`
  listed in `PUBLIC_PATHS_PREFIX`
- `api/mission_envelope.py` lines ~94–120: `list_missions`, `get_mission`,
  `mission_status` — zero auth dependencies
- `api/ring_router.py`: all routes — zero auth dependencies
- `api/roe_engine.py` lines ~32–65: `get_policy`, `evaluate_roe` — zero auth
  dependencies

**Why existing gates did not catch this:** Auth gate middleware sets
`_is_public()` based on `PUBLIC_PATHS_PREFIX`. No CI test asserts that every
route has a `require_scopes` dependency. No route-inventory gate exists.

**Minimal fix:**
1. Add `Depends(require_scopes("missions:read"))` to all three handlers in
   `mission_envelope.py`; likewise `rings:read` and `roe:read` in ring/roe files.
2. Remove `/missions`, `/rings`, `/roe` from `PUBLIC_PATHS_PREFIX` in
   `api/security/public_paths.py`.

**Required test/gate:** New CI gate: introspect FastAPI route table; assert
every route has at least one auth dependency unless it is in an explicit allow-
list signed off by security. Add to `tests/test_route_auth_coverage.py`.

---

#### C-002 — `control_plane_event_ledger` RLS policy fails OPEN when tenant context is unset

**Impact:** Any DB session that queries `control_plane_event_ledger` without
first calling `set_tenant_context()` (e.g., admin endpoints, background jobs,
staging test sessions) sees ALL rows from ALL tenants.

**Exploit path:**
1. Call any admin endpoint that queries the event ledger directly (or via ORM)
   without setting `app.tenant_id`.
2. `current_setting('app.tenant_id', true)` returns NULL.
3. RLS clause `current_setting(...) IS NULL` = TRUE → entire table visible.

Compounded by G-008: `_apply_tenant_context` silently swallows binding
exceptions in non-production, guaranteeing this state is reachable in staging.

**Exact file/function:**
`migrations/postgres/0027_control_plane_v2.sql` lines 80–85:
```sql
USING (
    tenant_id IS NULL
    OR current_setting('app.tenant_id', true) IS NULL   -- ← fail-open
    OR current_setting('app.tenant_id', true) = ''
    OR tenant_id = current_setting('app.tenant_id', true)
);
```

**Why existing gates did not catch this:** No test exercises the ledger query
without tenant context set. No CI job validates RLS policy semantics by
injecting a context-less session and asserting row count = 0.

**Minimal fix:**
New migration (0029):
```sql
ALTER POLICY cp_event_ledger_tenant_isolation ON control_plane_event_ledger
    USING (
        tenant_id IS NOT NULL
        AND current_setting('app.tenant_id', true) IS NOT NULL
        AND tenant_id = current_setting('app.tenant_id', true)
    )
    WITH CHECK (
        tenant_id IS NOT NULL
        AND current_setting('app.tenant_id', true) IS NOT NULL
        AND tenant_id = current_setting('app.tenant_id', true)
    );
```
Also remove the exception-swallowing guard in `_apply_tenant_context`.

**Required test/gate:** Add to `tests/postgres/test_governance_rls_postgres.py`:
open a session with no tenant context, query ledger, assert empty result.

---

#### C-003 — Rate limiter always uses spoofable IP; tenant-scope is dead code

**Impact:** Rate limiting is completely bypassable. Any caller sends
`X-Forwarded-For: <unique-ip>` per request and gets a fresh token bucket each
time. Unlimited ingest throughput to `/defend`, `/ingest`, or any rate-limited
path.

**Exploit path:**
```
for i in $(seq 1 10000); do
  curl -H "X-Forwarded-For: 192.0.2.$((i % 254 + 1))" \
       -H "X-API-Key: valid-key" \
       http://prod/defend -d '...'
done
```
Each request gets a fresh bucket. The rate limiter is never consulted.

**Exact files/functions:**
- `api/ratelimit.py` `_key_from_request` lines 283–297: reads
  `request.state.telemetry_body` which is **never set** in any route; always
  falls back to IP.
- `api/ratelimit.py` `_extract_client_ip` lines 254–280: reads
  `X-Forwarded-For` unconditionally without proxy trust validation.

**Why existing gates did not catch this:** Rate-limit tests use a mock that
directly calls `allow()` with a fixed key; they do not exercise the key
derivation path under HTTP requests with spoofed headers.

**Minimal fix:**
```python
# _key_from_request: use auth result, not telemetry_body
auth = getattr(request.state, "auth", None)
tenant_id = getattr(auth, "tenant_id", None) if auth else None
if cfg.scope == "tenant" and tenant_id:
    return f"tenant:{tenant_id}"
```
For IP fallback, reuse `DoSGuardMiddleware`-style CIDR trust validation.

**Required test/gate:** Add integration test: two requests with same valid key
but different `X-Forwarded-For` values must share the same bucket when
`FG_RL_SCOPE=tenant`.

---

### 2) High-Risk Findings

---

#### H-001 — `ai_governance_reviews` and `tenant_ai_policy` have no RLS

**Impact:** Any DB query against these tables (authenticated or not, once inside
the DB session) can read or write across all tenants. AI governance decisions
(reviewer identity, approval/rejection, notes) and per-tenant AI policy
settings are globally readable.

**Exact file:** `migrations/postgres/0016_ai_plane_extension.sql` — tables
created; no subsequent migration adds `ENABLE ROW LEVEL SECURITY` or a policy.

**Why existing gates did not catch this:** No migration linter asserts that
every table with a `tenant_id` column has RLS enabled. No RLS test covers these
tables.

**Minimal fix:** New migration with standard tenant isolation pattern (see
GOTCHAS.md checklist). Must include `FORCE ROW LEVEL SECURITY`.

**Required test/gate:** Add cross-tenant RLS test to
`tests/postgres/test_governance_rls_postgres.py`.

---

#### H-002 — `FORCE ROW LEVEL SECURITY` absent from 12+ tenant-scoped tables

**Impact:** If the application DB user is the table owner (common in dev,
staging, and Fly.io/Heroku deployments), they bypass RLS completely. A
compromised application process can read all tenants' data.

**Exact files:** Migrations 0017 (ai_inference_records, ai_policy_violations),
0018 (evidence_runs, retention_policies), 0024 (agent_device_identities and 4
others), 0025 (connectors_idempotency), 0026 (connectors_tenant_state,
connectors_credentials, connectors_audit_ledger), 0027 (control_plane_commands,
control_plane_command_receipts, control_plane_heartbeats).

**Minimal fix:** Additive migration: `ALTER TABLE <t> FORCE ROW LEVEL SECURITY`
for each table. Wire into migration checklist (GOTCHAS.md).

---

#### H-003 — Timing oracle in `check_tenant_if_present`

**Impact:** API key brute-force for known tenant IDs via timing side-channel.
An attacker who knows a `X-Tenant-Id` value can test candidate API keys and
observe response timing differences to narrow the key space.

**Exact file/function:** `api/main.py` line 471:
```python
if expected is None or str(expected) != str(api_key):
```

**Minimal fix:** `hmac.compare_digest(str(expected), str(api_key))`

---

#### H-004 — `_apply_tenant_context` silently swallows exceptions outside production

**Impact:** Staging test sessions, admin endpoints, background jobs that fail
tenant context binding proceed without isolation. Combined with C-002 (fail-open
RLS), cross-tenant leaks in staging become reliable.

**Exact file/function:** `api/auth_scopes/resolution.py` ~line 755:
```python
except Exception:
    if _is_production_env():
        raise
```

**Minimal fix:** Remove the `_is_production_env()` guard. Always raise.

---

#### H-005 — Auth audit log IP is spoofable (proxy headers read without trust check)

**Impact:** Auth audit events (failed login attempts, key misuse) can be filed
with arbitrary source IPs. Forensic investigation of a breach is poisoned.

**Exact file/function:** `api/auth_scopes/resolution.py` lines 247–253 inside
`verify_api_key_detailed`; reads `x-forwarded-for` etc. unconditionally.

**Minimal fix:** Reuse `DoSGuardMiddleware._resolve_client_ip` logic
(CIDR-validated) for IP extraction in auth path.

---

#### H-006 — `auth_enabled()` defaults to False when no env vars set

**Impact:** A staging or dev container with missing env vars has zero
authentication. Any request is processed.

**Exact file/function:** `api/auth.py` line 43:
```python
return bool(os.getenv("FG_API_KEY"))
```

**Minimal fix:** Default to `True`; require `FG_AUTH_ENABLED=0` to disable.

---

#### H-007 — NATS URL unauthenticated by default (DR-021)

**Impact:** Ingest bus uses `nats://localhost:4222` with no credentials. In a
shared NATS cluster any process can publish/subscribe to FrostGate subjects.

**Minimal fix:** Require explicit NATS URL with auth credentials in
staging/prod; fail startup if absent.

---

#### H-008 — No GOTCHAS.md / PR_FIX_LOG.md existed — zero repo memory

**Impact:** Every security engineer who reviews this repo will rediscover the
same vulnerabilities. No CI gate enforces fixes remain in place.

**Minimal fix:** GOTCHAS.md and PR_FIX_LOG.md now created in this PR. Wire
`make gotchas-check` into CI (see G-009).

---

### 3) Architectural Drift

---

**Rate limiter scope configuration (SYSTEMIC):**
`FG_RL_SCOPE=tenant` configures tenant-scoped limiting but the key derivation
path never reads tenant state. Scope configuration has zero effect. This is
not an edge case — it is the default configured scope and it silently does
nothing. The drift between declared intent and actual behavior is total. Any
operator who tuned `FG_RL_SCOPE=tenant` to isolate tenants from each other has
a false sense of protection.

**Public paths list vs route-level auth (SPREADING):**
`PUBLIC_PATHS_EXACT` and `PUBLIC_PATHS_PREFIX` are the authoritative gate for
the auth middleware, but route handlers use `require_scopes` independently.
The two mechanisms have diverged: forensics paths are in the public list but
protected at route level; mission/ring/roe paths are in the public list AND
unprotected at route level. There is no single source of truth for "what is
public." This pattern will multiply with each new module.

**RLS FORCE omission (SPREADING):**
Every migration from 0017 onward that adds RLS has omitted `FORCE`. The pattern
has repeated across 12+ tables. Without a migration linter, each new migration
will repeat the same omission. This is systemic.

**Exception swallowing in non-prod (CONTAINED):**
The `_apply_tenant_context` guard is a single callsite. Contained, but
dangerous when combined with the fail-open RLS policy.

**In-process state for distributed concerns (SPREADING):**
Both rate limiting (`MemoryRateLimiter`) and single-use tokens
(`_ui_single_use_used`) live in process memory. Any new feature that requires
cross-worker coordination will either introduce a new in-process version of this
pattern or silently fail in multi-worker deployments. Redis exists in the
dependency graph but is not mandatory for correctness.

---

### 4) Security Invariants Checklist

| Invariant | Result | Evidence |
|---|---|---|
| Tenant binding enforced everywhere (no user-provided tenant_id) | **FAIL** | `/missions`, `/rings`, `/roe` have no tenant binding at all |
| AuthZ least privilege and explicit | **FAIL** | Three compliance router families have zero `require_scopes` |
| RLS enabled + policies for all tenant-owned tables | **FAIL** | `ai_governance_reviews`, `tenant_ai_policy` have no RLS; 12+ tables missing FORCE |
| Strict input validation (unknown fields rejected) | PASS | Pydantic models used throughout; DoSGuard enforces body/header limits |
| SSRF / injection mitigations | CONDITIONAL PASS | `outbound_policy.py` validates URL, resolves DNS, checks private ranges, validates rebinding. Gap: TOCTOU window between validation and request for DNS TTL exhaustion |
| Idempotency + replay controls | PARTIAL | DB-level idempotency key exists for some paths; single-use token store broken in multi-worker (G-004) |
| Secrets lifecycle sane | CONDITIONAL PASS | Keys hashed (bcrypt/sha256), no plaintext in DB. Gap: audit IP is spoofable (H-005), NATS URL carries no credentials (H-007) |
| OpenAPI / contract authority preserved | FAIL (per DR-001) | `blueprint_gate` CI job does not exist; contract drift not blocked at merge |
| Fail-closed behavior on guard/service outages | CONDITIONAL PASS | Auth gate fails closed; rate limiter fails closed by default; fail-open RLS on control_plane_event_ledger is fail-open (C-002) |
| Audit events complete and replayable | FAIL | Audit log IP is spoofable (H-005); no blueprint_gate CI job; NATS has no auth (H-007) |

---

### 5) Determinism & Replay Audit

**Deterministic:**
- API key verification (DB lookup + bcrypt comparison)
- Ingest pipeline decision recording (hash-chained)
- RLS policy evaluation (per-transaction `app.tenant_id` setting)

**Not deterministic:**
- Rate limiter key derivation: always uses IP; IP is attacker-controlled
- Single-use token enforcement: per-process set, non-shared

**Canonicalization missing:**
- `control_plane_event_ledger` `content_hash` is listed in schema but no code
  path was found that enforces canonical serialization before hashing. If two
  equivalent payloads serialize differently, chain verification fails.

**Replay would fail in incident response:**
- Audit log IP fields are poisoned (H-005); cannot reconstruct attacker IP from
  logs alone
- Single-use token set is lost on restart; replay window is unclear
- NATS ingest has no auth; replayed messages from any source are accepted

**Classification:**
Rate-limit key nondeterminism: **unacceptable** (directly exploitable).
Single-use token nondeterminism: **unacceptable** (distributed multi-worker
defeat).
Audit log IP nondeterminism: **dangerous** (forensic integrity).
Chain hash canonicalization gap: **acceptable risk** (chain exists, gap is
operational not exploitable).

---

### 6) Failure Mode Simulation

| Scenario | Observed behavior | Fails closed? | Evidence preserved? |
|---|---|---|---|
| Partial DB outage | `tenant_db_required` raises 503 via SQLAlchemy error propagation. Rate limiter on Redis backend raises 503 (fail-closed). | YES | Partial — SQLAlchemy error logged but not written to audit table (DB is down) |
| NATS/Redis outage | NATS: ingest bus will fail; no DLQ (DR-012). Redis: rate limiter raises 503 (fail-closed, unless `FG_RL_FAIL_OPEN_ACKNOWLEDGED=true`). | CONDITIONAL | No DLQ evidence (DR-012) |
| Duplicate delivery | Some paths have DB-level idempotency keys (control_plane_commands). Ingest path idempotency is listed as MISSING (DR-011). | NO for ingest | No evidence of DLQ treatment |
| Concurrent deploy overlap | No deploy-time migration locking mechanism observed. Multiple app instances can run against a partially-migrated schema. | UNKNOWN | No evidence |
| Rollback mid-flight | No rollback primitives exist (DR-007). Schema rollback is manual. | NO | No evidence |
| Retry storms | No exponential backoff or jitter in ingest bus reconnect. Default NATS reconnect behavior. Potential thundering herd on NATS restart. | NO | No evidence |

**Fail-open behaviors (FAIL audit):**
- `control_plane_event_ledger` RLS is fail-open when tenant context unset (C-002)
- `_ui_single_use_used` is fail-open under multi-worker (G-004)
- Rate limiter is fail-open to IP spoofing (C-003)

---

### 7) CI / Gate Coverage Analysis

**Existing gates (from `.github/workflows/ci.yml` and `fg-required.yml`):**

| Gate | Covers | Does not cover |
|---|---|---|
| `fg_guard` | Auth unit tests, key verification | Rate-limit bypass via spoofed IP, route auth coverage |
| `contract_authority` | OpenAPI schema drift against stored spec | Route-level auth dependency inventory |
| `integration` | End-to-end ingest + defend paths | Cross-tenant queries without tenant context |
| `hardening` | Prod invariant checks (`FG_AUTH_ENABLED`, `FG_RL_FAIL_OPEN`, etc.) | NATS auth requirement, FORCE RLS, GOTCHAS regression |
| `compliance` | Compliance module load tests | Compliance route auth coverage |
| `evidence` | Evidence chain tests | Ledger RLS fail-open |

**Gates that SHOULD exist but do not:**

| Gate | Purpose | Where it should live | What it blocks |
|---|---|---|---|
| `route-auth-coverage` | Assert every FastAPI route has ≥1 auth dependency or is in explicit allow-list | `tests/test_route_auth_coverage.py` + CI job | C-001 type regressions |
| `rls-semantic-test` | Query every tenant table with no tenant context set; assert row count = 0 | `tests/postgres/test_rls_semantic.py` + postgres CI lane | C-002 type regressions |
| `rls-force-lint` | Parse all migration SQL; assert every `ENABLE ROW LEVEL SECURITY` is paired with `FORCE ROW LEVEL SECURITY` in same or earlier migration | `tools/lint_migrations.py` + CI | H-002 regressions |
| `gotchas-check` | Assert no `OPEN — BLOCKER` entry in GOTCHAS.md without a waiver | `Makefile: gotchas-check` + CI | All GOTCHAS regressions |
| `blueprint_gate` | Run `tools/align_score.py` + `tools/drift_check.py`; fail on new gaps | `.github/workflows/ci.yml` `blueprint_gate` job | Contract drift (DR-001) |
| `proxy-trust-lint` | Grep codebase for direct reads of `x-forwarded-for` outside of trusted extraction helpers | `tools/lint_proxy_headers.py` + CI | H-005 regressions |

---

### 8) Repo Memory Audit (Moat Check)

**GOTCHAS.md:** Did not exist before this PR. Created with 14 entries. Not
enforced by CI.

**PR_FIX_LOG.md:** Did not exist before this PR. Created.

**DRIFT_LEDGER.md:** Exists with 25 entries. Well-maintained. Not enforced
by CI (DR-001: `blueprint_gate` job missing).

**Is repo memory enforced or advisory?** Advisory only. No CI gate reads or
blocks on any of these files.

**What will be rediscovered in 90 days:**
- `/missions`, `/rings`, `/roe` auth gap — no route coverage test
- FORCE RLS omission — no migration linter
- Rate-limit IP spoofability — rate limit tests use mock key derivation
- `ai_governance_reviews` RLS gap — no cross-table RLS coverage test
- `_apply_tenant_context` exception suppression — no staging-specific RLS test

**Gate that should enforce it:** `make gotchas-check` (see G-009). Wire into
`fg-required.yml` as a required step before any merge to `main`.

---

### 9) Required Fix Plan (Ordered, Lowest Risk First)

**1. Fix timing oracle in `check_tenant_if_present`**
Files: `api/main.py` line 471
Change: `str(expected) != str(api_key)` → `not hmac.compare_digest(...)`
Tests: existing auth tests pass; add timing invariant test
Blast radius: none — one line change
PR_FIX_LOG: REQUIRED (G-007)

**2. Fix `_apply_tenant_context` exception swallowing**
Files: `api/auth_scopes/resolution.py`
Change: remove `if _is_production_env(): raise` guard; always raise
Tests: add test that exercises binding failure path
Blast radius: may surface latent failures in staging test suites
PR_FIX_LOG: REQUIRED (G-008)

**3. Fix `auth.py` docstring / return-code mismatch**
Files: `api/auth.py` lines 56–81
Change: return 403 for invalid (wrong/expired/disabled) key, 401 for missing
Tests: update auth status-code tests
Blast radius: any client that tests for 401 on invalid key must update
PR_FIX_LOG: REQUIRED (G-011)

**4. Add `FORCE ROW LEVEL SECURITY` to all affected tables**
Files: new migration 0029
Change: `ALTER TABLE <12 tables> FORCE ROW LEVEL SECURITY`
Tests: add `test_rls_semantic.py` (no-context-session returns 0 rows for all tables)
Blast radius: if app DB user is table owner and currently bypassing RLS,
queries that relied on bypass will start returning 0 rows (correct behavior)
PR_FIX_LOG: REQUIRED (G-006)

**5. Fix `control_plane_event_ledger` RLS policy (fail-open → fail-closed)**
Files: new migration 0030
Change: replace policy with standard fail-closed pattern
Tests: add context-less session test for ledger
Blast radius: admin jobs that query ledger without tenant context will stop
working (they should be using superuser role for cross-tenant reads, not app role)
PR_FIX_LOG: REQUIRED (G-002)

**6. Add RLS to `ai_governance_reviews` and `tenant_ai_policy`**
Files: new migration 0031
Change: ENABLE + FORCE + policy on both tables
Tests: add cross-tenant RLS test
Blast radius: none if app already sets tenant context correctly
PR_FIX_LOG: REQUIRED (G-005)

**7. Fix rate limiter key derivation (use auth state, not telemetry_body)**
Files: `api/ratelimit.py` `_key_from_request`
Change: read `request.state.auth.tenant_id` for tenant scope; use CIDR-
validated IP for fallback
Tests: add integration test with spoofed `X-Forwarded-For`
Blast radius: rate limit behavior changes (becomes correct)
PR_FIX_LOG: REQUIRED (G-003)

**8. Move single-use token store to Redis**
Files: `api/main.py` (`_ui_single_use_key_guard`)
Change: Redis `SET NX EX` with 5-minute TTL
Tests: multi-worker simulation test
Blast radius: requires Redis in all environments
PR_FIX_LOG: REQUIRED (G-004)

**9. Add auth dependencies to `/missions`, `/rings`, `/roe` routes**
Files: `api/mission_envelope.py`, `api/ring_router.py`, `api/roe_engine.py`,
`api/security/public_paths.py`
Change: add `Depends(require_scopes(...))` to all handlers; remove from
`PUBLIC_PATHS_PREFIX`
Tests: add `test_route_auth_coverage.py` as gating test
Blast radius: any existing callers who relied on unauthenticated access break
PR_FIX_LOG: REQUIRED (G-001)

**10. Wire CI gates**
Files: `.github/workflows/ci.yml`, `Makefile`
Change: add `route-auth-coverage`, `rls-semantic-test`, `rls-force-lint`,
`gotchas-check`, `blueprint_gate` gates
Tests: the gates themselves
Blast radius: PRs that currently pass will fail until fixes 1–9 are applied
PR_FIX_LOG: REQUIRED (G-009)

---

### 10) Competitive / Moat Impact

**Position vs CrowdStrike / Wiz / Defender / SentinelOne:**

| Dimension | Position |
|---|---|
| Tenant isolation architecture | Behind — RLS FORCE gaps and fail-open policy in ledger are not defensible |
| Auth gate design | Parity — layered middleware + route deps is sound; implementation has gaps |
| Evidence chain / forensics | Ahead — hash-chained ledger, append-only triggers, cross-tenant blindness by default is a genuine differentiator |
| Rate limiting | Behind — IP-spoofable, effectively absent |
| Compliance module exposure | Behind — unauth routes are a liability in any enterprise security RFP |

**Moat that exists today:**
- Hash-chained audit ledger with append-only DB enforcement (trigger-level)
- Per-transaction RLS via `set_config('app.tenant_id', true)` — correct pattern
  when properly wired
- `assert_prod_invariants` startup check prevents the worst misconfigurations
  in production
- DoSGuard middleware is well-implemented (body limits, multipart bombing,
  concurrency cap, trusted-proxy CIDR logic)

**Moat achievable with small changes:**
- Fix G-001 (auth on compliance routes) + G-002 (fail-closed RLS) and the
  evidence-chain story becomes genuinely differentiated: immutable, cross-tenant
  isolated, cryptographically verifiable
- Fix G-003 (rate limiter) and per-tenant SLA guarantees become real
- Fix G-009 (CI gates) and the enforcement story becomes a competitive claim:
  "security invariants are CI-gated, not advisory"

---

### 11) Final Recommendation

**BLOCK ALL MERGES until fixes applied.**

Specific blockers:
- C-001 must be resolved before any compliance-module code ships to production.
  Unauthenticated access to mission envelopes and ring policies violates the
  product's core security promise.
- C-002 must be resolved before any multi-tenant production traffic touches
  `control_plane_event_ledger`. The fail-open RLS policy is a cross-tenant leak
  on every admin operation.
- C-003 must be resolved before any rate-limit SLA is communicated to customers.
  The rate limiter is currently inoperative.

CONDITIONAL ALLOW for non-compliance-module PRs (e.g., documentation, tooling)
with the following constraints:
1. No new routes added without `require_scopes` dependency
2. No new migrations without `ENABLE ROW LEVEL SECURITY` + `FORCE ROW LEVEL SECURITY` + policy
3. All new PRs must add a GOTCHAS.md entry if they touch auth, RLS, or rate limiting

Fixes 1–6 (critical path) are estimated to require < 200 lines of code combined.
The risk of delay is not theoretical — the `/missions`, `/rings`, `/roe` auth
gap is exploitable today with a single unauthenticated HTTP request.
