# GOTCHAS

Mandatory repo memory. Each entry records a real bug or architectural trap that
was found, fixed (or accepted), and must not be reintroduced.

CI MUST block any PR that removes entries from this file or regresses a fix
described here. Gate: `make gotchas-check` (not yet wired — see entry G-009).

---

## G-001 — `/missions`, `/rings`, `/roe` routes are completely unauthenticated

**Date found:** 2026-02-27
**Status:** OPEN — BLOCKER

`PUBLIC_PATHS_PREFIX` contains `"/missions"`, `"/rings"`, `"/roe"`. The auth-gate
middleware skips auth for every path that starts with those prefixes.
The route handlers themselves (`api/mission_envelope.py`, `api/ring_router.py`,
`api/roe_engine.py`) declare **zero** `Depends(require_scopes(...))` or equivalent.
Result: unauthenticated callers can read mission envelopes, ring policies, and
invoke ROE evaluation.

**Fix:** Add `Depends(require_scopes("missions:read"))` / `rings:read` / `roe:read`
to every route handler, then remove the prefixes from `PUBLIC_PATHS_PREFIX`.

**File(s):** `api/security/public_paths.py`, `api/mission_envelope.py`,
`api/ring_router.py`, `api/roe_engine.py`

---

## G-002 — `control_plane_event_ledger` RLS policy fails OPEN when tenant context is unset

**Date found:** 2026-02-27
**Status:** OPEN — BLOCKER

`migrations/postgres/0027_control_plane_v2.sql` line 80–85:

```sql
USING (
    tenant_id IS NULL
    OR current_setting('app.tenant_id', true) IS NULL  -- ← FAIL-OPEN branch
    OR current_setting('app.tenant_id', true) = ''
    OR tenant_id = current_setting('app.tenant_id', true)
);
```

If `app.tenant_id` is not set for the session (admin ops, background jobs,
staging where `_apply_tenant_context` silently swallows exceptions), the
`IS NULL` branch is TRUE and **all rows from all tenants are visible**.

Every other tenant table in the repo uses fail-closed policy (no IS NULL escape
hatch). This one is unique — and wrong.

**Fix:** Remove the `OR current_setting(...) IS NULL` and `OR current_setting(...) = ''`
branches. Replace entire policy with the standard pattern:
```sql
USING (
    tenant_id IS NOT NULL
    AND current_setting('app.tenant_id', true) IS NOT NULL
    AND tenant_id = current_setting('app.tenant_id', true)
);
```
Global events (`tenant_id IS NULL`) must be excluded from tenant-scoped sessions
by design.

**File(s):** `migrations/postgres/0027_control_plane_v2.sql`

---

## G-003 — Rate limiter tenant-scope is dead code; IP always used; IP is spoofable

**Date found:** 2026-02-27
**Status:** OPEN — BLOCKER

`api/ratelimit.py` `_key_from_request` reads `request.state.telemetry_body` to
derive the tenant key. That attribute is **never set** anywhere in the codebase.
`body` is always `None`, `tenant` is always `None`, rate limiting always falls
through to `ip:{client_ip}`.

`_extract_client_ip` unconditionally reads `X-Forwarded-For` / `X-Real-IP` /
`CF-Connecting-IP` / `True-Client-IP` headers **without any proxy-trust
validation**. Any caller can set `X-Forwarded-For: 1.2.3.4` and immediately
shift into a fresh bucket, defeating rate limiting entirely.

**Fix (two-part):**
1. Derive rate-limit key from `request.state.auth.tenant_id` (already set by
   auth gate on authenticated paths) rather than from `telemetry_body`.
2. Honour `FG_TRUSTED_PROXY_CIDRS` (already validated in `DoSGuardMiddleware`)
   before trusting proxy headers — or reuse `DoSGuardMiddleware._resolve_client_ip`.

**File(s):** `api/ratelimit.py` lines 283–297, `_extract_client_ip`

---

## G-004 — Single-use UI token set is in-memory, unbounded, and breaks under multiple workers

**Date found:** 2026-02-27
**Status:** OPEN — HIGH

`app.state._ui_single_use_used` (`api/main.py`) is a plain Python `set`.
Problems:
1. **Multi-worker bypass:** Each gunicorn/uvicorn worker has its own set. A
   single-use token can be consumed once per worker, not once total.
2. **Unbounded growth:** The set is never evicted. Under sustained unique-key
   traffic it grows until OOM.
3. **Lost on restart:** Tokens consumed before a crash are forgotten; they can
   be replayed after restart.

**Fix:** Move the used-token store to Redis with a short TTL (e.g., 5 minutes).
Use `SET NX EX` (atomic: set if not exists, with expiry). Fail-closed if Redis
is unavailable.

**File(s):** `api/main.py` (`_ui_single_use_key_guard` middleware)

---

## G-005 — `ai_governance_reviews` and `tenant_ai_policy` have no RLS

**Date found:** 2026-02-27
**Status:** OPEN — HIGH

`migrations/postgres/0016_ai_plane_extension.sql` creates both tables with
`tenant_id TEXT NOT NULL`. No subsequent migration adds
`ENABLE ROW LEVEL SECURITY`, `FORCE ROW LEVEL SECURITY`, or a tenant isolation
policy. Any DB query that resolves to a tenant (or to no tenant) can read or
write across all tenants for these tables.

**Fix:** New migration (0029 or similar):
```sql
ALTER TABLE ai_governance_reviews ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_governance_reviews FORCE ROW LEVEL SECURITY;
ALTER TABLE tenant_ai_policy ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_ai_policy FORCE ROW LEVEL SECURITY;
-- then CREATE POLICY ... with standard tenant_id = current_setting(...) check
```

**File(s):** `migrations/postgres/0016_ai_plane_extension.sql`

---

## G-006 — FORCE ROW LEVEL SECURITY missing from many newer tables

**Date found:** 2026-02-27
**Status:** OPEN — HIGH

`ENABLE ROW LEVEL SECURITY` without `FORCE ROW LEVEL SECURITY` allows the
PostgreSQL table owner (the application DB user in most deployments) to bypass
RLS entirely. Tables affected (have ENABLE but not FORCE):

- `ai_inference_records`, `ai_policy_violations` (0017)
- `evidence_runs`, `retention_policies` (0018)
- `agent_device_identities`, `agent_commands`, `agent_policy_bundles`,
  `agent_log_anchors`, `agent_quarantine_events` (0024)
- `connectors_idempotency` (0025)
- `connectors_tenant_state`, `connectors_credentials`, `connectors_audit_ledger` (0026)
- `control_plane_commands`, `control_plane_command_receipts`,
  `control_plane_heartbeats` (0027)

**Fix:** Additive migration: `ALTER TABLE <t> FORCE ROW LEVEL SECURITY;` for
each table above. Also add `FORCE` to every future tenant-scoped table as a
migration checklist item (see G-009).

**File(s):** Migrations 0017–0027

---

## G-007 — Timing oracle in `check_tenant_if_present` (main.py)

**Date found:** 2026-02-27
**Status:** OPEN — HIGH

`api/main.py` line 471:
```python
if expected is None or str(expected) != str(api_key):
```
`str(expected) != str(api_key)` is a standard Python string comparison.
It short-circuits and returns early on the first differing byte, creating a
timing side-channel that allows brute-forcing valid API keys for known tenants.

**Fix:** Replace with `hmac.compare_digest(str(expected), str(api_key))`.

**File(s):** `api/main.py` line ~471

---

## G-008 — `_apply_tenant_context` silently swallows exceptions outside production

**Date found:** 2026-02-27
**Status:** OPEN — HIGH

`api/auth_scopes/resolution.py` (approximately line 755):
```python
except Exception:
    if _is_production_env():
        raise
```
If tenant context binding fails in staging or dev, the exception is suppressed
and the query proceeds without `app.tenant_id` set. Combined with G-002's
fail-open RLS policy, this is a cross-tenant leak path in staging.

**Fix:** Always raise. Remove the `_is_production_env()` guard. Failure to bind
tenant context is always a critical error.

**File(s):** `api/auth_scopes/resolution.py`

---

## G-009 — No CI gate enforces GOTCHAS.md / PR_FIX_LOG.md / DRIFT_LEDGER

**Date found:** 2026-02-27
**Status:** OPEN — HIGH

GOTCHAS.md (this file) and DRIFT_LEDGER.md exist but:
- No CI job reads them or blocks on content regression
- No PR template references them
- `blueprint_gate` CI job (required by BLUEPRINT_STAGED.md) does not exist (DR-001)
- `PR_FIX_LOG.md` does not exist at all

Without enforcement, these files become aspirational noise. Every fix in this
file will be rediscovered in 90 days by the next engineer.

**Fix:**
1. Create `PR_FIX_LOG.md` (see that file for format)
2. Add `make gotchas-check` script that fails if any `OPEN — BLOCKER` entry
   exists without a corresponding waiver in `waivers.yml`
3. Wire `gotchas-check` into `.github/workflows/ci.yml` as a required gate

**File(s):** `.github/workflows/ci.yml`, `Makefile`, `PR_FIX_LOG.md` (to create)

---

## G-010 — `verify_api_key_detailed` reads proxy headers for audit log IP without trust check

**Date found:** 2026-02-27
**Status:** OPEN — MEDIUM

`api/auth_scopes/resolution.py` lines 247–253 (inside `verify_api_key_detailed`)
reads `x-forwarded-for`, `x-real-ip`, `cf-connecting-ip` unconditionally to
derive `client_ip` for audit log events. This ignores `FG_TRUST_PROXY_HEADERS`
and `FG_TRUSTED_PROXY_CIDRS`. Any caller can poison auth audit logs with a
fabricated source IP.

**Fix:** Call the same `_resolve_client_ip` helper that respects trusted CIDR
list (as implemented in `DoSGuardMiddleware`).

**File(s):** `api/auth_scopes/resolution.py`

---

## G-011 — `auth.py` docstring says 403 for invalid key; code returns 401

**Date found:** 2026-02-27
**Status:** OPEN — LOW

`api/auth.py` `verify_api_key` docstring:
```
  - 401: Missing key
  - 403: Invalid key (wrong, expired, disabled, etc.)
```
Actual code at lines 76–81 returns `HTTP_401_UNAUTHORIZED` for both missing
and invalid. The docstring is wrong. Clients and firewalls that gate on 401 vs
403 will behave incorrectly.

**Fix:** Either fix the code to return 403 for invalid keys (preferred) or fix
the docstring. Keep consistent with `require_api_key_always` in resolution.py.

**File(s):** `api/auth.py` lines 56–81

---

## G-012 — `auth_enabled()` defaults to False when neither FG_AUTH_ENABLED nor FG_API_KEY is set

**Date found:** 2026-02-27
**Status:** OPEN — MEDIUM

`api/auth.py` line 43:
```python
return bool(os.getenv("FG_API_KEY"))
```
If `FG_AUTH_ENABLED` is not set AND `FG_API_KEY` is empty/missing, auth is
**disabled**. In dev/staging containers spun up without env vars, the entire API
is unauthenticated. `assert_prod_invariants` guards this in prod, but staging
containers that forget `FG_AUTH_ENABLED=1` are completely open.

**Fix:** Default to `True` (fail-closed). Require `FG_AUTH_ENABLED=0` to
explicitly disable, not the absence of `FG_API_KEY`.

**File(s):** `api/auth.py` line 43

---

## G-013 — NATS default URL has no auth; unauthenticated in dev by default (DR-021)

**Date found:** 2026-02-27  (carried from DRIFT_LEDGER DR-021)
**Status:** OPEN — HIGH

`api/ingest_bus.py` default `NATS_URL = "nats://localhost:4222"` with no
credentials. In a shared cluster or any env that deploys NATS externally, the
ingest bus has no AuthN/AuthZ.

**Fix:** Require `NATS_URL` to be explicitly set in staging/prod. Fail startup
if URL contains no auth credentials in production env.

**File(s):** `api/ingest_bus.py`, `api/config/startup_validation.py`

---

## G-014 — SQLite path defaults to `/tmp/fg-core.db` instead of `<repo>/state/` (DR-023)

**Date found:** 2026-02-27  (carried from DRIFT_LEDGER DR-023)
**Status:** OPEN — MEDIUM

Inconsistency with CONTRACT.md. `/tmp` path is world-readable on shared hosts
and not persisted across container restarts. Any process on the host can read
the DB.

**Fix:** Use `api.db._resolve_sqlite_path` in `api/main.py`. Ensure path is
`<repo>/state/frostgate.db` as specified in CONTRACT.md.

**File(s):** `api/main.py` lines ~99–108, `api/db.py`

---

## CHECKLIST FOR NEW TENANT-SCOPED TABLES

Every migration that creates a tenant-scoped table MUST include:

```sql
ALTER TABLE <table> ENABLE ROW LEVEL SECURITY;
ALTER TABLE <table> FORCE ROW LEVEL SECURITY;        -- mandatory, not optional
CREATE POLICY <table>_tenant_isolation ON <table>
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

Do NOT add `OR current_setting(...) IS NULL` escape hatches. Fail-closed.
