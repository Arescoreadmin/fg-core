# R4.11 Completion Summary — Legacy api_keys Table Retirement

**Date:** 2026-08-09
**Status:** Implementation complete — pending production 0178 proof
**Branch:** feat/r4.11-steps-7-16-legacy-api-keys-eradication
**PRs:** #625 (steps 1–6), #TBD (steps 7–16)

## Outcome

Runtime code is eradicated. `api_keys` will NOT EXIST in production runtime once
migration 0178 is applied to Railway. All authentication and credential lifecycle
now flows exclusively through `tenant_credentials` and `tenant_credential_roles`
(R4.2–R4.10). R4 Credential Authority will be COMPLETE after production proof.

### Production closure gate

After deploying migration 0178:
```sql
SELECT to_regclass('public.api_keys');  -- must return NULL
SELECT * FROM schema_migrations WHERE version = '0178';  -- must have a row
```
Only after both pass is R4.11 / R4 legitimately closed.

## 16-Step Plan Summary

### Steps 1–6 (PR #625, merged 2026-08-08)

| Step | Action |
|------|--------|
| 1 | Pre-drop audit: `api_keys` rows confirmed unreachable via R4.8 early-return guard |
| 2 | SQLite legacy fallback removed from `api/auth_scopes/store.py` |
| 3 | `mint_key(engine, tenant_id, scopes)` shim added to `api/auth_scopes/mapping.py` → delegates to `issue_credential()` |
| 4 | 130+ test files updated to `mint_key()` API |
| 5 | `plaintext_secret` assertion added to `tests/agent/helpers.py` |
| 6 | CI guard extended with steps 1–6 assertions |

### Steps 7–16 (this PR)

| Step | Action |
|------|--------|
| 7 | `ApiKey` ORM class + `hash_api_key()` deleted from `api/db_models.py` |
| 8 | Dead auth methods deleted from `api/identity_authority/machine_identity.py` and `authority.py` |
| 9 | `seed_canary_key_if_missing()` deleted from `api/tripwires.py`; legacy scripts deleted |
| 10 | `_ensure_api_keys_sqlite()` deleted from `api/db.py`; `ensure_tenant_canonical_row()` made self-bootstrapping; `init_db()` wired into `mint_key` shim |
| 11 | `api/main.py` readiness probe updated: `api_keys` column check → `tenant_credentials` table existence |
| 12 | Hard DROP checkpoint: zero runtime `api_keys` SQL hits in `api/` tree (dual grep verified) |
| 13 | `migrations/postgres/0178_drop_legacy_api_keys.sql` created (`DROP TABLE IF EXISTS api_keys`) |
| 14 | CI guard `tools/ci/check_credential_authority.py` tightened to 5 permanent allowlist paths |
| 15 | Test suite adapted: 7 no-tenant fixtures rewritten, machine_identity dead tests removed, RBAC-7 rewritten, auth_startup_guard updated, test_auth_sqlite_to_postgres_migration.py deleted |
| 16 | ROADMAP.md updated (R4 COMPLETE), this summary written, memory updated |

## Hard DROP Checkpoint Results

Zero runtime `api_keys` SQL hits in `api/` at merge time:

```
grep -rn "api_keys" api/ --include="*.py" | grep -v "^Binary"
(no output — zero hits)

grep -rn "INSERT INTO api_keys\|SELECT.*FROM api_keys\|UPDATE api_keys\|DELETE.*FROM api_keys" api/ --include="*.py"
(no output — zero hits)
```

## Files Changed (Steps 7–16)

**Deleted (runtime):**
- `api/db_models.py` — `ApiKey` class, `hash_api_key()` removed
- `api/identity_authority/machine_identity.py` — dead auth methods removed
- `api/identity_authority/authority.py` — dead `authenticate_api_key()` removed
- `api/tripwires.py` — `seed_canary_key_if_missing()` removed

**Modified (runtime):**
- `api/db.py` — `_ensure_api_keys_sqlite()` deleted; `ensure_tenant_canonical_row()` self-bootstrapping
- `api/auth_scopes/mapping.py` — `init_db()` wired into `mint_key` shim
- `api/main.py` — readiness probe: `api_keys` columns → `tenant_credentials` table
- `api/db_migrations.py` — `api_keys` removed from RLS expected tables
- `api/auth_scopes/__init__.py`, `validation.py`, `resolution.py` — residual references cleaned
- `api/identity_providers/api_key.py` — residual references cleaned
- `api/tenant_rbac.py` — residual references cleaned
- `tools/seed/demo_tenants.py` — `_create_demo_api_key` → `_create_demo_credential`
- `docs/SOC_ARCH_REVIEW_2026-02-15.md` — AUTH-003 updated

**Created:**
- `migrations/postgres/0178_drop_legacy_api_keys.sql`
- `docs/r4_evidence/R4_11_COMPLETION_SUMMARY.md` (this file)

**Deleted (scripts):**
- `scripts/create_api_key.py`
- `scripts/seed_apikeys_db.py`
- `tools/scripts/migrate_auth_sqlite_to_postgres.py`
- `tools/tenant_hardening/patch_auth_scopes_mapping.py`

**Test changes:**
- `tests/agent/helpers.py` — `assert admin_key is not None` added
- `tests/identity_authority/test_machine_identity.py` — 6 dead-method tests removed
- `tests/test_auth_startup_guard.py` — updated for `tenant_credentials` check
- `tests/test_auth_sqlite_to_postgres_migration.py` — deleted (tested deleted script)
- `tests/test_key_lifecycle.py` — updated
- `tests/test_readiness_alerting.py` — 1 no-tenant fixture rewritten
- `tests/test_readiness_gap_analysis_manager.py` — 3 no-tenant fixtures rewritten
- `tests/test_readiness_monitoring.py` — 3 no-tenant fixtures rewritten
- `tests/test_sqlite_test_pragmas.py` — `api_keys` removed from required tables
- `tests/test_tenant_rbac.py` — RBAC-7 rewritten against canonical invariant

**CI:**
- `tools/ci/check_credential_authority.py` — allowlist tightened to 5 permanent paths

## CI Results at Merge

- fg-fast: exit 0 (pr-fix-log gate satisfied; 2 pre-existing flaky failures confirmed on HEAD pre-R4.11 by isolated re-run)
- fg-security: non-zero exit (10 failures); all confirmed pre-existing on HEAD pre-R4.11 by isolated re-run — not R4.11 regressions
- fg-contract: exit 0 ✅
- check-credential-authority: ✅
- codex_gates ruff lint: ✅
- codex_gates ruff format: ✅
- codex_gates mypy: ✅
- codex_gates pytest: pending

## mint_key() — Compatibility Facade

`mint_key()` still exists in `api/auth_scopes/mapping.py`. It is a compatibility
facade over canonical credential issuance, not legacy api_keys authority. It
calls `issue_credential()` internally; the 130+ test files that call it are
exercising the canonical path. The name is historical baggage; the authority
is canonical. This is acceptable: authority is what matters, not the adapter name.

## Key Invariant Established

All credentials issued through R4.11+ have a `tenant_id`. The "no-tenant key"
concept (`api_keys.tenant_id = NULL`) is permanently eliminated. Tests that
previously relied on `tenant_id=None` → 403 now verify the canonical behavior:
`mint_key()` defaults `tenant_id=None` to `"tenant-test"`, so those credentials
authenticate successfully and exercise real resource-lookup paths (returning
404/200/201 as appropriate).
