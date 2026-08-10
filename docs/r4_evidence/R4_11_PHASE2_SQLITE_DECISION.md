# R4.11 Phase 2 — SQLite Fate Decision

Date: 2026-08-09
Status: **LOCKED**

## Decision

SQLite will migrate to canonical `tenant_credentials` / `tenant_credential_roles`.
Legacy `api_keys` support will be removed from all runtime environments.
No permanent `api_keys` allowlist survives R4.11.

## Rationale

Keeping SQLite legacy compatibility preserves the exact class of dual-authority code R4.11
is designed to eradicate. The 28 production rows are demo/seed keys. The 9 SQLite test
fixtures were already documented as temporary in R4.10. There is no production workload
that requires `api_keys` to survive.

Target authority model:

```
Postgres        SQLite
   │               │
   └──────┬────────┘
          ▼
  tenant_credentials
          │
  tenant_credential_roles
          │
  canonical auth / RBAC
```

One authority model, one test model, one CI policy.

## Implementation scope (Phases 3/4)

1. Remove the `_is_postgres` split in `resolution.py:437` that prevents canonical
   `fgk.*` credential handling in SQLite. Canonical auth must work regardless of
   dialect.

2. Make SQLite initialize and use `tenant_credentials` / `tenant_credential_roles`
   consistently (already partially done in R4.10; remaining gaps in test schemas
   and `init_db` path).

3. Migrate the 9 SQLite test fixtures off `UPDATE api_keys SET role = ...` to the
   canonical `assign_role()` / `tenant_credential_roles` path.

4. Remove once canonical fixture path works:
   - `_legacy_get_key_role()` in `api/tenant_rbac.py`
   - SQLite `api_keys` mint / read / revoke paths in `api/auth_scopes/mapping.py`
   - `_ensure_api_keys_sqlite()` in `api/db.py` and `api/main.py`
   - `api_keys` model in `api/db_models.py` (SQLAlchemy ORM model)
   - `api_keys` in `api/tripwires.py`
   - All Phase 3 tool targets (migrate scripts, seed tool, patch tools)

## What does NOT survive R4.11

- `api_keys` table in Postgres (dropped by migration 0178)
- `api_keys` table in SQLite (removed from `init_db` / `_auto_migrate_sqlite`)
- `_is_postgres` gate in `resolution.py` for canonical credential auth
- `_legacy_get_key_role()` function
- `_ensure_api_keys_sqlite()` function
- `list_api_keys` export from `api/auth_scopes/__init__.py`
- Any CI allowlist exception for `api_keys` reads or writes

## Permanent survivals

- `check_credential_authority.py` resurrection guards (strengthened, no exceptions)
- Historical Postgres migrations 0001–0047 (immutable replay chain, reference only)
- `docs/r4_evidence/` snapshot and this decision record
