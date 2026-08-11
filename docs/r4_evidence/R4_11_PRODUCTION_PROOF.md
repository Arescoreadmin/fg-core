# R4.11 Production Closure Proof

**Status:** COMPLETE  
**Date:** 2026-08-11T15:10:25Z  
**Git SHA:** 06c7f97623b883313d050dbb3ea37590335785c6 (main at proof time)  
**Evidence commit:** 19983595 (docs update recording this proof)

## Target

| Field | Value |
|---|---|
| Railway project | frostgate-core |
| Railway environment | production |
| PostgreSQL service | Postgres |
| Database | railway |

## Proof Query

```sql
SELECT
    current_database()                                            AS database_name,
    (to_regclass('public.api_keys') IS NULL)                    AS api_keys_absent,
    EXISTS (
        SELECT 1 FROM schema_migrations WHERE version = '0178'
    )                                                            AS migration_0178_recorded;
```

## Result

```
 database_name | api_keys_absent | migration_0178_recorded
---------------+-----------------+-------------------------
 railway       | t               | t
(1 row)
```

## Interpretation

- `api_keys_absent = t` — `public.api_keys` does not exist in the production schema. The legacy table has been dropped.
- `migration_0178_recorded = t` — `schema_migrations` contains version `0178`, confirming `0178_drop_legacy_api_keys.sql` was applied by the FrostGate migration runner.

## Connection method

`railway connect Postgres` (Railway CLI 5.37.3, authenticated as admin@arescore.ai). No credentials in shell history. No DATABASE_URL or password in this document.

## R4.11 closure checklist

- [x] R4.11 steps 1–6: SQLite canonical auth — PR #625 (2026-08-08)
- [x] R4.11 steps 7–16: api_keys eradication — PR #627 (2026-08-10)
- [x] Full test suite: 21,455/21,462 pass, zero R4.11 regressions
- [x] CI gate `check_credential_authority`: 5 permanent allowlist paths only
- [x] Production migration 0178 applied: `migration_0178_recorded = t`
- [x] Legacy table absent: `api_keys_absent = t`

**R4.11 ✅ COMPLETE  
R4 Credential Authority ✅ COMPLETE**
