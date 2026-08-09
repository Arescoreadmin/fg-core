# R4.11 Phase 1 Evidence Snapshot

Date: 2026-08-09
Environment: production
Source: Railway PostgreSQL (frostgate-core, production environment)
Migration version at time of capture: 0177 (applied 2026-08-09 14:35:01 UTC)

## Legacy row count

Total legacy rows: **28**

## Tenant distribution

| tenant_id          | total | enabled | disabled |
|--------------------|-------|---------|----------|
| default            |     3 |       2 |        1 |
| demo-bank          |     8 |       6 |        2 |
| demo-healthcare    |     6 |       5 |        1 |
| demo-law           |     2 |       1 |        1 |
| the-trust-company  |     1 |       1 |        0 |
| the-trust-group    |     8 |       0 |        8 |

## Historical usage

| ever_used | has_last_used | most_recent_legacy_use         |
|-----------|---------------|-------------------------------|
|         6 |             6 | 2026-07-20 00:18:28.848202 UTC |

Last legacy api_keys authentication: **2026-07-20** (R4.8 retired Postgres auth on 2026-07-21).
No legacy key has authenticated since R4.8 merged.

## Legacy RBAC summary

| role_rows | enabled_role_rows |
|-----------|-------------------|
|         4 |                 0 |

4 rows have a role column value; 0 are enabled. All role-bearing rows are disabled.
Canonical RBAC authority (tenant_credential_roles) is the live path as of R4.10.

## Migration version proof (top 5 at snapshot time)

| version | applied_at                        |
|---------|-----------------------------------|
| 0177    | 2026-08-09 14:35:01.601741 UTC    |
| 0176    | 2026-08-07 00:12:13.694514 UTC    |
| 0175    | 2026-08-06 14:20:00.616822 UTC    |
| 0174    | 2026-08-06 13:58:20.545780 UTC    |
| 0173    | 2026-08-06 10:59:07.131819 UTC    |

## Export

File: `r4_11_api_keys_legacy_evidence_20260809.csv`
Columns exported: id, tenant_id, name, prefix, hash_alg, scopes_csv, enabled, created_at, version, expires_at, last_used_at, use_count, created_by, description, role
Columns excluded: key_hash, key_lookup (secret material — not exported)
Row count: 28 (COPY 28 confirmed)
File size: 9.9K

SHA256: `d9692bf8b31805ab4dba77862c89fa713ee85031d22031a4ccb10e361928d1d0`

## Disposition

Historical inert legacy evidence. No live Postgres auth authority.
- All 28 rows are seed/demo keys created by demo_tenants.py
- Last authentication: 2026-07-20 (before R4.8 retired the Postgres auth path)
- 0 enabled role-bearing rows (canonical RBAC is live via tenant_credential_roles since R4.10)
- Safe to DROP TABLE after R4.11 migration 0178

## Phase 1 verdict

**PASS** — evidence captured, hash recorded, file archived to docs/r4_evidence/.
Proceeding to Phase 2 SQLite fate decision.
