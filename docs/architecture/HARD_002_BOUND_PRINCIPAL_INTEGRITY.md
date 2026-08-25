# HARD-002 — BOUND Membership Principal Integrity

**Status:** ships with HARD-002
**Depends on:** PR-AUTH-001 through PR-AUTH-004, HARD-001
**Normative source:** `docs/architecture/IDENTITY_AUTHORITY_DATA_MODEL.md`

## Purpose

HARD-002 adds the deferred database invariant that PR-AUTH-004 made safe:

```sql
identity_binding_status <> 'bound'
OR principal_id IS NOT NULL
```

Constraint name:

```sql
chk_bound_requires_principal_id
```

HARD-002 ENFORCES THAT BOUND MEMBERSHIPS MUST HAVE A CANONICAL PRINCIPAL.
HARD-002 PRESERVES LEGITIMATE UNBOUND MEMBERSHIPS WITH NULL `principal_id`.
HARD-002 DOES NOT CHANGE RUNTIME IDENTITY AUTHORITY.
HARD-002 DOES NOT REMOVE LEGACY IDENTITY COLUMNS.

## Behavior

Valid states:

- `identity_binding_status != 'bound'` with `principal_id IS NULL`
- `identity_binding_status != 'bound'` with `principal_id IS NOT NULL`
- `identity_binding_status = 'bound'` with `principal_id IS NOT NULL`

Invalid state:

- `identity_binding_status = 'bound'` with `principal_id IS NULL`

This is intentionally not a global `principal_id NOT NULL`. AUTH-003C proved
that UNBOUND memberships legitimately exist and may not yet have a canonical
principal.

## Migration 0183

`migrations/postgres/0183_bound_membership_principal_integrity.sql` adds the
check through an idempotent `pg_constraint` guard:

```sql
ALTER TABLE tenant_users
    ADD CONSTRAINT chk_bound_requires_principal_id
    CHECK (
        identity_binding_status <> 'bound'
        OR principal_id IS NOT NULL
    )
    NOT VALID;

ALTER TABLE tenant_users
    VALIDATE CONSTRAINT chk_bound_requires_principal_id;
```

`VALIDATE CONSTRAINT` is safe to repeat.

The migration performs no `INSERT`, `UPDATE`, `DELETE`, `TRUNCATE`, backfill,
legacy cleanup, or data repair.

## Deployment Preconditions

Production precondition, already manually verified:

```sql
SELECT COUNT(*)
FROM tenant_users
WHERE identity_binding_status = 'bound'
  AND principal_id IS NULL;
```

Expected result:

```text
0
```

Deployment order:

1. PR-AUTH-004 runtime already live.
2. AUTH-003C production reconciliation already green.
3. BOUND + NULL production count already zero.
4. Deploy HARD-002 migration 0183.
5. Migration validates `chk_bound_requires_principal_id`.
6. Application continues normally.
7. Future invitation acceptance proves runtime + DB enforcement together.

If violating rows exist, `VALIDATE CONSTRAINT` fails. That is a deployment
blocker, not a warning.

## Lock And Rewrite Analysis

`ADD CONSTRAINT ... NOT VALID` briefly takes `ACCESS EXCLUSIVE` on
`tenant_users` to update catalog metadata. Existing rows are not scanned and no
table rewrite occurs.

`VALIDATE CONSTRAINT` takes `SHARE UPDATE EXCLUSIVE` on `tenant_users` and scans
existing rows. Concurrent reads and ordinary writes continue; conflicting DDL is
blocked. Future writes are checked immediately once the constraint has been
added, including before validation completes.

Expected deployment impact is a brief metadata lock plus a validation scan. No
table rewrite and no data movement occur.

## Rollback

Constraint-only rollback:

```sql
ALTER TABLE tenant_users
    DROP CONSTRAINT IF EXISTS chk_bound_requires_principal_id;
```

Rollback must not:

- remove `tenant_users.principal_id`
- alter canonical principal or external identity data
- remove the HARD-001 authority_version trigger
- delete principals
- delete external identities
- restore legacy runtime authority
- remove legacy `tenant_users.identity_*` columns

No automated rollback is implemented.

## Compatibility

PR-AUTH-004 already writes `tenant_users.principal_id` before setting
`identity_binding_status = 'bound'`. HARD-002 only enforces that ordering at the
database layer. It does not change login behavior, session issuance, token
claims, RBAC, canonical resolver semantics, invitation-flow application logic,
tenant membership semantics, lifecycle behavior, or legacy identity columns.
