-- 0183_bound_membership_principal_integrity
-- HARD-002: Enforce BOUND membership -> canonical principal linkage.
--
-- Depends on:
--   0179 fg_principals
--   0180 fg_external_identities
--   0181 tenant_users.principal_id
--   0182 fg_principals authority_version hardening trigger
--   PR-AUTH-004 runtime principal-authority cutover
--
-- This migration enforces exactly:
--
--   identity_binding_status <> 'bound'
--   OR principal_id IS NOT NULL
--
-- It intentionally does NOT add a global NOT NULL constraint on
-- tenant_users.principal_id. Legitimate UNBOUND memberships may keep
-- principal_id NULL.
--
-- No data repair is performed here. If any existing row has
-- identity_binding_status = 'bound' AND principal_id IS NULL, VALIDATE
-- CONSTRAINT fails and the deployment is blocked.
--
-- Rollback guidance, constraint-only:
--   ALTER TABLE tenant_users
--       DROP CONSTRAINT IF EXISTS chk_bound_requires_principal_id;
--
-- Rollback must not remove tenant_users.principal_id, canonical principal data,
-- external identities, the fg_principals authority_version trigger, or any
-- legacy tenant_users.identity_* column.
--
-- Lock / rewrite analysis:
--   - ADD CONSTRAINT ... NOT VALID briefly takes ACCESS EXCLUSIVE on
--     tenant_users for catalog metadata update. It does not scan existing rows.
--   - VALIDATE CONSTRAINT takes SHARE UPDATE EXCLUSIVE on tenant_users and
--     scans existing rows. Concurrent SELECT/INSERT/UPDATE/DELETE continue;
--     conflicting DDL is blocked.
--   - No table rewrite is performed.
--   - Future INSERT/UPDATE statements are checked immediately after the
--     constraint is added, including before validation completes.

DO $do$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint
         WHERE conname = 'chk_bound_requires_principal_id'
           AND conrelid = 'tenant_users'::regclass
    ) THEN
        ALTER TABLE tenant_users
            ADD CONSTRAINT chk_bound_requires_principal_id
            CHECK (
                identity_binding_status <> 'bound'
                OR principal_id IS NOT NULL
            )
            NOT VALID;
    END IF;
END
$do$;

ALTER TABLE tenant_users
    VALIDATE CONSTRAINT chk_bound_requires_principal_id;
