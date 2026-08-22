-- PR-AUTH-002: Add principal_id FK column to tenant_users
--
-- Additive-only. Nullable — no backfill, no NOT NULL constraint.
-- Existing rows remain NULL until PR-AUTH-003 (deterministic backfill).
-- No existing authentication behavior is changed by this migration.
--
-- Rollback: ALTER TABLE tenant_users DROP COLUMN principal_id;

ALTER TABLE tenant_users
    ADD COLUMN IF NOT EXISTS principal_id UUID
        REFERENCES fg_principals(id);

CREATE INDEX IF NOT EXISTS ix_tenant_users_principal_id
    ON tenant_users (principal_id)
    WHERE principal_id IS NOT NULL;
