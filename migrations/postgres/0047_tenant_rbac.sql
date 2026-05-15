-- 0047_tenant_rbac.sql
-- PR 57 — Intra-tenant RBAC.
--
-- Adds:
--   api_keys.role TEXT        — nullable; stores built-in role name for the key
--   tenant_role_audit         — immutable append-only log for all role changes
--
-- Both operations are fully idempotent.

-- Add role column to api_keys (idempotent guard)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_name = 'api_keys' AND column_name = 'role'
    ) THEN
        ALTER TABLE api_keys ADD COLUMN role TEXT;
    END IF;
END $$;

-- Append-only audit table for role assignment / revocation events
CREATE TABLE IF NOT EXISTS tenant_role_audit (
    id                BIGSERIAL PRIMARY KEY,
    event_id          TEXT      NOT NULL UNIQUE,
    tenant_id         TEXT      NOT NULL,
    actor_key_prefix  TEXT,
    action            TEXT      NOT NULL,
    target_key_prefix TEXT,
    role_name         TEXT,
    timestamp         TEXT      NOT NULL,
    success           INTEGER   NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS ix_tenant_role_audit_tenant_ts
    ON tenant_role_audit (tenant_id, timestamp DESC);

-- Enforce append-only on PostgreSQL via rules
CREATE OR REPLACE RULE tenant_role_audit_no_update AS
    ON UPDATE TO tenant_role_audit DO INSTEAD NOTHING;

CREATE OR REPLACE RULE tenant_role_audit_no_delete AS
    ON DELETE TO tenant_role_audit DO INSTEAD NOTHING;
