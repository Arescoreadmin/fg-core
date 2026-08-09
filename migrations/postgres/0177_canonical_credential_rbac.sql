-- R4.10: Canonical credential RBAC authority
--
-- Creates tenant_credential_roles as the sole canonical RBAC storage.
-- Roles are now bound to credential_id (UUID) from tenant_credentials.
--
-- Historical tenant_role_audit rows (target_key_prefix = str(api_keys.id)) are
-- preserved unchanged. New events write target_credential_id; target_key_prefix
-- is set to NULL for all post-R4.10 audit records.

CREATE TABLE IF NOT EXISTS tenant_credential_roles (
    id              BIGSERIAL       PRIMARY KEY,
    tenant_id       TEXT            NOT NULL,
    credential_id   UUID            NOT NULL REFERENCES tenant_credentials(credential_id),
    role_name       TEXT            NOT NULL,
    granted_at      TIMESTAMPTZ     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    granted_by      TEXT            NOT NULL,
    revoked_at      TIMESTAMPTZ,
    revoked_by      TEXT
);

-- One active role per credential per tenant. Partial index on revoked_at IS NULL
-- is supported in Postgres and SQLite 3.8.9+.
CREATE UNIQUE INDEX IF NOT EXISTS uidx_tcr_active_role
    ON tenant_credential_roles (tenant_id, credential_id)
    WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_tcr_tenant_id
    ON tenant_credential_roles (tenant_id);

ALTER TABLE tenant_credential_roles ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_credential_roles_tenant_isolation ON tenant_credential_roles;
CREATE POLICY tenant_credential_roles_tenant_isolation
    ON tenant_credential_roles USING (tenant_id = current_setting('app.tenant_id', true));

-- Add canonical target identity column to audit log.
-- Historical rows retain target_key_prefix (str repr of api_keys.id); new rows
-- set target_credential_id and leave target_key_prefix NULL.
ALTER TABLE tenant_role_audit
    ADD COLUMN target_credential_id UUID;
