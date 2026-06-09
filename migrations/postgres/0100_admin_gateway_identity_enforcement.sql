-- PR 2: provider-neutral Admin Gateway identity enforcement state.
-- Stores only short-lived correlation and validated identity metadata.
-- Raw provider tokens, invite tokens, refresh tokens, and secrets are forbidden.

CREATE TABLE IF NOT EXISTS tenant_identity_auth_states (
    id VARCHAR(128) PRIMARY KEY,
    tenant_id VARCHAR(128) NOT NULL,
    invitation_id VARCHAR(128) NOT NULL,
    membership_id VARCHAR(128),
    state_digest VARCHAR(64) NOT NULL,
    correlation_id VARCHAR(128) NOT NULL,
    requested_provider VARCHAR(64),
    requested_connection_id VARCHAR(256),
    return_url VARCHAR(1024),
    status VARCHAR(32) NOT NULL DEFAULT 'started',
    validated_provider VARCHAR(64),
    validated_issuer VARCHAR(512),
    validated_subject VARCHAR(512),
    validated_email VARCHAR(256),
    validated_email_verified BOOLEAN,
    validated_connection_id VARCHAR(256),
    validated_organization_id VARCHAR(256),
    validated_identity_type VARCHAR(32),
    expires_at TIMESTAMPTZ NOT NULL,
    validated_at TIMESTAMPTZ,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_tenant_identity_auth_state_digest UNIQUE (state_digest),
    CONSTRAINT uq_tenant_identity_auth_state_correlation UNIQUE (tenant_id, correlation_id),
    CONSTRAINT chk_tenant_identity_auth_state_status CHECK (status IN ('started','validated','bound','rejected','expired'))
);

CREATE INDEX IF NOT EXISTS ix_tenant_identity_auth_state_tenant_expiry ON tenant_identity_auth_states(tenant_id, expires_at);
CREATE INDEX IF NOT EXISTS ix_tenant_identity_auth_state_invitation ON tenant_identity_auth_states(tenant_id, invitation_id);

ALTER TABLE tenant_identity_auth_states ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_identity_auth_states FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_identity_auth_states_tenant_isolation ON tenant_identity_auth_states;
CREATE POLICY tenant_identity_auth_states_tenant_isolation ON tenant_identity_auth_states USING (tenant_id=current_setting('app.tenant_id',TRUE)) WITH CHECK (tenant_id=current_setting('app.tenant_id',TRUE));
