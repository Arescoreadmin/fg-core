CREATE TABLE IF NOT EXISTS agent_device_identities (
    id BIGSERIAL PRIMARY KEY,
    device_id VARCHAR(64) NOT NULL UNIQUE,
    tenant_id VARCHAR(128) NOT NULL,
    cert_fingerprint VARCHAR(64) NOT NULL,
    cert_pem TEXT NOT NULL,
    cert_chain_pem TEXT NULL,
    cert_not_after TIMESTAMPTZ NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'active',
    last_seen_at TIMESTAMPTZ NULL,
    revoked_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_agent_device_identities_tenant_id
    ON agent_device_identities (tenant_id);

CREATE TABLE IF NOT EXISTS agent_commands (
    id BIGSERIAL PRIMARY KEY,
    command_id VARCHAR(64) NOT NULL UNIQUE,
    tenant_id VARCHAR(128) NOT NULL,
    device_id VARCHAR(64) NOT NULL,
    command_type VARCHAR(64) NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    issued_by VARCHAR(128) NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    signature TEXT NOT NULL,
    nonce VARCHAR(128) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'issued',
    acked_at TIMESTAMPTZ NULL
);

CREATE INDEX IF NOT EXISTS ix_agent_commands_tenant_device_status
    ON agent_commands (tenant_id, device_id, status);

CREATE TABLE IF NOT EXISTS agent_policy_bundles (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(128) NOT NULL,
    version VARCHAR(64) NOT NULL,
    policy_hash VARCHAR(64) NOT NULL,
    policy_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    signature TEXT NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_agent_policy_bundles_tenant_hash
    ON agent_policy_bundles (tenant_id, policy_hash);

CREATE TABLE IF NOT EXISTS agent_log_anchors (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(128) NOT NULL,
    device_id VARCHAR(64) NOT NULL,
    hash VARCHAR(64) NOT NULL,
    anchored_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_agent_log_anchors_tenant_device
    ON agent_log_anchors (tenant_id, device_id);

CREATE TABLE IF NOT EXISTS agent_quarantine_events (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(128) NOT NULL,
    device_id VARCHAR(64) NOT NULL,
    action VARCHAR(32) NOT NULL,
    reason VARCHAR(512) NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_agent_quarantine_events_tenant_device
    ON agent_quarantine_events (tenant_id, device_id);

ALTER TABLE agent_device_identities ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_commands ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_policy_bundles ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_log_anchors ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_quarantine_events ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS agent_device_identities_tenant_isolation ON agent_device_identities;
CREATE POLICY agent_device_identities_tenant_isolation ON agent_device_identities
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

DROP POLICY IF EXISTS agent_commands_tenant_isolation ON agent_commands;
CREATE POLICY agent_commands_tenant_isolation ON agent_commands
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

DROP POLICY IF EXISTS agent_policy_bundles_tenant_isolation ON agent_policy_bundles;
CREATE POLICY agent_policy_bundles_tenant_isolation ON agent_policy_bundles
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

DROP POLICY IF EXISTS agent_log_anchors_tenant_isolation ON agent_log_anchors;
CREATE POLICY agent_log_anchors_tenant_isolation ON agent_log_anchors
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

DROP POLICY IF EXISTS agent_quarantine_events_tenant_isolation ON agent_quarantine_events;
CREATE POLICY agent_quarantine_events_tenant_isolation ON agent_quarantine_events
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
