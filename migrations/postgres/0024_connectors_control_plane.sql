CREATE TABLE IF NOT EXISTS connectors_tenant_state (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    connector_id TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    config_hash TEXT NOT NULL,
    last_success_at TIMESTAMPTZ,
    last_error_code TEXT,
    failure_count INTEGER NOT NULL DEFAULT 0,
    updated_by TEXT NOT NULL DEFAULT 'unknown',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_connectors_tenant_state UNIQUE (tenant_id, connector_id)
);

CREATE TABLE IF NOT EXISTS connectors_credentials (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    connector_id TEXT NOT NULL,
    credential_id TEXT NOT NULL DEFAULT 'primary',
    principal_id TEXT NOT NULL,
    auth_mode TEXT NOT NULL,
    ciphertext TEXT NOT NULL,
    kek_version TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS connectors_audit_ledger (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    connector_id TEXT NOT NULL,
    action TEXT NOT NULL,
    params_hash TEXT NOT NULL,
    actor TEXT NOT NULL,
    request_id TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_connectors_tenant_state_tenant_enabled
    ON connectors_tenant_state(tenant_id, enabled);
CREATE INDEX IF NOT EXISTS ix_connectors_credentials_tenant_connector
    ON connectors_credentials(tenant_id, connector_id);
CREATE INDEX IF NOT EXISTS ix_connectors_audit_tenant_connector
    ON connectors_audit_ledger(tenant_id, connector_id, created_at);

ALTER TABLE connectors_tenant_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE connectors_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE connectors_audit_ledger ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE tablename='connectors_tenant_state' AND policyname='connectors_tenant_state_tenant_isolation'
    ) THEN
        CREATE POLICY connectors_tenant_state_tenant_isolation ON connectors_tenant_state
            USING (
                tenant_id IS NOT NULL
                AND current_setting('app.tenant_id', true) IS NOT NULL
                AND tenant_id = current_setting('app.tenant_id', true)
            )
            WITH CHECK (
                tenant_id IS NOT NULL
                AND current_setting('app.tenant_id', true) IS NOT NULL
                AND tenant_id = current_setting('app.tenant_id', true)
            );
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE tablename='connectors_credentials' AND policyname='connectors_credentials_tenant_isolation'
    ) THEN
        CREATE POLICY connectors_credentials_tenant_isolation ON connectors_credentials
            USING (
                tenant_id IS NOT NULL
                AND current_setting('app.tenant_id', true) IS NOT NULL
                AND tenant_id = current_setting('app.tenant_id', true)
            )
            WITH CHECK (
                tenant_id IS NOT NULL
                AND current_setting('app.tenant_id', true) IS NOT NULL
                AND tenant_id = current_setting('app.tenant_id', true)
            );
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE tablename='connectors_audit_ledger' AND policyname='connectors_audit_ledger_tenant_isolation'
    ) THEN
        CREATE POLICY connectors_audit_ledger_tenant_isolation ON connectors_audit_ledger
            USING (
                tenant_id IS NOT NULL
                AND current_setting('app.tenant_id', true) IS NOT NULL
                AND tenant_id = current_setting('app.tenant_id', true)
            )
            WITH CHECK (
                tenant_id IS NOT NULL
                AND current_setting('app.tenant_id', true) IS NOT NULL
                AND tenant_id = current_setting('app.tenant_id', true)
            );
    END IF;
END $$;
