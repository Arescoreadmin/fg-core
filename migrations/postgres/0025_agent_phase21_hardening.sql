ALTER TABLE agent_device_registry
    ADD COLUMN IF NOT EXISTS ring VARCHAR(16) NOT NULL DEFAULT 'broad';

ALTER TABLE agent_commands
    ADD COLUMN IF NOT EXISTS idempotency_key VARCHAR(128),
    ADD COLUMN IF NOT EXISTS lease_owner VARCHAR(128),
    ADD COLUMN IF NOT EXISTS lease_expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS attempt_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS terminal_state VARCHAR(32);

CREATE INDEX IF NOT EXISTS ix_agent_commands_idempotency_key
    ON agent_commands (idempotency_key);
CREATE INDEX IF NOT EXISTS ix_agent_commands_lease_owner
    ON agent_commands (lease_owner);

CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_commands_tenant_device_idem
    ON agent_commands (tenant_id, device_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

CREATE TABLE IF NOT EXISTS agent_update_rollouts (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(128) NOT NULL UNIQUE,
    canary_percent_per_hour INTEGER NOT NULL DEFAULT 10,
    pilot_percent_per_hour INTEGER NOT NULL DEFAULT 30,
    broad_percent_per_hour INTEGER NOT NULL DEFAULT 100,
    canary_error_budget INTEGER NOT NULL DEFAULT 5,
    canary_error_count INTEGER NOT NULL DEFAULT 0,
    paused BOOLEAN NOT NULL DEFAULT FALSE,
    kill_switch BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS agent_rate_budget_counters (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(128) NOT NULL,
    device_id VARCHAR(64) NULL,
    metric VARCHAR(64) NOT NULL,
    window_start TIMESTAMPTZ NOT NULL,
    count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS connectors_idempotency (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    connector_id TEXT NOT NULL,
    action TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    response_hash TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '7 days')
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_connectors_idempotency_key
ON connectors_idempotency (tenant_id, connector_id, action, idempotency_key);

CREATE INDEX IF NOT EXISTS ix_connectors_idempotency_expiry
ON connectors_idempotency (expires_at);

ALTER TABLE connectors_idempotency ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE tablename='connectors_idempotency'
          AND policyname='connectors_idempotency_tenant_isolation'
    ) THEN
        CREATE POLICY connectors_idempotency_tenant_isolation ON connectors_idempotency
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

CREATE INDEX IF NOT EXISTS ix_agent_rate_budget_counters_scope
    ON agent_rate_budget_counters (tenant_id, device_id, metric, window_start);

ALTER TABLE agent_update_rollouts ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_rate_budget_counters ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS agent_update_rollouts_tenant_isolation ON agent_update_rollouts;
CREATE POLICY agent_update_rollouts_tenant_isolation ON agent_update_rollouts
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

DROP POLICY IF EXISTS agent_rate_budget_counters_tenant_isolation ON agent_rate_budget_counters;
CREATE POLICY agent_rate_budget_counters_tenant_isolation ON agent_rate_budget_counters
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
