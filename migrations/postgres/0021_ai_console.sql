CREATE TABLE IF NOT EXISTS ai_device_registry (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    registered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    telemetry_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    CONSTRAINT uq_ai_device_registry_tenant_device UNIQUE (tenant_id, device_id)
);

CREATE INDEX IF NOT EXISTS ix_ai_device_registry_tenant_enabled
    ON ai_device_registry(tenant_id, enabled);

CREATE TABLE IF NOT EXISTS ai_token_usage (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    user_id TEXT,
    persona TEXT NOT NULL DEFAULT 'default',
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    prompt_tokens INTEGER NOT NULL DEFAULT 0,
    completion_tokens INTEGER NOT NULL DEFAULT 0,
    total_tokens INTEGER NOT NULL DEFAULT 0,
    usage_day DATE NOT NULL,
    estimation_mode TEXT NOT NULL DEFAULT 'estimated',
    request_hash TEXT NOT NULL,
    policy_hash TEXT NOT NULL,
    experience_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_ai_token_usage_tenant_day
    ON ai_token_usage(tenant_id, usage_day);
CREATE INDEX IF NOT EXISTS ix_ai_token_usage_tenant_device_day
    ON ai_token_usage(tenant_id, device_id, usage_day);

ALTER TABLE IF EXISTS ai_device_registry ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS ai_device_registry FORCE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS ai_token_usage ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS ai_token_usage FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname='public' AND tablename='ai_device_registry' AND policyname='ai_device_registry_tenant_isolation'
    ) THEN
        CREATE POLICY ai_device_registry_tenant_isolation ON ai_device_registry
            USING (tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname='public' AND tablename='ai_token_usage' AND policyname='ai_token_usage_tenant_isolation'
    ) THEN
        CREATE POLICY ai_token_usage_tenant_isolation ON ai_token_usage
            USING (tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
    END IF;
END $$;
