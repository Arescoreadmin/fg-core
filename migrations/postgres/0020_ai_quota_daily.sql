CREATE TABLE IF NOT EXISTS ai_quota_daily (
    id BIGSERIAL PRIMARY KEY,
    quota_scope TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    device_id TEXT,
    usage_day DATE NOT NULL,
    token_limit INTEGER NOT NULL DEFAULT 0,
    used_tokens INTEGER NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_ai_quota_daily_scope_day UNIQUE (quota_scope, usage_day)
);

CREATE INDEX IF NOT EXISTS ix_ai_quota_daily_tenant_day
    ON ai_quota_daily(tenant_id, usage_day);

ALTER TABLE IF EXISTS ai_quota_daily ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS ai_quota_daily FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname='public' AND tablename='ai_quota_daily' AND policyname='ai_quota_daily_tenant_isolation'
    ) THEN
        CREATE POLICY ai_quota_daily_tenant_isolation ON ai_quota_daily
            USING (tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
    END IF;
END $$;
