-- additive nuclear hardening tables and RLS

CREATE TABLE IF NOT EXISTS evidence_runs (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    plane_id TEXT NOT NULL,
    artifact_type TEXT NOT NULL,
    artifact_path TEXT NOT NULL,
    artifact_sha256 TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    git_sha TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status TEXT NOT NULL,
    summary_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    retention_class TEXT NOT NULL DEFAULT 'hot',
    anchor_status TEXT NOT NULL DEFAULT 'none'
);

CREATE TABLE IF NOT EXISTS retention_policies (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    artifact_type TEXT NOT NULL,
    retention_days INTEGER NOT NULL,
    immutable_required BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, artifact_type)
);

ALTER TABLE IF EXISTS evidence_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS retention_policies ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname='public' AND tablename='evidence_runs' AND policyname='evidence_runs_tenant_isolation'
    ) THEN
        CREATE POLICY evidence_runs_tenant_isolation ON evidence_runs
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
        WHERE schemaname='public' AND tablename='retention_policies' AND policyname='retention_policies_tenant_isolation'
    ) THEN
        CREATE POLICY retention_policies_tenant_isolation ON retention_policies
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
