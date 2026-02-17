CREATE TABLE IF NOT EXISTS audit_export_jobs (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    job_id TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    start_utc TEXT NOT NULL,
    end_utc TEXT NOT NULL,
    purpose TEXT NOT NULL,
    retention_class TEXT NOT NULL,
    triggered_by TEXT NOT NULL,
    force BOOLEAN NOT NULL DEFAULT false,
    export_id TEXT,
    storage_uri TEXT,
    error_code TEXT
);

CREATE INDEX IF NOT EXISTS ix_audit_exports_created_at ON audit_exports(created_at);
CREATE INDEX IF NOT EXISTS ix_audit_exports_retention_class ON audit_exports(retention_class);
CREATE INDEX IF NOT EXISTS ix_audit_export_jobs_tenant_status ON audit_export_jobs(tenant_id, status);

ALTER TABLE audit_export_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_export_jobs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_export_jobs_tenant_isolation ON audit_export_jobs;
CREATE POLICY audit_export_jobs_tenant_isolation ON audit_export_jobs
USING (tenant_id = current_setting('app.tenant_id', true) OR current_setting('app.tenant_id', true) = 'system')
WITH CHECK (tenant_id = current_setting('app.tenant_id', true) OR current_setting('app.tenant_id', true) = 'system');
