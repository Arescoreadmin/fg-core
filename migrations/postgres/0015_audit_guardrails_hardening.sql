ALTER TABLE audit_exports
    ADD COLUMN IF NOT EXISTS export_range_start_utc TEXT NOT NULL DEFAULT '1970-01-01T00:00:00Z',
    ADD COLUMN IF NOT EXISTS export_range_end_utc TEXT NOT NULL DEFAULT '1970-01-01T00:00:00Z',
    ADD COLUMN IF NOT EXISTS export_range_end_inclusive BOOLEAN NOT NULL DEFAULT true;

CREATE INDEX IF NOT EXISTS ix_audit_exports_tenant_created_at ON audit_exports(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_audit_exports_tenant_range ON audit_exports(tenant_id, export_range_start_utc, export_range_end_utc);

ALTER TABLE audit_export_jobs
    ADD COLUMN IF NOT EXISTS idempotency_key TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS end_inclusive BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN IF NOT EXISTS signing_kid TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS attempts INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS job_event_seq INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS last_error_code TEXT,
    ADD COLUMN IF NOT EXISTS lease_owner TEXT,
    ADD COLUMN IF NOT EXISTS lease_expires_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS ix_audit_export_jobs_tenant_status ON audit_export_jobs(tenant_id, status);

CREATE TABLE IF NOT EXISTS audit_bypass_events (
    id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    tenant_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    operation TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    ticket_id TEXT NOT NULL,
    ttl_seconds INTEGER NOT NULL,
    expires_at_utc TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_audit_bypass_events_tenant_principal ON audit_bypass_events(tenant_id, principal_id, created_at DESC);

CREATE TABLE IF NOT EXISTS audit_retention_runs (
    id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    tenant_id TEXT NOT NULL,
    triggered_by TEXT NOT NULL,
    mode TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    ticket_id TEXT NOT NULL,
    confirmation_token TEXT,
    policy_json JSONB NOT NULL,
    policy_hash TEXT NOT NULL,
    affected_exports_digest TEXT NOT NULL,
    affected_jobs_digest TEXT NOT NULL,
    affected_exports_count INTEGER NOT NULL,
    affected_jobs_count INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_audit_retention_runs_tenant_created ON audit_retention_runs(tenant_id, created_at DESC);

ALTER TABLE audit_bypass_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_bypass_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_bypass_events_tenant_isolation ON audit_bypass_events;
CREATE POLICY audit_bypass_events_tenant_isolation ON audit_bypass_events
USING (tenant_id = current_setting('app.tenant_id', true) OR current_setting('app.tenant_id', true) = 'system')
WITH CHECK (tenant_id = current_setting('app.tenant_id', true) OR current_setting('app.tenant_id', true) = 'system');

ALTER TABLE audit_retention_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_retention_runs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_retention_runs_tenant_isolation ON audit_retention_runs;
CREATE POLICY audit_retention_runs_tenant_isolation ON audit_retention_runs
USING (tenant_id = current_setting('app.tenant_id', true) OR current_setting('app.tenant_id', true) = 'system')
WITH CHECK (tenant_id = current_setting('app.tenant_id', true) OR current_setting('app.tenant_id', true) = 'system');


CREATE OR REPLACE FUNCTION audit_export_jobs_terminal_update_guard_fn() RETURNS trigger AS $$
BEGIN
    IF OLD.status IN ('cancelled', 'succeeded', 'failed') AND NEW.status <> OLD.status THEN
        RAISE EXCEPTION 'audit_export_jobs terminal state is immutable';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_export_jobs_terminal_update_guard ON audit_export_jobs;
CREATE TRIGGER audit_export_jobs_terminal_update_guard
BEFORE UPDATE ON audit_export_jobs
FOR EACH ROW
EXECUTE FUNCTION audit_export_jobs_terminal_update_guard_fn();
