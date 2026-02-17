CREATE TABLE IF NOT EXISTS audit_ledger (
    id BIGSERIAL PRIMARY KEY,
    session_id TEXT NOT NULL,
    cycle_kind TEXT NOT NULL,
    timestamp_utc TEXT NOT NULL,
    invariant_id TEXT NOT NULL,
    decision TEXT NOT NULL,
    config_hash TEXT NOT NULL,
    policy_hash TEXT NOT NULL,
    git_commit TEXT NOT NULL,
    runtime_version TEXT NOT NULL,
    host_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL DEFAULT 'unknown',
    sha256_engine_code_hash TEXT NOT NULL DEFAULT '',
    sha256_self_hash TEXT NOT NULL UNIQUE,
    previous_record_hash TEXT NOT NULL,
    signature TEXT NOT NULL,
    details_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_audit_ledger_session_id ON audit_ledger(session_id);
CREATE INDEX IF NOT EXISTS ix_audit_ledger_timestamp_utc ON audit_ledger(timestamp_utc);
CREATE INDEX IF NOT EXISTS ix_audit_ledger_invariant_id ON audit_ledger(invariant_id);

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'audit_ledger_append_only_guard') THEN
        CREATE FUNCTION audit_ledger_append_only_guard() RETURNS trigger AS $fn$
        BEGIN
            RAISE EXCEPTION 'audit_ledger is append-only';
        END;
        $fn$ LANGUAGE plpgsql;
    END IF;
END;
$$;

DROP TRIGGER IF EXISTS audit_ledger_append_only_update ON audit_ledger;
CREATE TRIGGER audit_ledger_append_only_update
BEFORE UPDATE ON audit_ledger
FOR EACH ROW EXECUTE FUNCTION audit_ledger_append_only_guard();

DROP TRIGGER IF EXISTS audit_ledger_append_only_delete ON audit_ledger;
CREATE TRIGGER audit_ledger_append_only_delete
BEFORE DELETE ON audit_ledger
FOR EACH ROW EXECUTE FUNCTION audit_ledger_append_only_guard();

ALTER TABLE audit_ledger ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_ledger FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS audit_ledger_tenant_isolation ON audit_ledger;
CREATE POLICY audit_ledger_tenant_isolation
ON audit_ledger
USING (tenant_id = current_setting('app.tenant_id', true))
WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
REVOKE TRUNCATE ON audit_ledger FROM PUBLIC;
