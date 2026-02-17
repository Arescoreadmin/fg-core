CREATE TABLE IF NOT EXISTS audit_ledger (
    id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    tenant_id TEXT NOT NULL DEFAULT 'system',
    timestamp_utc TEXT NOT NULL,
    invariant_id TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('pass', 'fail')),
    config_hash TEXT NOT NULL,
    policy_hash TEXT NOT NULL,
    git_commit TEXT NOT NULL,
    runtime_version TEXT NOT NULL,
    host_id TEXT NOT NULL,
    sha256_self_hash TEXT NOT NULL UNIQUE,
    previous_record_hash TEXT NOT NULL,
    signature TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_audit_ledger_invariant_id ON audit_ledger(invariant_id);
CREATE INDEX IF NOT EXISTS ix_audit_ledger_tenant_id ON audit_ledger(tenant_id);

CREATE OR REPLACE FUNCTION enforce_audit_ledger_append_only()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'audit_ledger is append-only';
END;
$$;

DROP TRIGGER IF EXISTS audit_ledger_append_only_update ON audit_ledger;
CREATE TRIGGER audit_ledger_append_only_update
BEFORE UPDATE ON audit_ledger
FOR EACH ROW
EXECUTE FUNCTION enforce_audit_ledger_append_only();

DROP TRIGGER IF EXISTS audit_ledger_append_only_delete ON audit_ledger;
CREATE TRIGGER audit_ledger_append_only_delete
BEFORE DELETE ON audit_ledger
FOR EACH ROW
EXECUTE FUNCTION enforce_audit_ledger_append_only();

ALTER TABLE audit_ledger ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_ledger FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS audit_ledger_tenant_isolation ON audit_ledger;
CREATE POLICY audit_ledger_tenant_isolation
ON audit_ledger
USING (tenant_id = current_setting('app.tenant_id', true) OR current_setting('app.tenant_id', true) = 'system')
WITH CHECK (tenant_id = current_setting('app.tenant_id', true) OR current_setting('app.tenant_id', true) = 'system');
