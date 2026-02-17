-- Audit ledger (append-only) + shared append_only_guard() shim
-- Hardening:
-- - Replay-safe (DROP TRIGGER IF EXISTS, CREATE OR REPLACE FUNCTION)
-- - No nested $$ collisions (uses distinct $do$ / $fn$ / $body$ tags)
-- - Provides append_only_guard() for other migrations

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

CREATE INDEX IF NOT EXISTS ix_audit_ledger_session_id
    ON audit_ledger(session_id);

CREATE INDEX IF NOT EXISTS ix_audit_ledger_timestamp_utc
    ON audit_ledger(timestamp_utc);

CREATE INDEX IF NOT EXISTS ix_audit_ledger_invariant_id
    ON audit_ledger(invariant_id);

-- Append-only guard for audit_ledger (authoritative implementation)
DO $do$
BEGIN
    IF to_regprocedure('audit_ledger_append_only_guard()') IS NULL THEN
        EXECUTE $fn$
            CREATE FUNCTION audit_ledger_append_only_guard()
            RETURNS trigger
            LANGUAGE plpgsql
            AS $body$
            BEGIN
                -- stable error code for "writes not allowed"
                RAISE EXCEPTION 'audit_ledger is append-only'
                    USING ERRCODE = '42501';
            END;
            $body$;
        $fn$;
    END IF;
END;
$do$;

-- Generic append-only guard used by other append-only tables
-- (delegates to the authoritative ledger guard)
DO $do$
BEGIN
    IF to_regprocedure('append_only_guard()') IS NULL THEN
        EXECUTE $fn$
            CREATE FUNCTION append_only_guard()
            RETURNS trigger
            LANGUAGE plpgsql
            AS $body$
            BEGIN
                RETURN audit_ledger_append_only_guard();
            END;
            $body$;
        $fn$;
    END IF;
END;
$do$;

-- Enforce append-only at the table level (deterministic trigger names)
DROP TRIGGER IF EXISTS audit_ledger_append_only_update ON audit_ledger;
CREATE TRIGGER audit_ledger_append_only_update
BEFORE UPDATE ON audit_ledger
FOR EACH ROW
EXECUTE FUNCTION audit_ledger_append_only_guard();

DROP TRIGGER IF EXISTS audit_ledger_append_only_delete ON audit_ledger;
CREATE TRIGGER audit_ledger_append_only_delete
BEFORE DELETE ON audit_ledger
FOR EACH ROW
EXECUTE FUNCTION audit_ledger_append_only_guard();

-- RLS enforcement
ALTER TABLE audit_ledger ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_ledger FORCE ROW LEVEL SECURITY;

-- Tenant isolation policy
DROP POLICY IF EXISTS audit_ledger_tenant_isolation ON audit_ledger;
CREATE POLICY audit_ledger_tenant_isolation
ON audit_ledger
USING (tenant_id = current_setting('app.tenant_id', true))
WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

-- Reduce blast radius
REVOKE TRUNCATE ON audit_ledger FROM PUBLIC;
