# tests/postgres/pg_bootstrap.py
from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.engine import Engine

RLS_TABLES = [
    "decisions",
    "decision_evidence_artifacts",
    "api_keys",
    "security_audit_log",
    "policy_change_requests",
]

APPEND_ONLY_TABLES = [
    "decisions",
    "decision_evidence_artifacts",
]


def bootstrap_pg_for_tests(engine: Engine) -> None:
    """
    Bootstraps a Postgres DB to satisfy tests/postgres/* expectations:
      - Tables exist with the columns tests insert/select
      - RLS enabled + FORCE RLS on key tables
      - Per-table policy name matches tests: {table}_tenant_isolation
      - RLS policy uses current_setting('app.tenant_id', true)
      - Append-only enforced: UPDATE/DELETE raise exceptions
      - Idempotent: safe to run repeatedly
    """
    ddl = """
    -- Ensure tenant GUC is settable / referenced
    RESET app.tenant_id;
    -- 1) Core tables (minimal columns needed by tests)

    CREATE TABLE IF NOT EXISTS decisions (
        id BIGSERIAL PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        source TEXT NOT NULL,
        event_id TEXT NOT NULL,
        event_type TEXT NOT NULL,
        request_json JSONB NOT NULL DEFAULT '{}'::jsonb,
        response_json JSONB NOT NULL DEFAULT '{}'::jsonb
    );

    -- Unique constraint expected by tests (your failures showed ux_decisions_tenant_event exists)
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'ux_decisions_tenant_event'
      ) THEN
        ALTER TABLE decisions
          ADD CONSTRAINT ux_decisions_tenant_event UNIQUE (tenant_id, event_id);
      END IF;
    END $$;

    CREATE TABLE IF NOT EXISTS decision_evidence_artifacts (
        id BIGSERIAL PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        decision_id BIGINT NOT NULL REFERENCES decisions(id) ON DELETE CASCADE,
        evidence_sha256 TEXT NOT NULL DEFAULT '',
        storage_path TEXT NOT NULL,
        payload_json JSONB NOT NULL DEFAULT '{}'::jsonb
    );

    -- If an older schema exists missing columns, add them idempotently.
    ALTER TABLE decision_evidence_artifacts
      ADD COLUMN IF NOT EXISTS evidence_sha256 TEXT NOT NULL DEFAULT '';

    ALTER TABLE decision_evidence_artifacts
      ADD COLUMN IF NOT EXISTS storage_path TEXT NOT NULL DEFAULT '';

    ALTER TABLE decision_evidence_artifacts
      ADD COLUMN IF NOT EXISTS payload_json JSONB NOT NULL DEFAULT '{}'::jsonb;

    -- api_keys: tests only care that the table exists + has tenant_id for RLS diagnostics.
    -- Keep it minimal and tolerant.
    CREATE TABLE IF NOT EXISTS api_keys (
        id BIGSERIAL PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        prefix TEXT,
        key_hash TEXT,
        scopes_csv TEXT,
        enabled BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS security_audit_log (
        id BIGSERIAL PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        event_type TEXT,
        payload_json JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS policy_change_requests (
        id BIGSERIAL PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        change_id TEXT NOT NULL,
        change_type TEXT NOT NULL DEFAULT 'unknown',
        proposed_by TEXT NOT NULL DEFAULT 'system',
        proposed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        justification TEXT NOT NULL DEFAULT '',
        rule_definition_json JSONB,
        roe_update_json JSONB,
        simulation_results_json JSONB NOT NULL DEFAULT '{}'::jsonb,
        requires_approval_from_json JSONB NOT NULL DEFAULT '[]'::jsonb,
        approvals_json JSONB NOT NULL DEFAULT '[]'::jsonb,
        status TEXT NOT NULL DEFAULT 'pending',
        deployed_at TIMESTAMPTZ
    );

    ALTER TABLE policy_change_requests
      ADD COLUMN IF NOT EXISTS change_type TEXT NOT NULL DEFAULT 'unknown';
    ALTER TABLE policy_change_requests
      ADD COLUMN IF NOT EXISTS proposed_by TEXT NOT NULL DEFAULT 'system';
    ALTER TABLE policy_change_requests
      ADD COLUMN IF NOT EXISTS rule_definition_json JSONB;
    ALTER TABLE policy_change_requests
      ADD COLUMN IF NOT EXISTS roe_update_json JSONB;
    ALTER TABLE policy_change_requests
      ADD COLUMN IF NOT EXISTS simulation_results_json JSONB NOT NULL DEFAULT '{}'::jsonb;
    ALTER TABLE policy_change_requests
      ADD COLUMN IF NOT EXISTS requires_approval_from_json JSONB NOT NULL DEFAULT '[]'::jsonb;
    ALTER TABLE policy_change_requests
      ADD COLUMN IF NOT EXISTS approvals_json JSONB NOT NULL DEFAULT '[]'::jsonb;
    ALTER TABLE policy_change_requests
      ADD COLUMN IF NOT EXISTS deployed_at TIMESTAMPTZ;

    -- Helpful indexes (not required, just sensible)
    CREATE INDEX IF NOT EXISTS ix_decisions_tenant ON decisions(tenant_id);
    CREATE INDEX IF NOT EXISTS ix_artifacts_tenant ON decision_evidence_artifacts(tenant_id);
    CREATE INDEX IF NOT EXISTS ix_api_keys_tenant ON api_keys(tenant_id);
    CREATE INDEX IF NOT EXISTS ix_audit_tenant ON security_audit_log(tenant_id);
    CREATE INDEX IF NOT EXISTS ix_policy_changes_tenant ON policy_change_requests(tenant_id);

    -- 2) Append-only enforcement: block UPDATE/DELETE for append-only tables
    CREATE OR REPLACE FUNCTION fg_block_update_delete()
    RETURNS trigger AS $$
    BEGIN
      RAISE EXCEPTION 'append-only table: %', TG_TABLE_NAME;
    END;
    $$ LANGUAGE plpgsql;

    -- Drop + recreate triggers (idempotent)
    DO $$
    DECLARE t TEXT;
    BEGIN
      FOREACH t IN ARRAY ARRAY['decisions','decision_evidence_artifacts']
      LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS %I_append_only ON %I', t, t);
        EXECUTE format(
          'CREATE TRIGGER %I_append_only
           BEFORE UPDATE OR DELETE ON %I
           FOR EACH ROW
           EXECUTE FUNCTION fg_block_update_delete()',
           t, t
        );
      END LOOP;
    END $$;

    -- 3) Enable + FORCE RLS and create policies with expected per-table names
    DO $$
    DECLARE t TEXT;
    DECLARE policy TEXT;
    BEGIN
      FOREACH t IN ARRAY ARRAY['decisions','decision_evidence_artifacts','api_keys','security_audit_log','policy_change_requests']
      LOOP
        policy := t || '_tenant_isolation';

        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);

        -- Kill any old policy names (your earlier bootstrap created tenant_isolation)
        EXECUTE format('DROP POLICY IF EXISTS %I ON %I', policy, t);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);

        EXECUTE format(
          'CREATE POLICY %I ON %I
             USING (tenant_id = NULLIF(current_setting(''app.tenant_id'', true), ''''))
             WITH CHECK (tenant_id = NULLIF(current_setting(''app.tenant_id'', true), ''''))',
          policy, t
        );
      END LOOP;
    END $$;
    """

    with engine.begin() as conn:
        conn.execute(text(ddl))
