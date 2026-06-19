-- Migration 0119: Remediation Workflow Engine (PR 13.2)
--
-- Self-contained: creates both remediation tables if they do not exist.
-- In the Docker Compose / Postgres path, frostgate-migrate runs ONLY SQL
-- migrations (python -m api.db_migrations --apply) — it never calls
-- Base.metadata.create_all(). PR 13.1 introduced the ORM models but shipped
-- no SQL migration; this migration is therefore the authoritative Postgres
-- schema source for both tables.
--
-- Changes:
--   1. Creates remediation_tasks if not exists (all columns, indexes, RLS).
--   2. Creates remediation_task_audits if not exists (all columns incl. `reason`,
--      all indexes, RLS). The `reason` column is required for ACCEPTED_RISK
--      transitions and optional for all others.
--   3. ALTER TABLE ... ADD COLUMN IF NOT EXISTS reason TEXT — no-op on fresh
--      installs; handles any Postgres instance that had the ORM tables without
--      this column (e.g. a staging env that ran create_all() from PR 13.1).
--   4. Adds composite reporting index for status × tenant × created_at queries.
--
-- status values (VARCHAR in ORM; no CHECK constraint — enforced at app layer):
--   open | planned | in_progress | closed | accepted_risk
--
-- Safe:       IF NOT EXISTS / IF NOT EXISTS guards throughout.
-- Reversible: rollback drops tables (or columns/indexes for incremental envs).
-- Idempotent: re-running is a no-op.

-- ---------------------------------------------------------------------------
-- remediation_tasks
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS remediation_tasks (
    id                 TEXT        PRIMARY KEY,
    tenant_id          TEXT        NOT NULL,
    finding_id         TEXT        NOT NULL,
    assessment_id      TEXT        NOT NULL,
    title              TEXT        NOT NULL,
    description        TEXT,
    recommended_action TEXT,
    priority           TEXT        NOT NULL,
    status             TEXT        NOT NULL,
    created_by         TEXT        NOT NULL,
    assigned_to        TEXT,
    created_at         TEXT        NOT NULL,
    updated_at         TEXT        NOT NULL,
    closed_at          TEXT,
    task_metadata      JSON        NOT NULL DEFAULT '{}',
    schema_version     TEXT        NOT NULL DEFAULT '1.0'
);

CREATE INDEX IF NOT EXISTS ix_remediation_tasks_tenant_id
    ON remediation_tasks (tenant_id);
CREATE INDEX IF NOT EXISTS ix_remediation_tasks_tenant_finding
    ON remediation_tasks (tenant_id, finding_id);
CREATE INDEX IF NOT EXISTS ix_remediation_tasks_tenant_assessment
    ON remediation_tasks (tenant_id, assessment_id);
CREATE INDEX IF NOT EXISTS ix_remediation_tasks_tenant_status
    ON remediation_tasks (tenant_id, status);
CREATE INDEX IF NOT EXISTS ix_remediation_tasks_tenant_priority
    ON remediation_tasks (tenant_id, priority);

ALTER TABLE remediation_tasks ENABLE ROW LEVEL SECURITY;
ALTER TABLE remediation_tasks FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS remediation_tasks_tenant_isolation ON remediation_tasks;
CREATE POLICY remediation_tasks_tenant_isolation
    ON remediation_tasks
    USING (
        current_setting('app.tenant_id', true) IS NOT NULL
        AND tenant_id = current_setting('app.tenant_id', true)
    );

-- ---------------------------------------------------------------------------
-- remediation_task_audits  (append-only — no UPDATE or DELETE)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS remediation_task_audits (
    id         TEXT  PRIMARY KEY,
    tenant_id  TEXT  NOT NULL,
    task_id    TEXT  NOT NULL,
    event_type TEXT  NOT NULL,
    actor      TEXT  NOT NULL,
    old_state  JSON,
    new_state  JSON,
    reason     TEXT,
    event_at   TEXT  NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_remediation_task_audits_tenant_id
    ON remediation_task_audits (tenant_id);
CREATE INDEX IF NOT EXISTS ix_remediation_audits_tenant_task
    ON remediation_task_audits (tenant_id, task_id);
CREATE INDEX IF NOT EXISTS ix_remediation_audits_task_id
    ON remediation_task_audits (task_id);
CREATE INDEX IF NOT EXISTS ix_remediation_audits_tenant_event_type
    ON remediation_task_audits (tenant_id, event_type);
CREATE INDEX IF NOT EXISTS ix_remediation_audits_event_at
    ON remediation_task_audits (event_at);

ALTER TABLE remediation_task_audits ENABLE ROW LEVEL SECURITY;
ALTER TABLE remediation_task_audits FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS remediation_task_audits_tenant_isolation ON remediation_task_audits;
CREATE POLICY remediation_task_audits_tenant_isolation
    ON remediation_task_audits
    USING (
        current_setting('app.tenant_id', true) IS NOT NULL
        AND tenant_id = current_setting('app.tenant_id', true)
    );

-- ---------------------------------------------------------------------------
-- Idempotent column addition
-- No-op when the table is newly created above (reason is already present).
-- Handles any staging/prod instance that had the ORM tables from PR 13.1
-- without this column.
-- ---------------------------------------------------------------------------
ALTER TABLE remediation_task_audits
    ADD COLUMN IF NOT EXISTS reason TEXT;

-- ---------------------------------------------------------------------------
-- Reporting index: tenant × status × recency (used by governance dashboard)
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS ix_remediation_tasks_tenant_status_created
    ON remediation_tasks (tenant_id, status, created_at DESC);

-- ---------------------------------------------------------------------------
-- Append-only enforcement: remediation_task_audits must never be mutated.
-- Uses the shared append_only_guard() function from migration 0013.
-- DROP + CREATE is idempotent — safe for re-runs and blue/green deployments.
-- ---------------------------------------------------------------------------
DROP TRIGGER IF EXISTS remediation_task_audits_append_only_update
    ON remediation_task_audits;
CREATE TRIGGER remediation_task_audits_append_only_update
    BEFORE UPDATE ON remediation_task_audits
    FOR EACH ROW EXECUTE FUNCTION append_only_guard();

DROP TRIGGER IF EXISTS remediation_task_audits_append_only_delete
    ON remediation_task_audits;
CREATE TRIGGER remediation_task_audits_append_only_delete
    BEFORE DELETE ON remediation_task_audits
    FOR EACH ROW EXECUTE FUNCTION append_only_guard();

REVOKE TRUNCATE ON remediation_task_audits FROM PUBLIC;
