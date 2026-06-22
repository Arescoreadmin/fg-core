-- Migration: create governance_workflows table + add finding_id column
-- Root cause repair (PR 8 CI regression):
--   PR 6 introduced governance_workflows via ORM only — no SQL migration was
--   ever written.  SQLite dev path used Base.metadata.create_all(); PostgreSQL
--   migration replay failed with "relation does not exist" when migration 0061
--   tried to ALTER a table that had never been created by any prior migration.
--
-- This migration:
--   1. Creates governance_workflows for fresh PostgreSQL databases (idempotent).
--   2. Adds finding_id for databases where the table already existed without it
--      (created by create_all in dev/staging environments).
--   3. Creates all indexes with IF NOT EXISTS so replay is safe in every state.
--
-- Idempotency guarantees:
--   - Fresh Postgres replay from zero: CREATE TABLE runs; ALTER TABLE is no-op.
--   - Existing DB without finding_id:  CREATE TABLE is no-op; ALTER TABLE adds column.
--   - Existing DB with finding_id:     both are no-ops; indexes upserted safely.

BEGIN;

CREATE TABLE IF NOT EXISTS governance_workflows (
    id                  TEXT        NOT NULL,
    tenant_id           TEXT        NOT NULL,
    engagement_id       TEXT        NOT NULL,
    template_name       TEXT        NOT NULL,
    title               TEXT        NOT NULL,
    description         TEXT        NOT NULL,
    state               TEXT        NOT NULL DEFAULT 'draft',
    priority            TEXT        NOT NULL DEFAULT 'medium',
    assigned_to_role    TEXT        NOT NULL,
    context_ref_type    TEXT        NOT NULL,
    context_ref_id      TEXT        NOT NULL,
    due_at              TEXT        NOT NULL,
    created_by          TEXT        NOT NULL,
    created_at          TEXT        NOT NULL,
    updated_at          TEXT        NOT NULL,
    finding_id          TEXT,
    resolved_at         TEXT,
    archived_at         TEXT,
    metadata            JSONB       NOT NULL DEFAULT '{}',
    schema_version      TEXT        NOT NULL DEFAULT '1.0',
    PRIMARY KEY (id)
);

-- Handles databases where the table existed before this migration without finding_id
ALTER TABLE governance_workflows
    ADD COLUMN IF NOT EXISTS finding_id TEXT;

CREATE INDEX IF NOT EXISTS ix_governance_workflows_tenant_id
    ON governance_workflows (tenant_id);

CREATE INDEX IF NOT EXISTS ix_gw_workflows_engagement_state
    ON governance_workflows (tenant_id, engagement_id, state);

CREATE INDEX IF NOT EXISTS ix_gw_workflows_tenant_context
    ON governance_workflows (tenant_id, context_ref_id);

CREATE INDEX IF NOT EXISTS ix_gw_workflows_tenant_due
    ON governance_workflows (tenant_id, due_at);

CREATE INDEX IF NOT EXISTS ix_gw_workflows_finding_id
    ON governance_workflows (tenant_id, finding_id)
    WHERE finding_id IS NOT NULL;

COMMIT;
