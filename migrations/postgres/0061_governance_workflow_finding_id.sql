-- Migration: add finding_id to governance_workflows
-- PR 8: every workflow created by promotion must link to the finding that
-- caused it.  Nullable so pre-promotion workflows remain valid.

BEGIN;

ALTER TABLE governance_workflows
    ADD COLUMN IF NOT EXISTS finding_id TEXT;

CREATE INDEX IF NOT EXISTS ix_gw_workflows_finding_id
    ON governance_workflows (tenant_id, finding_id)
    WHERE finding_id IS NOT NULL;

COMMIT;
