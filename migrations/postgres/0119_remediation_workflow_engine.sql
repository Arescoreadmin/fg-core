-- Migration 0119: Remediation Workflow Engine (PR 13.2)
--
-- Extends the remediation audit trail to capture transition reasons.
-- The remediation_tasks.status column is a VARCHAR(32); no ALTER TABLE is
-- needed for the new enum values (planned, in_progress, accepted_risk) —
-- they are application-level values and the column has no CHECK constraint.
--
-- This migration:
--   1. Adds the `reason` column to remediation_task_audits (nullable TEXT).
--      Required for ACCEPTED_RISK transitions; optional for others.
--   2. Adds a composite index for governance reporting: status × tenant × created_at.
--
-- Safe:       IF NOT EXISTS / IF NOT EXISTS guards throughout.
-- Reversible: rollback script drops the column and index.
-- Idempotent: re-running is a no-op.

ALTER TABLE remediation_task_audits
    ADD COLUMN IF NOT EXISTS reason TEXT;

-- Supports future reporting queries:
--   SELECT * FROM remediation_tasks
--   WHERE tenant_id = $1 AND status = $2
--   ORDER BY created_at DESC
CREATE INDEX IF NOT EXISTS ix_remediation_tasks_tenant_status_created
    ON remediation_tasks (tenant_id, status, created_at DESC);
