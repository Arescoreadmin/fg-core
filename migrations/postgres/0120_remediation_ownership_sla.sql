-- Migration 0120: Remediation Ownership, Due Dates & SLA Authority (PR 13.3)
--
-- Extends remediation_tasks with ownership and SLA accountability fields.
-- All columns are nullable (backward safe; existing rows get NULL).
-- Includes a backfill UPDATE to populate sla_target_days and sla_breach_at
-- for any existing rows based on their priority values.
--
-- Safe:       ADD COLUMN IF NOT EXISTS throughout.
-- Reversible: rollback drops the columns.
-- Idempotent: re-running is a no-op.

ALTER TABLE remediation_tasks ADD COLUMN IF NOT EXISTS assigned_user_id TEXT;
ALTER TABLE remediation_tasks ADD COLUMN IF NOT EXISTS assigned_user_email TEXT;
ALTER TABLE remediation_tasks ADD COLUMN IF NOT EXISTS assigned_display_name TEXT;
ALTER TABLE remediation_tasks ADD COLUMN IF NOT EXISTS assigned_at TIMESTAMPTZ;
ALTER TABLE remediation_tasks ADD COLUMN IF NOT EXISTS due_date TIMESTAMPTZ;
ALTER TABLE remediation_tasks ADD COLUMN IF NOT EXISTS sla_target_days INTEGER;
ALTER TABLE remediation_tasks ADD COLUMN IF NOT EXISTS sla_breach_at TIMESTAMPTZ;
ALTER TABLE remediation_tasks ADD COLUMN IF NOT EXISTS ownership_reason TEXT;
ALTER TABLE remediation_tasks ADD COLUMN IF NOT EXISTS last_assignment_change_at TIMESTAMPTZ;

-- Backfill SLA targets for existing tasks (idempotent — only sets NULL rows)
UPDATE remediation_tasks
SET sla_target_days = CASE priority
    WHEN 'critical'    THEN 14
    WHEN 'high'        THEN 30
    WHEN 'medium'      THEN 60
    WHEN 'low'         THEN 90
    ELSE NULL
END
WHERE sla_target_days IS NULL;

-- Backfill sla_breach_at from created_at + sla_target_days
UPDATE remediation_tasks
SET sla_breach_at = (
    created_at::timestamptz + (sla_target_days || ' days')::interval
)
WHERE sla_target_days IS NOT NULL AND sla_breach_at IS NULL;

-- Ownership and SLA query indexes
CREATE INDEX IF NOT EXISTS ix_remediation_tasks_assigned_user
    ON remediation_tasks (tenant_id, assigned_user_id);

CREATE INDEX IF NOT EXISTS ix_remediation_tasks_due_date
    ON remediation_tasks (tenant_id, due_date);

CREATE INDEX IF NOT EXISTS ix_remediation_tasks_sla_breach_at
    ON remediation_tasks (tenant_id, sla_breach_at);
