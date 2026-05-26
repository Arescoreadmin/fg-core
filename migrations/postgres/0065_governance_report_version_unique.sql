-- PR 15 follow-up: unique constraint on (tenant_id, engagement_id, version)
-- Prevents duplicate versions from concurrent report generation requests.
-- Partial: only applies to rows where engagement_id IS NOT NULL (legacy
-- assessment-scoped reports have engagement_id NULL and are unaffected).

CREATE UNIQUE INDEX IF NOT EXISTS uq_governance_reports_tenant_engagement_version
    ON governance_reports (tenant_id, engagement_id, version)
    WHERE engagement_id IS NOT NULL;
