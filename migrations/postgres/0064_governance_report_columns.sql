-- PR 15: Add engagement_id, report_type, compiled_by, section_hashes, signature
-- to governance_reports. All changes are idempotent.
-- engagement_id must be added before the indexes that reference it.

ALTER TABLE governance_reports ADD COLUMN IF NOT EXISTS engagement_id TEXT;
ALTER TABLE governance_reports ADD COLUMN IF NOT EXISTS report_type TEXT;
ALTER TABLE governance_reports ADD COLUMN IF NOT EXISTS compiled_by TEXT;
ALTER TABLE governance_reports ADD COLUMN IF NOT EXISTS section_hashes JSONB;
ALTER TABLE governance_reports ADD COLUMN IF NOT EXISTS signature TEXT;

-- Composite indexes for common query paths (tenant + engagement scope)
CREATE INDEX IF NOT EXISTS ix_governance_reports_tenant_engagement_version
    ON governance_reports (tenant_id, engagement_id, version);

CREATE INDEX IF NOT EXISTS ix_governance_reports_tenant_engagement_type
    ON governance_reports (tenant_id, engagement_id, report_type);

CREATE INDEX IF NOT EXISTS ix_governance_reports_tenant_engagement_finalized
    ON governance_reports (tenant_id, engagement_id, is_finalized);
