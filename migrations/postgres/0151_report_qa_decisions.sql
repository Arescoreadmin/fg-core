-- REPORT-QA-001: immutable, exact-version QA decision evidence
CREATE TABLE IF NOT EXISTS fa_report_qa_decisions (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    engagement_id VARCHAR(64) NOT NULL,
    report_id VARCHAR(255) NOT NULL,
    report_version_id VARCHAR(64),
    report_version INTEGER NOT NULL DEFAULT 1,
    report_hash VARCHAR(64),
    manifest_hash VARCHAR(64),
    qa_stage VARCHAR(64) NOT NULL,
    decision VARCHAR(32) NOT NULL,
    reviewer_id VARCHAR(255) NOT NULL,
    actor_type VARCHAR(32) NOT NULL,
    reason TEXT,
    created_at VARCHAR(64) NOT NULL,
    schema_version VARCHAR(16) NOT NULL DEFAULT '1.0'
);
CREATE INDEX IF NOT EXISTS ix_fa_report_qa_decisions_tenant_engagement ON fa_report_qa_decisions (tenant_id, engagement_id);
CREATE INDEX IF NOT EXISTS ix_fa_report_qa_decisions_version_stage ON fa_report_qa_decisions (report_version_id, qa_stage);
ALTER TABLE fa_report_qa_decisions ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS fa_report_qa_decisions_tenant_isolation ON fa_report_qa_decisions;
CREATE POLICY fa_report_qa_decisions_tenant_isolation ON fa_report_qa_decisions USING (tenant_id = current_setting('app.tenant_id', true));
DO $$ BEGIN
    IF to_regclass('public.fa_report_qa_decisions') IS NOT NULL THEN
        DROP TRIGGER IF EXISTS fa_report_qa_decisions_append_only_update ON fa_report_qa_decisions;
        CREATE TRIGGER fa_report_qa_decisions_append_only_update BEFORE UPDATE ON fa_report_qa_decisions FOR EACH ROW EXECUTE FUNCTION append_only_guard();
        DROP TRIGGER IF EXISTS fa_report_qa_decisions_append_only_delete ON fa_report_qa_decisions;
        CREATE TRIGGER fa_report_qa_decisions_append_only_delete BEFORE DELETE ON fa_report_qa_decisions FOR EACH ROW EXECUTE FUNCTION append_only_guard();
    END IF;
END $$;
