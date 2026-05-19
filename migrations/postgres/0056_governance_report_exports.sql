-- 0055_governance_report_exports.sql
-- Deterministic governance export metadata, reviewer finalization, and lineage.

ALTER TABLE reports
    ADD COLUMN IF NOT EXISTS manifest_hash TEXT,
    ADD COLUMN IF NOT EXISTS manifest_version TEXT NOT NULL DEFAULT 'governance-export-manifest-v1',
    ADD COLUMN IF NOT EXISTS export_version TEXT NOT NULL DEFAULT 'governance-export-v1',
    ADD COLUMN IF NOT EXISTS report_version INTEGER NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS reviewer_ref TEXT,
    ADD COLUMN IF NOT EXISTS approval_status TEXT NOT NULL DEFAULT 'unapproved',
    ADD COLUMN IF NOT EXISTS finalized_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS finalized_manifest_hash TEXT,
    ADD COLUMN IF NOT EXISTS previous_report_id TEXT,
    ADD COLUMN IF NOT EXISTS superseded_by_report_id TEXT,
    ADD COLUMN IF NOT EXISTS evidence_snapshot_version TEXT NOT NULL DEFAULT 'evidence-snapshot-v1',
    ADD COLUMN IF NOT EXISTS scoring_contract_version TEXT NOT NULL DEFAULT 'assessment-scoring-v1',
    ADD COLUMN IF NOT EXISTS framework_mapping_version TEXT NOT NULL DEFAULT 'framework-mapping-v1';

CREATE INDEX IF NOT EXISTS ix_reports_manifest_hash ON reports(manifest_hash);
CREATE INDEX IF NOT EXISTS ix_reports_previous_report_id ON reports(previous_report_id);
CREATE INDEX IF NOT EXISTS ix_reports_superseded_by_report_id ON reports(superseded_by_report_id);
CREATE INDEX IF NOT EXISTS ix_reports_finalized_at ON reports(finalized_at);

ALTER TABLE reports
    DROP CONSTRAINT IF EXISTS ck_reports_approval_status;

ALTER TABLE reports
    ADD CONSTRAINT ck_reports_approval_status
    CHECK (approval_status IN ('unapproved','assigned','approved','finalized','superseded'));
