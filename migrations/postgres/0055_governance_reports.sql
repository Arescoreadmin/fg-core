BEGIN;

CREATE TABLE IF NOT EXISTS governance_reports (
    id             TEXT NOT NULL PRIMARY KEY,
    assessment_id  TEXT NOT NULL,
    tenant_id      TEXT NOT NULL,
    version        INTEGER NOT NULL DEFAULT 1,
    schema_version TEXT NOT NULL DEFAULT '1.0',
    manifest_hash  TEXT NOT NULL,
    report_json    JSONB NOT NULL,
    generated_at   TEXT NOT NULL,
    is_finalized   BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS ix_governance_reports_assessment ON governance_reports (assessment_id, tenant_id);
CREATE INDEX IF NOT EXISTS ix_governance_reports_tenant ON governance_reports (tenant_id);

ALTER TABLE governance_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE governance_reports FORCE ROW LEVEL SECURITY;

CREATE POLICY governance_reports_tenant_isolation
    ON governance_reports
    USING (tenant_id = current_setting('app.tenant_id', true));

COMMIT;
