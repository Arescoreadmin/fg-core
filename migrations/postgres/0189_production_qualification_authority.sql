-- PROD-QUAL-001: canonical production qualification authority
-- Three append-only tables that form the DB-backed qualification authority
-- checked by _require_production_qualified() before client delivery.
--
-- fa_production_qual_requests  — one row per qualification attempt on a report
-- fa_production_attestations   — one row per gate per attempt (unique per gate)
-- fa_qualification_decisions   — one row per finalized decision (unique per attempt)

CREATE TABLE IF NOT EXISTS fa_production_qual_requests (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    engagement_id VARCHAR(64) NOT NULL,
    report_id VARCHAR(255) NOT NULL,
    report_version_id VARCHAR(64),
    report_hash VARCHAR(64),
    requested_by VARCHAR(255) NOT NULL,
    actor_type VARCHAR(32) NOT NULL,
    requested_at VARCHAR(64) NOT NULL,
    schema_version VARCHAR(16) NOT NULL DEFAULT '1.0'
);
CREATE INDEX IF NOT EXISTS ix_fa_production_qual_requests_tenant_report
    ON fa_production_qual_requests (tenant_id, report_id);
CREATE INDEX IF NOT EXISTS ix_fa_production_qual_requests_tenant_engagement
    ON fa_production_qual_requests (tenant_id, engagement_id);
ALTER TABLE fa_production_qual_requests ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS fa_production_qual_requests_tenant_isolation ON fa_production_qual_requests;
CREATE POLICY fa_production_qual_requests_tenant_isolation ON fa_production_qual_requests
    USING (tenant_id = current_setting('app.tenant_id', true));
DO $$ BEGIN
    IF to_regclass('public.fa_production_qual_requests') IS NOT NULL THEN
        DROP TRIGGER IF EXISTS fa_production_qual_requests_no_update ON fa_production_qual_requests;
        CREATE TRIGGER fa_production_qual_requests_no_update
            BEFORE UPDATE ON fa_production_qual_requests
            FOR EACH ROW EXECUTE FUNCTION append_only_guard();
        DROP TRIGGER IF EXISTS fa_production_qual_requests_no_delete ON fa_production_qual_requests;
        CREATE TRIGGER fa_production_qual_requests_no_delete
            BEFORE DELETE ON fa_production_qual_requests
            FOR EACH ROW EXECUTE FUNCTION append_only_guard();
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS fa_production_attestations (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    engagement_id VARCHAR(64) NOT NULL,
    report_id VARCHAR(255) NOT NULL,
    qual_request_id VARCHAR(64) NOT NULL,
    gate_name VARCHAR(128) NOT NULL,
    attested BOOLEAN NOT NULL,
    attested_by VARCHAR(255) NOT NULL,
    actor_type VARCHAR(32) NOT NULL,
    notes TEXT,
    attested_at VARCHAR(64) NOT NULL,
    schema_version VARCHAR(16) NOT NULL DEFAULT '1.0'
);
CREATE INDEX IF NOT EXISTS ix_fa_production_attestations_tenant_report
    ON fa_production_attestations (tenant_id, report_id);
CREATE INDEX IF NOT EXISTS ix_fa_production_attestations_request
    ON fa_production_attestations (qual_request_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_fa_production_attestations_request_gate
    ON fa_production_attestations (tenant_id, qual_request_id, gate_name);
ALTER TABLE fa_production_attestations ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS fa_production_attestations_tenant_isolation ON fa_production_attestations;
CREATE POLICY fa_production_attestations_tenant_isolation ON fa_production_attestations
    USING (tenant_id = current_setting('app.tenant_id', true));
DO $$ BEGIN
    IF to_regclass('public.fa_production_attestations') IS NOT NULL THEN
        DROP TRIGGER IF EXISTS fa_production_attestations_no_update ON fa_production_attestations;
        CREATE TRIGGER fa_production_attestations_no_update
            BEFORE UPDATE ON fa_production_attestations
            FOR EACH ROW EXECUTE FUNCTION append_only_guard();
        DROP TRIGGER IF EXISTS fa_production_attestations_no_delete ON fa_production_attestations;
        CREATE TRIGGER fa_production_attestations_no_delete
            BEFORE DELETE ON fa_production_attestations
            FOR EACH ROW EXECUTE FUNCTION append_only_guard();
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS fa_qualification_decisions (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    engagement_id VARCHAR(64) NOT NULL,
    report_id VARCHAR(255) NOT NULL,
    qual_request_id VARCHAR(64) NOT NULL,
    -- Binding fields: QUALIFIED is bound to the exact version + content fingerprint
    -- that was evaluated. A decision for V1 cannot authorize V2 or a mutated report.
    report_version_id VARCHAR(64) NOT NULL DEFAULT '',
    report_fingerprint VARCHAR(64) NOT NULL DEFAULT '',
    decision VARCHAR(32) NOT NULL,
    decided_by VARCHAR(255) NOT NULL,
    actor_type VARCHAR(32) NOT NULL,
    reason TEXT,
    decided_at VARCHAR(64) NOT NULL,
    schema_version VARCHAR(16) NOT NULL DEFAULT '1.0'
);
CREATE INDEX IF NOT EXISTS ix_fa_qualification_decisions_tenant_report
    ON fa_qualification_decisions (tenant_id, report_id);
CREATE INDEX IF NOT EXISTS ix_fa_qualification_decisions_request
    ON fa_qualification_decisions (qual_request_id);
CREATE INDEX IF NOT EXISTS ix_fa_qualification_decisions_version_binding
    ON fa_qualification_decisions (tenant_id, report_id, report_version_id, report_fingerprint);
CREATE UNIQUE INDEX IF NOT EXISTS uq_fa_qualification_decisions_request
    ON fa_qualification_decisions (tenant_id, qual_request_id);
ALTER TABLE fa_qualification_decisions ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS fa_qualification_decisions_tenant_isolation ON fa_qualification_decisions;
CREATE POLICY fa_qualification_decisions_tenant_isolation ON fa_qualification_decisions
    USING (tenant_id = current_setting('app.tenant_id', true));
DO $$ BEGIN
    IF to_regclass('public.fa_qualification_decisions') IS NOT NULL THEN
        DROP TRIGGER IF EXISTS fa_qualification_decisions_no_update ON fa_qualification_decisions;
        CREATE TRIGGER fa_qualification_decisions_no_update
            BEFORE UPDATE ON fa_qualification_decisions
            FOR EACH ROW EXECUTE FUNCTION append_only_guard();
        DROP TRIGGER IF EXISTS fa_qualification_decisions_no_delete ON fa_qualification_decisions;
        CREATE TRIGGER fa_qualification_decisions_no_delete
            BEFORE DELETE ON fa_qualification_decisions
            FOR EACH ROW EXECUTE FUNCTION append_only_guard();
    END IF;
END $$;
