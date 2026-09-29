-- GOV-DELIVERY-001: canonical governed client delivery authority
-- Two append-only tables that form the DB-backed delivery authority.
--
-- fa_governed_delivery_requests  — one row per delivery operation
-- fa_governed_delivery_attempts  — one row per attempt (one per request)

CREATE TABLE IF NOT EXISTS fa_governed_delivery_requests (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    engagement_id VARCHAR(64) NOT NULL,
    report_id VARCHAR(255) NOT NULL,
    report_version_id VARCHAR(64) NOT NULL,
    report_fingerprint VARCHAR(64) NOT NULL DEFAULT '',
    qualification_decision_id VARCHAR(64) NOT NULL DEFAULT '',
    requested_by VARCHAR(255) NOT NULL,
    actor_type VARCHAR(32) NOT NULL,
    recipient_type VARCHAR(64) NOT NULL,
    recipient_id VARCHAR(255),
    channel VARCHAR(64) NOT NULL DEFAULT 'direct_download',
    idempotency_key VARCHAR(128) NOT NULL DEFAULT '',
    requested_at VARCHAR(64) NOT NULL,
    schema_version VARCHAR(16) NOT NULL DEFAULT '1.0'
);
CREATE INDEX IF NOT EXISTS ix_fa_governed_delivery_requests_tenant_engagement
    ON fa_governed_delivery_requests (tenant_id, engagement_id);
CREATE INDEX IF NOT EXISTS ix_fa_governed_delivery_requests_tenant_version
    ON fa_governed_delivery_requests (tenant_id, report_version_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_fa_governed_delivery_requests_idempotency
    ON fa_governed_delivery_requests (tenant_id, idempotency_key)
    WHERE idempotency_key != '';
ALTER TABLE fa_governed_delivery_requests ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS fa_governed_delivery_requests_tenant_isolation ON fa_governed_delivery_requests;
CREATE POLICY fa_governed_delivery_requests_tenant_isolation ON fa_governed_delivery_requests
    USING (tenant_id = current_setting('app.tenant_id', true));
DO $$ BEGIN
    IF to_regclass('public.fa_governed_delivery_requests') IS NOT NULL THEN
        DROP TRIGGER IF EXISTS fa_governed_delivery_requests_no_update ON fa_governed_delivery_requests;
        CREATE TRIGGER fa_governed_delivery_requests_no_update
            BEFORE UPDATE ON fa_governed_delivery_requests
            FOR EACH ROW EXECUTE FUNCTION append_only_guard();
        DROP TRIGGER IF EXISTS fa_governed_delivery_requests_no_delete ON fa_governed_delivery_requests;
        CREATE TRIGGER fa_governed_delivery_requests_no_delete
            BEFORE DELETE ON fa_governed_delivery_requests
            FOR EACH ROW EXECUTE FUNCTION append_only_guard();
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS fa_governed_delivery_attempts (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    engagement_id VARCHAR(64) NOT NULL,
    delivery_request_id VARCHAR(64) NOT NULL,
    report_id VARCHAR(255) NOT NULL,
    report_version_id VARCHAR(64) NOT NULL,
    report_fingerprint VARCHAR(64) NOT NULL DEFAULT '',
    qualification_decision_id VARCHAR(64) NOT NULL DEFAULT '',
    recipient_type VARCHAR(64) NOT NULL,
    recipient_id VARCHAR(255),
    channel VARCHAR(64) NOT NULL,
    attempted_by VARCHAR(255) NOT NULL,
    actor_type VARCHAR(32) NOT NULL,
    outcome VARCHAR(32) NOT NULL,
    rejection_reason_code VARCHAR(128),
    provider_ref VARCHAR(255),
    attempted_at VARCHAR(64) NOT NULL,
    schema_version VARCHAR(16) NOT NULL DEFAULT '1.0'
);
CREATE INDEX IF NOT EXISTS ix_fa_governed_delivery_attempts_tenant_engagement
    ON fa_governed_delivery_attempts (tenant_id, engagement_id);
CREATE INDEX IF NOT EXISTS ix_fa_governed_delivery_attempts_tenant_version
    ON fa_governed_delivery_attempts (tenant_id, report_version_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_fa_governed_delivery_attempts_request
    ON fa_governed_delivery_attempts (tenant_id, delivery_request_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_fa_governed_delivery_attempts_delivered
    ON fa_governed_delivery_attempts (tenant_id, engagement_id, report_version_id, recipient_id, channel)
    WHERE outcome = 'DELIVERED';
ALTER TABLE fa_governed_delivery_attempts ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS fa_governed_delivery_attempts_tenant_isolation ON fa_governed_delivery_attempts;
CREATE POLICY fa_governed_delivery_attempts_tenant_isolation ON fa_governed_delivery_attempts
    USING (tenant_id = current_setting('app.tenant_id', true));
DO $$ BEGIN
    IF to_regclass('public.fa_governed_delivery_attempts') IS NOT NULL THEN
        DROP TRIGGER IF EXISTS fa_governed_delivery_attempts_no_update ON fa_governed_delivery_attempts;
        CREATE TRIGGER fa_governed_delivery_attempts_no_update
            BEFORE UPDATE ON fa_governed_delivery_attempts
            FOR EACH ROW EXECUTE FUNCTION append_only_guard();
        DROP TRIGGER IF EXISTS fa_governed_delivery_attempts_no_delete ON fa_governed_delivery_attempts;
        CREATE TRIGGER fa_governed_delivery_attempts_no_delete
            BEFORE DELETE ON fa_governed_delivery_attempts
            FOR EACH ROW EXECUTE FUNCTION append_only_guard();
    END IF;
END $$;
