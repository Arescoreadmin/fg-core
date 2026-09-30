-- GOV-DELIVERY-TRANSPORT-001: fa_governed_delivery_attempts
-- Append-only transport attempt evidence.
--
-- Each row records one real transport attempt bound to a governing authorization.
-- outcome: SUCCEEDED | FAILED (not DELIVERED — that is a lifecycle state above
-- this table). SUCCEEDED means the artifact bytes were actually served or
-- transferred. SUCCEEDED != customer receipt. Customer receipt evidence
-- requires portal access confirmation (a separate concern).
--
-- Boundary chain:
--   authorization is not transport
--   transport attempt is not provider acceptance
--   provider acceptance is not delivery
--   delivery is not receipt

CREATE TABLE IF NOT EXISTS fa_governed_delivery_attempts (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    engagement_id VARCHAR(64) NOT NULL,
    authorization_id VARCHAR(64) NOT NULL REFERENCES fa_governed_delivery_authorizations(id),
    report_id VARCHAR(255) NOT NULL,
    report_version_id VARCHAR(64) NOT NULL,
    report_fingerprint VARCHAR(64) NOT NULL,  -- must be non-empty; enforced at service layer
    recipient_type VARCHAR(64) NOT NULL,
    recipient_id VARCHAR(255),                 -- null for operator_direct
    channel VARCHAR(64) NOT NULL,
    transport_type VARCHAR(64) NOT NULL,       -- 'operator_direct' | 'portal_download' | etc.
    artifact_sha256 VARCHAR(64),               -- SHA-256 of served bytes; set on SUCCEEDED
    artifact_bytes_length BIGINT,              -- byte count served; set on SUCCEEDED
    attempted_by VARCHAR(255) NOT NULL,        -- canonical actor subject
    actor_type VARCHAR(32) NOT NULL,
    attempted_at VARCHAR(64) NOT NULL,
    outcome VARCHAR(32) NOT NULL CHECK (outcome IN ('SUCCEEDED', 'FAILED')),
    failure_code VARCHAR(128),                 -- error classification for FAILED rows
    provider_ref VARCHAR(255),                 -- non-secret external reference, if any
    schema_version VARCHAR(16) NOT NULL DEFAULT '1.0'
);

CREATE INDEX IF NOT EXISTS ix_fa_governed_delivery_attempts_tenant_auth
    ON fa_governed_delivery_attempts (tenant_id, authorization_id);
CREATE INDEX IF NOT EXISTS ix_fa_governed_delivery_attempts_tenant_version
    ON fa_governed_delivery_attempts (tenant_id, report_version_id);
CREATE INDEX IF NOT EXISTS ix_fa_governed_delivery_attempts_tenant_engagement
    ON fa_governed_delivery_attempts (tenant_id, engagement_id);

-- Concurrency guard: at most one SUCCEEDED attempt per (tenant, authorization).
-- Two concurrent /execute callers must not both write SUCCEEDED rows for the
-- same authorization; the loser sees a unique-violation and is handled at the
-- service layer as an idempotent success (existing receipt returned).
-- Partial index because FAILED attempts may reoccur.
CREATE UNIQUE INDEX IF NOT EXISTS uq_fa_governed_delivery_attempts_succeeded
    ON fa_governed_delivery_attempts (tenant_id, authorization_id)
    WHERE outcome = 'SUCCEEDED';

-- Tenant isolation via RLS
ALTER TABLE fa_governed_delivery_attempts ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS fa_governed_delivery_attempts_tenant_isolation ON fa_governed_delivery_attempts;
CREATE POLICY fa_governed_delivery_attempts_tenant_isolation ON fa_governed_delivery_attempts
    USING (tenant_id = current_setting('app.tenant_id', true));

-- Append-only enforcement via shared guard
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
