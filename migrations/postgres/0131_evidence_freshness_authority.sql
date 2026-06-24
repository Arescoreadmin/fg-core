-- PR 14.6.7: Evidence Freshness Authority

CREATE TABLE IF NOT EXISTS fa_freshness_policies (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    evidence_type VARCHAR(64),
    review_interval_days INTEGER NOT NULL DEFAULT 90,
    verification_interval_days INTEGER NOT NULL DEFAULT 180,
    expiration_interval_days INTEGER NOT NULL DEFAULT 365,
    criticality VARCHAR(32) NOT NULL DEFAULT 'MEDIUM',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at VARCHAR(64) NOT NULL,
    updated_at VARCHAR(64) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_fa_freshness_policies_tenant ON fa_freshness_policies(tenant_id);
CREATE INDEX IF NOT EXISTS idx_fa_freshness_policies_type ON fa_freshness_policies(tenant_id, evidence_type);

CREATE TABLE IF NOT EXISTS fa_evidence_freshness_records (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    evidence_id VARCHAR(64) NOT NULL,
    policy_id VARCHAR(64),
    review_due_at VARCHAR(64),
    verification_due_at VARCHAR(64),
    expiration_due_at VARCHAR(64),
    last_reviewed_at VARCHAR(64),
    last_verified_at VARCHAR(64),
    freshness_score INTEGER NOT NULL DEFAULT 100,
    freshness_state VARCHAR(32) NOT NULL DEFAULT 'CURRENT',
    created_at VARCHAR(64) NOT NULL,
    updated_at VARCHAR(64) NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS uidx_fa_freshness_records_evidence ON fa_evidence_freshness_records(tenant_id, evidence_id);
CREATE INDEX IF NOT EXISTS idx_fa_freshness_records_state ON fa_evidence_freshness_records(tenant_id, freshness_state);

CREATE OR REPLACE FUNCTION prevent_freshness_exception_mutation() RETURNS trigger AS $$
BEGIN RAISE EXCEPTION 'fa_freshness_exceptions is append-only'; END;
$$ LANGUAGE plpgsql;

CREATE TABLE IF NOT EXISTS fa_freshness_exceptions (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    evidence_id VARCHAR(64) NOT NULL,
    reason TEXT NOT NULL,
    approved_by VARCHAR(255) NOT NULL,
    expires_at VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    created_at VARCHAR(64) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_fa_freshness_exceptions_tenant ON fa_freshness_exceptions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_fa_freshness_exceptions_evidence ON fa_freshness_exceptions(tenant_id, evidence_id);

CREATE OR REPLACE TRIGGER trg_freshness_exc_immutable_delete
    BEFORE DELETE ON fa_freshness_exceptions
    FOR EACH ROW EXECUTE FUNCTION prevent_freshness_exception_mutation();
