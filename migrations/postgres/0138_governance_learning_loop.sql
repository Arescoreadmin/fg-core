-- PR 17.6B: Governance Learning Loop Authority

-- ---------------------------------------------------------------------------
-- fa_governance_learning_records — per-outcome learning record (append-only)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS fa_governance_learning_records (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    learning_category VARCHAR(32) NOT NULL,
    control_id VARCHAR(64),
    remediation_category VARCHAR(32) NOT NULL,
    outcome_type VARCHAR(32) NOT NULL,
    effectiveness_before DOUBLE PRECISION,
    effectiveness_after DOUBLE PRECISION,
    effectiveness_delta DOUBLE PRECISION,
    verification_before DOUBLE PRECISION,
    verification_after DOUBLE PRECISION,
    verification_delta DOUBLE PRECISION,
    freshness_before DOUBLE PRECISION,
    freshness_after DOUBLE PRECISION,
    freshness_delta DOUBLE PRECISION,
    forecast_before DOUBLE PRECISION,
    forecast_after DOUBLE PRECISION,
    forecast_delta DOUBLE PRECISION,
    health_before DOUBLE PRECISION,
    health_after DOUBLE PRECISION,
    health_delta DOUBLE PRECISION,
    success_score DOUBLE PRECISION NOT NULL,
    confidence_score DOUBLE PRECISION NOT NULL,
    source_outcome_id VARCHAR(64),
    created_at VARCHAR(64) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_gl_record_tenant
    ON fa_governance_learning_records(tenant_id);
CREATE INDEX IF NOT EXISTS idx_gl_record_tenant_category
    ON fa_governance_learning_records(tenant_id, learning_category);
CREATE INDEX IF NOT EXISTS idx_gl_record_tenant_control
    ON fa_governance_learning_records(tenant_id, control_id);
CREATE INDEX IF NOT EXISTS idx_gl_record_tenant_rem_category
    ON fa_governance_learning_records(tenant_id, remediation_category);
CREATE INDEX IF NOT EXISTS idx_gl_record_source_outcome
    ON fa_governance_learning_records(source_outcome_id);

CREATE OR REPLACE FUNCTION prevent_gl_record_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'fa_governance_learning_records is append-only. Mutation is not permitted.';
END;
$$;

CREATE TRIGGER trg_gl_record_no_update
    BEFORE UPDATE ON fa_governance_learning_records
    FOR EACH ROW EXECUTE FUNCTION prevent_gl_record_mutation();

CREATE TRIGGER trg_gl_record_no_delete
    BEFORE DELETE ON fa_governance_learning_records
    FOR EACH ROW EXECUTE FUNCTION prevent_gl_record_mutation();

-- ---------------------------------------------------------------------------
-- fa_governance_learning_aggregates — mutable per-category aggregates
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS fa_governance_learning_aggregates (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    remediation_category VARCHAR(32) NOT NULL,
    success_count INTEGER NOT NULL DEFAULT 0,
    failure_count INTEGER NOT NULL DEFAULT 0,
    partial_success_count INTEGER NOT NULL DEFAULT 0,
    average_effectiveness_delta DOUBLE PRECISION,
    average_verification_delta DOUBLE PRECISION,
    average_freshness_delta DOUBLE PRECISION,
    average_forecast_delta DOUBLE PRECISION,
    average_health_delta DOUBLE PRECISION,
    confidence VARCHAR(16) NOT NULL DEFAULT 'UNKNOWN',
    last_updated_at VARCHAR(64) NOT NULL,
    CONSTRAINT uidx_fa_gl_aggregate_tenant_category UNIQUE (tenant_id, remediation_category)
);

CREATE INDEX IF NOT EXISTS idx_gl_aggregate_tenant
    ON fa_governance_learning_aggregates(tenant_id);
CREATE INDEX IF NOT EXISTS idx_gl_aggregate_tenant_category
    ON fa_governance_learning_aggregates(tenant_id, remediation_category);
