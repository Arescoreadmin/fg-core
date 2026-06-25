-- PR 16.5: Control Effectiveness Engine

CREATE TABLE IF NOT EXISTS fa_control_effectiveness (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    control_id VARCHAR(64) NOT NULL,
    effectiveness_score DOUBLE PRECISION NOT NULL,
    effectiveness_level VARCHAR(32) NOT NULL,
    effectiveness_risk VARCHAR(16) NOT NULL,
    coverage_score DOUBLE PRECISION,
    verification_score DOUBLE PRECISION,
    freshness_score DOUBLE PRECISION,
    trend_score DOUBLE PRECISION,
    forecast_score DOUBLE PRECISION,
    evidence_density_score DOUBLE PRECISION,
    exception_score DOUBLE PRECISION,
    governance_health_score DOUBLE PRECISION,
    trend_direction VARCHAR(16),
    score_delta_7d DOUBLE PRECISION,
    score_delta_30d DOUBLE PRECISION,
    score_delta_90d DOUBLE PRECISION,
    last_calculated_at VARCHAR(64) NOT NULL,
    calculation_version VARCHAR(16) NOT NULL DEFAULT '1.0'
);

CREATE INDEX IF NOT EXISTS idx_fa_control_effectiveness_tenant ON fa_control_effectiveness(tenant_id);
CREATE INDEX IF NOT EXISTS idx_fa_control_effectiveness_tenant_control ON fa_control_effectiveness(tenant_id, control_id);
CREATE INDEX IF NOT EXISTS idx_fa_control_effectiveness_score ON fa_control_effectiveness(tenant_id, effectiveness_score);
CREATE UNIQUE INDEX IF NOT EXISTS uidx_fa_control_effectiveness_tenant_control ON fa_control_effectiveness(tenant_id, control_id);

CREATE TABLE IF NOT EXISTS fa_control_effectiveness_history (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    control_id VARCHAR(64) NOT NULL,
    effectiveness_score DOUBLE PRECISION NOT NULL,
    effectiveness_level VARCHAR(32) NOT NULL,
    effectiveness_risk VARCHAR(16) NOT NULL,
    coverage_score DOUBLE PRECISION,
    verification_score DOUBLE PRECISION,
    freshness_score DOUBLE PRECISION,
    trend_score DOUBLE PRECISION,
    captured_at VARCHAR(64) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_fa_ce_history_tenant ON fa_control_effectiveness_history(tenant_id);
CREATE INDEX IF NOT EXISTS idx_fa_ce_history_tenant_control ON fa_control_effectiveness_history(tenant_id, control_id);
CREATE INDEX IF NOT EXISTS idx_fa_ce_history_captured ON fa_control_effectiveness_history(tenant_id, captured_at);

-- Delete prevention on fa_control_effectiveness (updates allowed for recalculation)

CREATE OR REPLACE FUNCTION prevent_control_effectiveness_delete() RETURNS trigger AS $$
BEGIN RAISE EXCEPTION 'fa_control_effectiveness rows cannot be deleted'; END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER trg_fa_control_effectiveness_no_delete
    BEFORE DELETE ON fa_control_effectiveness
    FOR EACH ROW EXECUTE FUNCTION prevent_control_effectiveness_delete();

-- Append-only guards on history table

CREATE OR REPLACE FUNCTION prevent_control_effectiveness_history_mutation() RETURNS trigger AS $$
BEGIN RAISE EXCEPTION 'fa_control_effectiveness_history is append-only'; END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER trg_fa_ce_history_immutable_update
    BEFORE UPDATE ON fa_control_effectiveness_history
    FOR EACH ROW EXECUTE FUNCTION prevent_control_effectiveness_history_mutation();

CREATE OR REPLACE TRIGGER trg_fa_ce_history_immutable_delete
    BEFORE DELETE ON fa_control_effectiveness_history
    FOR EACH ROW EXECUTE FUNCTION prevent_control_effectiveness_history_mutation();
