-- PR 17.5: Remediation Effectiveness Analytics Authority

CREATE TABLE IF NOT EXISTS fa_remediation_outcome (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    remediation_task_id VARCHAR(64) NOT NULL,
    control_id VARCHAR(64) NOT NULL,
    before_score DOUBLE PRECISION NOT NULL,
    after_score DOUBLE PRECISION NOT NULL,
    score_delta DOUBLE PRECISION NOT NULL,
    before_effectiveness_level VARCHAR(32) NOT NULL,
    after_effectiveness_level VARCHAR(32) NOT NULL,
    outcome_classification VARCHAR(32) NOT NULL,
    remediation_effectiveness_score DOUBLE PRECISION NOT NULL,
    effectiveness_level VARCHAR(32) NOT NULL,
    roi_score DOUBLE PRECISION NOT NULL,
    roi_classification VARCHAR(32) NOT NULL,
    remediation_category VARCHAR(32) NOT NULL,
    verification_before DOUBLE PRECISION,
    verification_after DOUBLE PRECISION,
    verification_delta DOUBLE PRECISION,
    freshness_before DOUBLE PRECISION,
    freshness_after DOUBLE PRECISION,
    freshness_delta DOUBLE PRECISION,
    forecast_before DOUBLE PRECISION,
    forecast_after DOUBLE PRECISION,
    forecast_delta DOUBLE PRECISION,
    governance_health_before DOUBLE PRECISION,
    governance_health_after DOUBLE PRECISION,
    governance_health_delta DOUBLE PRECISION,
    status VARCHAR(32) NOT NULL DEFAULT 'COMPLETE',
    measured_at VARCHAR(64) NOT NULL,
    calculation_version VARCHAR(16) NOT NULL DEFAULT '1.0'
);

CREATE INDEX IF NOT EXISTS idx_fa_remediation_outcome_tenant ON fa_remediation_outcome(tenant_id);
CREATE INDEX IF NOT EXISTS idx_fa_remediation_outcome_tenant_control ON fa_remediation_outcome(tenant_id, control_id);
CREATE INDEX IF NOT EXISTS idx_fa_remediation_outcome_tenant_classification ON fa_remediation_outcome(tenant_id, outcome_classification);

CREATE TABLE IF NOT EXISTS fa_remediation_persistence (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    remediation_id VARCHAR(64) NOT NULL,
    control_id VARCHAR(64) NOT NULL,
    window_days INTEGER NOT NULL,
    score_at_window DOUBLE PRECISION NOT NULL,
    delta_from_close DOUBLE PRECISION NOT NULL,
    persistence_classification VARCHAR(32) NOT NULL,
    measured_at VARCHAR(64) NOT NULL,
    UNIQUE (tenant_id, remediation_id, window_days)
);

CREATE INDEX IF NOT EXISTS idx_fa_remediation_persistence_tenant ON fa_remediation_persistence(tenant_id);
CREATE INDEX IF NOT EXISTS idx_fa_remediation_persistence_tenant_remediation ON fa_remediation_persistence(tenant_id, remediation_id);

CREATE TABLE IF NOT EXISTS fa_remediation_learning (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    remediation_category VARCHAR(32) NOT NULL,
    total_remediations INTEGER NOT NULL DEFAULT 0,
    success_count INTEGER NOT NULL DEFAULT 0,
    partial_success_count INTEGER NOT NULL DEFAULT 0,
    no_change_count INTEGER NOT NULL DEFAULT 0,
    regression_count INTEGER NOT NULL DEFAULT 0,
    failure_count INTEGER NOT NULL DEFAULT 0,
    success_rate DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    average_score_delta DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    average_roi_score DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    last_updated_at VARCHAR(64) NOT NULL,
    UNIQUE (tenant_id, remediation_category)
);

CREATE INDEX IF NOT EXISTS idx_fa_remediation_learning_tenant ON fa_remediation_learning(tenant_id);

CREATE TABLE IF NOT EXISTS fa_remediation_pattern (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    control_id VARCHAR(64) NOT NULL,
    pattern_type VARCHAR(32) NOT NULL,
    severity VARCHAR(16) NOT NULL,
    occurrence_count INTEGER NOT NULL DEFAULT 1,
    description TEXT NOT NULL,
    detected_at VARCHAR(64) NOT NULL,
    last_seen_at VARCHAR(64) NOT NULL,
    UNIQUE (tenant_id, control_id, pattern_type)
);

CREATE INDEX IF NOT EXISTS idx_fa_remediation_pattern_tenant ON fa_remediation_pattern(tenant_id);
CREATE INDEX IF NOT EXISTS idx_fa_remediation_pattern_tenant_control ON fa_remediation_pattern(tenant_id, control_id);
