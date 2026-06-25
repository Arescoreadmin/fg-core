-- PR 16.5.1: Control Effectiveness Explainability & Governance Action Engine

CREATE TABLE IF NOT EXISTS fa_control_ranking (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    control_id VARCHAR(64) NOT NULL,
    rank_type VARCHAR(32) NOT NULL,
    rank_position INTEGER NOT NULL,
    effectiveness_score DOUBLE PRECISION NOT NULL,
    effectiveness_level VARCHAR(32) NOT NULL,
    effectiveness_risk VARCHAR(16) NOT NULL,
    generated_at VARCHAR(64) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_fa_control_ranking_tenant ON fa_control_ranking(tenant_id);
CREATE INDEX IF NOT EXISTS idx_fa_control_ranking_tenant_type ON fa_control_ranking(tenant_id, rank_type);
CREATE INDEX IF NOT EXISTS idx_fa_control_ranking_tenant_control ON fa_control_ranking(tenant_id, control_id);
