-- PR 14.6.8: Freshness Score History & Governance Trend Intelligence

CREATE TABLE IF NOT EXISTS fa_freshness_score_snapshots (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    evidence_id VARCHAR(64) NOT NULL,
    freshness_record_id VARCHAR(64),
    freshness_score INTEGER NOT NULL,
    freshness_state VARCHAR(32) NOT NULL,
    review_due_at VARCHAR(64),
    verification_due_at VARCHAR(64),
    expiration_due_at VARCHAR(64),
    captured_at VARCHAR(64) NOT NULL,
    capture_date VARCHAR(16) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_fa_score_snapshots_tenant ON fa_freshness_score_snapshots(tenant_id);
CREATE INDEX IF NOT EXISTS idx_fa_score_snapshots_evidence_date ON fa_freshness_score_snapshots(tenant_id, evidence_id, capture_date);
CREATE UNIQUE INDEX IF NOT EXISTS uidx_fa_score_snapshots_evidence_date ON fa_freshness_score_snapshots(tenant_id, evidence_id, capture_date);

CREATE TABLE IF NOT EXISTS fa_freshness_daily_snapshots (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    average_freshness_score DOUBLE PRECISION NOT NULL,
    fresh_evidence_count INTEGER NOT NULL DEFAULT 0,
    due_soon_count INTEGER NOT NULL DEFAULT 0,
    review_required_count INTEGER NOT NULL DEFAULT 0,
    verification_required_count INTEGER NOT NULL DEFAULT 0,
    expired_count INTEGER NOT NULL DEFAULT 0,
    coverage_at_risk_count INTEGER NOT NULL DEFAULT 0,
    total_evidence_count INTEGER NOT NULL DEFAULT 0,
    captured_at VARCHAR(64) NOT NULL,
    capture_date VARCHAR(16) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_fa_daily_snapshots_tenant ON fa_freshness_daily_snapshots(tenant_id);
CREATE INDEX IF NOT EXISTS idx_fa_daily_snapshots_date ON fa_freshness_daily_snapshots(tenant_id, capture_date);
CREATE UNIQUE INDEX IF NOT EXISTS uidx_fa_daily_snapshots_tenant_date ON fa_freshness_daily_snapshots(tenant_id, capture_date);

CREATE TABLE IF NOT EXISTS fa_freshness_trend_snapshots (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    period VARCHAR(16) NOT NULL,
    average_score DOUBLE PRECISION NOT NULL,
    score_delta DOUBLE PRECISION,
    fresh_delta INTEGER,
    expired_delta INTEGER,
    coverage_risk_delta INTEGER,
    generated_at VARCHAR(64) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_fa_trend_snapshots_tenant ON fa_freshness_trend_snapshots(tenant_id);
CREATE INDEX IF NOT EXISTS idx_fa_trend_snapshots_period ON fa_freshness_trend_snapshots(tenant_id, period);

-- Append-only guard functions

CREATE OR REPLACE FUNCTION prevent_freshness_score_snapshot_mutation() RETURNS trigger AS $$
BEGIN RAISE EXCEPTION 'fa_freshness_score_snapshots is append-only'; END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER trg_fa_score_snapshots_immutable_update
    BEFORE UPDATE ON fa_freshness_score_snapshots
    FOR EACH ROW EXECUTE FUNCTION prevent_freshness_score_snapshot_mutation();

CREATE OR REPLACE TRIGGER trg_fa_score_snapshots_immutable_delete
    BEFORE DELETE ON fa_freshness_score_snapshots
    FOR EACH ROW EXECUTE FUNCTION prevent_freshness_score_snapshot_mutation();

CREATE OR REPLACE FUNCTION prevent_freshness_daily_snapshot_mutation() RETURNS trigger AS $$
BEGIN RAISE EXCEPTION 'fa_freshness_daily_snapshots is append-only'; END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER trg_fa_daily_snapshots_immutable_update
    BEFORE UPDATE ON fa_freshness_daily_snapshots
    FOR EACH ROW EXECUTE FUNCTION prevent_freshness_daily_snapshot_mutation();

CREATE OR REPLACE TRIGGER trg_fa_daily_snapshots_immutable_delete
    BEFORE DELETE ON fa_freshness_daily_snapshots
    FOR EACH ROW EXECUTE FUNCTION prevent_freshness_daily_snapshot_mutation();

CREATE OR REPLACE FUNCTION prevent_freshness_trend_snapshot_mutation() RETURNS trigger AS $$
BEGIN RAISE EXCEPTION 'fa_freshness_trend_snapshots is append-only'; END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER trg_fa_trend_snapshots_immutable_update
    BEFORE UPDATE ON fa_freshness_trend_snapshots
    FOR EACH ROW EXECUTE FUNCTION prevent_freshness_trend_snapshot_mutation();

CREATE OR REPLACE TRIGGER trg_fa_trend_snapshots_immutable_delete
    BEFORE DELETE ON fa_freshness_trend_snapshots
    FOR EACH ROW EXECUTE FUNCTION prevent_freshness_trend_snapshot_mutation();
