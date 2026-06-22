-- 0070_risk_score_snapshots.sql
-- Daily risk score snapshots for trend tracking (PR 37)
-- One row per user per day (upserted on admin leaderboard load).

CREATE TABLE IF NOT EXISTS risk_score_snapshots (
    id              TEXT        PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    tenant_id       TEXT        NOT NULL,
    user_id         TEXT        NOT NULL,
    risk_score      NUMERIC(5,1) NOT NULL DEFAULT 0,
    risk_band       TEXT        NOT NULL DEFAULT 'low',
    total_queries   INTEGER     NOT NULL DEFAULT 0,
    policy_violations INTEGER   NOT NULL DEFAULT 0,
    personal_ratio  NUMERIC(5,3) NOT NULL DEFAULT 0,
    sensitive_topic_count INTEGER NOT NULL DEFAULT 0,
    pii_query_count INTEGER     NOT NULL DEFAULT 0,
    competitor_query_count INTEGER NOT NULL DEFAULT 0,
    active_days     INTEGER     NOT NULL DEFAULT 0,
    period_days     INTEGER     NOT NULL DEFAULT 30,
    captured_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One snapshot per user per calendar day (tenant-scoped).
CREATE UNIQUE INDEX IF NOT EXISTS uq_risk_snapshot_user_day
    ON risk_score_snapshots (tenant_id, user_id, DATE(captured_at AT TIME ZONE 'UTC'));

CREATE INDEX IF NOT EXISTS idx_risk_snapshot_user_date
    ON risk_score_snapshots (tenant_id, user_id, captured_at DESC);
