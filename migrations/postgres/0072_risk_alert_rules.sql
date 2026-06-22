-- 0072_risk_alert_rules.sql
-- Threshold-based risk alert rules per tenant (PR 37)

CREATE TABLE IF NOT EXISTS risk_alert_rules (
    id                  TEXT        PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    tenant_id           TEXT        NOT NULL,
    name                TEXT        NOT NULL,
    threshold_score     NUMERIC(5,1),
    -- fire when risk_score >= this value (NULL = ignore)
    threshold_band      TEXT,
    -- fire when risk_band IN ('high','critical') etc. (NULL = ignore)
    -- comma-separated list of bands: 'high,critical'
    cooldown_hours      INTEGER     NOT NULL DEFAULT 24,
    active              BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_alert_rules_tenant
    ON risk_alert_rules (tenant_id, active);

-- Fired alerts log (audit trail + cooldown tracking)
CREATE TABLE IF NOT EXISTS risk_alerts_fired (
    id          TEXT        PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    tenant_id   TEXT        NOT NULL,
    rule_id     TEXT        NOT NULL REFERENCES risk_alert_rules(id) ON DELETE CASCADE,
    user_id     TEXT        NOT NULL,
    user_email  TEXT,
    risk_score  NUMERIC(5,1) NOT NULL,
    risk_band   TEXT        NOT NULL,
    dismissed   BOOLEAN     NOT NULL DEFAULT FALSE,
    dismissed_at TIMESTAMPTZ,
    fired_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_alerts_fired_tenant
    ON risk_alerts_fired (tenant_id, fired_at DESC);

CREATE INDEX IF NOT EXISTS idx_alerts_fired_rule_user
    ON risk_alerts_fired (rule_id, user_id, fired_at DESC);
