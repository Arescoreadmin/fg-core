-- PR 17.6C: Governance Adaptive Intelligence Authority
-- Migration 0140

-- ---------------------------------------------------------------------------
-- fa_governance_recommendation_history — append-only
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS fa_governance_recommendation_history (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    recommendation_id VARCHAR(64) NOT NULL,
    recommendation_type VARCHAR(64) NOT NULL,
    recommendation_category VARCHAR(32),
    recommendation_reason TEXT NOT NULL,
    recommendation_confidence VARCHAR(16) NOT NULL,
    generated_at VARCHAR(64) NOT NULL,
    accepted_at VARCHAR(64),
    rejected_at VARCHAR(64),
    executed_at VARCHAR(64),
    closed_at VARCHAR(64),
    status VARCHAR(32) NOT NULL DEFAULT 'PENDING',
    source_learning_record_id VARCHAR(64),
    source_aggregate_id VARCHAR(64),
    source_authority VARCHAR(64) NOT NULL DEFAULT 'governance_learning'
);

CREATE INDEX IF NOT EXISTS idx_gai_rh_tenant
    ON fa_governance_recommendation_history(tenant_id);
CREATE INDEX IF NOT EXISTS idx_gai_rh_tenant_status
    ON fa_governance_recommendation_history(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_gai_rh_tenant_type
    ON fa_governance_recommendation_history(tenant_id, recommendation_type);
CREATE INDEX IF NOT EXISTS idx_gai_rh_tenant_rec_id
    ON fa_governance_recommendation_history(tenant_id, recommendation_id);

CREATE OR REPLACE FUNCTION prevent_gai_rh_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'fa_governance_recommendation_history is append-only. Mutation is not permitted.';
END;
$$;

CREATE TRIGGER trg_gai_rh_no_update
    BEFORE UPDATE ON fa_governance_recommendation_history
    FOR EACH ROW EXECUTE FUNCTION prevent_gai_rh_mutation();

CREATE TRIGGER trg_gai_rh_no_delete
    BEFORE DELETE ON fa_governance_recommendation_history
    FOR EACH ROW EXECUTE FUNCTION prevent_gai_rh_mutation();

-- ---------------------------------------------------------------------------
-- fa_governance_recommendation_outcomes — mutable
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS fa_governance_recommendation_outcomes (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    recommendation_history_id VARCHAR(64) NOT NULL,
    health_before DOUBLE PRECISION,
    health_after DOUBLE PRECISION,
    health_delta DOUBLE PRECISION,
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
    success BOOLEAN NOT NULL,
    confidence_adjustment DOUBLE PRECISION,
    recorded_at VARCHAR(64) NOT NULL,
    CONSTRAINT uidx_gai_ro_tenant_history UNIQUE (tenant_id, recommendation_history_id)
);

CREATE INDEX IF NOT EXISTS idx_gai_ro_tenant
    ON fa_governance_recommendation_outcomes(tenant_id);
CREATE INDEX IF NOT EXISTS idx_gai_ro_tenant_history_id
    ON fa_governance_recommendation_outcomes(tenant_id, recommendation_history_id);
CREATE INDEX IF NOT EXISTS idx_gai_ro_tenant_success
    ON fa_governance_recommendation_outcomes(tenant_id, success);

-- ---------------------------------------------------------------------------
-- fa_governance_accuracy_aggregates — mutable
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS fa_governance_accuracy_aggregates (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    recommendation_type VARCHAR(64) NOT NULL,
    recommendations_generated INTEGER NOT NULL DEFAULT 0,
    recommendations_accepted INTEGER NOT NULL DEFAULT 0,
    recommendations_executed INTEGER NOT NULL DEFAULT 0,
    recommendations_successful INTEGER NOT NULL DEFAULT 0,
    recommendations_failed INTEGER NOT NULL DEFAULT 0,
    avg_health_delta DOUBLE PRECISION,
    avg_effectiveness_delta DOUBLE PRECISION,
    avg_verification_delta DOUBLE PRECISION,
    avg_freshness_delta DOUBLE PRECISION,
    avg_forecast_delta DOUBLE PRECISION,
    calibrated_confidence VARCHAR(32) NOT NULL DEFAULT 'CALIBRATED_UNKNOWN',
    last_updated_at VARCHAR(64) NOT NULL,
    CONSTRAINT uidx_gai_aa_tenant_type UNIQUE (tenant_id, recommendation_type)
);

CREATE INDEX IF NOT EXISTS idx_gai_aa_tenant
    ON fa_governance_accuracy_aggregates(tenant_id);

-- ---------------------------------------------------------------------------
-- fa_governance_playbooks — mutable
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS fa_governance_playbooks (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    playbook_type VARCHAR(64) NOT NULL,
    recommended_path TEXT NOT NULL,
    success_rate DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    avg_health_improvement DOUBLE PRECISION,
    confidence VARCHAR(32) NOT NULL DEFAULT 'CALIBRATED_UNKNOWN',
    sample_size INTEGER NOT NULL DEFAULT 0,
    last_updated_at VARCHAR(64) NOT NULL,
    CONSTRAINT uidx_gai_pb_tenant_type UNIQUE (tenant_id, playbook_type)
);

CREATE INDEX IF NOT EXISTS idx_gai_pb_tenant
    ON fa_governance_playbooks(tenant_id);

-- ---------------------------------------------------------------------------
-- RLS
-- ---------------------------------------------------------------------------

DO $$ BEGIN
  IF to_regclass('public.fa_governance_recommendation_history') IS NOT NULL THEN
    ALTER TABLE fa_governance_recommendation_history ENABLE ROW LEVEL SECURITY;
    ALTER TABLE fa_governance_recommendation_history FORCE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS fa_grh_tenant_isolation ON fa_governance_recommendation_history;
    CREATE POLICY fa_grh_tenant_isolation ON fa_governance_recommendation_history
      USING (tenant_id = current_setting('app.tenant_id', true) OR current_setting('app.tenant_id', true) = '');
  END IF;
END $$;

DO $$ BEGIN
  IF to_regclass('public.fa_governance_recommendation_outcomes') IS NOT NULL THEN
    ALTER TABLE fa_governance_recommendation_outcomes ENABLE ROW LEVEL SECURITY;
    ALTER TABLE fa_governance_recommendation_outcomes FORCE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS fa_gro_tenant_isolation ON fa_governance_recommendation_outcomes;
    CREATE POLICY fa_gro_tenant_isolation ON fa_governance_recommendation_outcomes
      USING (tenant_id = current_setting('app.tenant_id', true) OR current_setting('app.tenant_id', true) = '');
  END IF;
END $$;

DO $$ BEGIN
  IF to_regclass('public.fa_governance_accuracy_aggregates') IS NOT NULL THEN
    ALTER TABLE fa_governance_accuracy_aggregates ENABLE ROW LEVEL SECURITY;
    ALTER TABLE fa_governance_accuracy_aggregates FORCE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS fa_gaa_tenant_isolation ON fa_governance_accuracy_aggregates;
    CREATE POLICY fa_gaa_tenant_isolation ON fa_governance_accuracy_aggregates
      USING (tenant_id = current_setting('app.tenant_id', true) OR current_setting('app.tenant_id', true) = '');
  END IF;
END $$;

DO $$ BEGIN
  IF to_regclass('public.fa_governance_playbooks') IS NOT NULL THEN
    ALTER TABLE fa_governance_playbooks ENABLE ROW LEVEL SECURITY;
    ALTER TABLE fa_governance_playbooks FORCE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS fa_gpb_tenant_isolation ON fa_governance_playbooks;
    CREATE POLICY fa_gpb_tenant_isolation ON fa_governance_playbooks
      USING (tenant_id = current_setting('app.tenant_id', true) OR current_setting('app.tenant_id', true) = '');
  END IF;
END $$;
