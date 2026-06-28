-- PR 17.6D: Governance Optimization Engine
-- Migration 0141

-- ---------------------------------------------------------------------------
-- fa_governance_optimization_decisions — append-only
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS fa_governance_optimization_decisions (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    optimization_id VARCHAR(64) NOT NULL,
    optimization_type VARCHAR(64) NOT NULL,
    target_type VARCHAR(64) NOT NULL,
    target_id VARCHAR(255) NOT NULL,
    priority_score DOUBLE PRECISION NOT NULL,
    rank INTEGER NOT NULL,
    reason TEXT NOT NULL,
    evidence_summary TEXT NOT NULL,
    source_authorities TEXT NOT NULL,
    source_record_ids TEXT,
    confidence VARCHAR(32) NOT NULL,
    created_at VARCHAR(64) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_god_tenant
    ON fa_governance_optimization_decisions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_god_tenant_opt_type
    ON fa_governance_optimization_decisions(tenant_id, optimization_type);
CREATE INDEX IF NOT EXISTS idx_god_tenant_target_type
    ON fa_governance_optimization_decisions(tenant_id, target_type);
CREATE INDEX IF NOT EXISTS idx_god_tenant_target_id
    ON fa_governance_optimization_decisions(tenant_id, target_id);
CREATE INDEX IF NOT EXISTS idx_god_tenant_created_at
    ON fa_governance_optimization_decisions(tenant_id, created_at);

CREATE OR REPLACE FUNCTION prevent_god_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'fa_governance_optimization_decisions is append-only. Mutation is not permitted.';
END;
$$;

CREATE TRIGGER trg_god_no_update
    BEFORE UPDATE ON fa_governance_optimization_decisions
    FOR EACH ROW EXECUTE FUNCTION prevent_god_mutation();

CREATE TRIGGER trg_god_no_delete
    BEFORE DELETE ON fa_governance_optimization_decisions
    FOR EACH ROW EXECUTE FUNCTION prevent_god_mutation();

-- ---------------------------------------------------------------------------
-- fa_governance_optimization_aggregates — mutable
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS fa_governance_optimization_aggregates (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    target_type VARCHAR(64) NOT NULL,
    target_id VARCHAR(255) NOT NULL,
    optimization_type VARCHAR(64) NOT NULL,
    times_ranked INTEGER NOT NULL DEFAULT 0,
    average_priority_score DOUBLE PRECISION,
    latest_priority_score DOUBLE PRECISION,
    highest_priority_score DOUBLE PRECISION,
    lowest_priority_score DOUBLE PRECISION,
    average_health_lift DOUBLE PRECISION,
    average_effectiveness_lift DOUBLE PRECISION,
    average_confidence DOUBLE PRECISION,
    last_ranked_at VARCHAR(64) NOT NULL,
    CONSTRAINT uidx_goa_tenant_target_opt UNIQUE (tenant_id, target_type, target_id, optimization_type)
);

CREATE INDEX IF NOT EXISTS idx_goa_tenant
    ON fa_governance_optimization_aggregates(tenant_id);
CREATE INDEX IF NOT EXISTS idx_goa_tenant_target_type
    ON fa_governance_optimization_aggregates(tenant_id, target_type);
CREATE INDEX IF NOT EXISTS idx_goa_tenant_opt_type
    ON fa_governance_optimization_aggregates(tenant_id, optimization_type);

-- ---------------------------------------------------------------------------
-- fa_governance_optimization_snapshots — append-only
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS fa_governance_optimization_snapshots (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    snapshot_type VARCHAR(64) NOT NULL,
    total_items_ranked INTEGER NOT NULL DEFAULT 0,
    top_priority_target_id VARCHAR(255),
    top_priority_score DOUBLE PRECISION,
    average_priority_score DOUBLE PRECISION,
    optimization_confidence VARCHAR(32) NOT NULL,
    generated_at VARCHAR(64) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_gos_tenant
    ON fa_governance_optimization_snapshots(tenant_id);
CREATE INDEX IF NOT EXISTS idx_gos_tenant_snapshot_type
    ON fa_governance_optimization_snapshots(tenant_id, snapshot_type);
CREATE INDEX IF NOT EXISTS idx_gos_tenant_generated_at
    ON fa_governance_optimization_snapshots(tenant_id, generated_at);

CREATE OR REPLACE FUNCTION prevent_gos_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'fa_governance_optimization_snapshots is append-only. Mutation is not permitted.';
END;
$$;

CREATE TRIGGER trg_gos_no_update
    BEFORE UPDATE ON fa_governance_optimization_snapshots
    FOR EACH ROW EXECUTE FUNCTION prevent_gos_mutation();

CREATE TRIGGER trg_gos_no_delete
    BEFORE DELETE ON fa_governance_optimization_snapshots
    FOR EACH ROW EXECUTE FUNCTION prevent_gos_mutation();

-- ---------------------------------------------------------------------------
-- RLS
-- ---------------------------------------------------------------------------

DO $$ BEGIN
  IF to_regclass('public.fa_governance_optimization_decisions') IS NOT NULL THEN
    ALTER TABLE fa_governance_optimization_decisions ENABLE ROW LEVEL SECURITY;
    ALTER TABLE fa_governance_optimization_decisions FORCE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS fa_god_tenant_isolation ON fa_governance_optimization_decisions;
    CREATE POLICY fa_god_tenant_isolation ON fa_governance_optimization_decisions
      USING (tenant_id = current_setting('app.tenant_id', true) OR current_setting('app.tenant_id', true) = '');
  END IF;
END $$;

DO $$ BEGIN
  IF to_regclass('public.fa_governance_optimization_aggregates') IS NOT NULL THEN
    ALTER TABLE fa_governance_optimization_aggregates ENABLE ROW LEVEL SECURITY;
    ALTER TABLE fa_governance_optimization_aggregates FORCE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS fa_goa_tenant_isolation ON fa_governance_optimization_aggregates;
    CREATE POLICY fa_goa_tenant_isolation ON fa_governance_optimization_aggregates
      USING (tenant_id = current_setting('app.tenant_id', true) OR current_setting('app.tenant_id', true) = '');
  END IF;
END $$;

DO $$ BEGIN
  IF to_regclass('public.fa_governance_optimization_snapshots') IS NOT NULL THEN
    ALTER TABLE fa_governance_optimization_snapshots ENABLE ROW LEVEL SECURITY;
    ALTER TABLE fa_governance_optimization_snapshots FORCE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS fa_gos_tenant_isolation ON fa_governance_optimization_snapshots;
    CREATE POLICY fa_gos_tenant_isolation ON fa_governance_optimization_snapshots
      USING (tenant_id = current_setting('app.tenant_id', true) OR current_setting('app.tenant_id', true) = '');
  END IF;
END $$;
