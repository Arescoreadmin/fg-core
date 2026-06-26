-- PR 17.6: Canonical Governance Chain Authority

-- ---------------------------------------------------------------------------
-- fa_governance_chain_events — canonical governance event log (append-only)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS fa_governance_chain_events (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    authority VARCHAR(64) NOT NULL,
    object_type VARCHAR(64) NOT NULL,
    object_id VARCHAR(255) NOT NULL,
    correlation_id VARCHAR(64),
    actor_id VARCHAR(255),
    actor_type VARCHAR(64),
    reason TEXT,
    payload_json TEXT,
    created_at VARCHAR(64) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_gc_events_tenant ON fa_governance_chain_events(tenant_id);
CREATE INDEX IF NOT EXISTS idx_gc_events_tenant_type ON fa_governance_chain_events(tenant_id, event_type);
CREATE INDEX IF NOT EXISTS idx_gc_events_tenant_authority ON fa_governance_chain_events(tenant_id, authority);
CREATE INDEX IF NOT EXISTS idx_gc_events_correlation ON fa_governance_chain_events(correlation_id);
CREATE INDEX IF NOT EXISTS idx_gc_events_tenant_object ON fa_governance_chain_events(tenant_id, object_id);

CREATE OR REPLACE FUNCTION prevent_gc_event_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'fa_governance_chain_events is append-only. Mutation is not permitted.';
END;
$$;

CREATE TRIGGER trg_gc_event_no_update
    BEFORE UPDATE ON fa_governance_chain_events
    FOR EACH ROW EXECUTE FUNCTION prevent_gc_event_mutation();

CREATE TRIGGER trg_gc_event_no_delete
    BEFORE DELETE ON fa_governance_chain_events
    FOR EACH ROW EXECUTE FUNCTION prevent_gc_event_mutation();

-- ---------------------------------------------------------------------------
-- fa_governance_chain_executions — bridge execution audit (append-only)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS fa_governance_chain_executions (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    chain_execution_id VARCHAR(64) NOT NULL,
    source_authority VARCHAR(64) NOT NULL,
    target_authority VARCHAR(64) NOT NULL,
    bridge_type VARCHAR(64) NOT NULL,
    trigger_reason TEXT,
    trigger_object_id VARCHAR(255) NOT NULL,
    trigger_object_type VARCHAR(64) NOT NULL,
    execution_result VARCHAR(32) NOT NULL,
    success INTEGER NOT NULL DEFAULT 0,
    failure_reason TEXT,
    duration_ms DOUBLE PRECISION,
    executed_at VARCHAR(64) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_gc_exec_tenant ON fa_governance_chain_executions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_gc_exec_tenant_bridge ON fa_governance_chain_executions(tenant_id, bridge_type);
CREATE INDEX IF NOT EXISTS idx_gc_exec_tenant_success ON fa_governance_chain_executions(tenant_id, success);
CREATE INDEX IF NOT EXISTS idx_gc_exec_chain_id ON fa_governance_chain_executions(chain_execution_id);

CREATE OR REPLACE FUNCTION prevent_gc_execution_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'fa_governance_chain_executions is append-only. Mutation is not permitted.';
END;
$$;

CREATE TRIGGER trg_gc_exec_no_update
    BEFORE UPDATE ON fa_governance_chain_executions
    FOR EACH ROW EXECUTE FUNCTION prevent_gc_execution_mutation();

CREATE TRIGGER trg_gc_exec_no_delete
    BEFORE DELETE ON fa_governance_chain_executions
    FOR EACH ROW EXECUTE FUNCTION prevent_gc_execution_mutation();

-- ---------------------------------------------------------------------------
-- fa_governance_health_snapshots — governance health snapshots (append-only)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS fa_governance_health_snapshots (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    verification_health DOUBLE PRECISION NOT NULL,
    freshness_health DOUBLE PRECISION NOT NULL,
    effectiveness_health DOUBLE PRECISION NOT NULL,
    remediation_health DOUBLE PRECISION NOT NULL,
    forecast_health DOUBLE PRECISION NOT NULL,
    governance_health_score DOUBLE PRECISION NOT NULL,
    governance_health_rating VARCHAR(32) NOT NULL,
    missing_inputs_json TEXT,
    snapshot_at VARCHAR(64) NOT NULL,
    calculation_version VARCHAR(16) NOT NULL DEFAULT '1.0'
);

CREATE INDEX IF NOT EXISTS idx_gc_health_tenant ON fa_governance_health_snapshots(tenant_id);
CREATE INDEX IF NOT EXISTS idx_gc_health_tenant_at ON fa_governance_health_snapshots(tenant_id, snapshot_at);

CREATE OR REPLACE FUNCTION prevent_gc_health_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'fa_governance_health_snapshots is append-only. Mutation is not permitted.';
END;
$$;

CREATE TRIGGER trg_gc_health_no_update
    BEFORE UPDATE ON fa_governance_health_snapshots
    FOR EACH ROW EXECUTE FUNCTION prevent_gc_health_mutation();

CREATE TRIGGER trg_gc_health_no_delete
    BEFORE DELETE ON fa_governance_health_snapshots
    FOR EACH ROW EXECUTE FUNCTION prevent_gc_health_mutation();

-- ---------------------------------------------------------------------------
-- fa_governance_chain_snapshots — CGIN anonymized benchmark snapshots (mutable)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS fa_governance_chain_snapshots (
    id VARCHAR(64) PRIMARY KEY,
    tenant_fingerprint VARCHAR(64) NOT NULL,
    authority VARCHAR(64) NOT NULL,
    execution_count INTEGER NOT NULL DEFAULT 0,
    success_count INTEGER NOT NULL DEFAULT 0,
    failure_count INTEGER NOT NULL DEFAULT 0,
    skipped_count INTEGER NOT NULL DEFAULT 0,
    average_duration_ms DOUBLE PRECISION,
    generated_at VARCHAR(64) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_gc_snap_fingerprint ON fa_governance_chain_snapshots(tenant_fingerprint);
CREATE INDEX IF NOT EXISTS idx_gc_snap_authority ON fa_governance_chain_snapshots(authority);
