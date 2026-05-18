-- Migration: 0052_readiness_simulation_runs
-- Adds the readiness_simulation_runs table with RLS and tenant isolation.
-- This table stores write-once, immutable governance simulation run records.
--
-- Rollback:
--   DROP TABLE IF EXISTS readiness_simulation_runs;
-- (No existing data is mutated by this migration.)

BEGIN;

CREATE TABLE IF NOT EXISTS readiness_simulation_runs (
    run_id                   VARCHAR(64)   PRIMARY KEY,
    tenant_id                VARCHAR(255)  NOT NULL,
    assessment_id            VARCHAR(255),
    framework_id             VARCHAR(255),
    scenario_type            VARCHAR(64)   NOT NULL,
    simulation_contract_version VARCHAR(32) NOT NULL,
    simulation_engine_version   VARCHAR(32) NOT NULL,
    snapshot_id              VARCHAR(64)   NOT NULL,
    projection_json          TEXT          NOT NULL,
    uncertainty              VARCHAR(64)   NOT NULL,
    total_warnings           INTEGER       NOT NULL DEFAULT 0,
    total_impacts            INTEGER       NOT NULL DEFAULT 0,
    total_critical_warnings  INTEGER       NOT NULL DEFAULT 0,
    simulated_at_iso         VARCHAR(64)   NOT NULL,
    completed                BOOLEAN       NOT NULL DEFAULT TRUE,
    error_summary            VARCHAR(512),
    -- Actor attribution: who submitted this simulation
    created_by_actor_id      VARCHAR(255),
    actor_type               VARCHAR(64),
    request_id               VARCHAR(128),
    trace_id                 VARCHAR(128),
    auth_scope_snapshot      VARCHAR(512),
    -- Replay/hash integrity: regulator-grade evidence chain
    input_hash               VARCHAR(64)   NOT NULL DEFAULT '',
    projection_hash          VARCHAR(64)   NOT NULL DEFAULT '',
    contract_hash            VARCHAR(64)   NOT NULL DEFAULT '',
    created_at               TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_simulation_runs_tenant_created
    ON readiness_simulation_runs (tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS ix_simulation_runs_tenant_assessment
    ON readiness_simulation_runs (tenant_id, assessment_id);

CREATE INDEX IF NOT EXISTS ix_simulation_runs_tenant_scenario
    ON readiness_simulation_runs (tenant_id, scenario_type);

-- Row-Level Security: tenant isolation enforced at the Postgres layer.
-- app.tenant_id must be set per-session (SET LOCAL "app.tenant_id" = '...').
ALTER TABLE readiness_simulation_runs ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename  = 'readiness_simulation_runs'
          AND policyname = 'readiness_simulation_runs_tenant_isolation'
    ) THEN
        CREATE POLICY readiness_simulation_runs_tenant_isolation
            ON readiness_simulation_runs
            USING (
                tenant_id IS NOT NULL
                AND current_setting('app.tenant_id', true) IS NOT NULL
                AND tenant_id = current_setting('app.tenant_id', true)
            )
            WITH CHECK (
                tenant_id IS NOT NULL
                AND current_setting('app.tenant_id', true) IS NOT NULL
                AND tenant_id = current_setting('app.tenant_id', true)
            );
    END IF;
END $$;

COMMIT;
