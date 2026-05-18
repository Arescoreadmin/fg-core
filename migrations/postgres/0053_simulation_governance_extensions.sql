-- Migration: 0053_simulation_governance_extensions
-- Extends the governance simulation schema with:
--   1. classification column on readiness_simulation_runs
--   2. readiness_simulation_events table with RLS and tenant isolation
--
-- Rollback:
--   DROP TABLE IF EXISTS readiness_simulation_events;
--   ALTER TABLE readiness_simulation_runs DROP COLUMN IF EXISTS classification;
-- (No existing data is mutated by this migration.)

BEGIN;

-- 1. Add classification column to readiness_simulation_runs
--    Existing rows default to 'internal' (safe backward-compatible default).
ALTER TABLE readiness_simulation_runs
    ADD COLUMN IF NOT EXISTS classification VARCHAR(64) NOT NULL DEFAULT 'internal';

-- 2. Create readiness_simulation_events table
CREATE TABLE IF NOT EXISTS readiness_simulation_events (
    event_id            VARCHAR(64)   PRIMARY KEY,
    event_type          VARCHAR(64)   NOT NULL,
    simulation_id       VARCHAR(64)   NOT NULL,
    tenant_id           VARCHAR(255)  NOT NULL,
    classification      VARCHAR(64)   NOT NULL DEFAULT 'internal',
    scenario_type       VARCHAR(64)   NOT NULL,
    severity            VARCHAR(32)   NOT NULL,
    occurred_at_iso     VARCHAR(64)   NOT NULL,
    actor_id            VARCHAR(255),
    metadata_json       TEXT,
    created_at          TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_simulation_events_tenant_simulation
    ON readiness_simulation_events (tenant_id, simulation_id);

CREATE INDEX IF NOT EXISTS ix_simulation_events_tenant_event_type
    ON readiness_simulation_events (tenant_id, event_type);

-- Row-Level Security: tenant isolation enforced at the Postgres layer.
ALTER TABLE readiness_simulation_events ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename  = 'readiness_simulation_events'
          AND policyname = 'readiness_simulation_events_tenant_isolation'
    ) THEN
        CREATE POLICY readiness_simulation_events_tenant_isolation
            ON readiness_simulation_events
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
