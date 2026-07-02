-- PR 18.5: Governance Intelligence Authority
-- Creates:
--   fa_gov_intel_simulation          -- intelligence simulations
--   fa_gov_intel_simulation_history  -- append-only simulation history
--   fa_gov_intel_policy              -- intelligence policy lifecycle
--   fa_gov_intel_policy_version      -- append-only policy version history
--   fa_gov_intel_benchmark           -- governance benchmarks
--   fa_gov_intel_external_event      -- append-only external events
--   fa_gov_intel_federation          -- federated governance registrations
--   fa_gov_intel_explainability      -- decision explainability records
--   fa_gov_intel_confidence_history  -- append-only confidence score history
--   fa_gov_intel_timeline            -- append-only intelligence timeline

-- ---------------------------------------------------------------------------
-- fa_gov_intel_simulation
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fa_gov_intel_simulation (
    id            VARCHAR(64)  PRIMARY KEY,
    tenant_id     VARCHAR(255) NOT NULL,
    name          VARCHAR(255) NOT NULL,
    description   TEXT,
    scenario_type VARCHAR(64)  NOT NULL,
    parameters    TEXT,
    state         VARCHAR(32)  NOT NULL DEFAULT 'DRAFT',
    result        TEXT,
    created_at    VARCHAR(64)  NOT NULL,
    updated_at    VARCHAR(64)  NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_fa_gov_intel_simulation_tenant
    ON fa_gov_intel_simulation (tenant_id);
CREATE INDEX IF NOT EXISTS ix_fa_gov_intel_simulation_tenant_state
    ON fa_gov_intel_simulation (tenant_id, state);

ALTER TABLE fa_gov_intel_simulation ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename  = 'fa_gov_intel_simulation'
          AND policyname = 'fa_gov_intel_simulation_tenant_isolation'
    ) THEN
        CREATE POLICY fa_gov_intel_simulation_tenant_isolation ON fa_gov_intel_simulation
            USING (tenant_id = current_setting('app.tenant_id', true));
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- fa_gov_intel_simulation_history (append-only)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fa_gov_intel_simulation_history (
    id            VARCHAR(64)  PRIMARY KEY,
    tenant_id     VARCHAR(255) NOT NULL,
    simulation_id VARCHAR(64)  NOT NULL,
    state         VARCHAR(32)  NOT NULL,
    actor_id      VARCHAR(255) NOT NULL,
    data          TEXT,
    created_at    VARCHAR(64)  NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_fa_gov_intel_sim_history_tenant
    ON fa_gov_intel_simulation_history (tenant_id);
CREATE INDEX IF NOT EXISTS ix_fa_gov_intel_sim_history_tenant_sim
    ON fa_gov_intel_simulation_history (tenant_id, simulation_id, created_at);

ALTER TABLE fa_gov_intel_simulation_history ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename  = 'fa_gov_intel_simulation_history'
          AND policyname = 'fa_gov_intel_simulation_history_tenant_isolation'
    ) THEN
        CREATE POLICY fa_gov_intel_simulation_history_tenant_isolation
            ON fa_gov_intel_simulation_history
            USING (tenant_id = current_setting('app.tenant_id', true));
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_rules
        WHERE tablename = 'fa_gov_intel_simulation_history'
          AND rulename  = 'fa_gov_intel_simulation_history_no_update'
    ) THEN
        CREATE RULE fa_gov_intel_simulation_history_no_update
            AS ON UPDATE TO fa_gov_intel_simulation_history DO INSTEAD NOTHING;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_rules
        WHERE tablename = 'fa_gov_intel_simulation_history'
          AND rulename  = 'fa_gov_intel_simulation_history_no_delete'
    ) THEN
        CREATE RULE fa_gov_intel_simulation_history_no_delete
            AS ON DELETE TO fa_gov_intel_simulation_history DO INSTEAD NOTHING;
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- fa_gov_intel_policy
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fa_gov_intel_policy (
    id              VARCHAR(64)  PRIMARY KEY,
    tenant_id       VARCHAR(255) NOT NULL,
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    policy_type     VARCHAR(64)  NOT NULL,
    policy_data     TEXT,
    framework       VARCHAR(128),
    lifecycle_state VARCHAR(32)  NOT NULL DEFAULT 'DRAFT',
    version         VARCHAR(32)  NOT NULL DEFAULT '1.0',
    created_at      VARCHAR(64)  NOT NULL,
    updated_at      VARCHAR(64)  NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_fa_gov_intel_policy_tenant
    ON fa_gov_intel_policy (tenant_id);
CREATE INDEX IF NOT EXISTS ix_fa_gov_intel_policy_tenant_state
    ON fa_gov_intel_policy (tenant_id, lifecycle_state);

ALTER TABLE fa_gov_intel_policy ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename  = 'fa_gov_intel_policy'
          AND policyname = 'fa_gov_intel_policy_tenant_isolation'
    ) THEN
        CREATE POLICY fa_gov_intel_policy_tenant_isolation ON fa_gov_intel_policy
            USING (tenant_id = current_setting('app.tenant_id', true));
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- fa_gov_intel_policy_version (append-only)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fa_gov_intel_policy_version (
    id          VARCHAR(64)  PRIMARY KEY,
    policy_id   VARCHAR(64)  NOT NULL,
    tenant_id   VARCHAR(255) NOT NULL,
    version     VARCHAR(32)  NOT NULL,
    policy_data TEXT,
    changed_by  VARCHAR(255),
    created_at  VARCHAR(64)  NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_fa_gov_intel_policy_version_tenant
    ON fa_gov_intel_policy_version (tenant_id);
CREATE INDEX IF NOT EXISTS ix_fa_gov_intel_policy_version_tenant_policy
    ON fa_gov_intel_policy_version (tenant_id, policy_id, created_at);

ALTER TABLE fa_gov_intel_policy_version ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename  = 'fa_gov_intel_policy_version'
          AND policyname = 'fa_gov_intel_policy_version_tenant_isolation'
    ) THEN
        CREATE POLICY fa_gov_intel_policy_version_tenant_isolation
            ON fa_gov_intel_policy_version
            USING (tenant_id = current_setting('app.tenant_id', true));
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_rules
        WHERE tablename = 'fa_gov_intel_policy_version'
          AND rulename  = 'fa_gov_intel_policy_version_no_update'
    ) THEN
        CREATE RULE fa_gov_intel_policy_version_no_update
            AS ON UPDATE TO fa_gov_intel_policy_version DO INSTEAD NOTHING;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_rules
        WHERE tablename = 'fa_gov_intel_policy_version'
          AND rulename  = 'fa_gov_intel_policy_version_no_delete'
    ) THEN
        CREATE RULE fa_gov_intel_policy_version_no_delete
            AS ON DELETE TO fa_gov_intel_policy_version DO INSTEAD NOTHING;
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- fa_gov_intel_benchmark
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fa_gov_intel_benchmark (
    id          VARCHAR(64)  PRIMARY KEY,
    tenant_id   VARCHAR(255) NOT NULL,
    framework   VARCHAR(128) NOT NULL,
    category    VARCHAR(128) NOT NULL,
    metric_key  VARCHAR(255) NOT NULL,
    value       REAL         NOT NULL,
    percentile  REAL,
    tier        VARCHAR(32),
    metadata    TEXT,
    created_at  VARCHAR(64)  NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_fa_gov_intel_benchmark_tenant
    ON fa_gov_intel_benchmark (tenant_id);
CREATE INDEX IF NOT EXISTS ix_fa_gov_intel_benchmark_tenant_metric
    ON fa_gov_intel_benchmark (tenant_id, metric_key);

ALTER TABLE fa_gov_intel_benchmark ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename  = 'fa_gov_intel_benchmark'
          AND policyname = 'fa_gov_intel_benchmark_tenant_isolation'
    ) THEN
        CREATE POLICY fa_gov_intel_benchmark_tenant_isolation ON fa_gov_intel_benchmark
            USING (tenant_id = current_setting('app.tenant_id', true));
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- fa_gov_intel_external_event (append-only)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fa_gov_intel_external_event (
    id          VARCHAR(64)  PRIMARY KEY,
    tenant_id   VARCHAR(255) NOT NULL,
    event_type  VARCHAR(64)  NOT NULL,
    source      VARCHAR(255) NOT NULL,
    payload     TEXT,
    occurred_at VARCHAR(64)  NOT NULL,
    created_at  VARCHAR(64)  NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_fa_gov_intel_ext_event_tenant
    ON fa_gov_intel_external_event (tenant_id);
CREATE INDEX IF NOT EXISTS ix_fa_gov_intel_ext_event_tenant_type
    ON fa_gov_intel_external_event (tenant_id, event_type, created_at);

ALTER TABLE fa_gov_intel_external_event ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename  = 'fa_gov_intel_external_event'
          AND policyname = 'fa_gov_intel_external_event_tenant_isolation'
    ) THEN
        CREATE POLICY fa_gov_intel_external_event_tenant_isolation
            ON fa_gov_intel_external_event
            USING (tenant_id = current_setting('app.tenant_id', true));
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_rules
        WHERE tablename = 'fa_gov_intel_external_event'
          AND rulename  = 'fa_gov_intel_external_event_no_update'
    ) THEN
        CREATE RULE fa_gov_intel_external_event_no_update
            AS ON UPDATE TO fa_gov_intel_external_event DO INSTEAD NOTHING;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_rules
        WHERE tablename = 'fa_gov_intel_external_event'
          AND rulename  = 'fa_gov_intel_external_event_no_delete'
    ) THEN
        CREATE RULE fa_gov_intel_external_event_no_delete
            AS ON DELETE TO fa_gov_intel_external_event DO INSTEAD NOTHING;
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- fa_gov_intel_federation
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fa_gov_intel_federation (
    id           VARCHAR(64)  PRIMARY KEY,
    tenant_id    VARCHAR(255) NOT NULL,
    instance_id  VARCHAR(255) NOT NULL,
    role         VARCHAR(32)  NOT NULL,
    metadata     TEXT,
    last_sync_at VARCHAR(64),
    created_at   VARCHAR(64)  NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_fa_gov_intel_federation_tenant
    ON fa_gov_intel_federation (tenant_id);

ALTER TABLE fa_gov_intel_federation ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename  = 'fa_gov_intel_federation'
          AND policyname = 'fa_gov_intel_federation_tenant_isolation'
    ) THEN
        CREATE POLICY fa_gov_intel_federation_tenant_isolation ON fa_gov_intel_federation
            USING (tenant_id = current_setting('app.tenant_id', true));
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- fa_gov_intel_explainability
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fa_gov_intel_explainability (
    id                  VARCHAR(64)  PRIMARY KEY,
    tenant_id           VARCHAR(255) NOT NULL,
    decision_id         VARCHAR(64)  NOT NULL,
    trigger             VARCHAR(255) NOT NULL,
    policy_version      VARCHAR(32)  NOT NULL,
    evaluation          TEXT,
    decision            VARCHAR(255) NOT NULL,
    authorities_invoked TEXT,
    expected_impact     TEXT,
    observed_impact     TEXT,
    created_at          VARCHAR(64)  NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_fa_gov_intel_explainability_tenant
    ON fa_gov_intel_explainability (tenant_id);
CREATE INDEX IF NOT EXISTS ix_fa_gov_intel_explainability_tenant_decision
    ON fa_gov_intel_explainability (tenant_id, decision_id);

ALTER TABLE fa_gov_intel_explainability ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename  = 'fa_gov_intel_explainability'
          AND policyname = 'fa_gov_intel_explainability_tenant_isolation'
    ) THEN
        CREATE POLICY fa_gov_intel_explainability_tenant_isolation
            ON fa_gov_intel_explainability
            USING (tenant_id = current_setting('app.tenant_id', true));
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- fa_gov_intel_confidence_history (append-only)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fa_gov_intel_confidence_history (
    id          VARCHAR(64)  PRIMARY KEY,
    tenant_id   VARCHAR(255) NOT NULL,
    dimension   VARCHAR(255) NOT NULL,
    score       REAL         NOT NULL,
    level       VARCHAR(32)  NOT NULL,
    factors     TEXT,
    computed_at VARCHAR(64)  NOT NULL,
    created_at  VARCHAR(64)  NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_fa_gov_intel_confidence_history_tenant
    ON fa_gov_intel_confidence_history (tenant_id);
CREATE INDEX IF NOT EXISTS ix_fa_gov_intel_confidence_history_tenant_dim
    ON fa_gov_intel_confidence_history (tenant_id, dimension, created_at);

ALTER TABLE fa_gov_intel_confidence_history ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename  = 'fa_gov_intel_confidence_history'
          AND policyname = 'fa_gov_intel_confidence_history_tenant_isolation'
    ) THEN
        CREATE POLICY fa_gov_intel_confidence_history_tenant_isolation
            ON fa_gov_intel_confidence_history
            USING (tenant_id = current_setting('app.tenant_id', true));
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_rules
        WHERE tablename = 'fa_gov_intel_confidence_history'
          AND rulename  = 'fa_gov_intel_confidence_history_no_update'
    ) THEN
        CREATE RULE fa_gov_intel_confidence_history_no_update
            AS ON UPDATE TO fa_gov_intel_confidence_history DO INSTEAD NOTHING;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_rules
        WHERE tablename = 'fa_gov_intel_confidence_history'
          AND rulename  = 'fa_gov_intel_confidence_history_no_delete'
    ) THEN
        CREATE RULE fa_gov_intel_confidence_history_no_delete
            AS ON DELETE TO fa_gov_intel_confidence_history DO INSTEAD NOTHING;
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- fa_gov_intel_timeline (append-only)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fa_gov_intel_timeline (
    id          VARCHAR(64)  PRIMARY KEY,
    tenant_id   VARCHAR(255) NOT NULL,
    event_type  VARCHAR(64)  NOT NULL,
    entity_id   VARCHAR(64)  NOT NULL,
    entity_type VARCHAR(64)  NOT NULL,
    actor_id    VARCHAR(255) NOT NULL,
    data        TEXT,
    created_at  VARCHAR(64)  NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_fa_gov_intel_timeline_tenant
    ON fa_gov_intel_timeline (tenant_id);
CREATE INDEX IF NOT EXISTS ix_fa_gov_intel_timeline_tenant_entity
    ON fa_gov_intel_timeline (tenant_id, entity_type, entity_id, created_at);

ALTER TABLE fa_gov_intel_timeline ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename  = 'fa_gov_intel_timeline'
          AND policyname = 'fa_gov_intel_timeline_tenant_isolation'
    ) THEN
        CREATE POLICY fa_gov_intel_timeline_tenant_isolation ON fa_gov_intel_timeline
            USING (tenant_id = current_setting('app.tenant_id', true));
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_rules
        WHERE tablename = 'fa_gov_intel_timeline'
          AND rulename  = 'fa_gov_intel_timeline_no_update'
    ) THEN
        CREATE RULE fa_gov_intel_timeline_no_update
            AS ON UPDATE TO fa_gov_intel_timeline DO INSTEAD NOTHING;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_rules
        WHERE tablename = 'fa_gov_intel_timeline'
          AND rulename  = 'fa_gov_intel_timeline_no_delete'
    ) THEN
        CREATE RULE fa_gov_intel_timeline_no_delete
            AS ON DELETE TO fa_gov_intel_timeline DO INSTEAD NOTHING;
    END IF;
END $$;
