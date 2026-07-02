-- PR 18.4: Continuous Governance Orchestration Authority
-- Creates:
--   fa_gov_orch_policy              -- policies
--   fa_gov_orch_policy_version      -- append-only policy history
--   fa_gov_orch_playbook            -- playbook definitions
--   fa_gov_orch_workflow            -- workflow executions
--   fa_gov_orch_reassessment        -- reassessment records
--   fa_gov_orch_trigger             -- detected triggers
--   fa_gov_orch_trigger_timeline    -- append-only trigger history
--   fa_gov_orch_simulation          -- impact simulations
--   fa_gov_orch_approval            -- approval records
--   fa_gov_orch_maintenance_window  -- maintenance/blackout windows
--   fa_gov_orch_change_detection    -- detected changes
--   fa_gov_orch_timeline            -- append-only orchestration timeline

-- ---------------------------------------------------------------------------
-- fa_gov_orch_policy
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fa_gov_orch_policy (
    id           VARCHAR(64)  PRIMARY KEY,
    tenant_id    VARCHAR(255) NOT NULL,
    name         VARCHAR(255) NOT NULL,
    description  TEXT,
    risk_level   VARCHAR(32)  NOT NULL DEFAULT 'MEDIUM',
    policy_data  TEXT,
    active       INTEGER      NOT NULL DEFAULT 1,
    version      VARCHAR(32)  NOT NULL DEFAULT '1.0',
    created_at   VARCHAR(64)  NOT NULL,
    updated_at   VARCHAR(64)  NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_fa_gov_orch_policy_tenant
    ON fa_gov_orch_policy (tenant_id);
CREATE INDEX IF NOT EXISTS ix_fa_gov_orch_policy_tenant_active
    ON fa_gov_orch_policy (tenant_id, active);

ALTER TABLE fa_gov_orch_policy ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename  = 'fa_gov_orch_policy'
          AND policyname = 'fa_gov_orch_policy_tenant_isolation'
    ) THEN
        CREATE POLICY fa_gov_orch_policy_tenant_isolation ON fa_gov_orch_policy
            USING (tenant_id = current_setting('app.tenant_id', true));
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- fa_gov_orch_policy_version (append-only)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fa_gov_orch_policy_version (
    id          VARCHAR(64)  PRIMARY KEY,
    tenant_id   VARCHAR(255) NOT NULL,
    policy_id   VARCHAR(64)  NOT NULL,
    version     VARCHAR(32)  NOT NULL,
    policy_data TEXT,
    actor_id    VARCHAR(255),
    created_at  VARCHAR(64)  NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_fa_gov_orch_policy_version_tenant
    ON fa_gov_orch_policy_version (tenant_id);
CREATE INDEX IF NOT EXISTS ix_fa_gov_orch_policy_version_tenant_policy
    ON fa_gov_orch_policy_version (tenant_id, policy_id, created_at);

ALTER TABLE fa_gov_orch_policy_version ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename  = 'fa_gov_orch_policy_version'
          AND policyname = 'fa_gov_orch_policy_version_tenant_isolation'
    ) THEN
        CREATE POLICY fa_gov_orch_policy_version_tenant_isolation
            ON fa_gov_orch_policy_version
            USING (tenant_id = current_setting('app.tenant_id', true));
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_rules
        WHERE tablename = 'fa_gov_orch_policy_version'
          AND rulename  = 'fa_gov_orch_policy_version_no_update'
    ) THEN
        CREATE RULE fa_gov_orch_policy_version_no_update
            AS ON UPDATE TO fa_gov_orch_policy_version DO INSTEAD NOTHING;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_rules
        WHERE tablename = 'fa_gov_orch_policy_version'
          AND rulename  = 'fa_gov_orch_policy_version_no_delete'
    ) THEN
        CREATE RULE fa_gov_orch_policy_version_no_delete
            AS ON DELETE TO fa_gov_orch_policy_version DO INSTEAD NOTHING;
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- fa_gov_orch_playbook
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fa_gov_orch_playbook (
    id            VARCHAR(64)  PRIMARY KEY,
    tenant_id     VARCHAR(255) NOT NULL,
    name          VARCHAR(255) NOT NULL,
    playbook_type VARCHAR(64)  NOT NULL,
    description   TEXT,
    playbook_data TEXT,
    created_at    VARCHAR(64)  NOT NULL,
    updated_at    VARCHAR(64)  NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_fa_gov_orch_playbook_tenant
    ON fa_gov_orch_playbook (tenant_id);
CREATE INDEX IF NOT EXISTS ix_fa_gov_orch_playbook_tenant_type
    ON fa_gov_orch_playbook (tenant_id, playbook_type);

ALTER TABLE fa_gov_orch_playbook ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename  = 'fa_gov_orch_playbook'
          AND policyname = 'fa_gov_orch_playbook_tenant_isolation'
    ) THEN
        CREATE POLICY fa_gov_orch_playbook_tenant_isolation ON fa_gov_orch_playbook
            USING (tenant_id = current_setting('app.tenant_id', true));
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- fa_gov_orch_workflow
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fa_gov_orch_workflow (
    id             VARCHAR(64)  PRIMARY KEY,
    tenant_id      VARCHAR(255) NOT NULL,
    name           VARCHAR(255) NOT NULL,
    workflow_state VARCHAR(32)  NOT NULL DEFAULT 'PENDING',
    playbook_id    VARCHAR(64),
    trigger_id     VARCHAR(64),
    context        TEXT,
    created_at     VARCHAR(64)  NOT NULL,
    updated_at     VARCHAR(64)  NOT NULL,
    completed_at   VARCHAR(64)
);

CREATE INDEX IF NOT EXISTS ix_fa_gov_orch_workflow_tenant
    ON fa_gov_orch_workflow (tenant_id);
CREATE INDEX IF NOT EXISTS ix_fa_gov_orch_workflow_tenant_state
    ON fa_gov_orch_workflow (tenant_id, workflow_state);

ALTER TABLE fa_gov_orch_workflow ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename  = 'fa_gov_orch_workflow'
          AND policyname = 'fa_gov_orch_workflow_tenant_isolation'
    ) THEN
        CREATE POLICY fa_gov_orch_workflow_tenant_isolation ON fa_gov_orch_workflow
            USING (tenant_id = current_setting('app.tenant_id', true));
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- fa_gov_orch_reassessment
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fa_gov_orch_reassessment (
    id                 VARCHAR(64)  PRIMARY KEY,
    tenant_id          VARCHAR(255) NOT NULL,
    assessment_id      VARCHAR(64)  NOT NULL,
    trigger_id         VARCHAR(64),
    reassessment_state VARCHAR(32)  NOT NULL DEFAULT 'REQUESTED',
    reason             TEXT,
    scheduled_at       VARCHAR(64),
    completed_at       VARCHAR(64),
    outcome            TEXT,
    created_at         VARCHAR(64)  NOT NULL,
    updated_at         VARCHAR(64)  NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_fa_gov_orch_reassessment_tenant
    ON fa_gov_orch_reassessment (tenant_id);
CREATE INDEX IF NOT EXISTS ix_fa_gov_orch_reassessment_tenant_state
    ON fa_gov_orch_reassessment (tenant_id, reassessment_state);

ALTER TABLE fa_gov_orch_reassessment ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename  = 'fa_gov_orch_reassessment'
          AND policyname = 'fa_gov_orch_reassessment_tenant_isolation'
    ) THEN
        CREATE POLICY fa_gov_orch_reassessment_tenant_isolation
            ON fa_gov_orch_reassessment
            USING (tenant_id = current_setting('app.tenant_id', true));
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- fa_gov_orch_trigger
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fa_gov_orch_trigger (
    id             VARCHAR(64)  PRIMARY KEY,
    tenant_id      VARCHAR(255) NOT NULL,
    trigger_type   VARCHAR(64)  NOT NULL,
    source_id      VARCHAR(64),
    reason         TEXT,
    confidence     DOUBLE PRECISION NOT NULL DEFAULT 1.0,
    policy_version VARCHAR(32)  NOT NULL DEFAULT '1.0',
    created_at     VARCHAR(64)  NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_fa_gov_orch_trigger_tenant
    ON fa_gov_orch_trigger (tenant_id);
CREATE INDEX IF NOT EXISTS ix_fa_gov_orch_trigger_tenant_type
    ON fa_gov_orch_trigger (tenant_id, trigger_type);

ALTER TABLE fa_gov_orch_trigger ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename  = 'fa_gov_orch_trigger'
          AND policyname = 'fa_gov_orch_trigger_tenant_isolation'
    ) THEN
        CREATE POLICY fa_gov_orch_trigger_tenant_isolation ON fa_gov_orch_trigger
            USING (tenant_id = current_setting('app.tenant_id', true));
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- fa_gov_orch_trigger_timeline (append-only)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fa_gov_orch_trigger_timeline (
    id             VARCHAR(64)  PRIMARY KEY,
    tenant_id      VARCHAR(255) NOT NULL,
    trigger_id     VARCHAR(64)  NOT NULL,
    event_type     VARCHAR(64)  NOT NULL,
    actor_id       VARCHAR(255),
    event_metadata TEXT,
    created_at     VARCHAR(64)  NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_fa_gov_orch_trigger_timeline_tenant
    ON fa_gov_orch_trigger_timeline (tenant_id);
CREATE INDEX IF NOT EXISTS ix_fa_gov_orch_trigger_timeline_tenant_trigger
    ON fa_gov_orch_trigger_timeline (tenant_id, trigger_id, created_at);

ALTER TABLE fa_gov_orch_trigger_timeline ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename  = 'fa_gov_orch_trigger_timeline'
          AND policyname = 'fa_gov_orch_trigger_timeline_tenant_isolation'
    ) THEN
        CREATE POLICY fa_gov_orch_trigger_timeline_tenant_isolation
            ON fa_gov_orch_trigger_timeline
            USING (tenant_id = current_setting('app.tenant_id', true));
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_rules
        WHERE tablename = 'fa_gov_orch_trigger_timeline'
          AND rulename  = 'fa_gov_orch_trigger_timeline_no_update'
    ) THEN
        CREATE RULE fa_gov_orch_trigger_timeline_no_update
            AS ON UPDATE TO fa_gov_orch_trigger_timeline DO INSTEAD NOTHING;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_rules
        WHERE tablename = 'fa_gov_orch_trigger_timeline'
          AND rulename  = 'fa_gov_orch_trigger_timeline_no_delete'
    ) THEN
        CREATE RULE fa_gov_orch_trigger_timeline_no_delete
            AS ON DELETE TO fa_gov_orch_trigger_timeline DO INSTEAD NOTHING;
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- fa_gov_orch_simulation
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fa_gov_orch_simulation (
    id               VARCHAR(64)  PRIMARY KEY,
    tenant_id        VARCHAR(255) NOT NULL,
    name             VARCHAR(255) NOT NULL,
    change_type      VARCHAR(64)  NOT NULL,
    change_data      TEXT,
    simulation_state VARCHAR(32)  NOT NULL DEFAULT 'PENDING',
    result           TEXT,
    created_at       VARCHAR(64)  NOT NULL,
    updated_at       VARCHAR(64)  NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_fa_gov_orch_simulation_tenant
    ON fa_gov_orch_simulation (tenant_id);
CREATE INDEX IF NOT EXISTS ix_fa_gov_orch_simulation_tenant_state
    ON fa_gov_orch_simulation (tenant_id, simulation_state);

ALTER TABLE fa_gov_orch_simulation ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename  = 'fa_gov_orch_simulation'
          AND policyname = 'fa_gov_orch_simulation_tenant_isolation'
    ) THEN
        CREATE POLICY fa_gov_orch_simulation_tenant_isolation ON fa_gov_orch_simulation
            USING (tenant_id = current_setting('app.tenant_id', true));
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- fa_gov_orch_approval
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fa_gov_orch_approval (
    id             VARCHAR(64)  PRIMARY KEY,
    tenant_id      VARCHAR(255) NOT NULL,
    workflow_id    VARCHAR(64)  NOT NULL,
    actor_id       VARCHAR(255) NOT NULL,
    stage          INTEGER      NOT NULL DEFAULT 1,
    quorum         INTEGER      NOT NULL DEFAULT 1,
    approval_state VARCHAR(32)  NOT NULL DEFAULT 'PENDING',
    decision       VARCHAR(32),
    reason         TEXT,
    delegated_to   VARCHAR(255),
    created_at     VARCHAR(64)  NOT NULL,
    updated_at     VARCHAR(64)  NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_fa_gov_orch_approval_tenant
    ON fa_gov_orch_approval (tenant_id);
CREATE INDEX IF NOT EXISTS ix_fa_gov_orch_approval_tenant_workflow
    ON fa_gov_orch_approval (tenant_id, workflow_id, stage);

ALTER TABLE fa_gov_orch_approval ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename  = 'fa_gov_orch_approval'
          AND policyname = 'fa_gov_orch_approval_tenant_isolation'
    ) THEN
        CREATE POLICY fa_gov_orch_approval_tenant_isolation ON fa_gov_orch_approval
            USING (tenant_id = current_setting('app.tenant_id', true));
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- fa_gov_orch_maintenance_window
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fa_gov_orch_maintenance_window (
    id           VARCHAR(64)  PRIMARY KEY,
    tenant_id    VARCHAR(255) NOT NULL,
    name         VARCHAR(255) NOT NULL,
    window_state VARCHAR(32)  NOT NULL DEFAULT 'SCHEDULED',
    starts_at    VARCHAR(64)  NOT NULL,
    ends_at      VARCHAR(64)  NOT NULL,
    reason       TEXT,
    created_at   VARCHAR(64)  NOT NULL,
    updated_at   VARCHAR(64)  NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_fa_gov_orch_mw_tenant
    ON fa_gov_orch_maintenance_window (tenant_id);
CREATE INDEX IF NOT EXISTS ix_fa_gov_orch_mw_tenant_state
    ON fa_gov_orch_maintenance_window (tenant_id, window_state);

ALTER TABLE fa_gov_orch_maintenance_window ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename  = 'fa_gov_orch_maintenance_window'
          AND policyname = 'fa_gov_orch_mw_tenant_isolation'
    ) THEN
        CREATE POLICY fa_gov_orch_mw_tenant_isolation
            ON fa_gov_orch_maintenance_window
            USING (tenant_id = current_setting('app.tenant_id', true));
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- fa_gov_orch_change_detection
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fa_gov_orch_change_detection (
    id           VARCHAR(64)  PRIMARY KEY,
    tenant_id    VARCHAR(255) NOT NULL,
    change_type  VARCHAR(64)  NOT NULL,
    source_id    VARCHAR(64),
    impact_level VARCHAR(32)  NOT NULL DEFAULT 'LOW',
    change_data  TEXT,
    created_at   VARCHAR(64)  NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_fa_gov_orch_change_tenant
    ON fa_gov_orch_change_detection (tenant_id);
CREATE INDEX IF NOT EXISTS ix_fa_gov_orch_change_tenant_type
    ON fa_gov_orch_change_detection (tenant_id, change_type, created_at);

ALTER TABLE fa_gov_orch_change_detection ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename  = 'fa_gov_orch_change_detection'
          AND policyname = 'fa_gov_orch_change_tenant_isolation'
    ) THEN
        CREATE POLICY fa_gov_orch_change_tenant_isolation
            ON fa_gov_orch_change_detection
            USING (tenant_id = current_setting('app.tenant_id', true));
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- fa_gov_orch_timeline (append-only)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fa_gov_orch_timeline (
    id             VARCHAR(64)  PRIMARY KEY,
    tenant_id      VARCHAR(255) NOT NULL,
    entity_type    VARCHAR(64)  NOT NULL,
    entity_id      VARCHAR(64)  NOT NULL,
    event_type     VARCHAR(64)  NOT NULL,
    actor_id       VARCHAR(255),
    event_metadata TEXT,
    created_at     VARCHAR(64)  NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_fa_gov_orch_timeline_tenant
    ON fa_gov_orch_timeline (tenant_id);
CREATE INDEX IF NOT EXISTS ix_fa_gov_orch_timeline_tenant_entity
    ON fa_gov_orch_timeline (tenant_id, entity_type, entity_id, created_at);

ALTER TABLE fa_gov_orch_timeline ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename  = 'fa_gov_orch_timeline'
          AND policyname = 'fa_gov_orch_timeline_tenant_isolation'
    ) THEN
        CREATE POLICY fa_gov_orch_timeline_tenant_isolation ON fa_gov_orch_timeline
            USING (tenant_id = current_setting('app.tenant_id', true));
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_rules
        WHERE tablename = 'fa_gov_orch_timeline'
          AND rulename  = 'fa_gov_orch_timeline_no_update'
    ) THEN
        CREATE RULE fa_gov_orch_timeline_no_update
            AS ON UPDATE TO fa_gov_orch_timeline DO INSTEAD NOTHING;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_rules
        WHERE tablename = 'fa_gov_orch_timeline'
          AND rulename  = 'fa_gov_orch_timeline_no_delete'
    ) THEN
        CREATE RULE fa_gov_orch_timeline_no_delete
            AS ON DELETE TO fa_gov_orch_timeline DO INSTEAD NOTHING;
    END IF;
END $$;
