-- PR 18.3: Enterprise Remediation Authority
-- Creates:
--   fa_rem_plan          -- remediation plans
--   fa_rem_task          -- remediation tasks
--   fa_rem_timeline      -- append-only timeline events
--   fa_rem_assignment    -- task assignments
--   fa_rem_dependency    -- dependency edges
--   fa_rem_verification  -- verification records
--   fa_rem_evidence_link -- evidence -> task links

-- ---------------------------------------------------------------------------
-- fa_rem_plan
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fa_rem_plan (
    id            VARCHAR(64)  PRIMARY KEY,
    tenant_id     VARCHAR(255) NOT NULL,
    title         TEXT         NOT NULL,
    description   TEXT,
    plan_state    VARCHAR(32)  NOT NULL DEFAULT 'DRAFT',
    assessment_id VARCHAR(64),
    target_date   VARCHAR(64),
    created_at    VARCHAR(64)  NOT NULL,
    updated_at    VARCHAR(64)  NOT NULL,
    completed_at  VARCHAR(64)
);

CREATE INDEX IF NOT EXISTS ix_fa_rem_plan_tenant
    ON fa_rem_plan (tenant_id);
CREATE INDEX IF NOT EXISTS ix_fa_rem_plan_tenant_state
    ON fa_rem_plan (tenant_id, plan_state);

ALTER TABLE fa_rem_plan ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename  = 'fa_rem_plan'
          AND policyname = 'fa_rem_plan_tenant_isolation'
    ) THEN
        CREATE POLICY fa_rem_plan_tenant_isolation ON fa_rem_plan
            USING (tenant_id = current_setting('app.tenant_id', true));
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- fa_rem_task
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fa_rem_task (
    id           VARCHAR(64)  PRIMARY KEY,
    tenant_id    VARCHAR(255) NOT NULL,
    plan_id      VARCHAR(64),
    title        TEXT         NOT NULL,
    description  TEXT,
    task_state   VARCHAR(32)  NOT NULL DEFAULT 'OPEN',
    priority     VARCHAR(32)  NOT NULL DEFAULT 'MEDIUM',
    owner_id     VARCHAR(255),
    reviewer_id  VARCHAR(255),
    approver_id  VARCHAR(255),
    finding_id   VARCHAR(64),
    control_id   VARCHAR(64),
    evidence_id  VARCHAR(64),
    target_date  VARCHAR(64),
    risk_score   DOUBLE PRECISION,
    sla_status   VARCHAR(32)  NOT NULL DEFAULT 'UNSCHEDULED',
    created_at   VARCHAR(64)  NOT NULL,
    updated_at   VARCHAR(64)  NOT NULL,
    completed_at VARCHAR(64)
);

CREATE INDEX IF NOT EXISTS ix_fa_rem_task_tenant
    ON fa_rem_task (tenant_id);
CREATE INDEX IF NOT EXISTS ix_fa_rem_task_tenant_state
    ON fa_rem_task (tenant_id, task_state);
CREATE INDEX IF NOT EXISTS ix_fa_rem_task_tenant_priority
    ON fa_rem_task (tenant_id, priority);
CREATE INDEX IF NOT EXISTS ix_fa_rem_task_tenant_owner
    ON fa_rem_task (tenant_id, owner_id);
CREATE INDEX IF NOT EXISTS ix_fa_rem_task_plan
    ON fa_rem_task (plan_id);

ALTER TABLE fa_rem_task ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename  = 'fa_rem_task'
          AND policyname = 'fa_rem_task_tenant_isolation'
    ) THEN
        CREATE POLICY fa_rem_task_tenant_isolation ON fa_rem_task
            USING (tenant_id = current_setting('app.tenant_id', true));
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- fa_rem_timeline (append-only)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fa_rem_timeline (
    id             VARCHAR(64)  PRIMARY KEY,
    tenant_id      VARCHAR(255) NOT NULL,
    task_id        VARCHAR(64)  NOT NULL,
    event_type     VARCHAR(64)  NOT NULL,
    from_state     VARCHAR(32),
    to_state       VARCHAR(32),
    actor_id       VARCHAR(255),
    reason         TEXT,
    event_metadata TEXT,
    created_at     VARCHAR(64)  NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_fa_rem_timeline_tenant
    ON fa_rem_timeline (tenant_id);
CREATE INDEX IF NOT EXISTS ix_fa_rem_timeline_tenant_task
    ON fa_rem_timeline (tenant_id, task_id, created_at);

ALTER TABLE fa_rem_timeline ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename  = 'fa_rem_timeline'
          AND policyname = 'fa_rem_timeline_tenant_isolation'
    ) THEN
        CREATE POLICY fa_rem_timeline_tenant_isolation ON fa_rem_timeline
            USING (tenant_id = current_setting('app.tenant_id', true));
    END IF;
END $$;

-- Append-only enforcement at DB level
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_rules
        WHERE tablename = 'fa_rem_timeline'
          AND rulename  = 'fa_rem_timeline_no_update'
    ) THEN
        CREATE RULE fa_rem_timeline_no_update
            AS ON UPDATE TO fa_rem_timeline DO INSTEAD NOTHING;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_rules
        WHERE tablename = 'fa_rem_timeline'
          AND rulename  = 'fa_rem_timeline_no_delete'
    ) THEN
        CREATE RULE fa_rem_timeline_no_delete
            AS ON DELETE TO fa_rem_timeline DO INSTEAD NOTHING;
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- fa_rem_assignment
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fa_rem_assignment (
    id         VARCHAR(64)  PRIMARY KEY,
    tenant_id  VARCHAR(255) NOT NULL,
    task_id    VARCHAR(64)  NOT NULL,
    actor_id   VARCHAR(255) NOT NULL,
    role       VARCHAR(32)  NOT NULL,
    created_at VARCHAR(64)  NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_fa_rem_assignment_tenant
    ON fa_rem_assignment (tenant_id);
CREATE INDEX IF NOT EXISTS ix_fa_rem_assignment_tenant_task_role
    ON fa_rem_assignment (tenant_id, task_id, role);

ALTER TABLE fa_rem_assignment ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename  = 'fa_rem_assignment'
          AND policyname = 'fa_rem_assignment_tenant_isolation'
    ) THEN
        CREATE POLICY fa_rem_assignment_tenant_isolation ON fa_rem_assignment
            USING (tenant_id = current_setting('app.tenant_id', true));
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- fa_rem_dependency
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fa_rem_dependency (
    id              VARCHAR(64)  PRIMARY KEY,
    tenant_id       VARCHAR(255) NOT NULL,
    source_task_id  VARCHAR(64)  NOT NULL,
    target_task_id  VARCHAR(64)  NOT NULL,
    dependency_type VARCHAR(32)  NOT NULL DEFAULT 'BLOCKS',
    created_at      VARCHAR(64)  NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_fa_rem_dependency_tenant
    ON fa_rem_dependency (tenant_id);
CREATE INDEX IF NOT EXISTS ix_fa_rem_dependency_tenant_edge
    ON fa_rem_dependency (tenant_id, source_task_id, target_task_id);

ALTER TABLE fa_rem_dependency ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename  = 'fa_rem_dependency'
          AND policyname = 'fa_rem_dependency_tenant_isolation'
    ) THEN
        CREATE POLICY fa_rem_dependency_tenant_isolation ON fa_rem_dependency
            USING (tenant_id = current_setting('app.tenant_id', true));
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- fa_rem_verification
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fa_rem_verification (
    id                 VARCHAR(64)  PRIMARY KEY,
    tenant_id          VARCHAR(255) NOT NULL,
    task_id            VARCHAR(64)  NOT NULL,
    verifier_id        VARCHAR(255) NOT NULL,
    verification_state VARCHAR(32)  NOT NULL DEFAULT 'PENDING',
    evidence_id        VARCHAR(64),
    notes              TEXT,
    created_at         VARCHAR(64)  NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_fa_rem_verification_tenant
    ON fa_rem_verification (tenant_id);
CREATE INDEX IF NOT EXISTS ix_fa_rem_verification_tenant_task
    ON fa_rem_verification (tenant_id, task_id, created_at);

ALTER TABLE fa_rem_verification ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename  = 'fa_rem_verification'
          AND policyname = 'fa_rem_verification_tenant_isolation'
    ) THEN
        CREATE POLICY fa_rem_verification_tenant_isolation ON fa_rem_verification
            USING (tenant_id = current_setting('app.tenant_id', true));
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- fa_rem_evidence_link
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fa_rem_evidence_link (
    id          VARCHAR(64)  PRIMARY KEY,
    tenant_id   VARCHAR(255) NOT NULL,
    task_id     VARCHAR(64)  NOT NULL,
    evidence_id VARCHAR(64)  NOT NULL,
    created_at  VARCHAR(64)  NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_fa_rem_evidence_link_tenant
    ON fa_rem_evidence_link (tenant_id);
CREATE INDEX IF NOT EXISTS ix_fa_rem_evidence_link_tenant_task
    ON fa_rem_evidence_link (tenant_id, task_id, evidence_id);

ALTER TABLE fa_rem_evidence_link ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename  = 'fa_rem_evidence_link'
          AND policyname = 'fa_rem_evidence_link_tenant_isolation'
    ) THEN
        CREATE POLICY fa_rem_evidence_link_tenant_isolation ON fa_rem_evidence_link
            USING (tenant_id = current_setting('app.tenant_id', true));
    END IF;
END $$;
