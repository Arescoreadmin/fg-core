-- PR-01a: Identity Governance Foundation — persistence tables
-- Creates:
--   identity_lifecycle_events       -- append-only lifecycle transitions
--   identity_devices                -- device trust registry
--   identity_timeline_events        -- append-only, hash-chained timeline
--   identity_break_glass_requests   -- break-glass emergency access workflow
--   identity_risk_snapshots         -- append-only risk score snapshots
--
-- All tables carry tenant_id NOT NULL, and enable Row Level Security using
-- the same current_setting('app.tenant_id', true) pattern used by prior
-- governance migrations.
--
-- Notes:
--   * Uses CREATE TABLE IF NOT EXISTS so the migration is idempotent.
--   * No BEGIN;/COMMIT; wrapper — the migration runner handles transactions.
--   * Phase 1 in api/identity_governance/ operates in memory; these tables
--     are provisioned in advance so the Phase 2 persistence layer can
--     write without a schema change.

-- ---------------------------------------------------------------------------
-- identity_lifecycle_events
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS identity_lifecycle_events (
    record_id   VARCHAR(64)  PRIMARY KEY,
    tenant_id   VARCHAR(255) NOT NULL,
    subject     VARCHAR(255) NOT NULL,
    from_state  VARCHAR(32)  NOT NULL,
    to_state    VARCHAR(32)  NOT NULL,
    reason      TEXT         NOT NULL,
    actor       VARCHAR(255) NOT NULL,
    occurred_at VARCHAR(64)  NOT NULL,
    created_at  VARCHAR(64)  NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_identity_lifecycle_events_tenant_subject
    ON identity_lifecycle_events (tenant_id, subject);
CREATE INDEX IF NOT EXISTS ix_identity_lifecycle_events_tenant_created
    ON identity_lifecycle_events (tenant_id, created_at);

ALTER TABLE identity_lifecycle_events ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename  = 'identity_lifecycle_events'
          AND policyname = 'identity_lifecycle_events_tenant_isolation'
    ) THEN
        CREATE POLICY identity_lifecycle_events_tenant_isolation
            ON identity_lifecycle_events
            USING (tenant_id = current_setting('app.tenant_id', true));
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- identity_devices
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS identity_devices (
    device_id         VARCHAR(64)  PRIMARY KEY,
    tenant_id         VARCHAR(255) NOT NULL,
    subject           VARCHAR(255) NOT NULL,
    fingerprint_hash  VARCHAR(128) NOT NULL,
    user_agent_hash   VARCHAR(128) NOT NULL,
    ip_metadata       TEXT,
    trust_state       VARCHAR(32)  NOT NULL,
    risk_score        DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    last_reason       TEXT,
    registered_at     VARCHAR(64)  NOT NULL,
    updated_at        VARCHAR(64)  NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_identity_devices_tenant_subject
    ON identity_devices (tenant_id, subject);
CREATE INDEX IF NOT EXISTS ix_identity_devices_tenant_updated
    ON identity_devices (tenant_id, updated_at);

ALTER TABLE identity_devices ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename  = 'identity_devices'
          AND policyname = 'identity_devices_tenant_isolation'
    ) THEN
        CREATE POLICY identity_devices_tenant_isolation
            ON identity_devices
            USING (tenant_id = current_setting('app.tenant_id', true));
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- identity_timeline_events (append-only, hash-chained)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS identity_timeline_events (
    event_id       VARCHAR(64)  PRIMARY KEY,
    tenant_id      VARCHAR(255) NOT NULL,
    subject        VARCHAR(255) NOT NULL,
    actor          VARCHAR(255) NOT NULL,
    event_type     VARCHAR(64)  NOT NULL,
    occurred_at    VARCHAR(64)  NOT NULL,
    correlation_id VARCHAR(255),
    details_json   TEXT,
    previous_hash  VARCHAR(64)  NOT NULL,
    event_hash     VARCHAR(64)  NOT NULL,
    created_at     VARCHAR(64)  NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_identity_timeline_events_tenant_subject
    ON identity_timeline_events (tenant_id, subject);
CREATE INDEX IF NOT EXISTS ix_identity_timeline_events_tenant_created
    ON identity_timeline_events (tenant_id, created_at);
CREATE INDEX IF NOT EXISTS ix_identity_timeline_events_tenant_event_type
    ON identity_timeline_events (tenant_id, event_type);

ALTER TABLE identity_timeline_events ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename  = 'identity_timeline_events'
          AND policyname = 'identity_timeline_events_tenant_isolation'
    ) THEN
        CREATE POLICY identity_timeline_events_tenant_isolation
            ON identity_timeline_events
            USING (tenant_id = current_setting('app.tenant_id', true));
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- identity_break_glass_requests
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS identity_break_glass_requests (
    request_id            VARCHAR(64)  PRIMARY KEY,
    tenant_id             VARCHAR(255) NOT NULL,
    subject               VARCHAR(255) NOT NULL,
    requested_capability  VARCHAR(255) NOT NULL,
    reason                TEXT         NOT NULL,
    requested_by          VARCHAR(255) NOT NULL,
    requested_at          VARCHAR(64)  NOT NULL,
    duration_seconds      INTEGER      NOT NULL,
    status                VARCHAR(32)  NOT NULL,
    approver              VARCHAR(255),
    approved_at           VARCHAR(64),
    expires_at            VARCHAR(64),
    revoked_by            VARCHAR(255),
    revoked_at            VARCHAR(64),
    created_at            VARCHAR(64)  NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_identity_break_glass_requests_tenant_subject
    ON identity_break_glass_requests (tenant_id, subject);
CREATE INDEX IF NOT EXISTS ix_identity_break_glass_requests_tenant_created
    ON identity_break_glass_requests (tenant_id, created_at);
CREATE INDEX IF NOT EXISTS ix_identity_break_glass_requests_tenant_status
    ON identity_break_glass_requests (tenant_id, status);

ALTER TABLE identity_break_glass_requests ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename  = 'identity_break_glass_requests'
          AND policyname = 'identity_break_glass_requests_tenant_isolation'
    ) THEN
        CREATE POLICY identity_break_glass_requests_tenant_isolation
            ON identity_break_glass_requests
            USING (tenant_id = current_setting('app.tenant_id', true));
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- identity_risk_snapshots (append-only)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS identity_risk_snapshots (
    snapshot_id       VARCHAR(64)  PRIMARY KEY,
    tenant_id         VARCHAR(255) NOT NULL,
    subject           VARCHAR(255) NOT NULL,
    score             DOUBLE PRECISION NOT NULL,
    band              VARCHAR(16)  NOT NULL,
    factors_json      TEXT,
    evaluator_version VARCHAR(16)  NOT NULL,
    evaluated_at      VARCHAR(64)  NOT NULL,
    created_at        VARCHAR(64)  NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_identity_risk_snapshots_tenant_subject
    ON identity_risk_snapshots (tenant_id, subject);
CREATE INDEX IF NOT EXISTS ix_identity_risk_snapshots_tenant_created
    ON identity_risk_snapshots (tenant_id, created_at);

ALTER TABLE identity_risk_snapshots ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename  = 'identity_risk_snapshots'
          AND policyname = 'identity_risk_snapshots_tenant_isolation'
    ) THEN
        CREATE POLICY identity_risk_snapshots_tenant_isolation
            ON identity_risk_snapshots
            USING (tenant_id = current_setting('app.tenant_id', true));
    END IF;
END $$;
