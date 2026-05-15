-- 0048_deployment_manager.sql
-- PR 80 — Deployment Manager Foundation.
-- Touching schema — flagged explicitly per CLAUDE.md.
--
-- Adds four tables:
--   deployment_environments    — immutable env descriptors (platform + tenant-dedicated)
--   deployment_records         — mutable deployment lifecycle state
--   deployment_events          — append-only audit trail (state changes, health, rollback)
--   deployment_health_records  — point-in-time health check results per deployment
--
-- Security posture:
--   - No secrets, credentials, or raw error messages stored.
--   - tenant_id nullable: NULL = platform-level (multi-tenant) env,
--     non-NULL = tenant-dedicated, visible only to that tenant.
--   - deployment_events is enforced append-only via Postgres rules.
--   - All tables are fully idempotent (CREATE TABLE IF NOT EXISTS).
--
-- Downgrade: tables can be dropped safely — no foreign keys to existing tables.

-- ─── Deployment Environments ─────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS deployment_environments (
    id                        BIGSERIAL    PRIMARY KEY,
    env_id                    TEXT         NOT NULL UNIQUE,
    env_type                  TEXT         NOT NULL,
    region                    TEXT         NOT NULL,
    lifecycle_state           TEXT         NOT NULL DEFAULT 'active',
    compliance_classification TEXT         NOT NULL DEFAULT 'standard',
    created_by                TEXT         NOT NULL,
    created_at                TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    tenant_id                 TEXT,
    deployment_policy_json    TEXT,

    CONSTRAINT chk_deploy_env_type CHECK (
        env_type IN ('local', 'dev', 'staging', 'production', 'tenant-dedicated', 'regulated')
    ),
    CONSTRAINT chk_deploy_env_lifecycle CHECK (
        lifecycle_state IN ('active', 'maintenance', 'decommissioned')
    ),
    CONSTRAINT chk_deploy_env_compliance CHECK (
        compliance_classification IN ('standard', 'regulated', 'hipaa', 'fedramp', 'govcon')
    )
);

CREATE INDEX IF NOT EXISTS ix_deployment_env_tenant_type
    ON deployment_environments (tenant_id, env_type);

CREATE INDEX IF NOT EXISTS ix_deployment_env_lifecycle
    ON deployment_environments (lifecycle_state);

-- ─── Deployment Records ───────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS deployment_records (
    id                       BIGSERIAL    PRIMARY KEY,
    deployment_id            TEXT         NOT NULL UNIQUE,
    env_id                   TEXT         NOT NULL,
    version_ref              TEXT         NOT NULL,
    strategy                 TEXT         NOT NULL DEFAULT 'rolling',
    state                    TEXT         NOT NULL DEFAULT 'pending',
    initiated_by             TEXT         NOT NULL,
    initiated_at             TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    completed_at             TIMESTAMPTZ,
    tenant_id                TEXT,
    artifact_hash            TEXT,
    rollback_from_id         TEXT,
    rollback_reason          TEXT,
    approval_required        INTEGER      NOT NULL DEFAULT 0,
    approval_granted_by      TEXT,
    deployment_metadata_json TEXT,

    CONSTRAINT chk_deploy_strategy CHECK (
        strategy IN ('rolling', 'blue_green', 'canary', 'direct')
    ),
    CONSTRAINT chk_deploy_state CHECK (
        state IN (
            'pending', 'validating', 'deploying',
            'healthy', 'degraded', 'failed', 'rolled_back'
        )
    )
);

CREATE INDEX IF NOT EXISTS ix_deploy_record_env_state
    ON deployment_records (env_id, state);

CREATE INDEX IF NOT EXISTS ix_deploy_record_tenant_state
    ON deployment_records (tenant_id, state);

CREATE INDEX IF NOT EXISTS ix_deploy_record_initiated_at
    ON deployment_records (initiated_at DESC);

-- ─── Deployment Events (append-only audit trail) ──────────────────────────────

CREATE TABLE IF NOT EXISTS deployment_events (
    id            BIGSERIAL    PRIMARY KEY,
    event_id      TEXT         NOT NULL UNIQUE,
    deployment_id TEXT         NOT NULL,
    env_id        TEXT         NOT NULL,
    tenant_id     TEXT,
    event_type    TEXT         NOT NULL,
    actor         TEXT         NOT NULL,
    timestamp     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    from_state    TEXT,
    to_state      TEXT,
    details_json  TEXT,

    CONSTRAINT chk_deploy_event_type CHECK (
        event_type IN (
            'created', 'state_transition', 'health_recorded',
            'rollback_initiated', 'approval_requested',
            'approval_granted', 'approval_denied', 'metadata_updated'
        )
    )
);

CREATE INDEX IF NOT EXISTS ix_deploy_event_deployment_ts
    ON deployment_events (deployment_id, timestamp ASC);

CREATE INDEX IF NOT EXISTS ix_deploy_event_env_ts
    ON deployment_events (env_id, timestamp DESC);

CREATE INDEX IF NOT EXISTS ix_deploy_event_tenant_ts
    ON deployment_events (tenant_id, timestamp DESC);

-- Enforce append-only semantics on PostgreSQL.
CREATE OR REPLACE RULE deployment_events_no_update AS
    ON UPDATE TO deployment_events DO INSTEAD NOTHING;

CREATE OR REPLACE RULE deployment_events_no_delete AS
    ON DELETE TO deployment_events DO INSTEAD NOTHING;

-- ─── Deployment Health Records ────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS deployment_health_records (
    id                      BIGSERIAL    PRIMARY KEY,
    record_id               TEXT         NOT NULL UNIQUE,
    deployment_id           TEXT         NOT NULL,
    env_id                  TEXT         NOT NULL,
    tenant_id               TEXT,
    readiness_result        TEXT         NOT NULL DEFAULT 'unknown',
    liveness_result         TEXT         NOT NULL DEFAULT 'unknown',
    smoke_test_result       TEXT         NOT NULL DEFAULT 'unknown',
    validation_result       TEXT         NOT NULL DEFAULT 'unknown',
    checked_by              TEXT         NOT NULL,
    checked_at              TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    rollback_trigger_reason TEXT,

    CONSTRAINT chk_health_readiness CHECK (
        readiness_result IN ('pass', 'fail', 'skip', 'unknown')
    ),
    CONSTRAINT chk_health_liveness CHECK (
        liveness_result IN ('pass', 'fail', 'skip', 'unknown')
    ),
    CONSTRAINT chk_health_smoke CHECK (
        smoke_test_result IN ('pass', 'fail', 'skip', 'unknown')
    ),
    CONSTRAINT chk_health_validation CHECK (
        validation_result IN ('pass', 'fail', 'skip', 'unknown')
    )
);

CREATE INDEX IF NOT EXISTS ix_deploy_health_deployment_ts
    ON deployment_health_records (deployment_id, checked_at DESC);

CREATE INDEX IF NOT EXISTS ix_deploy_health_tenant_ts
    ON deployment_health_records (tenant_id, checked_at DESC);
