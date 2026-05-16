-- 0051_ops_governance.sql
-- PR 82 — Environment Management, Secrets, Retention, Export & Recovery Governance Foundation.
-- Touching schema — flagged explicitly per CLAUDE.md.
--
-- Adds nine tables:
--   ops_environments            — environment lifecycle governance records
--   ops_secret_governance       — secret governance metadata (NO raw secrets stored)
--   ops_key_rotation_schedules  — key rotation tracking per governed secret
--   ops_retention_policies      — retention governance per org/env/tenant
--   ops_export_requests         — export governance and audit lineage
--   ops_backup_records          — backup lineage (governance metadata only)
--   ops_restore_records         — restore attempt lineage
--   ops_recovery_records        — operational recovery tracking
--   ops_governance_audit_events — append-only immutable audit trail
--
-- Security posture:
--   - Raw secrets NEVER stored in any column in any table.
--   - external_reference_id is a pointer to an external KMS/Vault; not a secret.
--   - tenant_id nullable: NULL = platform-level record.
--   - ops_governance_audit_events enforced append-only via Postgres rules.
--   - All tables are fully idempotent (CREATE TABLE IF NOT EXISTS).
--   - Optimistic locking via state_version on all mutable governance records.
--
-- Downgrade: tables can be dropped safely — no foreign keys to existing tables.

-- ─── Environments ─────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ops_environments (
    environment_id           TEXT         PRIMARY KEY,
    tenant_id                TEXT,
    env_name                 TEXT         NOT NULL,
    slug                     TEXT         NOT NULL UNIQUE,
    lifecycle_state          TEXT         NOT NULL DEFAULT 'provisioning',
    env_type                 TEXT         NOT NULL DEFAULT 'shared',
    compliance_classification TEXT        NOT NULL DEFAULT 'standard',
    isolation_level          TEXT         NOT NULL DEFAULT 'standard',
    residency_classification TEXT         NOT NULL DEFAULT 'unrestricted',
    region                   TEXT,
    recovery_readiness       TEXT         NOT NULL DEFAULT 'unknown',
    validation_token         TEXT,        -- opaque token required to unblock failed_recovery -> active
    idempotency_key          TEXT,
    metadata_json            TEXT         NOT NULL DEFAULT '{}',
    created_by               TEXT         NOT NULL,
    created_at               TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    archived_at              TIMESTAMPTZ,
    state_version            INTEGER      NOT NULL DEFAULT 0,

    CONSTRAINT chk_ops_env_lifecycle CHECK (
        lifecycle_state IN ('provisioning','active','maintenance','restricted','archived','failed_recovery')
    ),
    CONSTRAINT chk_ops_env_type CHECK (
        env_type IN ('shared','dedicated','regulated_dedicated','sovereign','dr_standby')
    ),
    CONSTRAINT chk_ops_env_compliance CHECK (
        compliance_classification IN ('standard','regulated','hipaa','fedramp','govcon')
    ),
    CONSTRAINT chk_ops_env_isolation CHECK (
        isolation_level IN ('standard','network_isolated','process_isolated','hardware_isolated')
    ),
    CONSTRAINT chk_ops_env_residency CHECK (
        residency_classification IN ('unrestricted','regional','sovereign','air_gapped')
    ),
    CONSTRAINT chk_ops_env_recovery CHECK (
        recovery_readiness IN ('unknown','not_ready','partial','ready','validated')
    )
);

CREATE INDEX IF NOT EXISTS ix_ops_env_tenant
    ON ops_environments (tenant_id);
CREATE INDEX IF NOT EXISTS ix_ops_env_lifecycle
    ON ops_environments (lifecycle_state);
CREATE UNIQUE INDEX IF NOT EXISTS ix_ops_env_slug
    ON ops_environments (slug);
CREATE UNIQUE INDEX IF NOT EXISTS ix_ops_env_idem_tenant
    ON ops_environments (tenant_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL AND tenant_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ix_ops_env_idem_platform
    ON ops_environments (idempotency_key)
    WHERE idempotency_key IS NOT NULL AND tenant_id IS NULL;

-- ─── Secret Governance Metadata ───────────────────────────────────────────────
-- SECURITY: No raw secret values are stored here. external_reference_id is
-- a pointer (e.g. Vault path, KMS key ARN) — not the secret material itself.

CREATE TABLE IF NOT EXISTS ops_secret_governance (
    secret_governance_id     TEXT         PRIMARY KEY,
    tenant_id                TEXT,
    environment_id           TEXT,
    secret_name              TEXT         NOT NULL,
    secret_classification    TEXT         NOT NULL DEFAULT 'standard',
    secret_type              TEXT         NOT NULL DEFAULT 'generic',
    lifecycle_state          TEXT         NOT NULL DEFAULT 'active',
    external_provider        TEXT,        -- e.g. 'vault', 'aws_kms', 'azure_kv', 'gcp_sm', 'hsm'
    external_reference_id    TEXT,        -- provider path/ARN/key-id — NOT the secret value
    owner_scope              TEXT,
    rotation_state           TEXT         NOT NULL DEFAULT 'not_scheduled',
    rotation_policy_days     INTEGER,
    last_rotated_at          TIMESTAMPTZ,
    next_rotation_due_at     TIMESTAMPTZ,
    expires_at               TIMESTAMPTZ,
    governance_policy_json   TEXT         NOT NULL DEFAULT '{}',
    idempotency_key          TEXT,
    created_by               TEXT         NOT NULL,
    created_at               TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    state_version            INTEGER      NOT NULL DEFAULT 0,

    CONSTRAINT chk_ops_secret_classification CHECK (
        secret_classification IN ('standard','restricted','critical','regulated','hipaa','fedramp')
    ),
    CONSTRAINT chk_ops_secret_type CHECK (
        secret_type IN ('generic','api_key','tls_cert','db_credential','oauth_token','signing_key','encryption_key','hmac_key')
    ),
    CONSTRAINT chk_ops_secret_lifecycle CHECK (
        lifecycle_state IN ('active','pending_rotation','expired','revoked','compromised','archived')
    ),
    CONSTRAINT chk_ops_secret_rotation CHECK (
        rotation_state IN ('not_scheduled','scheduled','in_progress','completed','failed','overridden','emergency')
    )
);

CREATE INDEX IF NOT EXISTS ix_ops_secret_tenant
    ON ops_secret_governance (tenant_id);
CREATE INDEX IF NOT EXISTS ix_ops_secret_env
    ON ops_secret_governance (environment_id);
CREATE INDEX IF NOT EXISTS ix_ops_secret_lifecycle
    ON ops_secret_governance (lifecycle_state);
CREATE INDEX IF NOT EXISTS ix_ops_secret_rotation_due
    ON ops_secret_governance (next_rotation_due_at)
    WHERE next_rotation_due_at IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ix_ops_secret_idem_tenant
    ON ops_secret_governance (tenant_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL AND tenant_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ix_ops_secret_idem_platform
    ON ops_secret_governance (idempotency_key)
    WHERE idempotency_key IS NOT NULL AND tenant_id IS NULL;

-- ─── Key Rotation Schedules ───────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ops_key_rotation_schedules (
    rotation_id              TEXT         PRIMARY KEY,
    secret_governance_id     TEXT         NOT NULL,
    tenant_id                TEXT,
    rotation_state           TEXT         NOT NULL DEFAULT 'scheduled',
    scheduled_at             TIMESTAMPTZ  NOT NULL,
    initiated_at             TIMESTAMPTZ,
    completed_at             TIMESTAMPTZ,
    failure_reason           TEXT,
    compliance_override      BOOLEAN      NOT NULL DEFAULT FALSE,
    override_reason          TEXT,
    override_approved_by     TEXT,
    emergency_rotation       BOOLEAN      NOT NULL DEFAULT FALSE,
    waiver_reference         TEXT,
    initiated_by             TEXT,
    outcome                  TEXT,
    metadata_json            TEXT         NOT NULL DEFAULT '{}',
    created_at               TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    state_version            INTEGER      NOT NULL DEFAULT 0,

    CONSTRAINT chk_ops_rotation_state CHECK (
        rotation_state IN ('scheduled','in_progress','completed','failed','cancelled','overridden','emergency')
    ),
    CONSTRAINT chk_ops_rotation_outcome CHECK (
        outcome IS NULL OR outcome IN ('success','failure','skipped','overridden')
    )
);

CREATE INDEX IF NOT EXISTS ix_ops_rotation_secret
    ON ops_key_rotation_schedules (secret_governance_id);
CREATE INDEX IF NOT EXISTS ix_ops_rotation_tenant
    ON ops_key_rotation_schedules (tenant_id);
CREATE INDEX IF NOT EXISTS ix_ops_rotation_state
    ON ops_key_rotation_schedules (rotation_state);
CREATE INDEX IF NOT EXISTS ix_ops_rotation_scheduled
    ON ops_key_rotation_schedules (scheduled_at);

-- ─── Retention Policies ───────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ops_retention_policies (
    retention_policy_id      TEXT         PRIMARY KEY,
    tenant_id                TEXT,
    environment_id           TEXT,
    policy_name              TEXT         NOT NULL,
    retention_classification TEXT         NOT NULL DEFAULT 'standard',
    retention_state          TEXT         NOT NULL DEFAULT 'active',
    retention_days           INTEGER      NOT NULL DEFAULT 90,
    archive_after_days       INTEGER,
    deletion_scheduled_at    TIMESTAMPTZ,
    archived_at              TIMESTAMPTZ,
    legal_hold               BOOLEAN      NOT NULL DEFAULT FALSE,
    legal_hold_reason        TEXT,
    legal_hold_set_by        TEXT,
    legal_hold_set_at        TIMESTAMPTZ,
    export_restricted        BOOLEAN      NOT NULL DEFAULT FALSE,
    compliance_policy_ref    TEXT,
    override_reason          TEXT,
    idempotency_key          TEXT,
    created_by               TEXT         NOT NULL,
    created_at               TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    state_version            INTEGER      NOT NULL DEFAULT 0,

    CONSTRAINT chk_ops_retention_classification CHECK (
        retention_classification IN ('standard','extended','regulated','hipaa','fedramp','legal')
    ),
    CONSTRAINT chk_ops_retention_state CHECK (
        retention_state IN ('active','scheduled_for_archive','archived','scheduled_for_deletion','deletion_blocked','legal_hold')
    )
);

CREATE INDEX IF NOT EXISTS ix_ops_retention_tenant
    ON ops_retention_policies (tenant_id);
CREATE INDEX IF NOT EXISTS ix_ops_retention_env
    ON ops_retention_policies (environment_id);
CREATE INDEX IF NOT EXISTS ix_ops_retention_state
    ON ops_retention_policies (retention_state);
CREATE INDEX IF NOT EXISTS ix_ops_retention_legal_hold
    ON ops_retention_policies (legal_hold)
    WHERE legal_hold = TRUE;
CREATE UNIQUE INDEX IF NOT EXISTS ix_ops_retention_idem_tenant
    ON ops_retention_policies (tenant_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL AND tenant_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ix_ops_retention_idem_platform
    ON ops_retention_policies (idempotency_key)
    WHERE idempotency_key IS NOT NULL AND tenant_id IS NULL;

-- ─── Export Requests ──────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ops_export_requests (
    export_id                TEXT         PRIMARY KEY,
    tenant_id                TEXT,
    environment_id           TEXT,
    export_state             TEXT         NOT NULL DEFAULT 'requested',
    export_scope             TEXT         NOT NULL DEFAULT 'tenant',
    export_classification    TEXT         NOT NULL DEFAULT 'standard',
    export_purpose           TEXT,
    requested_by             TEXT         NOT NULL,
    approved_by              TEXT,
    rejected_by              TEXT,
    approval_reason          TEXT,
    rejection_reason         TEXT,
    legal_hold_validated     BOOLEAN      NOT NULL DEFAULT FALSE,
    residency_validated      BOOLEAN      NOT NULL DEFAULT FALSE,
    retention_validated      BOOLEAN      NOT NULL DEFAULT FALSE,
    export_restriction_flags TEXT         NOT NULL DEFAULT '{}',
    expires_at               TIMESTAMPTZ,
    completed_at             TIMESTAMPTZ,
    idempotency_key          TEXT,
    created_at               TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    state_version            INTEGER      NOT NULL DEFAULT 0,

    CONSTRAINT chk_ops_export_state CHECK (
        export_state IN ('requested','validating','approved','rejected','expired','completed')
    ),
    CONSTRAINT chk_ops_export_scope CHECK (
        export_scope IN ('tenant','environment','audit','compliance','legal','forensic','portability','offboarding')
    ),
    CONSTRAINT chk_ops_export_classification CHECK (
        export_classification IN ('standard','restricted','regulated','legal','forensic')
    )
);

CREATE INDEX IF NOT EXISTS ix_ops_export_tenant
    ON ops_export_requests (tenant_id);
CREATE INDEX IF NOT EXISTS ix_ops_export_env
    ON ops_export_requests (environment_id);
CREATE INDEX IF NOT EXISTS ix_ops_export_state
    ON ops_export_requests (export_state);
CREATE UNIQUE INDEX IF NOT EXISTS ix_ops_export_idem_tenant
    ON ops_export_requests (tenant_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL AND tenant_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ix_ops_export_idem_platform
    ON ops_export_requests (idempotency_key)
    WHERE idempotency_key IS NOT NULL AND tenant_id IS NULL;

-- ─── Backup Records ───────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ops_backup_records (
    backup_id                TEXT         PRIMARY KEY,
    tenant_id                TEXT,
    environment_id           TEXT,
    backup_scope             TEXT         NOT NULL DEFAULT 'full',
    backup_classification    TEXT         NOT NULL DEFAULT 'standard',
    backup_state             TEXT         NOT NULL DEFAULT 'initiated',
    backup_reference         TEXT,        -- opaque reference to actual backup artifact (no contents)
    retention_policy_id      TEXT,
    backup_size_bytes        BIGINT,
    checksum_ref             TEXT,        -- hash of backup artifact (not contents)
    initiated_by             TEXT         NOT NULL,
    started_at               TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    completed_at             TIMESTAMPTZ,
    expires_at               TIMESTAMPTZ,
    failure_reason           TEXT,
    metadata_json            TEXT         NOT NULL DEFAULT '{}',
    created_at               TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    state_version            INTEGER      NOT NULL DEFAULT 0,

    CONSTRAINT chk_ops_backup_scope CHECK (
        backup_scope IN ('full','incremental','differential','snapshot','audit_trail','config_only')
    ),
    CONSTRAINT chk_ops_backup_classification CHECK (
        backup_classification IN ('standard','regulated','hipaa','fedramp','govcon')
    ),
    CONSTRAINT chk_ops_backup_state CHECK (
        backup_state IN ('initiated','in_progress','completed','failed','expired','archived')
    )
);

CREATE INDEX IF NOT EXISTS ix_ops_backup_tenant
    ON ops_backup_records (tenant_id);
CREATE INDEX IF NOT EXISTS ix_ops_backup_env
    ON ops_backup_records (environment_id);
CREATE INDEX IF NOT EXISTS ix_ops_backup_state
    ON ops_backup_records (backup_state);
CREATE INDEX IF NOT EXISTS ix_ops_backup_started
    ON ops_backup_records (started_at);

-- ─── Restore Records ──────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ops_restore_records (
    restore_id               TEXT         PRIMARY KEY,
    tenant_id                TEXT,
    source_backup_id         TEXT,
    target_environment_id    TEXT,
    restore_state            TEXT         NOT NULL DEFAULT 'initiated',
    restore_scope            TEXT         NOT NULL DEFAULT 'full',
    point_in_time_ref        TEXT,        -- opaque PiT marker, not a secret
    validation_state         TEXT         NOT NULL DEFAULT 'pending',
    validation_token         TEXT,        -- validation gate token
    initiated_by             TEXT         NOT NULL,
    started_at               TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    completed_at             TIMESTAMPTZ,
    failure_reason           TEXT,
    recovery_lineage_id      TEXT,        -- links to ops_recovery_records
    metadata_json            TEXT         NOT NULL DEFAULT '{}',
    created_at               TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    state_version            INTEGER      NOT NULL DEFAULT 0,

    CONSTRAINT chk_ops_restore_state CHECK (
        restore_state IN ('initiated','validating','in_progress','completed','failed','abandoned')
    ),
    CONSTRAINT chk_ops_restore_scope CHECK (
        restore_scope IN ('full','partial','audit_trail','config_only','point_in_time')
    ),
    CONSTRAINT chk_ops_restore_validation CHECK (
        validation_state IN ('pending','in_progress','passed','failed','waived')
    )
);

CREATE INDEX IF NOT EXISTS ix_ops_restore_tenant
    ON ops_restore_records (tenant_id);
CREATE INDEX IF NOT EXISTS ix_ops_restore_backup
    ON ops_restore_records (source_backup_id);
CREATE INDEX IF NOT EXISTS ix_ops_restore_env
    ON ops_restore_records (target_environment_id);
CREATE INDEX IF NOT EXISTS ix_ops_restore_state
    ON ops_restore_records (restore_state);

-- ─── Recovery Records ─────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ops_recovery_records (
    recovery_id              TEXT         PRIMARY KEY,
    tenant_id                TEXT,
    environment_id           TEXT,
    recovery_state           TEXT         NOT NULL DEFAULT 'initiated',
    recovery_type            TEXT         NOT NULL DEFAULT 'standard',
    recovery_trigger         TEXT,
    validation_state         TEXT         NOT NULL DEFAULT 'pending',
    readiness_classification TEXT         NOT NULL DEFAULT 'unknown',
    initiated_by             TEXT         NOT NULL,
    started_at               TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    validated_at             TIMESTAMPTZ,
    completed_at             TIMESTAMPTZ,
    failure_reason           TEXT,
    failure_count            INTEGER      NOT NULL DEFAULT 0,
    drill_mode               BOOLEAN      NOT NULL DEFAULT FALSE,
    metadata_json            TEXT         NOT NULL DEFAULT '{}',
    created_at               TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    state_version            INTEGER      NOT NULL DEFAULT 0,

    CONSTRAINT chk_ops_recovery_state CHECK (
        recovery_state IN ('initiated','validating','validated','in_progress','completed','failed','abandoned')
    ),
    CONSTRAINT chk_ops_recovery_type CHECK (
        recovery_type IN ('standard','disaster_recovery','failover','drill','quarantine_exit','staged')
    ),
    CONSTRAINT chk_ops_recovery_validation CHECK (
        validation_state IN ('pending','in_progress','passed','failed','waived')
    ),
    CONSTRAINT chk_ops_recovery_readiness CHECK (
        readiness_classification IN ('unknown','not_ready','partial','ready','validated')
    )
);

CREATE INDEX IF NOT EXISTS ix_ops_recovery_tenant
    ON ops_recovery_records (tenant_id);
CREATE INDEX IF NOT EXISTS ix_ops_recovery_env
    ON ops_recovery_records (environment_id);
CREATE INDEX IF NOT EXISTS ix_ops_recovery_state
    ON ops_recovery_records (recovery_state);

-- ─── Governance Audit Events ──────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ops_governance_audit_events (
    event_id                 TEXT         PRIMARY KEY,
    tenant_id                TEXT,
    environment_id           TEXT,
    resource_type            TEXT         NOT NULL,
    resource_id              TEXT         NOT NULL,
    event_type               TEXT         NOT NULL,
    actor                    TEXT         NOT NULL,
    outcome                  TEXT         NOT NULL DEFAULT 'success',
    policy_state             TEXT,
    operational_context      TEXT,
    failure_reason           TEXT,
    details_json             TEXT         NOT NULL DEFAULT '{}',
    event_hash               TEXT,
    previous_event_hash      TEXT,
    timestamp                TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_ops_audit_outcome CHECK (
        outcome IN ('success','failure','pending','blocked')
    )
);

CREATE INDEX IF NOT EXISTS ix_ops_audit_resource
    ON ops_governance_audit_events (resource_type, resource_id);
CREATE INDEX IF NOT EXISTS ix_ops_audit_tenant
    ON ops_governance_audit_events (tenant_id);
CREATE INDEX IF NOT EXISTS ix_ops_audit_env
    ON ops_governance_audit_events (environment_id);
CREATE INDEX IF NOT EXISTS ix_ops_audit_timestamp
    ON ops_governance_audit_events (timestamp);

-- Append-only enforcement
CREATE OR REPLACE RULE ops_governance_audit_events_no_update AS
  ON UPDATE TO ops_governance_audit_events DO INSTEAD NOTHING;

CREATE OR REPLACE RULE ops_governance_audit_events_no_delete AS
  ON DELETE TO ops_governance_audit_events DO INSTEAD NOTHING;
