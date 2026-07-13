-- 0152: Enterprise Actor Attribution & Non-Repudiation — actor identity registry + attribution records
--
-- Adds four tables that implement cryptographic actor attribution for all governance events:
--   actor_identities            — canonical actor registry; mutable for status/last_seen
--   actor_identity_snapshots    — append-only point-in-time snapshots (UPDATE/DELETE denied)
--   actor_attribution_records   — append-only per-event attribution with SHA-256 fingerprints
--   actor_audit_events          — append-only audit trail for actor identity mutations
--
-- Builds on migration 0151. Row-level tenant isolation matches the pattern established for
-- identity_* tables. Append-only triggers use append_only_guard() from migration 0002.

CREATE TABLE IF NOT EXISTS actor_identities (
    id                    VARCHAR(64)  PRIMARY KEY,
    tenant_id             VARCHAR(255) NOT NULL,
    organization_id       VARCHAR(255),
    actor_type            VARCHAR(64)  NOT NULL,
    actor_subject         VARCHAR(512) NOT NULL,
    actor_display_name    VARCHAR(512) NOT NULL,
    email_hash            VARCHAR(128),
    authentication_method VARCHAR(64)  NOT NULL,
    identity_provider     VARCHAR(128) NOT NULL,
    governance_role       VARCHAR(128),
    is_service_account    INTEGER      NOT NULL DEFAULT 0,
    is_robot              INTEGER      NOT NULL DEFAULT 0,
    service_account_id    VARCHAR(255),
    robot_identity        VARCHAR(255),
    delegated_by          VARCHAR(64),
    trust_level           VARCHAR(32)  NOT NULL DEFAULT 'unverified',
    status                VARCHAR(32)  NOT NULL DEFAULT 'active',
    created_at            VARCHAR(64)  NOT NULL,
    updated_at            VARCHAR(64)  NOT NULL,
    last_seen_at          VARCHAR(64),
    schema_version        VARCHAR(16)  NOT NULL DEFAULT '1.0'
);

CREATE INDEX IF NOT EXISTS ix_actor_identities_tenant_id
    ON actor_identities (tenant_id);
CREATE INDEX IF NOT EXISTS ix_actor_identities_tenant_type
    ON actor_identities (tenant_id, actor_type);
CREATE INDEX IF NOT EXISTS ix_actor_identities_tenant_status
    ON actor_identities (tenant_id, status);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'uq_actor_identities_tenant_subject'
    ) THEN
        ALTER TABLE actor_identities
            ADD CONSTRAINT uq_actor_identities_tenant_subject
            UNIQUE (tenant_id, actor_subject);
    END IF;
END $$;

ALTER TABLE actor_identities ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS actor_identities_tenant_isolation ON actor_identities;
CREATE POLICY actor_identities_tenant_isolation
    ON actor_identities USING (tenant_id = current_setting('app.tenant_id', true));


CREATE TABLE IF NOT EXISTS actor_identity_snapshots (
    id                    VARCHAR(64)  PRIMARY KEY,
    tenant_id             VARCHAR(255) NOT NULL,
    actor_id              VARCHAR(64)  NOT NULL,
    snapshot_reason       VARCHAR(64)  NOT NULL,
    actor_type            VARCHAR(64)  NOT NULL,
    actor_subject         VARCHAR(512) NOT NULL,
    actor_display_name    VARCHAR(512) NOT NULL,
    email_hash            VARCHAR(128),
    authentication_method VARCHAR(64)  NOT NULL,
    identity_provider     VARCHAR(128) NOT NULL,
    governance_role       VARCHAR(128),
    permission_snapshot   TEXT         NOT NULL DEFAULT '[]',
    groups_snapshot       TEXT         NOT NULL DEFAULT '[]',
    department            VARCHAR(255),
    organization_snapshot VARCHAR(255),
    trust_level           VARCHAR(32)  NOT NULL,
    is_service_account    INTEGER      NOT NULL DEFAULT 0,
    is_robot              INTEGER      NOT NULL DEFAULT 0,
    delegated_by          VARCHAR(64),
    captured_at           VARCHAR(64)  NOT NULL,
    schema_version        VARCHAR(16)  NOT NULL DEFAULT '1.0'
);

CREATE INDEX IF NOT EXISTS ix_actor_identity_snapshots_tenant_id
    ON actor_identity_snapshots (tenant_id);
CREATE INDEX IF NOT EXISTS ix_actor_identity_snapshots_tenant_actor
    ON actor_identity_snapshots (tenant_id, actor_id);

ALTER TABLE actor_identity_snapshots ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS actor_identity_snapshots_tenant_isolation ON actor_identity_snapshots;
CREATE POLICY actor_identity_snapshots_tenant_isolation
    ON actor_identity_snapshots USING (tenant_id = current_setting('app.tenant_id', true));

-- Append-only enforcement: block UPDATE and DELETE via the shared append_only_guard()
-- from migration 0002. Idempotent DROP + CREATE keeps re-runs safe.
DO $$
BEGIN
    IF to_regclass('public.actor_identity_snapshots') IS NOT NULL THEN
        DROP TRIGGER IF EXISTS actor_identity_snapshots_append_only_update
            ON actor_identity_snapshots;
        CREATE TRIGGER actor_identity_snapshots_append_only_update
            BEFORE UPDATE ON actor_identity_snapshots
            FOR EACH ROW
            EXECUTE FUNCTION append_only_guard();

        DROP TRIGGER IF EXISTS actor_identity_snapshots_append_only_delete
            ON actor_identity_snapshots;
        CREATE TRIGGER actor_identity_snapshots_append_only_delete
            BEFORE DELETE ON actor_identity_snapshots
            FOR EACH ROW
            EXECUTE FUNCTION append_only_guard();
    END IF;
END $$;


CREATE TABLE IF NOT EXISTS actor_attribution_records (
    id                              VARCHAR(64)  PRIMARY KEY,
    tenant_id                       VARCHAR(255) NOT NULL,
    organization_id                 VARCHAR(255),
    actor_id                        VARCHAR(64)  NOT NULL,
    snapshot_id                     VARCHAR(64)  NOT NULL,
    event_type                      VARCHAR(64)  NOT NULL,
    event_ref                       VARCHAR(255),
    event_ref_type                  VARCHAR(64),
    actor_type                      VARCHAR(64)  NOT NULL,
    actor_display_name              VARCHAR(512) NOT NULL,
    authentication_method           VARCHAR(64)  NOT NULL,
    identity_provider               VARCHAR(128) NOT NULL,
    session_id                      VARCHAR(255),
    request_id                      VARCHAR(255) NOT NULL,
    client_ip_hash                  VARCHAR(128),
    user_agent_hash                 VARCHAR(128),
    governance_role                 VARCHAR(128),
    trust_level                     VARCHAR(32)  NOT NULL,
    actor_fingerprint               VARCHAR(128) NOT NULL,
    identity_fingerprint            VARCHAR(128) NOT NULL,
    request_fingerprint             VARCHAR(128) NOT NULL,
    attribution_hash                VARCHAR(128) NOT NULL,
    event_hash                      VARCHAR(128) NOT NULL,
    previous_hash                   VARCHAR(128),
    created_at                      VARCHAR(64)  NOT NULL,
    schema_version                  VARCHAR(16)  NOT NULL DEFAULT '1.0',
    autonomous_decision_confidence  TEXT,
    autonomous_policy_version       VARCHAR(64),
    autonomous_authority_chain      TEXT,
    autonomous_execution_context    TEXT,
    autonomous_reasoning_reference  VARCHAR(512),
    autonomous_governance_scope     VARCHAR(255)
);

CREATE INDEX IF NOT EXISTS ix_actor_attribution_records_tenant_id
    ON actor_attribution_records (tenant_id);
CREATE INDEX IF NOT EXISTS ix_actor_attribution_records_tenant_actor
    ON actor_attribution_records (tenant_id, actor_id);
CREATE INDEX IF NOT EXISTS ix_actor_attribution_records_tenant_event_type
    ON actor_attribution_records (tenant_id, event_type);
CREATE INDEX IF NOT EXISTS ix_actor_attribution_records_tenant_event_ref
    ON actor_attribution_records (tenant_id, event_ref);
CREATE INDEX IF NOT EXISTS ix_actor_attribution_records_tenant_attribution_hash
    ON actor_attribution_records (tenant_id, attribution_hash);

ALTER TABLE actor_attribution_records ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS actor_attribution_records_tenant_isolation ON actor_attribution_records;
CREATE POLICY actor_attribution_records_tenant_isolation
    ON actor_attribution_records USING (tenant_id = current_setting('app.tenant_id', true));

-- Append-only enforcement
DO $$
BEGIN
    IF to_regclass('public.actor_attribution_records') IS NOT NULL THEN
        DROP TRIGGER IF EXISTS actor_attribution_records_append_only_update
            ON actor_attribution_records;
        CREATE TRIGGER actor_attribution_records_append_only_update
            BEFORE UPDATE ON actor_attribution_records
            FOR EACH ROW
            EXECUTE FUNCTION append_only_guard();

        DROP TRIGGER IF EXISTS actor_attribution_records_append_only_delete
            ON actor_attribution_records;
        CREATE TRIGGER actor_attribution_records_append_only_delete
            BEFORE DELETE ON actor_attribution_records
            FOR EACH ROW
            EXECUTE FUNCTION append_only_guard();
    END IF;
END $$;


CREATE TABLE IF NOT EXISTS actor_audit_events (
    id                   VARCHAR(64)  PRIMARY KEY,
    tenant_id            VARCHAR(255) NOT NULL,
    actor_id             VARCHAR(64)  NOT NULL,
    event_type           VARCHAR(64)  NOT NULL,
    actor_type_snapshot  VARCHAR(64)  NOT NULL,
    changed_by_actor_id  VARCHAR(64),
    old_value            TEXT,
    new_value            TEXT,
    reason               TEXT,
    created_at           VARCHAR(64)  NOT NULL,
    schema_version       VARCHAR(16)  NOT NULL DEFAULT '1.0'
);

CREATE INDEX IF NOT EXISTS ix_actor_audit_events_tenant_id
    ON actor_audit_events (tenant_id);
CREATE INDEX IF NOT EXISTS ix_actor_audit_events_tenant_actor
    ON actor_audit_events (tenant_id, actor_id);
CREATE INDEX IF NOT EXISTS ix_actor_audit_events_tenant_event_type
    ON actor_audit_events (tenant_id, event_type);

ALTER TABLE actor_audit_events ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS actor_audit_events_tenant_isolation ON actor_audit_events;
CREATE POLICY actor_audit_events_tenant_isolation
    ON actor_audit_events USING (tenant_id = current_setting('app.tenant_id', true));

-- Append-only enforcement
DO $$
BEGIN
    IF to_regclass('public.actor_audit_events') IS NOT NULL THEN
        DROP TRIGGER IF EXISTS actor_audit_events_append_only_update
            ON actor_audit_events;
        CREATE TRIGGER actor_audit_events_append_only_update
            BEFORE UPDATE ON actor_audit_events
            FOR EACH ROW
            EXECUTE FUNCTION append_only_guard();

        DROP TRIGGER IF EXISTS actor_audit_events_append_only_delete
            ON actor_audit_events;
        CREATE TRIGGER actor_audit_events_append_only_delete
            BEFORE DELETE ON actor_audit_events
            FOR EACH ROW
            EXECUTE FUNCTION append_only_guard();
    END IF;
END $$;
