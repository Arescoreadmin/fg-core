-- 0153: Enterprise Identity Assurance & Trust Levels
--
-- Adds four tables that implement identity-assurance level tracking and trust
-- scoring on top of the actor attribution substrate delivered in 0152:
--   actor_identity_assurance    — current assurance record per actor (mutable: is_current flips)
--   actor_assurance_snapshots   — append-only decision chain (UPDATE/DELETE denied)
--   actor_assurance_history     — append-only event history (UPDATE/DELETE denied)
--   actor_trust_metrics         — upsertable rolling metrics per (tenant, actor, period)
--
-- Builds on 0152 (actor_identities, actor_identity_snapshots, actor_attribution_records,
-- actor_audit_events). Row-level tenant isolation matches the pattern established for
-- identity_* / actor_* tables. Append-only triggers use append_only_guard() from 0002.

CREATE TABLE IF NOT EXISTS actor_identity_assurance (
    id                        VARCHAR(64)  PRIMARY KEY,
    tenant_id                 VARCHAR(64)  NOT NULL,
    actor_id                  VARCHAR(64),
    assurance_level           VARCHAR(64)  NOT NULL,
    trust_score               INTEGER      NOT NULL,
    identity_provider         VARCHAR(64),
    authentication_method     VARCHAR(128),
    provider_claims_hash      VARCHAR(64),
    decision_fingerprint      VARCHAR(64)  NOT NULL,
    chain_hash                VARCHAR(64)  NOT NULL,
    previous_assurance_level  VARCHAR(64),
    is_current                BOOLEAN      NOT NULL DEFAULT TRUE,
    computed_at               TIMESTAMPTZ,
    created_at                TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    schema_version            VARCHAR(16)  NOT NULL DEFAULT '1.0'
);

CREATE INDEX IF NOT EXISTS ix_actor_identity_assurance_tenant_id
    ON actor_identity_assurance (tenant_id);
CREATE INDEX IF NOT EXISTS ix_actor_identity_assurance_tenant_actor
    ON actor_identity_assurance (tenant_id, actor_id);
CREATE INDEX IF NOT EXISTS ix_actor_identity_assurance_tenant_level
    ON actor_identity_assurance (tenant_id, assurance_level);
CREATE INDEX IF NOT EXISTS ix_actor_identity_assurance_tenant_current
    ON actor_identity_assurance (tenant_id, is_current);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'uq_actor_identity_assurance_tenant_actor_fp'
    ) THEN
        ALTER TABLE actor_identity_assurance
            ADD CONSTRAINT uq_actor_identity_assurance_tenant_actor_fp
            UNIQUE (tenant_id, actor_id, decision_fingerprint);
    END IF;
END $$;

ALTER TABLE actor_identity_assurance ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS actor_identity_assurance_tenant_isolation ON actor_identity_assurance;
CREATE POLICY actor_identity_assurance_tenant_isolation
    ON actor_identity_assurance USING (tenant_id = current_setting('app.tenant_id', true));


CREATE TABLE IF NOT EXISTS actor_assurance_snapshots (
    id                        VARCHAR(64)  PRIMARY KEY,
    tenant_id                 VARCHAR(64)  NOT NULL,
    actor_id                  VARCHAR(64)  NOT NULL,
    sequence_number           INTEGER      NOT NULL,
    previous_assurance_level  VARCHAR(64),
    new_assurance_level       VARCHAR(64)  NOT NULL,
    trust_score               INTEGER      NOT NULL,
    identity_provider         VARCHAR(64),
    authentication_method     VARCHAR(128),
    reason                    VARCHAR(512),
    snapshot_fingerprint      VARCHAR(64),
    chain_hash                VARCHAR(64),
    created_at                TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    schema_version            VARCHAR(16)  NOT NULL DEFAULT '1.0'
);

CREATE INDEX IF NOT EXISTS ix_actor_assurance_snapshots_tenant_id
    ON actor_assurance_snapshots (tenant_id);
CREATE INDEX IF NOT EXISTS ix_actor_assurance_snapshots_tenant_actor
    ON actor_assurance_snapshots (tenant_id, actor_id);
CREATE INDEX IF NOT EXISTS ix_actor_assurance_snapshots_tenant_seq
    ON actor_assurance_snapshots (tenant_id, actor_id, sequence_number);

ALTER TABLE actor_assurance_snapshots ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS actor_assurance_snapshots_tenant_isolation ON actor_assurance_snapshots;
CREATE POLICY actor_assurance_snapshots_tenant_isolation
    ON actor_assurance_snapshots USING (tenant_id = current_setting('app.tenant_id', true));

-- Append-only enforcement.
DO $$
BEGIN
    IF to_regclass('public.actor_assurance_snapshots') IS NOT NULL THEN
        DROP TRIGGER IF EXISTS actor_assurance_snapshots_append_only_update
            ON actor_assurance_snapshots;
        CREATE TRIGGER actor_assurance_snapshots_append_only_update
            BEFORE UPDATE ON actor_assurance_snapshots
            FOR EACH ROW
            EXECUTE FUNCTION append_only_guard();

        DROP TRIGGER IF EXISTS actor_assurance_snapshots_append_only_delete
            ON actor_assurance_snapshots;
        CREATE TRIGGER actor_assurance_snapshots_append_only_delete
            BEFORE DELETE ON actor_assurance_snapshots
            FOR EACH ROW
            EXECUTE FUNCTION append_only_guard();
    END IF;
END $$;


CREATE TABLE IF NOT EXISTS actor_assurance_history (
    id                VARCHAR(64)  PRIMARY KEY,
    tenant_id         VARCHAR(64)  NOT NULL,
    actor_id          VARCHAR(64)  NOT NULL,
    event_type        VARCHAR(64)  NOT NULL,
    assurance_level   VARCHAR(64)  NOT NULL,
    trust_score       INTEGER      NOT NULL,
    triggered_by      VARCHAR(64),
    metadata          JSONB,
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    schema_version    VARCHAR(16)  NOT NULL DEFAULT '1.0'
);

CREATE INDEX IF NOT EXISTS ix_actor_assurance_history_tenant_id
    ON actor_assurance_history (tenant_id);
CREATE INDEX IF NOT EXISTS ix_actor_assurance_history_tenant_actor
    ON actor_assurance_history (tenant_id, actor_id);
CREATE INDEX IF NOT EXISTS ix_actor_assurance_history_tenant_event
    ON actor_assurance_history (tenant_id, event_type);

ALTER TABLE actor_assurance_history ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS actor_assurance_history_tenant_isolation ON actor_assurance_history;
CREATE POLICY actor_assurance_history_tenant_isolation
    ON actor_assurance_history USING (tenant_id = current_setting('app.tenant_id', true));

DO $$
BEGIN
    IF to_regclass('public.actor_assurance_history') IS NOT NULL THEN
        DROP TRIGGER IF EXISTS actor_assurance_history_append_only_update
            ON actor_assurance_history;
        CREATE TRIGGER actor_assurance_history_append_only_update
            BEFORE UPDATE ON actor_assurance_history
            FOR EACH ROW
            EXECUTE FUNCTION append_only_guard();

        DROP TRIGGER IF EXISTS actor_assurance_history_append_only_delete
            ON actor_assurance_history;
        CREATE TRIGGER actor_assurance_history_append_only_delete
            BEFORE DELETE ON actor_assurance_history
            FOR EACH ROW
            EXECUTE FUNCTION append_only_guard();
    END IF;
END $$;


CREATE TABLE IF NOT EXISTS actor_trust_metrics (
    id                 VARCHAR(64)  PRIMARY KEY,
    tenant_id          VARCHAR(64)  NOT NULL,
    actor_id           VARCHAR(64)  NOT NULL,
    period_key         VARCHAR(32)  NOT NULL,
    min_trust_score    INTEGER,
    max_trust_score    INTEGER,
    avg_trust_score    INTEGER,
    evaluation_count   INTEGER      NOT NULL DEFAULT 0,
    level_changes      INTEGER      NOT NULL DEFAULT 0,
    dominant_level     VARCHAR(64),
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    schema_version     VARCHAR(16)  NOT NULL DEFAULT '1.0'
);

CREATE INDEX IF NOT EXISTS ix_actor_trust_metrics_tenant_id
    ON actor_trust_metrics (tenant_id);
CREATE INDEX IF NOT EXISTS ix_actor_trust_metrics_tenant_actor
    ON actor_trust_metrics (tenant_id, actor_id);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'uq_actor_trust_metrics_tenant_actor_period'
    ) THEN
        ALTER TABLE actor_trust_metrics
            ADD CONSTRAINT uq_actor_trust_metrics_tenant_actor_period
            UNIQUE (tenant_id, actor_id, period_key);
    END IF;
END $$;

ALTER TABLE actor_trust_metrics ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS actor_trust_metrics_tenant_isolation ON actor_trust_metrics;
CREATE POLICY actor_trust_metrics_tenant_isolation
    ON actor_trust_metrics USING (tenant_id = current_setting('app.tenant_id', true));
