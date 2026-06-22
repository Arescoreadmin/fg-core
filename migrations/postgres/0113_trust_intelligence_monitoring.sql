-- Migration: 0113_trust_intelligence_monitoring
-- Creates TIM (Trust Intelligence Monitoring) persistence tables.
--
-- Tables:
--   fa_tim_trust_snapshots  — periodic TIM state aggregated from Trust Arc sources
--   fa_tim_drift_events     — deterministic drift detections (no AI; rules-based)
--
-- Design:
--   Append-only (no UPDATE/DELETE from application layer).
--   All events are tenant-scoped and RLS enforced.
--   Snapshots aggregate from: fa_trust_intelligence_snapshots,
--   fa_trust_certifications, fa_evidence_provenance, fa_verification_bundles.
--   Drift rules are deterministic: score_degradation, cert_expiration,
--   cert_expired, evidence_staleness, replay_failure, missing_bundle,
--   consecutive_degradation.
--
-- Governance Readiness:
--   actor_type field supports: human | agent | system | workflow
--   No code changes required to add new actor types.
--
-- RLS:
--   Both ENABLE and FORCE ensure table owners / superusers are subject to
--   the tenant isolation policy.
--
-- Rollback:
--   DROP TABLE IF EXISTS fa_tim_drift_events;
--   DROP TABLE IF EXISTS fa_tim_trust_snapshots;

BEGIN;

-- ---------------------------------------------------------------------------
-- 1. TIM Trust Snapshots
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS fa_tim_trust_snapshots (
    id                      TEXT        NOT NULL PRIMARY KEY,
    tenant_id               TEXT        NOT NULL,
    engagement_id           TEXT        NOT NULL,

    -- Trust posture (from latest fa_trust_intelligence_snapshot)
    posture_score           INTEGER     NOT NULL DEFAULT 0,
    posture_level           TEXT        NOT NULL DEFAULT 'unknown',
    risk_level              TEXT        NOT NULL DEFAULT 'unknown',

    -- Certification state (from latest fa_trust_certifications)
    certification_level     TEXT        NOT NULL DEFAULT 'not_certified',
    composite_score         INTEGER     NOT NULL DEFAULT 0,
    certification_valid_until TEXT,

    -- Drift summary (derived vs. previous snapshot)
    drift_score             INTEGER     NOT NULL DEFAULT 0,
    drift_direction         TEXT        NOT NULL DEFAULT 'stable',
    open_drift_count        INTEGER     NOT NULL DEFAULT 0,

    -- Evidence freshness
    evidence_count          INTEGER     NOT NULL DEFAULT 0,

    -- Replay state ('ok' | 'failed' | 'no_chain')
    replay_status           TEXT        NOT NULL DEFAULT 'no_chain',

    -- Source links
    last_snapshot_id        TEXT,
    last_certification_id   TEXT,

    -- Provenance fingerprint (SHA-256 of source IDs that produced this snapshot)
    source_fingerprint      TEXT,
    -- Source bundle ID
    last_bundle_id          TEXT,

    evaluated_at            TEXT        NOT NULL,
    schema_version          TEXT        NOT NULL DEFAULT '1.0'
);

-- ---------------------------------------------------------------------------
-- 2. Indexes — fa_tim_trust_snapshots
-- ---------------------------------------------------------------------------

CREATE INDEX IF NOT EXISTS ix_fa_tts_tenant_id
    ON fa_tim_trust_snapshots (tenant_id);

CREATE INDEX IF NOT EXISTS ix_fa_tts_engagement
    ON fa_tim_trust_snapshots (tenant_id, engagement_id);

CREATE INDEX IF NOT EXISTS ix_fa_tts_evaluated_at
    ON fa_tim_trust_snapshots (tenant_id, engagement_id, evaluated_at);

CREATE INDEX IF NOT EXISTS ix_fa_tts_posture_level
    ON fa_tim_trust_snapshots (tenant_id, posture_level);

CREATE INDEX IF NOT EXISTS ix_fa_tts_cert_level
    ON fa_tim_trust_snapshots (tenant_id, certification_level);

-- ---------------------------------------------------------------------------
-- 3. RLS — fa_tim_trust_snapshots
-- ---------------------------------------------------------------------------

ALTER TABLE fa_tim_trust_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE fa_tim_trust_snapshots FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS fa_tim_trust_snapshots_tenant_isolation ON fa_tim_trust_snapshots;
CREATE POLICY fa_tim_trust_snapshots_tenant_isolation
    ON fa_tim_trust_snapshots
    USING (
        current_setting('app.tenant_id', true) IS NOT NULL
        AND tenant_id = current_setting('app.tenant_id', true)
    );

-- ---------------------------------------------------------------------------
-- 4. Append-only — fa_tim_trust_snapshots
-- ---------------------------------------------------------------------------

DROP TRIGGER IF EXISTS fa_tts_append_only_update ON fa_tim_trust_snapshots;
CREATE TRIGGER fa_tts_append_only_update
    BEFORE UPDATE ON fa_tim_trust_snapshots
    FOR EACH ROW
    EXECUTE FUNCTION append_only_guard();

DROP TRIGGER IF EXISTS fa_tts_append_only_delete ON fa_tim_trust_snapshots;
CREATE TRIGGER fa_tts_append_only_delete
    BEFORE DELETE ON fa_tim_trust_snapshots
    FOR EACH ROW
    EXECUTE FUNCTION append_only_guard();

-- ---------------------------------------------------------------------------
-- 5. TIM Drift Events
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS fa_tim_drift_events (
    id              TEXT        NOT NULL PRIMARY KEY,
    tenant_id       TEXT        NOT NULL,
    engagement_id   TEXT        NOT NULL,

    -- Rule that triggered this drift event
    -- Values: score_degradation | cert_expiration | cert_expired |
    --         evidence_staleness | replay_failure | missing_bundle |
    --         consecutive_degradation
    drift_rule      TEXT        NOT NULL,

    -- Severity: info | low | medium | high | critical (deterministic)
    severity        TEXT        NOT NULL,

    -- Status: open | resolved | acknowledged (append-only; resolved = new row)
    status          TEXT        NOT NULL DEFAULT 'open',

    detected_at     TEXT        NOT NULL,
    resolved_at     TEXT,

    -- Structured drift evidence (before/after values, threshold, etc.)
    evidence        TEXT        NOT NULL DEFAULT '{}',

    -- Source that triggered drift (snapshot_id, cert_id, etc.)
    correlation_id  TEXT,

    -- Actor that ran detection (always 'system' for deterministic rules;
    -- extensible to: human | agent | system | workflow)
    actor_type      TEXT        NOT NULL DEFAULT 'system',

    -- Acknowledgement state (governance audit trail — who saw it and when)
    acknowledged_by         TEXT,
    acknowledged_at         TEXT,

    schema_version  TEXT        NOT NULL DEFAULT '1.0'
);

-- ---------------------------------------------------------------------------
-- 6. Indexes — fa_tim_drift_events
-- ---------------------------------------------------------------------------

CREATE INDEX IF NOT EXISTS ix_fa_tde_tenant_id
    ON fa_tim_drift_events (tenant_id);

CREATE INDEX IF NOT EXISTS ix_fa_tde_engagement
    ON fa_tim_drift_events (tenant_id, engagement_id);

CREATE INDEX IF NOT EXISTS ix_fa_tde_detected_at
    ON fa_tim_drift_events (tenant_id, engagement_id, detected_at);

CREATE INDEX IF NOT EXISTS ix_fa_tde_status
    ON fa_tim_drift_events (tenant_id, status, detected_at);

CREATE INDEX IF NOT EXISTS ix_fa_tde_severity
    ON fa_tim_drift_events (tenant_id, severity, detected_at);

CREATE INDEX IF NOT EXISTS ix_fa_tde_drift_rule
    ON fa_tim_drift_events (tenant_id, drift_rule);

-- ---------------------------------------------------------------------------
-- 7. RLS — fa_tim_drift_events
-- ---------------------------------------------------------------------------

ALTER TABLE fa_tim_drift_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE fa_tim_drift_events FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS fa_tim_drift_events_tenant_isolation ON fa_tim_drift_events;
CREATE POLICY fa_tim_drift_events_tenant_isolation
    ON fa_tim_drift_events
    USING (
        current_setting('app.tenant_id', true) IS NOT NULL
        AND tenant_id = current_setting('app.tenant_id', true)
    );

-- ---------------------------------------------------------------------------
-- 8. Append-only — fa_tim_drift_events
-- ---------------------------------------------------------------------------

DROP TRIGGER IF EXISTS fa_tde_append_only_update ON fa_tim_drift_events;
CREATE TRIGGER fa_tde_append_only_update
    BEFORE UPDATE ON fa_tim_drift_events
    FOR EACH ROW
    EXECUTE FUNCTION append_only_guard();

DROP TRIGGER IF EXISTS fa_tde_append_only_delete ON fa_tim_drift_events;
CREATE TRIGGER fa_tde_append_only_delete
    BEFORE DELETE ON fa_tim_drift_events
    FOR EACH ROW
    EXECUTE FUNCTION append_only_guard();

COMMIT;
