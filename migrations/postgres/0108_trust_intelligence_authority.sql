-- Migration 0108: Trust Intelligence Authority (PR 1.8A)
-- SCHEMA CHANGE — new tables for immutable trust intelligence persistence
--
-- Creates three append-only tables:
--   fa_trust_intelligence_snapshots — signed, immutable intelligence states
--   fa_trust_intelligence_ledger    — hash-chained tamper-evident event log
--   fa_trust_decision_memory        — governance decision audit records
--
-- All tables: append-only (no UPDATE/DELETE), RLS enforced, tenant isolated.
-- Authority version: trust-intelligence-authority-v1

-- ---------------------------------------------------------------------------
-- 1. Trust Intelligence Snapshots
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS fa_trust_intelligence_snapshots (
    id                       TEXT PRIMARY KEY,
    tenant_id                TEXT NOT NULL,
    engagement_id            TEXT NOT NULL,
    authority_version        TEXT NOT NULL,
    -- Scalar intelligence summary (included in snapshot_hash)
    posture_score            INTEGER NOT NULL DEFAULT 0,
    posture_level            TEXT NOT NULL DEFAULT 'unknown',
    trend_direction          TEXT NOT NULL DEFAULT 'stable',
    trend_velocity           TEXT NOT NULL DEFAULT 'none',
    risk_level               TEXT NOT NULL DEFAULT 'unknown',
    risk_score               INTEGER NOT NULL DEFAULT 0,
    priorities_count         INTEGER NOT NULL DEFAULT 0,
    insights_count           INTEGER NOT NULL DEFAULT 0,
    recommendations_count    INTEGER NOT NULL DEFAULT 0,
    forecast_projected_score INTEGER NOT NULL DEFAULT 0,
    graph_node_count         INTEGER NOT NULL DEFAULT 0,
    -- Full intelligence payloads (stored for replay, not in hash)
    posture_result           TEXT,
    trend_result             TEXT,
    risk_result              TEXT,
    priorities               TEXT,
    insights                 TEXT,
    recommendations          TEXT,
    forecast_result          TEXT,
    graph_result             TEXT,
    -- Authority fields
    snapshot_hash            TEXT NOT NULL,
    snapshot_signature       TEXT NOT NULL,
    signing_key_id           TEXT NOT NULL,
    created_at               TEXT NOT NULL,
    schema_version           TEXT NOT NULL DEFAULT '1.0'
);

-- ---------------------------------------------------------------------------
-- 2. Indexes — trust_intelligence_snapshots
-- ---------------------------------------------------------------------------

CREATE INDEX IF NOT EXISTS ix_fa_tis_tenant_id
    ON fa_trust_intelligence_snapshots (tenant_id);

CREATE INDEX IF NOT EXISTS ix_fa_tis_engagement
    ON fa_trust_intelligence_snapshots (tenant_id, engagement_id);

CREATE INDEX IF NOT EXISTS ix_fa_tis_created_at
    ON fa_trust_intelligence_snapshots (tenant_id, engagement_id, created_at);

CREATE INDEX IF NOT EXISTS ix_fa_tis_snapshot_hash
    ON fa_trust_intelligence_snapshots (snapshot_hash);

CREATE INDEX IF NOT EXISTS ix_fa_tis_signing_key_id
    ON fa_trust_intelligence_snapshots (signing_key_id);

CREATE INDEX IF NOT EXISTS ix_fa_tis_posture_level
    ON fa_trust_intelligence_snapshots (tenant_id, posture_level);

CREATE INDEX IF NOT EXISTS ix_fa_tis_risk_level
    ON fa_trust_intelligence_snapshots (tenant_id, risk_level);

-- ---------------------------------------------------------------------------
-- 3. RLS — trust_intelligence_snapshots
-- ---------------------------------------------------------------------------

DO $$
BEGIN
    IF to_regclass('public.fa_trust_intelligence_snapshots') IS NOT NULL THEN
        ALTER TABLE fa_trust_intelligence_snapshots ENABLE ROW LEVEL SECURITY;
        ALTER TABLE fa_trust_intelligence_snapshots FORCE ROW LEVEL SECURITY;

        DROP POLICY IF EXISTS fa_tis_tenant_isolation
            ON fa_trust_intelligence_snapshots;
        CREATE POLICY fa_tis_tenant_isolation
            ON fa_trust_intelligence_snapshots
            USING (
                tenant_id = current_setting('app.current_tenant_id', true)
                OR current_setting('app.current_tenant_id', true) = ''
            );
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 4. Append-only — trust_intelligence_snapshots
-- ---------------------------------------------------------------------------

DO $$
BEGIN
    IF to_regclass('public.fa_trust_intelligence_snapshots') IS NOT NULL THEN
        DROP TRIGGER IF EXISTS fa_tis_append_only_update
            ON fa_trust_intelligence_snapshots;
        CREATE TRIGGER fa_tis_append_only_update
            BEFORE UPDATE ON fa_trust_intelligence_snapshots
            FOR EACH ROW
            EXECUTE FUNCTION append_only_guard();

        DROP TRIGGER IF EXISTS fa_tis_append_only_delete
            ON fa_trust_intelligence_snapshots;
        CREATE TRIGGER fa_tis_append_only_delete
            BEFORE DELETE ON fa_trust_intelligence_snapshots
            FOR EACH ROW
            EXECUTE FUNCTION append_only_guard();
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 5. Trust Intelligence Ledger
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS fa_trust_intelligence_ledger (
    id                  TEXT PRIMARY KEY,
    tenant_id           TEXT NOT NULL,
    engagement_id       TEXT NOT NULL,
    snapshot_id         TEXT NOT NULL,
    snapshot_hash       TEXT NOT NULL,
    snapshot_signature  TEXT NOT NULL,
    signing_key_id      TEXT NOT NULL,
    authority_version   TEXT NOT NULL,
    posture_level       TEXT NOT NULL DEFAULT 'unknown',
    risk_level          TEXT NOT NULL DEFAULT 'unknown',
    posture_score       INTEGER NOT NULL DEFAULT 0,
    previous_hash       TEXT NOT NULL,
    ledger_entry_hash   TEXT NOT NULL,
    timestamp           TEXT NOT NULL,
    created_at          TEXT NOT NULL,
    schema_version      TEXT NOT NULL DEFAULT '1.0'
);

-- ---------------------------------------------------------------------------
-- 6. Indexes — trust_intelligence_ledger
-- ---------------------------------------------------------------------------

CREATE INDEX IF NOT EXISTS ix_fa_til_tenant_id
    ON fa_trust_intelligence_ledger (tenant_id);

CREATE INDEX IF NOT EXISTS ix_fa_til_engagement
    ON fa_trust_intelligence_ledger (tenant_id, engagement_id);

CREATE INDEX IF NOT EXISTS ix_fa_til_timestamp
    ON fa_trust_intelligence_ledger (tenant_id, engagement_id, timestamp);

CREATE INDEX IF NOT EXISTS ix_fa_til_snapshot_hash
    ON fa_trust_intelligence_ledger (snapshot_hash);

CREATE INDEX IF NOT EXISTS ix_fa_til_ledger_entry_hash
    ON fa_trust_intelligence_ledger (ledger_entry_hash);

CREATE INDEX IF NOT EXISTS ix_fa_til_previous_hash
    ON fa_trust_intelligence_ledger (previous_hash);

-- ---------------------------------------------------------------------------
-- 7. RLS — trust_intelligence_ledger
-- ---------------------------------------------------------------------------

DO $$
BEGIN
    IF to_regclass('public.fa_trust_intelligence_ledger') IS NOT NULL THEN
        ALTER TABLE fa_trust_intelligence_ledger ENABLE ROW LEVEL SECURITY;
        ALTER TABLE fa_trust_intelligence_ledger FORCE ROW LEVEL SECURITY;

        DROP POLICY IF EXISTS fa_til_tenant_isolation
            ON fa_trust_intelligence_ledger;
        CREATE POLICY fa_til_tenant_isolation
            ON fa_trust_intelligence_ledger
            USING (
                tenant_id = current_setting('app.current_tenant_id', true)
                OR current_setting('app.current_tenant_id', true) = ''
            );
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 8. Append-only — trust_intelligence_ledger
-- ---------------------------------------------------------------------------

DO $$
BEGIN
    IF to_regclass('public.fa_trust_intelligence_ledger') IS NOT NULL THEN
        DROP TRIGGER IF EXISTS fa_til_append_only_update
            ON fa_trust_intelligence_ledger;
        CREATE TRIGGER fa_til_append_only_update
            BEFORE UPDATE ON fa_trust_intelligence_ledger
            FOR EACH ROW
            EXECUTE FUNCTION append_only_guard();

        DROP TRIGGER IF EXISTS fa_til_append_only_delete
            ON fa_trust_intelligence_ledger;
        CREATE TRIGGER fa_til_append_only_delete
            BEFORE DELETE ON fa_trust_intelligence_ledger
            FOR EACH ROW
            EXECUTE FUNCTION append_only_guard();
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 9. Trust Decision Memory
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS fa_trust_decision_memory (
    id                      TEXT PRIMARY KEY,
    tenant_id               TEXT NOT NULL,
    engagement_id           TEXT NOT NULL,
    decision_type           TEXT NOT NULL,
    entity_type             TEXT NOT NULL DEFAULT 'human',
    decision_reasoning      TEXT,
    supporting_intelligence TEXT,
    supporting_evidence     TEXT,
    authority_version       TEXT NOT NULL,
    created_at              TEXT NOT NULL,
    schema_version          TEXT NOT NULL DEFAULT '1.0'
);

-- ---------------------------------------------------------------------------
-- 10. Indexes — trust_decision_memory
-- ---------------------------------------------------------------------------

CREATE INDEX IF NOT EXISTS ix_fa_tdm_tenant_id
    ON fa_trust_decision_memory (tenant_id);

CREATE INDEX IF NOT EXISTS ix_fa_tdm_engagement
    ON fa_trust_decision_memory (tenant_id, engagement_id);

CREATE INDEX IF NOT EXISTS ix_fa_tdm_created_at
    ON fa_trust_decision_memory (tenant_id, engagement_id, created_at);

CREATE INDEX IF NOT EXISTS ix_fa_tdm_entity_type
    ON fa_trust_decision_memory (entity_type);

CREATE INDEX IF NOT EXISTS ix_fa_tdm_decision_type
    ON fa_trust_decision_memory (tenant_id, decision_type);

-- ---------------------------------------------------------------------------
-- 11. RLS — trust_decision_memory
-- ---------------------------------------------------------------------------

DO $$
BEGIN
    IF to_regclass('public.fa_trust_decision_memory') IS NOT NULL THEN
        ALTER TABLE fa_trust_decision_memory ENABLE ROW LEVEL SECURITY;
        ALTER TABLE fa_trust_decision_memory FORCE ROW LEVEL SECURITY;

        DROP POLICY IF EXISTS fa_tdm_tenant_isolation
            ON fa_trust_decision_memory;
        CREATE POLICY fa_tdm_tenant_isolation
            ON fa_trust_decision_memory
            USING (
                tenant_id = current_setting('app.current_tenant_id', true)
                OR current_setting('app.current_tenant_id', true) = ''
            );
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 12. Append-only — trust_decision_memory
-- ---------------------------------------------------------------------------

DO $$
BEGIN
    IF to_regclass('public.fa_trust_decision_memory') IS NOT NULL THEN
        DROP TRIGGER IF EXISTS fa_tdm_append_only_update
            ON fa_trust_decision_memory;
        CREATE TRIGGER fa_tdm_append_only_update
            BEFORE UPDATE ON fa_trust_decision_memory
            FOR EACH ROW
            EXECUTE FUNCTION append_only_guard();

        DROP TRIGGER IF EXISTS fa_tdm_append_only_delete
            ON fa_trust_decision_memory;
        CREATE TRIGGER fa_tdm_append_only_delete
            BEFORE DELETE ON fa_trust_decision_memory
            FOR EACH ROW
            EXECUTE FUNCTION append_only_guard();
    END IF;
END $$;
