-- Migration 0109: Auditor Proof Package Authority (PR 1.9)
-- SCHEMA CHANGE — new tables for immutable proof package persistence
--
-- Creates four append-only tables:
--   fa_auditor_proof_packages        — signed, immutable proof packages
--   fa_trust_certifications          — verifiable trust certifications
--   fa_decision_reconstruction_records — legal defense records
--   fa_chain_of_custody_records      — hash-linked custody chains
--
-- All tables: append-only (no UPDATE/DELETE), RLS enforced, tenant isolated.
-- Authority version: auditor-proof-authority-v1

-- ---------------------------------------------------------------------------
-- 1. Auditor Proof Packages
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS fa_auditor_proof_packages (
    id                   TEXT PRIMARY KEY,
    tenant_id            TEXT NOT NULL,
    engagement_id        TEXT NOT NULL,
    authority_version    TEXT NOT NULL,
    assessed_by          TEXT NOT NULL DEFAULT 'human',
    -- Scalar summary (included in package_hash)
    section_count        INTEGER NOT NULL DEFAULT 0,
    -- Section hashes payload (bound into package_hash)
    section_hashes       TEXT NOT NULL,
    -- Full sections payload (authenticated via section_hashes)
    sections             TEXT,
    -- Authority fields
    package_hash         TEXT NOT NULL,
    package_signature    TEXT NOT NULL,
    signing_key_id       TEXT NOT NULL,
    verified_at          TEXT NOT NULL,
    schema_version       TEXT NOT NULL DEFAULT '1.0'
);

-- ---------------------------------------------------------------------------
-- 2. Indexes — auditor_proof_packages
-- ---------------------------------------------------------------------------

CREATE INDEX IF NOT EXISTS ix_fa_app_tenant_id
    ON fa_auditor_proof_packages (tenant_id);

CREATE INDEX IF NOT EXISTS ix_fa_app_engagement
    ON fa_auditor_proof_packages (tenant_id, engagement_id);

CREATE INDEX IF NOT EXISTS ix_fa_app_verified_at
    ON fa_auditor_proof_packages (tenant_id, engagement_id, verified_at);

CREATE INDEX IF NOT EXISTS ix_fa_app_package_hash
    ON fa_auditor_proof_packages (package_hash);

CREATE INDEX IF NOT EXISTS ix_fa_app_signing_key_id
    ON fa_auditor_proof_packages (signing_key_id);

CREATE INDEX IF NOT EXISTS ix_fa_app_assessed_by
    ON fa_auditor_proof_packages (assessed_by);

-- ---------------------------------------------------------------------------
-- 3. RLS — auditor_proof_packages
-- ---------------------------------------------------------------------------

DO $$
BEGIN
    IF to_regclass('public.fa_auditor_proof_packages') IS NOT NULL THEN
        ALTER TABLE fa_auditor_proof_packages ENABLE ROW LEVEL SECURITY;
        ALTER TABLE fa_auditor_proof_packages FORCE ROW LEVEL SECURITY;

        DROP POLICY IF EXISTS fa_app_tenant_isolation
            ON fa_auditor_proof_packages;
        CREATE POLICY fa_app_tenant_isolation
            ON fa_auditor_proof_packages
            USING (
                tenant_id = current_setting('app.current_tenant_id', true)
                OR current_setting('app.current_tenant_id', true) = ''
            );
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 4. Append-only — auditor_proof_packages
-- ---------------------------------------------------------------------------

DO $$
BEGIN
    IF to_regclass('public.fa_auditor_proof_packages') IS NOT NULL THEN
        DROP TRIGGER IF EXISTS fa_app_append_only_update
            ON fa_auditor_proof_packages;
        CREATE TRIGGER fa_app_append_only_update
            BEFORE UPDATE ON fa_auditor_proof_packages
            FOR EACH ROW
            EXECUTE FUNCTION append_only_guard();

        DROP TRIGGER IF EXISTS fa_app_append_only_delete
            ON fa_auditor_proof_packages;
        CREATE TRIGGER fa_app_append_only_delete
            BEFORE DELETE ON fa_auditor_proof_packages
            FOR EACH ROW
            EXECUTE FUNCTION append_only_guard();
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 5. Trust Certifications
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS fa_trust_certifications (
    id                   TEXT PRIMARY KEY,
    tenant_id            TEXT NOT NULL,
    engagement_id        TEXT NOT NULL,
    certification_level  TEXT NOT NULL DEFAULT 'not_certified',
    trust_score          INTEGER NOT NULL DEFAULT 0,
    confidence_score     INTEGER NOT NULL DEFAULT 0,
    composite_score      INTEGER NOT NULL DEFAULT 0,
    scored_by            TEXT NOT NULL DEFAULT 'deterministic_composite_v1',
    valid_from           TEXT NOT NULL,
    valid_until          TEXT NOT NULL,
    verification_hash    TEXT NOT NULL,
    authority_version    TEXT NOT NULL,
    schema_version       TEXT NOT NULL DEFAULT '1.0'
);

-- ---------------------------------------------------------------------------
-- 6. Indexes — trust_certifications
-- ---------------------------------------------------------------------------

CREATE INDEX IF NOT EXISTS ix_fa_tc_tenant_id
    ON fa_trust_certifications (tenant_id);

CREATE INDEX IF NOT EXISTS ix_fa_tc_engagement
    ON fa_trust_certifications (tenant_id, engagement_id);

CREATE INDEX IF NOT EXISTS ix_fa_tc_valid_until
    ON fa_trust_certifications (tenant_id, engagement_id, valid_until);

CREATE INDEX IF NOT EXISTS ix_fa_tc_certification_level
    ON fa_trust_certifications (tenant_id, certification_level);

CREATE INDEX IF NOT EXISTS ix_fa_tc_verification_hash
    ON fa_trust_certifications (verification_hash);

-- ---------------------------------------------------------------------------
-- 7. RLS — trust_certifications
-- ---------------------------------------------------------------------------

DO $$
BEGIN
    IF to_regclass('public.fa_trust_certifications') IS NOT NULL THEN
        ALTER TABLE fa_trust_certifications ENABLE ROW LEVEL SECURITY;
        ALTER TABLE fa_trust_certifications FORCE ROW LEVEL SECURITY;

        DROP POLICY IF EXISTS fa_tc_tenant_isolation
            ON fa_trust_certifications;
        CREATE POLICY fa_tc_tenant_isolation
            ON fa_trust_certifications
            USING (
                tenant_id = current_setting('app.current_tenant_id', true)
                OR current_setting('app.current_tenant_id', true) = ''
            );
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 8. Append-only — trust_certifications
-- ---------------------------------------------------------------------------

DO $$
BEGIN
    IF to_regclass('public.fa_trust_certifications') IS NOT NULL THEN
        DROP TRIGGER IF EXISTS fa_tc_append_only_update
            ON fa_trust_certifications;
        CREATE TRIGGER fa_tc_append_only_update
            BEFORE UPDATE ON fa_trust_certifications
            FOR EACH ROW
            EXECUTE FUNCTION append_only_guard();

        DROP TRIGGER IF EXISTS fa_tc_append_only_delete
            ON fa_trust_certifications;
        CREATE TRIGGER fa_tc_append_only_delete
            BEFORE DELETE ON fa_trust_certifications
            FOR EACH ROW
            EXECUTE FUNCTION append_only_guard();
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 9. Decision Reconstruction Records
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS fa_decision_reconstruction_records (
    id                      TEXT PRIMARY KEY,
    tenant_id               TEXT NOT NULL,
    engagement_id           TEXT NOT NULL,
    reconstruction_hash     TEXT NOT NULL,
    total_decisions         INTEGER NOT NULL DEFAULT 0,
    snapshot_hash           TEXT NOT NULL DEFAULT '',
    replay_valid            BOOLEAN NOT NULL DEFAULT FALSE,
    questions_answered      TEXT,
    decision_reconstruction TEXT,
    evidence_chain          TEXT,
    intelligence_chain      TEXT,
    replay_validation       TEXT,
    authority_version       TEXT NOT NULL,
    generated_at            TEXT NOT NULL,
    schema_version          TEXT NOT NULL DEFAULT '1.0'
);

-- ---------------------------------------------------------------------------
-- 10. Indexes — decision_reconstruction_records
-- ---------------------------------------------------------------------------

CREATE INDEX IF NOT EXISTS ix_fa_drr_tenant_id
    ON fa_decision_reconstruction_records (tenant_id);

CREATE INDEX IF NOT EXISTS ix_fa_drr_engagement
    ON fa_decision_reconstruction_records (tenant_id, engagement_id);

CREATE INDEX IF NOT EXISTS ix_fa_drr_generated_at
    ON fa_decision_reconstruction_records (tenant_id, engagement_id, generated_at);

CREATE INDEX IF NOT EXISTS ix_fa_drr_reconstruction_hash
    ON fa_decision_reconstruction_records (reconstruction_hash);

CREATE INDEX IF NOT EXISTS ix_fa_drr_replay_valid
    ON fa_decision_reconstruction_records (replay_valid);

-- ---------------------------------------------------------------------------
-- 11. RLS — decision_reconstruction_records
-- ---------------------------------------------------------------------------

DO $$
BEGIN
    IF to_regclass('public.fa_decision_reconstruction_records') IS NOT NULL THEN
        ALTER TABLE fa_decision_reconstruction_records ENABLE ROW LEVEL SECURITY;
        ALTER TABLE fa_decision_reconstruction_records FORCE ROW LEVEL SECURITY;

        DROP POLICY IF EXISTS fa_drr_tenant_isolation
            ON fa_decision_reconstruction_records;
        CREATE POLICY fa_drr_tenant_isolation
            ON fa_decision_reconstruction_records
            USING (
                tenant_id = current_setting('app.current_tenant_id', true)
                OR current_setting('app.current_tenant_id', true) = ''
            );
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 12. Append-only — decision_reconstruction_records
-- ---------------------------------------------------------------------------

DO $$
BEGIN
    IF to_regclass('public.fa_decision_reconstruction_records') IS NOT NULL THEN
        DROP TRIGGER IF EXISTS fa_drr_append_only_update
            ON fa_decision_reconstruction_records;
        CREATE TRIGGER fa_drr_append_only_update
            BEFORE UPDATE ON fa_decision_reconstruction_records
            FOR EACH ROW
            EXECUTE FUNCTION append_only_guard();

        DROP TRIGGER IF EXISTS fa_drr_append_only_delete
            ON fa_decision_reconstruction_records;
        CREATE TRIGGER fa_drr_append_only_delete
            BEFORE DELETE ON fa_decision_reconstruction_records
            FOR EACH ROW
            EXECUTE FUNCTION append_only_guard();
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 13. Chain of Custody Records
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS fa_chain_of_custody_records (
    id                   TEXT PRIMARY KEY,
    tenant_id            TEXT NOT NULL,
    engagement_id        TEXT NOT NULL,
    sequence             INTEGER NOT NULL DEFAULT 0,
    event_type           TEXT NOT NULL,
    entity_type          TEXT NOT NULL DEFAULT 'human',
    entity_id            TEXT NOT NULL DEFAULT '',
    description          TEXT,
    timestamp            TEXT NOT NULL,
    previous_hash        TEXT NOT NULL,
    custody_hash         TEXT NOT NULL,
    metadata             TEXT,
    authority_version    TEXT NOT NULL,
    schema_version       TEXT NOT NULL DEFAULT '1.0'
);

-- ---------------------------------------------------------------------------
-- 14. Indexes — chain_of_custody_records
-- ---------------------------------------------------------------------------

CREATE INDEX IF NOT EXISTS ix_fa_cocr_tenant_id
    ON fa_chain_of_custody_records (tenant_id);

CREATE INDEX IF NOT EXISTS ix_fa_cocr_engagement
    ON fa_chain_of_custody_records (tenant_id, engagement_id);

CREATE INDEX IF NOT EXISTS ix_fa_cocr_timestamp
    ON fa_chain_of_custody_records (tenant_id, engagement_id, timestamp);

CREATE INDEX IF NOT EXISTS ix_fa_cocr_custody_hash
    ON fa_chain_of_custody_records (custody_hash);

CREATE INDEX IF NOT EXISTS ix_fa_cocr_previous_hash
    ON fa_chain_of_custody_records (previous_hash);

CREATE INDEX IF NOT EXISTS ix_fa_cocr_event_type
    ON fa_chain_of_custody_records (tenant_id, event_type);

CREATE INDEX IF NOT EXISTS ix_fa_cocr_entity_type
    ON fa_chain_of_custody_records (entity_type);

-- ---------------------------------------------------------------------------
-- 15. RLS — chain_of_custody_records
-- ---------------------------------------------------------------------------

DO $$
BEGIN
    IF to_regclass('public.fa_chain_of_custody_records') IS NOT NULL THEN
        ALTER TABLE fa_chain_of_custody_records ENABLE ROW LEVEL SECURITY;
        ALTER TABLE fa_chain_of_custody_records FORCE ROW LEVEL SECURITY;

        DROP POLICY IF EXISTS fa_cocr_tenant_isolation
            ON fa_chain_of_custody_records;
        CREATE POLICY fa_cocr_tenant_isolation
            ON fa_chain_of_custody_records
            USING (
                tenant_id = current_setting('app.current_tenant_id', true)
                OR current_setting('app.current_tenant_id', true) = ''
            );
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 16. Append-only — chain_of_custody_records
-- ---------------------------------------------------------------------------

DO $$
BEGIN
    IF to_regclass('public.fa_chain_of_custody_records') IS NOT NULL THEN
        DROP TRIGGER IF EXISTS fa_cocr_append_only_update
            ON fa_chain_of_custody_records;
        CREATE TRIGGER fa_cocr_append_only_update
            BEFORE UPDATE ON fa_chain_of_custody_records
            FOR EACH ROW
            EXECUTE FUNCTION append_only_guard();

        DROP TRIGGER IF EXISTS fa_cocr_append_only_delete
            ON fa_chain_of_custody_records;
        CREATE TRIGGER fa_cocr_append_only_delete
            BEFORE DELETE ON fa_chain_of_custody_records
            FOR EACH ROW
            EXECUTE FUNCTION append_only_guard();
    END IF;
END $$;
