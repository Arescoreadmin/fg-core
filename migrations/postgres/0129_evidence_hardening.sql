-- PR 14.6.5A — Evidence Status Model Hardening & Governance Completion
-- Append-only tables: fa_verifications, fa_evidence_control_links, fa_evidence_risk_links
-- New columns: SLA deadlines + benchmark percentiles on fa_evidence

BEGIN;

-- ---------------------------------------------------------------------------
-- fa_verifications — append-only verification records
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS fa_verifications (
    id                       TEXT PRIMARY KEY,
    tenant_id                TEXT NOT NULL,
    evidence_id              TEXT NOT NULL,
    verification_type        TEXT NOT NULL,
    verification_method      TEXT,
    verification_result      TEXT NOT NULL,
    verification_confidence  INTEGER,
    verification_notes       TEXT,
    verified_by              TEXT NOT NULL,
    verified_actor_type      TEXT NOT NULL,
    verified_at              TEXT NOT NULL,
    schema_version           TEXT NOT NULL DEFAULT '1.0',
    created_at               TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_fa_verifications_tenant_evidence
    ON fa_verifications (tenant_id, evidence_id);

CREATE INDEX IF NOT EXISTS ix_fa_verifications_result
    ON fa_verifications (tenant_id, verification_result);

CREATE INDEX IF NOT EXISTS ix_fa_verifications_created
    ON fa_verifications (tenant_id, created_at DESC);

-- Append-only PostgreSQL triggers
CREATE OR REPLACE FUNCTION _fa_verifications_no_update()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'fa_verifications rows are immutable';
END;
$$;

DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger WHERE tgname = 'trg_fa_verifications_no_update'
    ) THEN
        CREATE TRIGGER trg_fa_verifications_no_update
            BEFORE UPDATE ON fa_verifications
            FOR EACH ROW EXECUTE FUNCTION _fa_verifications_no_update();
    END IF;
END $$;

CREATE OR REPLACE FUNCTION _fa_verifications_no_delete()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'fa_verifications rows are immutable';
END;
$$;

DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger WHERE tgname = 'trg_fa_verifications_no_delete'
    ) THEN
        CREATE TRIGGER trg_fa_verifications_no_delete
            BEFORE DELETE ON fa_verifications
            FOR EACH ROW EXECUTE FUNCTION _fa_verifications_no_delete();
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- fa_evidence_control_links — append-only evidence-to-control linkage
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS fa_evidence_control_links (
    id             TEXT PRIMARY KEY,
    tenant_id      TEXT NOT NULL,
    evidence_id    TEXT NOT NULL,
    control_id     TEXT NOT NULL,
    linked_by      TEXT NOT NULL,
    linked_at      TEXT NOT NULL,
    schema_version TEXT NOT NULL DEFAULT '1.0',
    created_at     TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_fa_evidence_control_link
    ON fa_evidence_control_links (tenant_id, evidence_id, control_id);

CREATE INDEX IF NOT EXISTS ix_fa_ecl_evidence
    ON fa_evidence_control_links (tenant_id, evidence_id);

CREATE INDEX IF NOT EXISTS ix_fa_ecl_control
    ON fa_evidence_control_links (tenant_id, control_id);

-- Append-only PostgreSQL triggers
CREATE OR REPLACE FUNCTION _fa_ecl_no_update()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'fa_evidence_control_links rows are immutable';
END;
$$;

DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger WHERE tgname = 'trg_fa_ecl_no_update'
    ) THEN
        CREATE TRIGGER trg_fa_ecl_no_update
            BEFORE UPDATE ON fa_evidence_control_links
            FOR EACH ROW EXECUTE FUNCTION _fa_ecl_no_update();
    END IF;
END $$;

CREATE OR REPLACE FUNCTION _fa_ecl_no_delete()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'fa_evidence_control_links rows are immutable';
END;
$$;

DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger WHERE tgname = 'trg_fa_ecl_no_delete'
    ) THEN
        CREATE TRIGGER trg_fa_ecl_no_delete
            BEFORE DELETE ON fa_evidence_control_links
            FOR EACH ROW EXECUTE FUNCTION _fa_ecl_no_delete();
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- fa_evidence_risk_links — append-only evidence-to-risk/finding/exception links
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS fa_evidence_risk_links (
    id                  TEXT PRIMARY KEY,
    tenant_id           TEXT NOT NULL,
    evidence_id         TEXT NOT NULL,
    linked_resource_id  TEXT NOT NULL,
    link_type           TEXT NOT NULL,  -- RISK|FINDING|EXCEPTION
    linked_by           TEXT NOT NULL,
    linked_at           TEXT NOT NULL,
    schema_version      TEXT NOT NULL DEFAULT '1.0',
    created_at          TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_fa_evidence_risk_link
    ON fa_evidence_risk_links (tenant_id, evidence_id, linked_resource_id, link_type);

CREATE INDEX IF NOT EXISTS ix_fa_erl_evidence
    ON fa_evidence_risk_links (tenant_id, evidence_id);

CREATE INDEX IF NOT EXISTS ix_fa_erl_resource
    ON fa_evidence_risk_links (tenant_id, linked_resource_id);

CREATE INDEX IF NOT EXISTS ix_fa_erl_link_type
    ON fa_evidence_risk_links (tenant_id, link_type);

-- Append-only PostgreSQL triggers
CREATE OR REPLACE FUNCTION _fa_erl_no_update()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'fa_evidence_risk_links rows are immutable';
END;
$$;

DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger WHERE tgname = 'trg_fa_erl_no_update'
    ) THEN
        CREATE TRIGGER trg_fa_erl_no_update
            BEFORE UPDATE ON fa_evidence_risk_links
            FOR EACH ROW EXECUTE FUNCTION _fa_erl_no_update();
    END IF;
END $$;

CREATE OR REPLACE FUNCTION _fa_erl_no_delete()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'fa_evidence_risk_links rows are immutable';
END;
$$;

DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger WHERE tgname = 'trg_fa_erl_no_delete'
    ) THEN
        CREATE TRIGGER trg_fa_erl_no_delete
            BEFORE DELETE ON fa_evidence_risk_links
            FOR EACH ROW EXECUTE FUNCTION _fa_erl_no_delete();
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- fa_evidence — new SLA deadline + benchmark columns
-- ---------------------------------------------------------------------------

ALTER TABLE fa_evidence
    ADD COLUMN IF NOT EXISTS review_due_at                     TEXT,
    ADD COLUMN IF NOT EXISTS verification_due_at               TEXT,
    ADD COLUMN IF NOT EXISTS freshness_due_at                  TEXT,
    ADD COLUMN IF NOT EXISTS benchmark_freshness_percentile    INTEGER,
    ADD COLUMN IF NOT EXISTS benchmark_verification_percentile INTEGER,
    ADD COLUMN IF NOT EXISTS benchmark_density_percentile      INTEGER,
    ADD COLUMN IF NOT EXISTS benchmark_coverage_percentile     INTEGER;

CREATE INDEX IF NOT EXISTS ix_fa_evidence_verification_due
    ON fa_evidence (tenant_id, verification_due_at)
    WHERE verification_due_at IS NOT NULL;

COMMIT;
