-- Migration 0105: Evidence Provenance Foundation (PR 1.1)
-- SCHEMA CHANGE — new table fa_evidence_provenance
--
-- Creates an append-only chain-of-custody provenance ledger for FA evidence.
-- Every evidence item can carry a provenance record answering: where did it
-- come from, who collected it, when, what artifact backs it, has it been
-- reviewed, and was it used in a report?
--
-- Table is ORM-managed (FaEvidenceProvenance in db_models_field_assessment.py);
-- this migration adds Postgres-specific enforcement: RLS tenant isolation and
-- append-only triggers using the shared append_only_guard() function.
--
-- Append-only: amendments create a new row (chain_status='active') with
-- previous_hash pointing to the superseded row. The prior row is not mutated.
--
-- All columns nullable unless noted — new table, no existing rows.

-- ---------------------------------------------------------------------------
-- 1. Row-level security — tenant isolation
-- ---------------------------------------------------------------------------

DO $$
BEGIN
    IF to_regclass('public.fa_evidence_provenance') IS NOT NULL THEN
        ALTER TABLE fa_evidence_provenance ENABLE ROW LEVEL SECURITY;
        ALTER TABLE fa_evidence_provenance FORCE ROW LEVEL SECURITY;

        DROP POLICY IF EXISTS fa_evidence_provenance_tenant_isolation
            ON fa_evidence_provenance;
        CREATE POLICY fa_evidence_provenance_tenant_isolation
            ON fa_evidence_provenance
            USING (
                tenant_id = current_setting('app.current_tenant_id', true)
                OR current_setting('app.current_tenant_id', true) = ''
            );
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 2. Append-only enforcement
-- ---------------------------------------------------------------------------

DO $$
BEGIN
    IF to_regclass('public.fa_evidence_provenance') IS NOT NULL THEN
        DROP TRIGGER IF EXISTS fa_evidence_provenance_append_only_update
            ON fa_evidence_provenance;
        CREATE TRIGGER fa_evidence_provenance_append_only_update
            BEFORE UPDATE ON fa_evidence_provenance
            FOR EACH ROW
            EXECUTE FUNCTION append_only_guard();

        DROP TRIGGER IF EXISTS fa_evidence_provenance_append_only_delete
            ON fa_evidence_provenance;
        CREATE TRIGGER fa_evidence_provenance_append_only_delete
            BEFORE DELETE ON fa_evidence_provenance
            FOR EACH ROW
            EXECUTE FUNCTION append_only_guard();
    END IF;
END $$;
