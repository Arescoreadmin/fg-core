-- Migration 0083: H15 Evidence Lifecycle Locks & Chain-of-Custody.
--
-- Adds lifecycle_state column to four evidence tables and creates database-level
-- immutability triggers as a second line of defence behind the application-layer
-- EvidenceLifecycleService guards.
--
-- Lifecycle state machine (enforced at both service and DB layers):
--   collected  →  locked      (bulk-applied at QA approval)
--   collected  →  legal_hold  (immediate preservation; bypasses locked step)
--   locked     →  legal_hold  (operator-applied)
--
-- LEGAL_HOLD is a one-way ratchet in H15. Release requires a future dual-auth
-- workflow (LEGAL_HOLD_RELEASE_WORKFLOW) and is out of scope here.
--
-- Trigger summary:
--   fa_evidence_update_guard()          — blocks UPDATE on legal_hold; blocks downgrade
--   fa_evidence_delete_guard()          — blocks DELETE on locked or legal_hold
--   governance_report_immutability_guard() — blocks report_json/manifest_hash mutation
--                                            on finalized reports
--
-- Triggers are applied to:
--   fa_field_observations  — UPDATE (legal_hold + downgrade) + DELETE (locked/legal_hold)
--   fa_scan_results        — UPDATE (legal_hold + downgrade) + DELETE (locked/legal_hold)
--   fa_document_analyses   — UPDATE (legal_hold + downgrade) + DELETE (locked/legal_hold)
--   fa_evidence_links      — UPDATE (legal_hold + downgrade) + DELETE (locked/legal_hold)
--   governance_reports     — UPDATE (report content when is_finalized=TRUE)
--
-- All blocks are idempotent via to_regclass() and column-existence checks.
-- New tables fa_evidence_lifecycle_events and fa_legal_holds are ORM-managed.

-- ---------------------------------------------------------------------------
-- 1. Add lifecycle_state to existing evidence tables
-- ---------------------------------------------------------------------------

DO $$
BEGIN
    IF to_regclass('public.fa_scan_results') IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
             WHERE table_name = 'fa_scan_results' AND column_name = 'lifecycle_state'
        ) THEN
            ALTER TABLE fa_scan_results
                ADD COLUMN IF NOT EXISTS lifecycle_state VARCHAR(32) NOT NULL DEFAULT 'collected';
        END IF;
    END IF;
END $$;

DO $$
BEGIN
    IF to_regclass('public.fa_document_analyses') IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
             WHERE table_name = 'fa_document_analyses' AND column_name = 'lifecycle_state'
        ) THEN
            ALTER TABLE fa_document_analyses
                ADD COLUMN IF NOT EXISTS lifecycle_state VARCHAR(32) NOT NULL DEFAULT 'collected';
        END IF;
    END IF;
END $$;

DO $$
BEGIN
    IF to_regclass('public.fa_field_observations') IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
             WHERE table_name = 'fa_field_observations' AND column_name = 'lifecycle_state'
        ) THEN
            ALTER TABLE fa_field_observations
                ADD COLUMN IF NOT EXISTS lifecycle_state VARCHAR(32) NOT NULL DEFAULT 'collected';
        END IF;
    END IF;
END $$;

DO $$
BEGIN
    IF to_regclass('public.fa_evidence_links') IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
             WHERE table_name = 'fa_evidence_links' AND column_name = 'lifecycle_state'
        ) THEN
            ALTER TABLE fa_evidence_links
                ADD COLUMN IF NOT EXISTS lifecycle_state VARCHAR(32) NOT NULL DEFAULT 'collected';
        END IF;
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 2. Shared trigger functions for evidence immutability
-- ---------------------------------------------------------------------------

-- Block all UPDATE on legal_hold evidence; block state downgrade from locked/legal_hold.
-- Note: %%s in format() calls is the psycopg3-escaped form of the Postgres format placeholder.
CREATE OR REPLACE FUNCTION fa_evidence_update_guard()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    -- Legal hold is a one-way ratchet: all mutations blocked once applied.
    IF OLD.lifecycle_state = 'legal_hold' THEN
        RAISE EXCEPTION 'EVIDENCE_LEGAL_HOLD'
            USING ERRCODE = 'P0001',
                  DETAIL = format(
                      'evidence %%s is under legal hold; all mutations are blocked',
                      OLD.id
                  );
    END IF;
    -- Prevent state downgrade (locked -> collected is forbidden).
    IF NEW.lifecycle_state = 'collected'
       AND OLD.lifecycle_state IN ('locked', 'legal_hold') THEN
        RAISE EXCEPTION 'LIFECYCLE_DOWNGRADE'
            USING ERRCODE = 'P0001',
                  DETAIL = format(
                      'cannot downgrade evidence %%s from %%s to collected',
                      OLD.id, OLD.lifecycle_state
                  );
    END IF;
    RETURN NEW;
END;
$$;

-- Block DELETE on locked or legal_hold evidence.
CREATE OR REPLACE FUNCTION fa_evidence_delete_guard()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.lifecycle_state IN ('locked', 'legal_hold') THEN
        RAISE EXCEPTION 'EVIDENCE_LOCKED'
            USING ERRCODE = 'P0001',
                  DETAIL = format(
                      'evidence %%s is in state %%s and cannot be deleted',
                      OLD.id, OLD.lifecycle_state
                  );
    END IF;
    RETURN OLD;
END;
$$;

-- ---------------------------------------------------------------------------
-- 3. Apply UPDATE + DELETE triggers to all evidence tables
-- ---------------------------------------------------------------------------

DO $$
BEGIN
    IF to_regclass('public.fa_field_observations') IS NOT NULL THEN
        DROP TRIGGER IF EXISTS fa_field_observations_update_lifecycle_guard
            ON fa_field_observations;
        CREATE TRIGGER fa_field_observations_update_lifecycle_guard
            BEFORE UPDATE ON fa_field_observations
            FOR EACH ROW
            EXECUTE FUNCTION fa_evidence_update_guard();

        DROP TRIGGER IF EXISTS fa_field_observations_delete_lifecycle_guard
            ON fa_field_observations;
        CREATE TRIGGER fa_field_observations_delete_lifecycle_guard
            BEFORE DELETE ON fa_field_observations
            FOR EACH ROW
            EXECUTE FUNCTION fa_evidence_delete_guard();
    END IF;
END $$;

DO $$
BEGIN
    IF to_regclass('public.fa_scan_results') IS NOT NULL THEN
        DROP TRIGGER IF EXISTS fa_scan_results_update_lifecycle_guard
            ON fa_scan_results;
        CREATE TRIGGER fa_scan_results_update_lifecycle_guard
            BEFORE UPDATE ON fa_scan_results
            FOR EACH ROW
            EXECUTE FUNCTION fa_evidence_update_guard();

        DROP TRIGGER IF EXISTS fa_scan_results_delete_lifecycle_guard
            ON fa_scan_results;
        CREATE TRIGGER fa_scan_results_delete_lifecycle_guard
            BEFORE DELETE ON fa_scan_results
            FOR EACH ROW
            EXECUTE FUNCTION fa_evidence_delete_guard();
    END IF;
END $$;

DO $$
BEGIN
    IF to_regclass('public.fa_document_analyses') IS NOT NULL THEN
        DROP TRIGGER IF EXISTS fa_document_analyses_update_lifecycle_guard
            ON fa_document_analyses;
        CREATE TRIGGER fa_document_analyses_update_lifecycle_guard
            BEFORE UPDATE ON fa_document_analyses
            FOR EACH ROW
            EXECUTE FUNCTION fa_evidence_update_guard();

        DROP TRIGGER IF EXISTS fa_document_analyses_delete_lifecycle_guard
            ON fa_document_analyses;
        CREATE TRIGGER fa_document_analyses_delete_lifecycle_guard
            BEFORE DELETE ON fa_document_analyses
            FOR EACH ROW
            EXECUTE FUNCTION fa_evidence_delete_guard();
    END IF;
END $$;

DO $$
BEGIN
    IF to_regclass('public.fa_evidence_links') IS NOT NULL THEN
        DROP TRIGGER IF EXISTS fa_evidence_links_update_lifecycle_guard
            ON fa_evidence_links;
        CREATE TRIGGER fa_evidence_links_update_lifecycle_guard
            BEFORE UPDATE ON fa_evidence_links
            FOR EACH ROW
            EXECUTE FUNCTION fa_evidence_update_guard();

        DROP TRIGGER IF EXISTS fa_evidence_links_delete_lifecycle_guard
            ON fa_evidence_links;
        CREATE TRIGGER fa_evidence_links_delete_lifecycle_guard
            BEFORE DELETE ON fa_evidence_links
            FOR EACH ROW
            EXECUTE FUNCTION fa_evidence_delete_guard();
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 4. Trigger: block report_json / manifest_hash mutation on finalized reports
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION governance_report_immutability_guard()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.is_finalized = TRUE THEN
        IF NEW.report_json IS DISTINCT FROM OLD.report_json OR
           NEW.manifest_hash IS DISTINCT FROM OLD.manifest_hash THEN
            RAISE EXCEPTION 'REPORT_IMMUTABLE'
                USING ERRCODE = 'P0001',
                      DETAIL = format(
                          'governance_report %%s is finalized; report_json and manifest_hash are immutable',
                          OLD.id
                      );
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

DO $$
BEGIN
    IF to_regclass('public.governance_reports') IS NOT NULL THEN
        DROP TRIGGER IF EXISTS governance_reports_immutability_guard
            ON governance_reports;
        CREATE TRIGGER governance_reports_immutability_guard
            BEFORE UPDATE ON governance_reports
            FOR EACH ROW
            EXECUTE FUNCTION governance_report_immutability_guard();
    END IF;
END $$;
