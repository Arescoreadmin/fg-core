-- Migration 0205: L14-ASSESSMENT-ASSURANCE-001 — one terminal QA decision per
-- governance report record and stage.
--
-- fa_report_qa_decisions (0188) already allows one decision per
-- (tenant_id, report_version_id, qa_stage) for version-bound decisions.
-- Governance-stage decisions (POST /qa-approve, POST /qa-reject) are bound to
-- the governance report record and carry report_version_id = NULL, which the
-- 0188 unique index treats as distinct.  This partial unique index gives those
-- decisions the same guarantee, so concurrent approve / reject / replayed
-- requests resolve to exactly one durable decision.
--
-- Safety: additive only; no row is read back or rewritten.  The table is
-- append-only (0188 triggers), so pre-existing duplicates cannot be cleaned
-- here: the migration fails closed with an explicit message instead of
-- silently weakening the index.  No CREATE INDEX CONCURRENTLY (the migration
-- executor runs in one transaction).  RLS from 0188 is unchanged.

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM fa_report_qa_decisions
        WHERE report_version_id IS NULL
        GROUP BY tenant_id, report_id, qa_stage
        HAVING count(*) > 1
    ) THEN
        RAISE EXCEPTION
            '0205: duplicate governance-stage QA decisions exist; resolve before applying (L14-ASSESSMENT-ASSURANCE-001)';
    END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS uq_fa_report_qa_decisions_governance_stage
    ON fa_report_qa_decisions (tenant_id, report_id, qa_stage)
    WHERE report_version_id IS NULL;
