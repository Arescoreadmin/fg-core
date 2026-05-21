-- Migration: add QA approval columns to governance_reports
-- PR 7: report.qa.approved gate requires qa_approved_by and qa_approved_at
-- to be persisted on GovernanceReportRecord so the gate can evaluate them.
--
-- Both columns are nullable: existing finalized reports are not QA-approved
-- until an operator calls POST /engagements/{id}/reports/{report_id}/qa-approve.

BEGIN;

ALTER TABLE governance_reports
    ADD COLUMN IF NOT EXISTS qa_approved_by  TEXT,
    ADD COLUMN IF NOT EXISTS qa_approved_at  TEXT;

COMMIT;
