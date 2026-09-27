-- PROD-QUAL-001 hardening: enforce one QUALIFIED decision per (tenant, report).
--
-- The per-request unique index (0189) permits multiple pending requests before
-- either is finalized; two concurrent finalizations could each write a QUALIFIED
-- row, causing scalar_one_or_none() to raise MultipleResultsFound at delivery.
-- This partial unique index makes that impossible at the DB layer.

CREATE UNIQUE INDEX IF NOT EXISTS uq_fa_qualification_decisions_report_qualified
    ON fa_qualification_decisions (tenant_id, report_id)
    WHERE decision = 'QUALIFIED';
