-- Migration 0128: PR 14.6.5 — Canonical Evidence Status Model
--
-- Adds deterministic quality score columns to fa_evidence.
-- Trust state ATTESTED and ownership roles BUSINESS_OWNER/TECHNICAL_OWNER
-- are enforced at the application layer (VARCHAR columns, no DB enum changes).
--
-- All columns are nullable — existing rows receive NULL until the quality
-- scoring engine populates them on next mutation or explicit recompute.

BEGIN;

-- Quality score columns
ALTER TABLE fa_evidence
    ADD COLUMN IF NOT EXISTS freshness_score      INTEGER,
    ADD COLUMN IF NOT EXISTS verification_score   INTEGER,
    ADD COLUMN IF NOT EXISTS completeness_score   INTEGER,
    ADD COLUMN IF NOT EXISTS quality_last_computed_at TEXT;

-- Index for quality-score-based reporting queries
CREATE INDEX IF NOT EXISTS ix_fa_evidence_quality_computed
    ON fa_evidence (tenant_id, quality_last_computed_at)
    WHERE quality_last_computed_at IS NOT NULL;

-- Index for freshness-based expiry reports
CREATE INDEX IF NOT EXISTS ix_fa_evidence_freshness_score
    ON fa_evidence (tenant_id, freshness_score)
    WHERE freshness_score IS NOT NULL;

COMMIT;
