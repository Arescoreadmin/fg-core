-- Migration: add provenance columns to governance_assets
-- PR 8: assets promoted from Field Assessment must carry the scan result and
-- engagement that first surfaced them so the evidence chain is traceable.

BEGIN;

ALTER TABLE governance_assets
    ADD COLUMN IF NOT EXISTS source_scan_result_id TEXT,
    ADD COLUMN IF NOT EXISTS source_engagement_id   TEXT;

CREATE INDEX IF NOT EXISTS ix_ga_assets_source_scan
    ON governance_assets (tenant_id, source_scan_result_id)
    WHERE source_scan_result_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS ix_ga_assets_source_engagement
    ON governance_assets (tenant_id, source_engagement_id)
    WHERE source_engagement_id IS NOT NULL;

COMMIT;
