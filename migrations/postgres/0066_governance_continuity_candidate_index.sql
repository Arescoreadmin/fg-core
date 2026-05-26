-- PR 18: Governance Asset Continuity Service
-- Adds a composite index to support the connector-run promote-assets query:
--   WHERE tenant_id = ? AND engagement_id = ? AND scan_result_id = ? AND status = 'detected'
-- This query pattern is new and not covered by ix_ga_candidates_tenant_status.

CREATE INDEX IF NOT EXISTS ix_ga_candidates_tenant_engagement_scan_status
    ON ga_asset_candidates (tenant_id, engagement_id, scan_result_id, status);
