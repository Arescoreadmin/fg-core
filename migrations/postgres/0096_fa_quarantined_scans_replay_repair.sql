-- Migration 0096: Replay repair for fa_quarantined_scans.
--
-- The ORM model requires fa_quarantined_scans, and assert_tenant_rls() expects
-- it to exist with RLS enforced during pure SQL replay.

CREATE TABLE IF NOT EXISTS fa_quarantined_scans (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    engagement_id VARCHAR(64) NOT NULL,
    source_type VARCHAR(64) NOT NULL,
    schema_version VARCHAR(16) NOT NULL,
    quarantine_reason VARCHAR(64) NOT NULL,
    quarantine_detail TEXT NOT NULL,
    payload_hash VARCHAR(64) NOT NULL,
    object_count INTEGER NOT NULL DEFAULT 0,
    schema_version_deprecated TEXT,
    created_at VARCHAR(64) NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_fa_quarantined_engagement_tenant
    ON fa_quarantined_scans (engagement_id, tenant_id);

-- 0093 may already have created fa_quarantined_scans without the newer
-- ORM-required quarantine columns. CREATE TABLE IF NOT EXISTS will not backfill
-- missing columns, so repair the table explicitly before creating indexes.
ALTER TABLE fa_quarantined_scans
    ADD COLUMN IF NOT EXISTS quarantine_reason VARCHAR(64);

UPDATE fa_quarantined_scans
SET quarantine_reason = 'SCAN_QUARANTINED'
WHERE quarantine_reason IS NULL;

ALTER TABLE fa_quarantined_scans
    ALTER COLUMN quarantine_reason SET NOT NULL;

CREATE INDEX IF NOT EXISTS ix_fa_quarantined_tenant_reason
    ON fa_quarantined_scans (tenant_id, quarantine_reason);

ALTER TABLE fa_quarantined_scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE fa_quarantined_scans FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS fa_quarantined_scans_tenant_isolation
    ON fa_quarantined_scans;

CREATE POLICY fa_quarantined_scans_tenant_isolation
    ON fa_quarantined_scans
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)
        OR current_setting('app.current_tenant_id', true) = ''
    );
