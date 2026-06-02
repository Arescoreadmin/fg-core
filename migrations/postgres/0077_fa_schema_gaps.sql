-- Migration 0077: Back-fill ORM columns absent from earlier FA migrations.
--
-- fa_scan_results.finding_count  — Integer NOT NULL DEFAULT 0
--   Added to the ORM model but never backfilled for existing Postgres tables.
--   create_all(checkfirst=True) skips tables that already exist, so the column
--   would be silently missing on databases predating this migration.
--
-- fa_normalized_findings.asset_id — VARCHAR(64) nullable, indexed
--   Same issue: column and its index are in the ORM model but have no migration.
--
-- Both statements use IF NOT EXISTS so they are safe on fresh databases where
-- create_all() already materialised the columns as part of the C2 fix.

ALTER TABLE fa_scan_results
    ADD COLUMN IF NOT EXISTS finding_count INTEGER NOT NULL DEFAULT 0;

ALTER TABLE fa_normalized_findings
    ADD COLUMN IF NOT EXISTS asset_id VARCHAR(64);

CREATE INDEX IF NOT EXISTS ix_fa_findings_asset
    ON fa_normalized_findings (asset_id);
