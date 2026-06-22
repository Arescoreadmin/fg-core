-- Migration 0077: Back-fill ORM columns absent from earlier FA migrations.
--
-- Replay-safe:
-- These Field Assessment tables may be ORM-managed and absent during pure SQL
-- replay. Guard each ALTER/INDEX so migration replay is deterministic.

DO $$
BEGIN
    IF to_regclass('public.fa_scan_results') IS NOT NULL THEN
        ALTER TABLE fa_scan_results
            ADD COLUMN IF NOT EXISTS finding_count INTEGER NOT NULL DEFAULT 0;
    END IF;
END $$;

DO $$
BEGIN
    IF to_regclass('public.fa_normalized_findings') IS NOT NULL THEN
        ALTER TABLE fa_normalized_findings
            ADD COLUMN IF NOT EXISTS asset_id VARCHAR(64);
    END IF;
END $$;

DO $$
BEGIN
    IF to_regclass('public.fa_normalized_findings') IS NOT NULL THEN
        CREATE INDEX IF NOT EXISTS ix_fa_findings_asset
            ON fa_normalized_findings (asset_id);
    END IF;
END $$;
