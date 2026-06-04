-- Migration 0087: Verification Bundle append-only hardening.
--
-- Replay-safe:
-- fa_verification_bundles may be ORM-managed and absent during pure SQL replay.

DO $$
BEGIN
    IF to_regclass('public.fa_verification_bundles') IS NOT NULL THEN
        ALTER TABLE fa_verification_bundles
            ADD COLUMN IF NOT EXISTS generated_by VARCHAR(255),
            ADD COLUMN IF NOT EXISTS report_artifact_hash VARCHAR(64),
            ADD COLUMN IF NOT EXISTS report_artifact_hash_status VARCHAR(32),
            ADD COLUMN IF NOT EXISTS regulatory_context TEXT,
            ADD COLUMN IF NOT EXISTS signature_metadata TEXT,
            ADD COLUMN IF NOT EXISTS tamper_details TEXT,
            ADD COLUMN IF NOT EXISTS component_summary TEXT,
            ADD COLUMN IF NOT EXISTS governance_activity TEXT;
    END IF;
END $$;
