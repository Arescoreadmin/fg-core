-- PR 52.5: Regulatory-Grade Verification Bundle Hardening
--
-- 1. Extend fa_verification_bundles with new columns for hardening items 2, 4-10.
-- 2. Enforce DB-level append-only semantics via BEFORE UPDATE/DELETE triggers.

-- ── New columns ────────────────────────────────────────────────────────────────
ALTER TABLE fa_verification_bundles
    ADD COLUMN IF NOT EXISTS engagement_audit_event_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS coverage_status VARCHAR(32) NOT NULL DEFAULT 'unknown',
    ADD COLUMN IF NOT EXISTS report_artifact_hash VARCHAR(64),
    ADD COLUMN IF NOT EXISTS report_artifact_hash_status VARCHAR(32) NOT NULL DEFAULT 'not_available',
    ADD COLUMN IF NOT EXISTS chain_of_custody_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS signature_metadata TEXT,
    ADD COLUMN IF NOT EXISTS regulatory_context TEXT,
    ADD COLUMN IF NOT EXISTS governance_activity TEXT;

-- ── Append-only trigger functions ──────────────────────────────────────────────
CREATE OR REPLACE FUNCTION fa_verification_bundles_no_update()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION
        'fa_verification_bundles is append-only: UPDATE is not permitted (bundle_id: %)',
        OLD.id;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION fa_verification_bundles_no_delete()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION
        'fa_verification_bundles is append-only: DELETE is not permitted (bundle_id: %)',
        OLD.id;
END;
$$ LANGUAGE plpgsql;

-- Idempotent trigger creation (drop then recreate)
DROP TRIGGER IF EXISTS trg_fa_verification_bundles_no_update ON fa_verification_bundles;
CREATE TRIGGER trg_fa_verification_bundles_no_update
    BEFORE UPDATE ON fa_verification_bundles
    FOR EACH ROW EXECUTE FUNCTION fa_verification_bundles_no_update();

DROP TRIGGER IF EXISTS trg_fa_verification_bundles_no_delete ON fa_verification_bundles;
CREATE TRIGGER trg_fa_verification_bundles_no_delete
    BEFORE DELETE ON fa_verification_bundles
    FOR EACH ROW EXECUTE FUNCTION fa_verification_bundles_no_delete();
