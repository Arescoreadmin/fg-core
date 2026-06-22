-- Migration 0101: Identity Governance Cutover — Legacy Invite Removal
-- PR5: Remove raw invite_token from tenant_users; mark rows with governance metadata.
--
-- Replay-safe: COALESCE protects legacy_invite_disabled_at from overwrite on re-run.
-- Idempotent: WHERE invite_token IS NOT NULL matches only un-migrated rows.

ALTER TABLE tenant_users
    ADD COLUMN IF NOT EXISTS legacy_invite_disabled_at   TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS legacy_invite_disabled_reason TEXT;

-- Clear invite_token for any rows that still have one, and stamp governance metadata.
-- COALESCE on the timestamp column ensures a second run is a no-op for already-migrated rows.
UPDATE tenant_users
SET
    invite_token               = NULL,
    invite_expires_at          = NULL,
    legacy_invite_disabled_at  = COALESCE(legacy_invite_disabled_at, NOW()),
    legacy_invite_disabled_reason = COALESCE(legacy_invite_disabled_reason, 'IDENTITY_GOVERNANCE_CUTOVER')
WHERE invite_token IS NOT NULL;
