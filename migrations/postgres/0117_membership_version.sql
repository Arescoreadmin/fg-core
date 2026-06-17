-- 0117_membership_version.sql
-- Adds membership_version to tenant_users.
-- Incremented on every authorization-affecting field change (active, role,
-- identity_binding_status, identity_provider, identity_issuer, identity_subject,
-- identity_type, identity_risk_state, identity_verification_level).
-- Sessions embed the version at issuance; a mismatch = immediate revocation.

ALTER TABLE tenant_users
    ADD COLUMN IF NOT EXISTS membership_version BIGINT NOT NULL DEFAULT 1;

-- Backfill: set all existing rows to version 1 (the DEFAULT handles new rows).
UPDATE tenant_users SET membership_version = 1 WHERE membership_version IS NULL;
