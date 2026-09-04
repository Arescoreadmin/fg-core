-- Migration 0186: Add acceptance_token_hash to tenant_invitations
--
-- Supports P-113.8 canonical invitation acceptance flow.
-- Stores HMAC fingerprint of the fgwi1.* bearer token; plaintext never persisted.
-- Nullable — existing rows have no hash and fail closed at the acceptance endpoint.
--
-- Rollback: ALTER TABLE tenant_invitations DROP COLUMN acceptance_token_hash;

ALTER TABLE tenant_invitations
    ADD COLUMN IF NOT EXISTS acceptance_token_hash TEXT;

CREATE INDEX IF NOT EXISTS ix_tenant_invitations_acceptance_token_hash
    ON tenant_invitations (acceptance_token_hash)
    WHERE acceptance_token_hash IS NOT NULL;
