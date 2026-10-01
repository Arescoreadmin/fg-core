-- TRUST-BINDING-001 follow-up: bind governance report records to canonical Vault Transit trust authority
--
-- Adds the same 8 trust signature columns to governance_reports that migration 0193
-- added to fa_qualification_decisions and fa_governed_delivery_authorizations.
--
-- Column design:
--   trust_signature              — vault:v<n>:<base64> signature from Vault Transit
--   trust_signing_algorithm      — always 'ed25519' for Customer-Zero roles
--   trust_signing_role           — TrustRole value (customer-zero-identity)
--   trust_signing_key_id         — Vault key ID (non-secret, public configuration)
--   trust_signing_key_version    — integer key version embedded in vault:v<n>
--   trust_public_key_fingerprint — SHA-256 hex of the Ed25519 public key raw bytes
--   trust_signed_payload_sha256  — SHA-256 hex of the bytes actually signed
--                                  (domain\n<canonical-json>)
--   trust_signature_schema_version — '1' for this schema

-- governance_reports — sign with IDENTITY trust role
ALTER TABLE governance_reports
    ADD COLUMN IF NOT EXISTS trust_signature TEXT,
    ADD COLUMN IF NOT EXISTS trust_signing_algorithm TEXT,
    ADD COLUMN IF NOT EXISTS trust_signing_role TEXT,
    ADD COLUMN IF NOT EXISTS trust_signing_key_id TEXT,
    ADD COLUMN IF NOT EXISTS trust_signing_key_version INTEGER,
    ADD COLUMN IF NOT EXISTS trust_public_key_fingerprint TEXT,
    ADD COLUMN IF NOT EXISTS trust_signed_payload_sha256 TEXT,
    ADD COLUMN IF NOT EXISTS trust_signature_schema_version TEXT;

-- Index for audit/lookup by trust role — non-unique, nullable
CREATE INDEX IF NOT EXISTS ix_governance_reports_trust_role
    ON governance_reports (trust_signing_role)
    WHERE trust_signing_role IS NOT NULL;
