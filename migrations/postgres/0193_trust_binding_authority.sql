-- TRUST-BINDING-001: bind governance artifacts to canonical Vault Transit trust authority
--
-- Adds signature columns to fa_qualification_decisions and
-- fa_governed_delivery_authorizations so that each finalized decision and
-- each delivery authorization is cryptographically bound to the Customer-Zero
-- Vault Transit trust roles.
--
-- Column design:
--   trust_signature              — vault:v<n>:<base64> signature from Vault Transit
--   trust_signing_algorithm      — always 'ed25519' for Customer-Zero roles
--   trust_signing_role           — TrustRole value (customer-zero-approval / customer-zero-acceptance)
--   trust_signing_key_id         — Vault key ID (non-secret, public configuration)
--   trust_signing_key_version    — integer key version embedded in vault:v<n>
--   trust_public_key_fingerprint — SHA-256 hex of the Ed25519 public key raw bytes
--   trust_signed_payload_sha256  — SHA-256 hex of the bytes actually signed
--                                  (domain\n<canonical-json>)
--   trust_signature_schema_version — '1' for this schema

-- fa_qualification_decisions — sign with APPROVAL trust role
ALTER TABLE fa_qualification_decisions
    ADD COLUMN IF NOT EXISTS trust_signature TEXT,
    ADD COLUMN IF NOT EXISTS trust_signing_algorithm TEXT,
    ADD COLUMN IF NOT EXISTS trust_signing_role TEXT,
    ADD COLUMN IF NOT EXISTS trust_signing_key_id TEXT,
    ADD COLUMN IF NOT EXISTS trust_signing_key_version INTEGER,
    ADD COLUMN IF NOT EXISTS trust_public_key_fingerprint TEXT,
    ADD COLUMN IF NOT EXISTS trust_signed_payload_sha256 TEXT,
    ADD COLUMN IF NOT EXISTS trust_signature_schema_version TEXT;

-- fa_governed_delivery_authorizations — sign with ACCEPTANCE trust role
ALTER TABLE fa_governed_delivery_authorizations
    ADD COLUMN IF NOT EXISTS trust_signature TEXT,
    ADD COLUMN IF NOT EXISTS trust_signing_algorithm TEXT,
    ADD COLUMN IF NOT EXISTS trust_signing_role TEXT,
    ADD COLUMN IF NOT EXISTS trust_signing_key_id TEXT,
    ADD COLUMN IF NOT EXISTS trust_signing_key_version INTEGER,
    ADD COLUMN IF NOT EXISTS trust_public_key_fingerprint TEXT,
    ADD COLUMN IF NOT EXISTS trust_signed_payload_sha256 TEXT,
    ADD COLUMN IF NOT EXISTS trust_signature_schema_version TEXT;

-- Indexes for audit/lookup by key ID and role — non-unique, nullable
CREATE INDEX IF NOT EXISTS ix_fa_qualification_decisions_trust_role
    ON fa_qualification_decisions (trust_signing_role)
    WHERE trust_signing_role IS NOT NULL;

CREATE INDEX IF NOT EXISTS ix_fa_governed_delivery_authorizations_trust_role
    ON fa_governed_delivery_authorizations (trust_signing_role)
    WHERE trust_signing_role IS NOT NULL;
