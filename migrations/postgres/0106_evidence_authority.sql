-- Migration 0106: Evidence Authority Foundation (PR 1.3)
-- SCHEMA CHANGE — adds 5 Ed25519 authority signing columns to fa_evidence_provenance
--
-- All columns nullable for backward compatibility.
-- Existing rows remain valid legacy records (unsigned, not invalid).
-- No backfill in this migration.
--
-- Authority version: evidence-authority-v1
-- Signature version: evidence-signature-v1
-- Algorithm: Ed25519, digest: SHA-256(canonical_event_json_bytes)

DO $$
BEGIN
    IF to_regclass('public.fa_evidence_provenance') IS NOT NULL THEN

        -- signature: hex-encoded Ed25519 signature over SHA-256(canonical_event_json)
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'fa_evidence_provenance' AND column_name = 'signature'
        ) THEN
            ALTER TABLE fa_evidence_provenance ADD COLUMN signature TEXT;
        END IF;

        -- signing_key_id: SHA256(public_key_bytes)[:16] — stable key fingerprint
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'fa_evidence_provenance' AND column_name = 'signing_key_id'
        ) THEN
            ALTER TABLE fa_evidence_provenance ADD COLUMN signing_key_id TEXT;
        END IF;

        -- signed_at: ISO8601-Z string when the authority signature was computed
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'fa_evidence_provenance' AND column_name = 'signed_at'
        ) THEN
            ALTER TABLE fa_evidence_provenance ADD COLUMN signed_at TEXT;
        END IF;

        -- signature_version: "evidence-signature-v1" — versioned for algorithm evolution
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'fa_evidence_provenance' AND column_name = 'signature_version'
        ) THEN
            ALTER TABLE fa_evidence_provenance ADD COLUMN signature_version TEXT;
        END IF;

        -- authority_version: "evidence-authority-v1" — versioned for authority model evolution
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'fa_evidence_provenance' AND column_name = 'authority_version'
        ) THEN
            ALTER TABLE fa_evidence_provenance ADD COLUMN authority_version TEXT;
        END IF;

        -- Partial index on signing_key_id for key rotation queries
        -- (only indexes signed rows; legacy null rows are excluded)
        IF NOT EXISTS (
            SELECT 1 FROM pg_indexes
            WHERE tablename = 'fa_evidence_provenance'
              AND indexname = 'ix_fa_evidence_provenance_signing_key_id'
        ) THEN
            CREATE INDEX ix_fa_evidence_provenance_signing_key_id
                ON fa_evidence_provenance (signing_key_id)
                WHERE signing_key_id IS NOT NULL;
        END IF;

    END IF;
END;
$$;
