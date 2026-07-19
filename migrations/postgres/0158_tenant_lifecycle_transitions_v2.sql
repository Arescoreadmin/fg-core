-- Migration 0158: tenant_lifecycle_transitions v2 fields
-- Adds transition_hash and schema_version to every audit record.
--
-- transition_hash: SHA-256 of (tenant_id, from_state, to_state, occurred_at,
--   request_id, actor_id) — enables tamper detection, audit export
--   verification, and Digital Twin replay validation without storing
--   any secret material.
--
-- schema_version: integer version of the audit record schema.  Starts at 1.
--   Lets future migrations evolve the record shape without ambiguity.
--
-- Both columns are nullable so the migration is safe against the 0157 rows
-- that were inserted before this migration runs.

ALTER TABLE tenant_lifecycle_transitions
    ADD COLUMN IF NOT EXISTS transition_hash  VARCHAR(64),
    ADD COLUMN IF NOT EXISTS schema_version   INTEGER NOT NULL DEFAULT 1;
