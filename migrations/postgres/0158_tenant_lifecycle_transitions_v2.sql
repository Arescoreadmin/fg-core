-- Migration 0158: tenant_lifecycle_transitions v2 fields
-- Adds transition_hash and schema_version to every audit record.
--
-- transition_hash: SHA-256 of (transition_id, tenant_id, from_state, to_state,
--   occurred_at, request_id, actor_id) — enables tamper detection, audit export
--   verification, and Digital Twin replay validation.
--
-- schema_version: 0 for rows written before this migration (no hash),
--   1 for rows written by api/tenant_lifecycle.py TRANSITION_SCHEMA_VERSION = 1.
--   DEFAULT 0 is intentional: existing 0157 rows must NOT inherit version 1,
--   which would make them indistinguishable from hash-bearing v1 records.
--   Consumers can filter schema_version = 0 to identify pre-0158 rows and
--   either skip hash verification or backfill hashes separately.

ALTER TABLE tenant_lifecycle_transitions
    ADD COLUMN IF NOT EXISTS transition_hash  VARCHAR(64),
    ADD COLUMN IF NOT EXISTS schema_version   INTEGER NOT NULL DEFAULT 0;
