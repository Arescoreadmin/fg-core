-- Migration 0104: Persistent signature metadata on ingest ReportRecord
-- Closes PR-SIGN-5 gap: ingest reports now store the signing event at
-- finalization time so signatures are independently verifiable after the fact.
-- All columns are nullable for migration compatibility; existing rows remain
-- unsigned until a new finalize cycle runs.
-- SCHEMA CHANGE — must be called out.

ALTER TABLE reports
    ADD COLUMN IF NOT EXISTS signature              TEXT,
    ADD COLUMN IF NOT EXISTS signature_algorithm   TEXT,
    ADD COLUMN IF NOT EXISTS signature_key_id      TEXT,
    ADD COLUMN IF NOT EXISTS signed_at             TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS signature_payload_hash TEXT,
    ADD COLUMN IF NOT EXISTS signature_version     TEXT;
