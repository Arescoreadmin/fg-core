-- Migration: 0058_governance_timeline_event_version
-- Adds event_version column to governance_timeline_events.
--
-- Purpose:
--   event_version tracks the payload contract version for each event type
--   independently of schema_version (which versions the envelope structure).
--   Required for replay evolution, event migrations, and AGI governance
--   audit survivability — events must carry their own contract lineage.
--
-- Safety:
--   NOT NULL with DEFAULT '1.0' — existing rows acquire version "1.0"
--   without table rewrite on Postgres 11+.

ALTER TABLE governance_timeline_events
    ADD COLUMN IF NOT EXISTS event_version TEXT NOT NULL DEFAULT '1.0';
