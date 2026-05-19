-- Migration: 0057_governance_timeline
-- Creates the append-only governance_timeline_events table.
--
-- Purpose:
--   Unified timeline surface for all governance events across simulations,
--   monitoring, alerting, report generation, exports, replay verification,
--   and evidence lineage.  All events are tenant-scoped and append-only.
--
-- Design:
--   occurred_at stored as TEXT (ISO 8601 UTC).  Lexicographic ordering matches
--   temporal ordering for UTC timestamps with consistent formatting.
--
--   Idempotent inserts: application layer uses INSERT ... ON CONFLICT DO NOTHING
--   (or catches IntegrityError).  No UPDATE or DELETE from application code.
--
-- RLS:
--   Both ENABLE and FORCE ensure table owners / superusers are also subject
--   to the tenant isolation policy.
--
-- Rollback:
--   DROP TABLE IF EXISTS governance_timeline_events;
--   (Safe: table is new; no existing data.)

BEGIN;

CREATE TABLE IF NOT EXISTS governance_timeline_events (
    id              TEXT        NOT NULL PRIMARY KEY,
    tenant_id       TEXT        NOT NULL,
    source_type     TEXT        NOT NULL,
    source_id       TEXT        NOT NULL,
    event_type      TEXT        NOT NULL,
    occurred_at     TEXT        NOT NULL,
    recorded_at     TEXT        NOT NULL,
    payload         JSONB       NOT NULL DEFAULT '{}',
    classification  TEXT        NOT NULL DEFAULT 'internal',
    manifest_hash   TEXT,
    replay_eligible BOOLEAN     NOT NULL DEFAULT FALSE,
    schema_version  TEXT        NOT NULL DEFAULT '1.0'
);

-- Primary list query: tenant feed, newest first
CREATE INDEX IF NOT EXISTS ix_timeline_tenant_time
    ON governance_timeline_events (tenant_id, occurred_at DESC);

-- Filtered by source type within tenant
CREATE INDEX IF NOT EXISTS ix_timeline_tenant_source
    ON governance_timeline_events (tenant_id, source_type, occurred_at DESC);

-- Source entity lookup (all events for a given run / report)
CREATE INDEX IF NOT EXISTS ix_timeline_source_entity
    ON governance_timeline_events (tenant_id, source_id);

-- Replay-eligible events only
CREATE INDEX IF NOT EXISTS ix_timeline_replay
    ON governance_timeline_events (tenant_id, replay_eligible, occurred_at DESC)
    WHERE replay_eligible = TRUE;

ALTER TABLE governance_timeline_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE governance_timeline_events FORCE ROW LEVEL SECURITY;

CREATE POLICY timeline_tenant_isolation
    ON governance_timeline_events
    USING (tenant_id = current_setting('app.tenant_id', true));

COMMIT;
