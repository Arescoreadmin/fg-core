-- 0125_timeline_authority.sql
-- PR 14.6.2 — Timeline Authority (Canonical Governance Ledger)

CREATE TABLE IF NOT EXISTS fa_timeline_events (
    id                TEXT PRIMARY KEY,
    tenant_id         TEXT NOT NULL,
    event_id          TEXT NOT NULL,
    event_hash        TEXT NOT NULL DEFAULT '',
    prev_event_hash   TEXT NOT NULL DEFAULT '',
    source_system     TEXT NOT NULL,
    source_type       TEXT NOT NULL DEFAULT '',
    entity_type       TEXT NOT NULL,
    entity_id         TEXT NOT NULL,
    event_type        TEXT NOT NULL,
    actor_type        TEXT NOT NULL DEFAULT '',
    actor_id          TEXT NOT NULL DEFAULT '',
    occurred_at       TIMESTAMPTZ NOT NULL,
    recorded_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    severity          TEXT NOT NULL DEFAULT 'INFO',
    metadata_json     JSONB NOT NULL DEFAULT '{}'::jsonb,
    correlation_id    TEXT NOT NULL DEFAULT '',
    causation_id      TEXT NOT NULL DEFAULT '',
    replay_version    INTEGER NOT NULL DEFAULT 1,
    schema_version    INTEGER NOT NULL DEFAULT 1,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_fa_timeline_severity CHECK (
        severity IN ('DEBUG','INFO','WARNING','ERROR','CRITICAL')
    ),
    CONSTRAINT uq_fa_timeline_event_id UNIQUE (tenant_id, event_id)
);

CREATE INDEX IF NOT EXISTS ix_fa_timeline_tenant_entity
    ON fa_timeline_events (tenant_id, entity_type, entity_id, occurred_at);
CREATE INDEX IF NOT EXISTS ix_fa_timeline_tenant_source
    ON fa_timeline_events (tenant_id, source_system, occurred_at);
CREATE INDEX IF NOT EXISTS ix_fa_timeline_tenant_occurred
    ON fa_timeline_events (tenant_id, occurred_at);
CREATE INDEX IF NOT EXISTS ix_fa_timeline_correlation
    ON fa_timeline_events (tenant_id, correlation_id);
CREATE INDEX IF NOT EXISTS ix_fa_timeline_event_hash
    ON fa_timeline_events (event_hash);

ALTER TABLE fa_timeline_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE fa_timeline_events FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'fa_timeline_events'
          AND policyname = 'fa_timeline_events_tenant_isolation'
    ) THEN
        CREATE POLICY fa_timeline_events_tenant_isolation
            ON fa_timeline_events
            USING (
                tenant_id IS NOT NULL
                AND current_setting('app.tenant_id', true) IS NOT NULL
                AND tenant_id = current_setting('app.tenant_id', true)
            )
            WITH CHECK (
                tenant_id IS NOT NULL
                AND current_setting('app.tenant_id', true) IS NOT NULL
                AND tenant_id = current_setting('app.tenant_id', true)
            );
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'fa_timeline_events_append_only_update'
    ) THEN
        CREATE TRIGGER fa_timeline_events_append_only_update
        BEFORE UPDATE ON fa_timeline_events
        FOR EACH ROW EXECUTE FUNCTION fg_append_only_enforcer();
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'fa_timeline_events_append_only_delete'
    ) THEN
        CREATE TRIGGER fa_timeline_events_append_only_delete
        BEFORE DELETE ON fa_timeline_events
        FOR EACH ROW EXECUTE FUNCTION fg_append_only_enforcer();
    END IF;
END $$;
