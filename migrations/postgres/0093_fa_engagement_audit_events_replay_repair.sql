-- Migration 0093: Replay repair for fa_engagement_audit_events.
--
-- Clean SQL replay expects fa_engagement_audit_events to exist because
-- api.db_migrations.assert_append_only_triggers() requires append-only triggers
-- for it. Earlier environments may rely on ORM create_all(), so this migration
-- creates the table if missing and attaches append-only triggers idempotently.

CREATE TABLE IF NOT EXISTS fa_engagement_audit_events (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    engagement_id VARCHAR(64) NOT NULL,
    event_type VARCHAR(128) NOT NULL,
    actor VARCHAR(255),
    payload TEXT,
    created_at VARCHAR(64) NOT NULL,

    transaction_id VARCHAR(64),
    correlation_id VARCHAR(128),
    before_hash VARCHAR(64),
    after_hash VARCHAR(64),
    entity_type VARCHAR(64),
    entity_id VARCHAR(64),
    actor_type VARCHAR(32)
);

CREATE INDEX IF NOT EXISTS ix_fa_engagement_audit_events_tenant_engagement
    ON fa_engagement_audit_events (tenant_id, engagement_id);

CREATE INDEX IF NOT EXISTS ix_fa_engagement_audit_events_created_at
    ON fa_engagement_audit_events (created_at);

CREATE INDEX IF NOT EXISTS ix_fa_engagement_audit_tx
    ON fa_engagement_audit_events (transaction_id)
    WHERE transaction_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS ix_fa_engagement_audit_entity
    ON fa_engagement_audit_events (entity_type, entity_id)
    WHERE entity_type IS NOT NULL AND entity_id IS NOT NULL;

DROP TRIGGER IF EXISTS fa_engagement_audit_events_append_only_update
    ON fa_engagement_audit_events;

CREATE TRIGGER fa_engagement_audit_events_append_only_update
    BEFORE UPDATE ON fa_engagement_audit_events
    FOR EACH ROW
    EXECUTE FUNCTION append_only_guard();

DROP TRIGGER IF EXISTS fa_engagement_audit_events_append_only_delete
    ON fa_engagement_audit_events;

CREATE TRIGGER fa_engagement_audit_events_append_only_delete
    BEFORE DELETE ON fa_engagement_audit_events
    FOR EACH ROW
    EXECUTE FUNCTION append_only_guard();

-- Replay repair for fa_quarantined_scans.
-- Clean SQL replay expects this ORM-managed table to exist and have RLS enforced.

CREATE TABLE IF NOT EXISTS fa_quarantined_scans (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    engagement_id VARCHAR(64),
    source_type VARCHAR(64),
    reason TEXT,
    raw_payload TEXT,
    created_at VARCHAR(64) NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_fa_quarantined_scans_tenant
    ON fa_quarantined_scans (tenant_id);

CREATE INDEX IF NOT EXISTS ix_fa_quarantined_scans_engagement
    ON fa_quarantined_scans (engagement_id);

ALTER TABLE fa_quarantined_scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE fa_quarantined_scans FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS fa_quarantined_scans_tenant_isolation
    ON fa_quarantined_scans;

CREATE POLICY fa_quarantined_scans_tenant_isolation
    ON fa_quarantined_scans
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)
        OR current_setting('app.current_tenant_id', true) = ''
    );

