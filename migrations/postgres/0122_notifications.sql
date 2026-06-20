-- Migration 0122: Notification Records (PR 13.7)
--
-- Creates the notifications table for the Notification Authority bounded context.
-- Tracks delivery state machine: pending → sent/failed → acknowledged.
--
-- RLS enabled: app.tenant_id GUC required for all access.
-- No append-only trigger — notifications are mutable (delivery_status changes).
--
-- Safe:       IF NOT EXISTS throughout.
-- Idempotent: re-running is a no-op.

-- ---------------------------------------------------------------------------
-- notifications
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS notifications (
    id                  TEXT        PRIMARY KEY,
    tenant_id           TEXT        NOT NULL,
    task_id             TEXT        NOT NULL,
    trigger_type        TEXT        NOT NULL,
    channel             TEXT        NOT NULL DEFAULT 'email',
    recipient           TEXT        NOT NULL,
    subject             TEXT,
    delivery_status     TEXT        NOT NULL DEFAULT 'pending',
    sent_at             TEXT,
    acknowledged_at     TEXT,
    failure_reason      TEXT,
    event_metadata      JSON        NOT NULL DEFAULT '{}',
    created_at          TEXT        NOT NULL,
    updated_at          TEXT        NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_notifications_tenant_id
    ON notifications (tenant_id);
CREATE INDEX IF NOT EXISTS ix_notifications_tenant_task
    ON notifications (tenant_id, task_id);
CREATE INDEX IF NOT EXISTS ix_notifications_tenant_status
    ON notifications (tenant_id, delivery_status);
CREATE INDEX IF NOT EXISTS ix_notifications_trigger_type
    ON notifications (tenant_id, trigger_type);

ALTER TABLE notifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE notifications FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS notifications_tenant_isolation ON notifications;
CREATE POLICY notifications_tenant_isolation
    ON notifications
    USING (
        current_setting('app.tenant_id', true) IS NOT NULL
        AND tenant_id = current_setting('app.tenant_id', true)
    );
