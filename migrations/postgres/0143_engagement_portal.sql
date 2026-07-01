-- PR 18.2: Enterprise Engagement Portal Authority
-- Creates:
--   portal_engagement_preferences   — per-tenant preference record
--   portal_engagement_activity      — append-only activity log
--   portal_engagement_notifications — notification queue

-- portal_engagement_preferences
CREATE TABLE IF NOT EXISTS portal_engagement_preferences (
    id                 VARCHAR(64)  PRIMARY KEY,
    tenant_id          VARCHAR(255) NOT NULL UNIQUE,
    theme              VARCHAR(64),
    notification_email INTEGER      NOT NULL DEFAULT 1,
    timezone           VARCHAR(64),
    language           VARCHAR(32),
    created_at         VARCHAR(64)  NOT NULL,
    updated_at         VARCHAR(64)  NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_portal_engagement_preferences_tenant
    ON portal_engagement_preferences (tenant_id);

ALTER TABLE portal_engagement_preferences ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename  = 'portal_engagement_preferences'
          AND policyname = 'portal_engagement_preferences_tenant_isolation'
    ) THEN
        CREATE POLICY portal_engagement_preferences_tenant_isolation
            ON portal_engagement_preferences
            USING (tenant_id = current_setting('app.tenant_id', true));
    END IF;
END $$;

-- portal_engagement_activity (append-only)
CREATE TABLE IF NOT EXISTS portal_engagement_activity (
    id            VARCHAR(64)  PRIMARY KEY,
    tenant_id     VARCHAR(255) NOT NULL,
    event_type    VARCHAR(64)  NOT NULL,
    workspace     VARCHAR(64),
    entity_id     VARCHAR(255),
    actor_id      VARCHAR(255),
    summary       TEXT,
    metadata_json TEXT,
    created_at    VARCHAR(64)  NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_portal_engagement_activity_tenant
    ON portal_engagement_activity (tenant_id);
CREATE INDEX IF NOT EXISTS ix_portal_engagement_activity_tenant_event
    ON portal_engagement_activity (tenant_id, event_type, created_at);
CREATE INDEX IF NOT EXISTS ix_portal_engagement_activity_tenant_workspace
    ON portal_engagement_activity (tenant_id, workspace);

ALTER TABLE portal_engagement_activity ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename  = 'portal_engagement_activity'
          AND policyname = 'portal_engagement_activity_tenant_isolation'
    ) THEN
        CREATE POLICY portal_engagement_activity_tenant_isolation
            ON portal_engagement_activity
            USING (tenant_id = current_setting('app.tenant_id', true));
    END IF;
END $$;

-- Append-only enforcement at DB level
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_rules
        WHERE tablename = 'portal_engagement_activity'
          AND rulename  = 'portal_engagement_activity_no_update'
    ) THEN
        CREATE RULE portal_engagement_activity_no_update
            AS ON UPDATE TO portal_engagement_activity DO INSTEAD NOTHING;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_rules
        WHERE tablename = 'portal_engagement_activity'
          AND rulename  = 'portal_engagement_activity_no_delete'
    ) THEN
        CREATE RULE portal_engagement_activity_no_delete
            AS ON DELETE TO portal_engagement_activity DO INSTEAD NOTHING;
    END IF;
END $$;

-- portal_engagement_notifications
CREATE TABLE IF NOT EXISTS portal_engagement_notifications (
    id                VARCHAR(64)  PRIMARY KEY,
    tenant_id         VARCHAR(255) NOT NULL,
    notification_type VARCHAR(64)  NOT NULL,
    status            VARCHAR(32)  NOT NULL DEFAULT 'PENDING',
    subject           TEXT,
    body              TEXT,
    created_at        VARCHAR(64)  NOT NULL,
    updated_at        VARCHAR(64)  NOT NULL,
    delivered_at      VARCHAR(64)
);

CREATE INDEX IF NOT EXISTS ix_portal_engagement_notifications_tenant
    ON portal_engagement_notifications (tenant_id);
CREATE INDEX IF NOT EXISTS ix_portal_engagement_notifications_tenant_status
    ON portal_engagement_notifications (tenant_id, status, created_at);

ALTER TABLE portal_engagement_notifications ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename  = 'portal_engagement_notifications'
          AND policyname = 'portal_engagement_notifications_tenant_isolation'
    ) THEN
        CREATE POLICY portal_engagement_notifications_tenant_isolation
            ON portal_engagement_notifications
            USING (tenant_id = current_setting('app.tenant_id', true));
    END IF;
END $$;
