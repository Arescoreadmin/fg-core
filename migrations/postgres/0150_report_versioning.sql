-- 0150: Enterprise Report Delivery — versioned report rows + append-only delivery events
--
-- Adds two tables that sit on top of governance_reports (created by ORM):
--   fa_report_versions          — mutable through status transitions; guarded at route layer
--   fa_report_delivery_events   — append-only audit trail (UPDATE/DELETE denied by trigger)
--
-- Row-level tenant isolation matches the pattern established for identity_* tables.
-- Append-only trigger uses append_only_guard() from migration 0002.

CREATE TABLE IF NOT EXISTS fa_report_versions (
    id                    VARCHAR(64)  PRIMARY KEY,
    tenant_id             VARCHAR(255) NOT NULL,
    engagement_id         VARCHAR(64)  NOT NULL,
    report_id             VARCHAR(64)  NOT NULL,
    version               INTEGER      NOT NULL DEFAULT 1,
    revision              VARCHAR(32)  NOT NULL DEFAULT '1.0',
    status                VARCHAR(32)  NOT NULL DEFAULT 'draft',
    parent_version_id     VARCHAR(64),
    superseded_by_id      VARCHAR(64),
    created_at            VARCHAR(64)  NOT NULL,
    approved_at           VARCHAR(64),
    approved_by           VARCHAR(255),
    generated_by          VARCHAR(255) NOT NULL,
    delivered_at          VARCHAR(64),
    manifest_hash         VARCHAR(64),
    report_hash           VARCHAR(64),
    evidence_count        INTEGER      NOT NULL DEFAULT 0,
    finding_count         INTEGER      NOT NULL DEFAULT 0,
    control_count         INTEGER      NOT NULL DEFAULT 0,
    framework_count       INTEGER      NOT NULL DEFAULT 0,
    confidence_score      DOUBLE PRECISION,
    approval_notes        TEXT,
    reviewer_name         VARCHAR(255),
    reviewer_role         VARCHAR(128),
    signature_placeholder TEXT,
    schema_version        VARCHAR(16)  NOT NULL DEFAULT '1.0'
);

CREATE INDEX IF NOT EXISTS ix_fa_report_versions_tenant_engagement
    ON fa_report_versions (tenant_id, engagement_id);
CREATE INDEX IF NOT EXISTS ix_fa_report_versions_tenant_report
    ON fa_report_versions (tenant_id, report_id);
CREATE INDEX IF NOT EXISTS ix_fa_report_versions_tenant_status
    ON fa_report_versions (tenant_id, status);

-- FK links back to the version lineage (nullable, self-referential)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'fa_report_versions_parent_fk'
    ) THEN
        ALTER TABLE fa_report_versions
            ADD CONSTRAINT fa_report_versions_parent_fk
            FOREIGN KEY (parent_version_id) REFERENCES fa_report_versions (id);
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'fa_report_versions_superseded_by_fk'
    ) THEN
        ALTER TABLE fa_report_versions
            ADD CONSTRAINT fa_report_versions_superseded_by_fk
            FOREIGN KEY (superseded_by_id) REFERENCES fa_report_versions (id);
    END IF;
END $$;

ALTER TABLE fa_report_versions ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS fa_report_versions_tenant_isolation ON fa_report_versions;
CREATE POLICY fa_report_versions_tenant_isolation
    ON fa_report_versions USING (tenant_id = current_setting('app.tenant_id', true));


CREATE TABLE IF NOT EXISTS fa_report_delivery_events (
    id                VARCHAR(64)  PRIMARY KEY,
    tenant_id         VARCHAR(255) NOT NULL,
    engagement_id     VARCHAR(64)  NOT NULL,
    report_version_id VARCHAR(64)  NOT NULL,
    event_type        VARCHAR(64)  NOT NULL,
    actor             VARCHAR(255) NOT NULL,
    actor_role        VARCHAR(128),
    report_version    INTEGER      NOT NULL DEFAULT 1,
    created_at        VARCHAR(64)  NOT NULL,
    schema_version    VARCHAR(16)  NOT NULL DEFAULT '1.0'
);

CREATE INDEX IF NOT EXISTS ix_fa_report_delivery_events_tenant_engagement
    ON fa_report_delivery_events (tenant_id, engagement_id);
CREATE INDEX IF NOT EXISTS ix_fa_report_delivery_events_tenant_version
    ON fa_report_delivery_events (tenant_id, report_version_id);
CREATE INDEX IF NOT EXISTS ix_fa_report_delivery_events_tenant_type
    ON fa_report_delivery_events (tenant_id, event_type);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'fa_report_delivery_events_version_fk'
    ) THEN
        ALTER TABLE fa_report_delivery_events
            ADD CONSTRAINT fa_report_delivery_events_version_fk
            FOREIGN KEY (report_version_id) REFERENCES fa_report_versions (id);
    END IF;
END $$;

ALTER TABLE fa_report_delivery_events ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS fa_report_delivery_events_tenant_isolation ON fa_report_delivery_events;
CREATE POLICY fa_report_delivery_events_tenant_isolation
    ON fa_report_delivery_events USING (tenant_id = current_setting('app.tenant_id', true));

-- Append-only enforcement: block UPDATE and DELETE via the shared append_only_guard()
-- from migration 0002 (or 0013). Idempotent DROP + CREATE keeps re-runs safe.
DO $$
BEGIN
    IF to_regclass('public.fa_report_delivery_events') IS NOT NULL THEN
        DROP TRIGGER IF EXISTS fa_report_delivery_events_append_only_update
            ON fa_report_delivery_events;
        CREATE TRIGGER fa_report_delivery_events_append_only_update
            BEFORE UPDATE ON fa_report_delivery_events
            FOR EACH ROW
            EXECUTE FUNCTION append_only_guard();

        DROP TRIGGER IF EXISTS fa_report_delivery_events_append_only_delete
            ON fa_report_delivery_events;
        CREATE TRIGGER fa_report_delivery_events_append_only_delete
            BEFORE DELETE ON fa_report_delivery_events
            FOR EACH ROW
            EXECUTE FUNCTION append_only_guard();
    END IF;
END $$;
