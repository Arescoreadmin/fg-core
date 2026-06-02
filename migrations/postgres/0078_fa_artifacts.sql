-- Migration 0078: fa_artifacts registry
-- Artifact registry for engagement evidence objects (audio, documents, exports).
-- The storage_key (blob URL) is stored here and must never be returned to client
-- browsers. The audio proxy resolves artifact_id → storage_key server-side, issues
-- a short-lived Vercel Blob signed URL, and streams the content.
--
-- Schema change: new table + RLS policy.
-- Called out per CLAUDE.md: every migration must be explicitly acknowledged.

CREATE TABLE IF NOT EXISTS fa_artifacts (
    id              VARCHAR(64)  PRIMARY KEY,
    tenant_id       VARCHAR(255) NOT NULL,
    engagement_id   VARCHAR(64)  NOT NULL,
    artifact_type   VARCHAR(64)  NOT NULL
        CHECK (artifact_type IN ('audio', 'document', 'export')),
    storage_key     TEXT         NOT NULL,
    sha256          VARCHAR(64),
    size_bytes      INTEGER,
    content_type    VARCHAR(128),
    created_by      VARCHAR(255) NOT NULL,
    created_at      VARCHAR(64)  NOT NULL,
    deleted_at      VARCHAR(64),
    retention_class VARCHAR(64)  NOT NULL DEFAULT 'standard_3y',
    legal_hold      BOOLEAN      NOT NULL DEFAULT FALSE,
    scheduled_purge_at  VARCHAR(64),
    purge_completed_at  VARCHAR(64)
);

CREATE INDEX IF NOT EXISTS ix_fa_artifacts_tenant_engagement
    ON fa_artifacts (tenant_id, engagement_id);

CREATE INDEX IF NOT EXISTS ix_fa_artifacts_tenant_type
    ON fa_artifacts (tenant_id, artifact_type);

-- Row-level security: each tenant row is visible only to that tenant's session.
ALTER TABLE fa_artifacts ENABLE ROW LEVEL SECURITY;

CREATE POLICY fa_artifacts_tenant_isolation ON fa_artifacts
    USING     (tenant_id = current_setting('app.tenant_id', TRUE))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', TRUE));
