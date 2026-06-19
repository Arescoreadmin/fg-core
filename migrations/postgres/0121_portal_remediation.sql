-- Migration 0121: Portal Remediation Integration (PR 13.4)
--
-- Creates three tables supporting the client-facing remediation portal:
--   portal_remediation_comments     — editable comments with audit
--   portal_evidence_submissions     — immutable evidence metadata records
--   portal_remediation_audit_events — append-only portal action log
--
-- All tables have RLS enabled. portal_remediation_audit_events has
-- append-only DB triggers using the shared append_only_guard() from 0013.
--
-- Safe:       IF NOT EXISTS throughout.
-- Idempotent: re-running is a no-op.

-- ---------------------------------------------------------------------------
-- portal_remediation_comments
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS portal_remediation_comments (
    id          TEXT        PRIMARY KEY,
    tenant_id   TEXT        NOT NULL,
    task_id     TEXT        NOT NULL,
    author      TEXT        NOT NULL,
    body        TEXT        NOT NULL,
    is_edited   BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at  TEXT        NOT NULL,
    updated_at  TEXT        NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_portal_comments_tenant_id
    ON portal_remediation_comments (tenant_id);
CREATE INDEX IF NOT EXISTS ix_portal_comments_tenant_task
    ON portal_remediation_comments (tenant_id, task_id);

ALTER TABLE portal_remediation_comments ENABLE ROW LEVEL SECURITY;
ALTER TABLE portal_remediation_comments FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS portal_remediation_comments_tenant_isolation ON portal_remediation_comments;
CREATE POLICY portal_remediation_comments_tenant_isolation
    ON portal_remediation_comments
    USING (
        current_setting('app.tenant_id', true) IS NOT NULL
        AND tenant_id = current_setting('app.tenant_id', true)
    );

-- ---------------------------------------------------------------------------
-- portal_evidence_submissions (immutable after insert)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS portal_evidence_submissions (
    id                  TEXT        PRIMARY KEY,
    tenant_id           TEXT        NOT NULL,
    task_id             TEXT        NOT NULL,
    filename            TEXT        NOT NULL,
    content_type        TEXT        NOT NULL,
    sha256              TEXT        NOT NULL,
    submitted_by        TEXT        NOT NULL,
    submitted_at        TEXT        NOT NULL,
    classification      TEXT,
    description         TEXT,
    verification_state  TEXT        NOT NULL DEFAULT 'pending',
    evidence_metadata   JSON        NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS ix_portal_evidence_tenant_id
    ON portal_evidence_submissions (tenant_id);
CREATE INDEX IF NOT EXISTS ix_portal_evidence_tenant_task
    ON portal_evidence_submissions (tenant_id, task_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_portal_evidence_sha256
    ON portal_evidence_submissions (tenant_id, task_id, sha256);
CREATE INDEX IF NOT EXISTS ix_portal_evidence_verification
    ON portal_evidence_submissions (tenant_id, verification_state);

ALTER TABLE portal_evidence_submissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE portal_evidence_submissions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS portal_evidence_submissions_tenant_isolation ON portal_evidence_submissions;
CREATE POLICY portal_evidence_submissions_tenant_isolation
    ON portal_evidence_submissions
    USING (
        current_setting('app.tenant_id', true) IS NOT NULL
        AND tenant_id = current_setting('app.tenant_id', true)
    );

-- ---------------------------------------------------------------------------
-- portal_remediation_audit_events (append-only)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS portal_remediation_audit_events (
    id              TEXT        PRIMARY KEY,
    tenant_id       TEXT        NOT NULL,
    task_id         TEXT        NOT NULL,
    event_type      TEXT        NOT NULL,
    actor           TEXT        NOT NULL,
    event_at        TEXT        NOT NULL,
    event_metadata  JSON        NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS ix_portal_audit_tenant_id
    ON portal_remediation_audit_events (tenant_id);
CREATE INDEX IF NOT EXISTS ix_portal_audit_tenant_task
    ON portal_remediation_audit_events (tenant_id, task_id);
CREATE INDEX IF NOT EXISTS ix_portal_audit_event_type
    ON portal_remediation_audit_events (tenant_id, event_type);
CREATE INDEX IF NOT EXISTS ix_portal_audit_event_at
    ON portal_remediation_audit_events (event_at);

ALTER TABLE portal_remediation_audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE portal_remediation_audit_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS portal_remediation_audit_events_tenant_isolation ON portal_remediation_audit_events;
CREATE POLICY portal_remediation_audit_events_tenant_isolation
    ON portal_remediation_audit_events
    USING (
        current_setting('app.tenant_id', true) IS NOT NULL
        AND tenant_id = current_setting('app.tenant_id', true)
    );

-- Append-only enforcement (uses shared function from migration 0013)
DROP TRIGGER IF EXISTS portal_audit_events_append_only_update
    ON portal_remediation_audit_events;
CREATE TRIGGER portal_audit_events_append_only_update
    BEFORE UPDATE ON portal_remediation_audit_events
    FOR EACH ROW EXECUTE FUNCTION append_only_guard();

DROP TRIGGER IF EXISTS portal_audit_events_append_only_delete
    ON portal_remediation_audit_events;
CREATE TRIGGER portal_audit_events_append_only_delete
    BEFORE DELETE ON portal_remediation_audit_events
    FOR EACH ROW EXECUTE FUNCTION append_only_guard();

REVOKE TRUNCATE ON portal_remediation_audit_events FROM PUBLIC;
