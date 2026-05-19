-- 0060_msgraph_connector.sql
--
-- Creates the assessment_scan_sessions table for Microsoft Graph
-- field assessment scans.
--
-- Trust-but-verify design:
--   - manifest_json: declared before execution (client reviews and signs off)
--   - ack_token: HMAC token the client submits to authorise execution
--   - action_log_json: HMAC-chained log of executed actions (summaries, no raw data)
--   - findings_json: structured governance findings derived from scan
--   - methodology_md: human-readable leave-behind for client compliance records
--
-- No raw Graph API response bodies are stored — only counts, summaries, and
-- structured findings derived from the responses.

CREATE TABLE IF NOT EXISTS assessment_scan_sessions (
    id                TEXT PRIMARY KEY,
    assessment_id     TEXT NOT NULL,
    tenant_id         TEXT NOT NULL,
    status            TEXT NOT NULL DEFAULT 'pending_acknowledgment',
    manifest_id       TEXT NOT NULL,
    manifest_json     TEXT NOT NULL,
    ack_token         TEXT,
    acknowledged_at   TEXT,
    started_at        TEXT,
    completed_at      TEXT,
    action_log_json   TEXT,
    findings_json     TEXT,
    methodology_md    TEXT,
    error_detail      TEXT,
    created_at        TEXT NOT NULL DEFAULT (to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
);

CREATE INDEX IF NOT EXISTS ix_scan_sessions_assessment_id
    ON assessment_scan_sessions (assessment_id);

CREATE INDEX IF NOT EXISTS ix_scan_sessions_tenant_id
    ON assessment_scan_sessions (tenant_id);

-- Row-level security: tenants can only see their own scan sessions.
ALTER TABLE assessment_scan_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE assessment_scan_sessions FORCE ROW LEVEL SECURITY;

CREATE POLICY scan_sessions_tenant_isolation
    ON assessment_scan_sessions
    USING (tenant_id = current_setting('app.current_tenant_id', true));
