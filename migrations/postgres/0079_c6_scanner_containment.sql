-- Migration 0079: C6 Scanner Containment — verified targets, durable scan jobs,
-- and append-only scan audit events.
--
-- Tables:
--   fa_verified_targets   — pre-validated scan targets per engagement; storage_key
--                           for the target is confirmed safe before any scan runs.
--   fa_scan_jobs          — durable job records; survives process restart (H12 prep).
--   fa_scan_audit_events  — append-only audit trail for every scanner action.
--
-- All three tables carry RLS policies enforcing tenant_id isolation.
-- Append-only contract: fa_scan_audit_events has no UPDATE or DELETE policy.

-- ---------------------------------------------------------------------------
-- fa_verified_targets
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fa_verified_targets (
    id                  VARCHAR(64)   PRIMARY KEY,
    tenant_id           VARCHAR(255)  NOT NULL,
    engagement_id       VARCHAR(64)   NOT NULL,
    target              VARCHAR(2048) NOT NULL,
    target_type         VARCHAR(32)   NOT NULL
                            CHECK (target_type IN ('ip', 'hostname', 'cidr', 'url')),
    verification_method VARCHAR(64)   NOT NULL DEFAULT 'platform_validation',
    verification_status VARCHAR(32)   NOT NULL DEFAULT 'verified'
                            CHECK (verification_status IN ('verified', 'rejected', 'pending')),
    verified_at         VARCHAR(64)   NOT NULL,
    verified_by         VARCHAR(255)  NOT NULL,
    resolved_ips        TEXT,         -- JSON array of strings
    rejection_reason    VARCHAR(1024),
    rejection_code      VARCHAR(64),
    ownership_evidence  TEXT,         -- future: DNS TXT, domain verification
    created_at          VARCHAR(64)   NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_fa_vt_tenant_engagement
    ON fa_verified_targets (tenant_id, engagement_id);
CREATE INDEX IF NOT EXISTS ix_fa_vt_tenant_status
    ON fa_verified_targets (tenant_id, verification_status);

ALTER TABLE fa_verified_targets ENABLE ROW LEVEL SECURITY;
CREATE POLICY fa_verified_targets_tenant_isolation ON fa_verified_targets
    USING     (tenant_id = current_setting('app.tenant_id', TRUE))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', TRUE));

-- ---------------------------------------------------------------------------
-- fa_scan_jobs
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fa_scan_jobs (
    id                  VARCHAR(64)   PRIMARY KEY,
    tenant_id           VARCHAR(255)  NOT NULL,
    engagement_id       VARCHAR(64)   NOT NULL,
    verified_target_ids TEXT          NOT NULL,  -- JSON array of fa_verified_targets.id
    scanner_type        VARCHAR(64)   NOT NULL
                            CHECK (scanner_type IN
                                ('network_scan', 'web_headers', 'dns_email',
                                 'oauth_inventory', 'endpoint_inventory', 'msgraph')),
    status              VARCHAR(32)   NOT NULL DEFAULT 'queued'
                            CHECK (status IN ('queued', 'running', 'complete', 'failed')),
    attempt_count       INTEGER       NOT NULL DEFAULT 0,
    lease_owner         VARCHAR(255),            -- for future H12 worker assignment
    lease_expires_at    VARCHAR(64),             -- for future H12 lease expiry
    started_at          VARCHAR(64),
    completed_at        VARCHAR(64),
    failure_reason      TEXT,
    scan_result_id      VARCHAR(64),             -- set on completion
    actor               VARCHAR(255)  NOT NULL,
    created_at          VARCHAR(64)   NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_fa_scan_jobs_tenant_engagement
    ON fa_scan_jobs (tenant_id, engagement_id);
CREATE INDEX IF NOT EXISTS ix_fa_scan_jobs_tenant_status
    ON fa_scan_jobs (tenant_id, status);
CREATE INDEX IF NOT EXISTS ix_fa_scan_jobs_engagement_status
    ON fa_scan_jobs (engagement_id, status);

ALTER TABLE fa_scan_jobs ENABLE ROW LEVEL SECURITY;
CREATE POLICY fa_scan_jobs_tenant_isolation ON fa_scan_jobs
    USING     (tenant_id = current_setting('app.tenant_id', TRUE))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', TRUE));

-- ---------------------------------------------------------------------------
-- fa_scan_audit_events  (append-only)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fa_scan_audit_events (
    id              VARCHAR(64)   PRIMARY KEY,
    tenant_id       VARCHAR(255)  NOT NULL,
    engagement_id   VARCHAR(64)   NOT NULL,
    scan_job_id     VARCHAR(64),                 -- references fa_scan_jobs.id
    event_type      VARCHAR(64)   NOT NULL
                        CHECK (event_type IN (
                            'scan.initiated',
                            'scan.validation_rejected',
                            'scan.running',
                            'scan.completed',
                            'scan.failed',
                            'scan.rate_limited'
                        )),
    actor           VARCHAR(255)  NOT NULL,
    target          VARCHAR(2048),               -- the specific target (if single-target event)
    resolved_ips    TEXT,                        -- JSON array of strings
    scanner_type    VARCHAR(64),
    rejection_reason VARCHAR(1024),
    rejection_code  VARCHAR(64),
    scan_result_id  VARCHAR(64),
    payload_summary TEXT,                        -- JSON, lightweight; no sensitive data
    created_at      VARCHAR(64)   NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_fa_scan_audit_tenant_engagement
    ON fa_scan_audit_events (tenant_id, engagement_id);
CREATE INDEX IF NOT EXISTS ix_fa_scan_audit_tenant_event
    ON fa_scan_audit_events (tenant_id, event_type);
CREATE INDEX IF NOT EXISTS ix_fa_scan_audit_job
    ON fa_scan_audit_events (scan_job_id);

ALTER TABLE fa_scan_audit_events ENABLE ROW LEVEL SECURITY;
-- Append-only: SELECT and INSERT only. No UPDATE or DELETE policy granted.
CREATE POLICY fa_scan_audit_events_select ON fa_scan_audit_events
    FOR SELECT
    USING (tenant_id = current_setting('app.tenant_id', TRUE));
CREATE POLICY fa_scan_audit_events_insert ON fa_scan_audit_events
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.tenant_id', TRUE));
