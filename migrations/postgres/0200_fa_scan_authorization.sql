-- Migration 0200: L14-SCAN-SAFETY-001 — per-engagement authorized scan scope and emergency stops
--
-- Adds:
--   fa_scan_authorizations  — durable per-engagement authorized target scope with lifecycle
--   fa_scan_emergency_stops — platform/tenant/engagement-scoped emergency halt records
--   cancel_requested_at, cancelled_at columns to fa_scan_jobs
--
-- Design notes:
--   - fa_scan_authorizations owns the approved target list (JSONB). Scans against targets
--     NOT present in the active authorization are denied fail-closed.
--   - fa_scan_emergency_stops provides a durable kill-switch at platform, tenant, or
--     engagement scope. is_active=TRUE blocks all new scan dispatch in scope.
--   - Cancellation columns on fa_scan_jobs complete the state machine:
--     queued -> cancel_requested -> cancelled | running -> cancel_requested -> cancelled
--   - No existing column is modified; all changes are additive.

-- ---------------------------------------------------------------------------
-- Authorized scan scope
-- ---------------------------------------------------------------------------

CREATE TABLE fa_scan_authorizations (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           TEXT NOT NULL,
    engagement_id       VARCHAR(64) NOT NULL REFERENCES fa_engagements(id) ON DELETE CASCADE,

    -- Authorization evidence (reference to external signed document or receipt)
    authorization_ref   TEXT NOT NULL,
    authorization_type  TEXT NOT NULL DEFAULT 'rules_of_engagement',

    -- Target scope (JSON array of approved targets)
    -- Each entry: {"target": "example.com", "type": "fqdn|ipv4|ipv6|cidr",
    --              "operations": ["network_scan", "web_headers", "dns_email"],
    --              "allow_subdomains": false}
    approved_targets    JSONB NOT NULL DEFAULT '[]',

    -- Lifecycle
    status              TEXT NOT NULL DEFAULT 'draft',
    approved_by         TEXT,
    approved_at         TIMESTAMPTZ,
    effective_from      TIMESTAMPTZ,
    expires_at          TIMESTAMPTZ NOT NULL,
    revoked_at          TIMESTAMPTZ,
    revocation_reason   TEXT,

    -- Optimistic locking and audit
    version             INTEGER NOT NULL DEFAULT 1,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX fa_scan_auth_engagement_idx ON fa_scan_authorizations(tenant_id, engagement_id, status);
CREATE INDEX fa_scan_auth_active_idx ON fa_scan_authorizations(engagement_id, status, effective_from, expires_at)
    WHERE status = 'active';

-- ---------------------------------------------------------------------------
-- Emergency stop table (platform-level kill switch)
-- ---------------------------------------------------------------------------

CREATE TABLE fa_scan_emergency_stops (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scope           TEXT NOT NULL,   -- 'platform' | 'tenant:{id}' | 'engagement:{id}'
    activated_by    TEXT NOT NULL,
    reason          TEXT NOT NULL,
    activated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    cleared_at      TIMESTAMPTZ,
    cleared_by      TEXT,
    is_active       BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE INDEX fa_scan_emergency_active_idx ON fa_scan_emergency_stops(scope, is_active)
    WHERE is_active = TRUE;

-- ---------------------------------------------------------------------------
-- Cancellation columns on fa_scan_jobs
-- ---------------------------------------------------------------------------

ALTER TABLE fa_scan_jobs
    ADD COLUMN IF NOT EXISTS cancel_requested_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS cancelled_at         TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS cancellation_reason  TEXT,
    ADD COLUMN IF NOT EXISTS cancelled_by         TEXT;

-- Extend the status CHECK constraint from migration 0079 to include cancellation
-- states. The original constraint only allowed queued/running/complete/failed.
ALTER TABLE fa_scan_jobs
    DROP CONSTRAINT IF EXISTS fa_scan_jobs_status_check;

ALTER TABLE fa_scan_jobs
    ADD CONSTRAINT fa_scan_jobs_status_check
    CHECK (status IN ('queued', 'running', 'complete', 'failed', 'cancel_requested', 'cancelled'));
