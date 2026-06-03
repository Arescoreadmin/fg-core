-- C7: Portal Grant Model
-- Replaces plaintext client_access_code with hashed, expiring, revocable,
-- engagement-bound portal grants.
--
-- Three new tables with Postgres RLS:
--   portal_grants              — one hashed grant per (tenant, client, engagement)
--   portal_grant_audit_events  — append-only audit trail (INSERT+SELECT RLS only)
--   portal_grant_sessions      — server-side session records (8-hour TTL)

-- ---------------------------------------------------------------------------
-- portal_grants
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS portal_grants (
    id               VARCHAR(64)  PRIMARY KEY,
    tenant_id        VARCHAR(255) NOT NULL,
    client_id        VARCHAR(255) NOT NULL,
    engagement_id    VARCHAR(64)  NOT NULL,
    grant_type       VARCHAR(64)  NOT NULL DEFAULT 'client_portal',
    grant_hash       TEXT         NOT NULL,   -- Argon2id hash of raw secret; never plaintext
    created_by       VARCHAR(255) NOT NULL,
    created_at       VARCHAR(64)  NOT NULL,
    expires_at       VARCHAR(64)  NOT NULL,   -- default 14 days from created_at
    last_used_at     VARCHAR(64),
    revoked_at       VARCHAR(64),
    revoked_by       VARCHAR(255),
    status           VARCHAR(32)  NOT NULL DEFAULT 'active',  -- active | revoked
    rotation_counter INTEGER      NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS ix_portal_grants_tenant_client
    ON portal_grants (tenant_id, client_id);
CREATE INDEX IF NOT EXISTS ix_portal_grants_tenant_engagement
    ON portal_grants (tenant_id, engagement_id);
CREATE INDEX IF NOT EXISTS ix_portal_grants_tenant_status
    ON portal_grants (tenant_id, status);

ALTER TABLE portal_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE portal_grants FORCE ROW LEVEL SECURITY;

CREATE POLICY portal_grants_tenant_isolation ON portal_grants
    USING (tenant_id = current_setting('app.tenant_id', TRUE));

-- ---------------------------------------------------------------------------
-- portal_grant_audit_events  (append-only)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS portal_grant_audit_events (
    id            VARCHAR(64)  PRIMARY KEY,
    tenant_id     VARCHAR(255) NOT NULL,
    grant_id      VARCHAR(64),
    client_id     VARCHAR(255),
    engagement_id VARCHAR(64),
    event_type    VARCHAR(64)  NOT NULL,  -- grant.created|used|rotated|revoked|expired|denied
    actor_id      VARCHAR(255),
    ip_address    VARCHAR(64),
    user_agent    VARCHAR(512),
    reason        TEXT,
    created_at    VARCHAR(64)  NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_portal_grant_audit_tenant_created
    ON portal_grant_audit_events (tenant_id, created_at);
CREATE INDEX IF NOT EXISTS ix_portal_grant_audit_grant_id
    ON portal_grant_audit_events (grant_id);

ALTER TABLE portal_grant_audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE portal_grant_audit_events FORCE ROW LEVEL SECURITY;

-- Append-only: SELECT and INSERT only — no UPDATE or DELETE policy
CREATE POLICY portal_grant_audit_select ON portal_grant_audit_events
    FOR SELECT
    USING (tenant_id = current_setting('app.tenant_id', TRUE));

CREATE POLICY portal_grant_audit_insert ON portal_grant_audit_events
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.tenant_id', TRUE));

-- ---------------------------------------------------------------------------
-- portal_grant_sessions
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS portal_grant_sessions (
    id            VARCHAR(128) PRIMARY KEY,   -- 64-char hex opaque session token
    tenant_id     VARCHAR(255) NOT NULL,
    client_id     VARCHAR(255) NOT NULL,
    auth_grant_id VARCHAR(64)  NOT NULL,       -- which grant was used for this authentication
    created_at    VARCHAR(64)  NOT NULL,
    expires_at    VARCHAR(64)  NOT NULL,       -- 8-hour default
    last_seen_at  VARCHAR(64),
    revoked_at    VARCHAR(64),
    ip_address    VARCHAR(64),
    user_agent    VARCHAR(512)
);

CREATE INDEX IF NOT EXISTS ix_portal_grant_sessions_tenant_expires
    ON portal_grant_sessions (tenant_id, expires_at);
CREATE INDEX IF NOT EXISTS ix_portal_grant_sessions_grant
    ON portal_grant_sessions (auth_grant_id);

ALTER TABLE portal_grant_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE portal_grant_sessions FORCE ROW LEVEL SECURITY;

CREATE POLICY portal_grant_sessions_tenant_isolation ON portal_grant_sessions
    USING (tenant_id = current_setting('app.tenant_id', TRUE));
