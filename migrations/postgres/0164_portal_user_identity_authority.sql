-- Migration 0164: portal_user_identity_authority — Portal Named-User Enrollment
--
-- Introduces five tables for the Portal Named-User identity population.
-- These tables are DISTINCT from tenant_users / workforce identity — they
-- represent external client-facing humans accessing the portal.
--
-- Tables (created in dependency order):
--   portal_users                 — OIDC-backed identity records
--   portal_user_invitations      — invitation tokens (fingerprint-only, never raw)
--   portal_user_memberships      — role grants per (user, engagement or tenant)
--   portal_user_sessions         — session tokens (fingerprint-only, never raw)
--   portal_user_audit_events     — append-only audit log
--
-- Security notes:
--   token_fingerprint is HMAC-SHA256(raw_token_hex, pepper).  Indexed for fast
--   lookup.  The raw token is never stored.
--   token_prefix is the first 8 chars of the raw hex part — display only.
--   RLS: all tables use tenant_id = current_setting('app.tenant_id', true).
--   Callers must issue SELECT pg_catalog.set_config('app.tenant_id', :tid, true)
--   (not SET LOCAL) due to psycopg3 bound-param restrictions.

BEGIN;

-- ── portal_users ──────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS portal_users (
    id              UUID            NOT NULL DEFAULT gen_random_uuid(),
    tenant_id       VARCHAR(128)    NOT NULL REFERENCES tenants(tenant_id),
    oidc_provider   VARCHAR(64)     NOT NULL,
    oidc_issuer     TEXT            NOT NULL,
    oidc_subject    TEXT            NOT NULL,
    email           TEXT            NOT NULL,
    display_name    TEXT,
    status          VARCHAR(32)     NOT NULL DEFAULT 'active'
        CONSTRAINT portal_users_status_valid
        CHECK (status IN ('active', 'suspended', 'deactivated')),
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ     NOT NULL DEFAULT now(),

    PRIMARY KEY (id),
    CONSTRAINT portal_users_oidc_unique UNIQUE (tenant_id, oidc_issuer, oidc_subject)
);

ALTER TABLE portal_users ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS portal_users_tenant_isolation ON portal_users;
CREATE POLICY portal_users_tenant_isolation
    ON portal_users
    USING (tenant_id = current_setting('app.tenant_id', true));

CREATE INDEX IF NOT EXISTS ix_pu_tenant
    ON portal_users (tenant_id);

CREATE INDEX IF NOT EXISTS ix_pu_oidc
    ON portal_users (tenant_id, oidc_issuer, oidc_subject);

-- ── portal_user_invitations ───────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS portal_user_invitations (
    id                          UUID            NOT NULL DEFAULT gen_random_uuid(),
    tenant_id                   VARCHAR(128)    NOT NULL REFERENCES tenants(tenant_id),
    email                       TEXT            NOT NULL,
    portal_role                 VARCHAR(32)     NOT NULL DEFAULT 'viewer'
        CONSTRAINT portal_user_invitations_role_valid
        CHECK (portal_role IN ('assessor', 'viewer', 'evidence_submitter', 'trust_center_viewer')),
    engagement_id               TEXT,
    token_fingerprint           VARCHAR(64)     NOT NULL,
    token_prefix                VARCHAR(16)     NOT NULL,
    token_version               INT             NOT NULL DEFAULT 1,
    status                      VARCHAR(32)     NOT NULL DEFAULT 'pending'
        CONSTRAINT portal_user_invitations_status_valid
        CHECK (status IN ('pending', 'accepted', 'revoked', 'expired')),
    invited_by_actor_id         TEXT,
    request_id                  VARCHAR(128),
    idempotency_key             VARCHAR(256),
    issued_at                   TIMESTAMPTZ     NOT NULL DEFAULT now(),
    expires_at                  TIMESTAMPTZ     NOT NULL,
    accepted_at                 TIMESTAMPTZ,
    revoked_at                  TIMESTAMPTZ,
    accepted_by_portal_user_id  UUID            REFERENCES portal_users(id),
    created_at                  TIMESTAMPTZ     NOT NULL DEFAULT now(),

    PRIMARY KEY (id),
    CONSTRAINT portal_user_invitations_fingerprint_unique UNIQUE (token_fingerprint),
    CONSTRAINT portal_user_invitations_idempotency_unique UNIQUE (idempotency_key)
);

ALTER TABLE portal_user_invitations ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS portal_user_invitations_tenant_isolation ON portal_user_invitations;
CREATE POLICY portal_user_invitations_tenant_isolation
    ON portal_user_invitations
    USING (tenant_id = current_setting('app.tenant_id', true));

CREATE INDEX IF NOT EXISTS ix_pui_tenant
    ON portal_user_invitations (tenant_id);

CREATE INDEX IF NOT EXISTS ix_pui_fingerprint
    ON portal_user_invitations (token_fingerprint);

CREATE INDEX IF NOT EXISTS ix_pui_email
    ON portal_user_invitations (tenant_id, email);

CREATE INDEX IF NOT EXISTS ix_pui_status
    ON portal_user_invitations (tenant_id, status)
    WHERE status = 'pending';

-- ── portal_user_memberships ───────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS portal_user_memberships (
    id                  UUID            NOT NULL DEFAULT gen_random_uuid(),
    portal_user_id      UUID            NOT NULL REFERENCES portal_users(id),
    tenant_id           VARCHAR(128)    NOT NULL REFERENCES tenants(tenant_id),
    engagement_id       TEXT,
    portal_role         VARCHAR(32)     NOT NULL DEFAULT 'viewer'
        CONSTRAINT portal_user_memberships_role_valid
        CHECK (portal_role IN ('assessor', 'viewer', 'evidence_submitter', 'trust_center_viewer')),
    auth_version        BIGINT          NOT NULL DEFAULT 1,
    active              BOOLEAN         NOT NULL DEFAULT TRUE,
    granted_by_actor_id TEXT,
    invitation_id       UUID,
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT now(),
    deactivated_at      TIMESTAMPTZ,

    PRIMARY KEY (id),
    CONSTRAINT portal_user_memberships_engagement_unique
        UNIQUE (portal_user_id, engagement_id)
        DEFERRABLE INITIALLY DEFERRED
);

-- Partial unique index for engagement-scoped memberships (NULL is excluded from
-- standard UNIQUE constraint, so we cover non-null engagement_id explicitly).
CREATE UNIQUE INDEX IF NOT EXISTS ix_pum_user_engagement_unique
    ON portal_user_memberships (portal_user_id, engagement_id)
    WHERE engagement_id IS NOT NULL;

ALTER TABLE portal_user_memberships ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS portal_user_memberships_tenant_isolation ON portal_user_memberships;
CREATE POLICY portal_user_memberships_tenant_isolation
    ON portal_user_memberships
    USING (tenant_id = current_setting('app.tenant_id', true));

CREATE INDEX IF NOT EXISTS ix_pum_portal_user
    ON portal_user_memberships (portal_user_id);

CREATE INDEX IF NOT EXISTS ix_pum_tenant
    ON portal_user_memberships (tenant_id);

CREATE INDEX IF NOT EXISTS ix_pum_active
    ON portal_user_memberships (portal_user_id)
    WHERE active = TRUE;

-- ── portal_user_sessions ──────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS portal_user_sessions (
    id                      UUID            NOT NULL DEFAULT gen_random_uuid(),
    portal_user_id          UUID            NOT NULL REFERENCES portal_users(id),
    portal_membership_id    UUID            REFERENCES portal_user_memberships(id),
    tenant_id               VARCHAR(128)    NOT NULL REFERENCES tenants(tenant_id),
    token_fingerprint       VARCHAR(64)     NOT NULL,
    token_prefix            VARCHAR(16)     NOT NULL,
    token_version           INT             NOT NULL DEFAULT 1,
    session_type            VARCHAR(32)     NOT NULL DEFAULT 'named_user_v1',
    auth_version_snapshot   BIGINT          NOT NULL,
    status                  VARCHAR(32)     NOT NULL DEFAULT 'active'
        CONSTRAINT portal_user_sessions_status_valid
        CHECK (status IN ('active', 'revoked', 'expired')),
    issued_at               TIMESTAMPTZ     NOT NULL DEFAULT now(),
    expires_at              TIMESTAMPTZ     NOT NULL,
    last_validated_at       TIMESTAMPTZ,
    revoked_at              TIMESTAMPTZ,
    ip_address              VARCHAR(64),
    user_agent              VARCHAR(512),
    created_at              TIMESTAMPTZ     NOT NULL DEFAULT now(),

    PRIMARY KEY (id),
    CONSTRAINT portal_user_sessions_fingerprint_unique UNIQUE (token_fingerprint)
);

ALTER TABLE portal_user_sessions ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS portal_user_sessions_tenant_isolation ON portal_user_sessions;
CREATE POLICY portal_user_sessions_tenant_isolation
    ON portal_user_sessions
    USING (tenant_id = current_setting('app.tenant_id', true));

CREATE INDEX IF NOT EXISTS ix_pus_fingerprint
    ON portal_user_sessions (token_fingerprint);

CREATE INDEX IF NOT EXISTS ix_pus_user
    ON portal_user_sessions (portal_user_id);

CREATE INDEX IF NOT EXISTS ix_pus_membership
    ON portal_user_sessions (portal_membership_id)
    WHERE portal_membership_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS ix_pus_active
    ON portal_user_sessions (tenant_id)
    WHERE status = 'active';

-- ── portal_user_audit_events ──────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS portal_user_audit_events (
    event_id        VARCHAR(64)     NOT NULL,
    tenant_id       VARCHAR(128)    NOT NULL REFERENCES tenants(tenant_id),
    event_type      VARCHAR(64)     NOT NULL
        CONSTRAINT puae_event_type_valid CHECK (event_type IN (
            'portal_user_created',
            'portal_membership_created',
            'portal_membership_deactivated',
            'portal_invitation_issued',
            'portal_invitation_accepted',
            'portal_invitation_revoked',
            'portal_invitation_expired',
            'portal_session_created',
            'portal_session_validated',
            'portal_session_revoked',
            'portal_session_expired',
            'portal_session_rejected_version_mismatch'
        )),
    portal_user_id  UUID,
    actor_id        TEXT,
    request_id      VARCHAR(128),
    occurred_at     TEXT            NOT NULL,
    outcome         VARCHAR(16)     NOT NULL DEFAULT 'success'
        CONSTRAINT puae_outcome_valid CHECK (outcome IN ('success', 'failure', 'denied')),
    metadata        TEXT,
    schema_version  INT             NOT NULL DEFAULT 1,

    PRIMARY KEY (event_id)
);

ALTER TABLE portal_user_audit_events ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS portal_user_audit_events_tenant_isolation ON portal_user_audit_events;
CREATE POLICY portal_user_audit_events_tenant_isolation
    ON portal_user_audit_events
    FOR ALL
    USING (tenant_id = current_setting('app.tenant_id', true));

-- Append-only enforcement: prevent any UPDATE or DELETE on audit rows.
CREATE OR REPLACE FUNCTION puae_prevent_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION USING
        MESSAGE = 'portal_user_audit_events is append-only: '
                  || TG_OP || ' on event_id ' || COALESCE(OLD.event_id, '(null)') || ' is not permitted',
        ERRCODE = 'restrict_violation';
    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS puae_no_update_or_delete ON portal_user_audit_events;
CREATE TRIGGER puae_no_update_or_delete
    BEFORE UPDATE OR DELETE ON portal_user_audit_events
    FOR EACH ROW EXECUTE FUNCTION puae_prevent_mutation();

CREATE INDEX IF NOT EXISTS ix_puae_tenant_occurred
    ON portal_user_audit_events (tenant_id, occurred_at DESC);

CREATE INDEX IF NOT EXISTS ix_puae_user
    ON portal_user_audit_events (portal_user_id)
    WHERE portal_user_id IS NOT NULL;

COMMIT;
