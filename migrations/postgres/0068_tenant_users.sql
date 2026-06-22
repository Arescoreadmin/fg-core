-- 0068: tenant_users — per-user identity registry within a tenant
-- Supports per-user AI query attribution and workforce intelligence.
-- Users are invited by the operator; they authenticate via invite token on first login.

CREATE TABLE IF NOT EXISTS tenant_users (
    id              TEXT PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    tenant_id       TEXT NOT NULL,
    email           TEXT NOT NULL,
    display_name    TEXT NOT NULL,
    role            TEXT NOT NULL DEFAULT 'user',   -- user | admin | auditor
    invite_token    TEXT UNIQUE,                    -- cleared on first login
    invite_expires_at TIMESTAMPTZ,
    active          BOOLEAN NOT NULL DEFAULT TRUE,
    last_active_at  TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, email)
);

CREATE INDEX IF NOT EXISTS ix_tenant_users_tenant_id  ON tenant_users (tenant_id);
CREATE INDEX IF NOT EXISTS ix_tenant_users_invite_token ON tenant_users (invite_token)
    WHERE invite_token IS NOT NULL;
