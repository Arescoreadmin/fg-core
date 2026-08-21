-- 0179_fg_principals
-- PR-AUTH-001: introduce fg_principals as the canonical cross-tenant human
-- principal table. Separates identity (who you are) from authorization (what
-- you may do within a tenant). Authorization stays in tenant_users (Membership).
--
-- No RLS: fg_principals is not tenant-scoped. Row-level isolation is enforced
-- through tenant_users memberships, not here.
-- Access is controlled at the application layer (platform_admin or
-- platform.identity.resolve capability required).
--
-- Rollback: DROP TABLE fg_principals;  (safe — no FK dependencies until 0181)

CREATE TABLE IF NOT EXISTS fg_principals (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    display_name      TEXT,
    primary_email     TEXT,
    principal_type    TEXT        NOT NULL DEFAULT 'human'
                                  CHECK (principal_type IN ('human')),
    lifecycle_state   TEXT        NOT NULL DEFAULT 'active'
                                  CHECK (lifecycle_state IN ('active', 'suspended', 'deactivated')),
    mfa_verified      BOOLEAN     NOT NULL DEFAULT FALSE,
    authority_version BIGINT      NOT NULL DEFAULT 1,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_fg_principals_lifecycle
    ON fg_principals (lifecycle_state);

CREATE INDEX IF NOT EXISTS ix_fg_principals_primary_email
    ON fg_principals (primary_email)
    WHERE primary_email IS NOT NULL;
