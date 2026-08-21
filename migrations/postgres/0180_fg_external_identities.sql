-- 0180_fg_external_identities
-- PR-AUTH-001: introduce fg_external_identities as the canonical cross-tenant
-- external identity binding table. Holds the immutable (provider, provider_issuer,
-- provider_subject) triple and the FK to fg_principals.
--
-- This table takes over the global uniqueness constraint that currently lives on
-- tenant_users as uq_tenant_users_bound_identity. That constraint blocks multi-tenant
-- users and will be dropped in a later cleanup PR (post-PR-AUTH-003) once the backfill
-- is verified.
--
-- No RLS: fg_external_identities is not tenant-scoped.
--
-- Rollback: DROP TABLE fg_external_identities;  (safe — no callers until 0182 backfill)

CREATE TABLE IF NOT EXISTS fg_external_identities (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    principal_id     UUID        NOT NULL REFERENCES fg_principals(id),
    provider         TEXT        NOT NULL
                                 CHECK (provider IN ('auth0', 'entra', 'okta', 'saml', 'oidc_generic')),
    provider_issuer  TEXT        NOT NULL,
    provider_subject TEXT        NOT NULL,
    provider_email   TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at     TIMESTAMPTZ,
    CONSTRAINT uq_fg_external_identities_binding
        UNIQUE (provider, provider_issuer, provider_subject)
);

CREATE INDEX IF NOT EXISTS ix_fg_external_identities_principal
    ON fg_external_identities (principal_id);
