-- 0185_workforce_membership_lifecycle
-- P-113.5: Workforce membership lifecycle state columns for tenant_users.
--
-- Adds explicit membership_lifecycle_state column distinguishing active/suspended/revoked,
-- plus metadata columns for suspension and revocation (reason, actor, timestamp).
-- The existing `active` bool continues to be FALSE for both suspended and revoked rows;
-- membership_lifecycle_state discriminates WHY it is inactive.
--
-- Rollback:
--   ALTER TABLE tenant_users
--     DROP COLUMN IF EXISTS membership_lifecycle_state,
--     DROP COLUMN IF EXISTS suspension_reason,
--     DROP COLUMN IF EXISTS suspended_by,
--     DROP COLUMN IF EXISTS suspended_at,
--     DROP COLUMN IF EXISTS revocation_reason,
--     DROP COLUMN IF EXISTS revoked_by,
--     DROP COLUMN IF EXISTS revoked_at;

ALTER TABLE tenant_users
    ADD COLUMN IF NOT EXISTS membership_lifecycle_state TEXT NOT NULL DEFAULT 'active'
        CHECK (membership_lifecycle_state IN ('active', 'suspended', 'revoked')),
    ADD COLUMN IF NOT EXISTS suspension_reason          TEXT,
    ADD COLUMN IF NOT EXISTS suspended_by              TEXT,
    ADD COLUMN IF NOT EXISTS suspended_at              TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS revocation_reason         TEXT,
    ADD COLUMN IF NOT EXISTS revoked_by                TEXT,
    ADD COLUMN IF NOT EXISTS revoked_at                TIMESTAMPTZ;

COMMENT ON COLUMN tenant_users.membership_lifecycle_state IS
    'Membership lifecycle state: active | suspended | revoked. Revoked is terminal.';
COMMENT ON COLUMN tenant_users.revocation_reason IS
    'Required when membership_lifecycle_state = revoked. Must not contain secret material.';
