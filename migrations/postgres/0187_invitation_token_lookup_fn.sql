-- Migration 0187: Security-definer function for cross-tenant invitation token lookup.
--
-- tenant_invitations has FORCE ROW LEVEL SECURITY with policy
--   tenant_id = current_setting('app.tenant_id', TRUE).
-- The acceptance token flow must look up an invitation by acceptance_token_hash
-- BEFORE the tenant_id is known (the hash is the only input). This function runs
-- with the definer's privileges (bypassing RLS) and returns only the minimal fields
-- needed to establish tenant context, after which the caller sets app.tenant_id and
-- re-queries within scope.
--
-- Rollback: DROP FUNCTION IF EXISTS get_invitation_by_token_hash(TEXT);

CREATE OR REPLACE FUNCTION get_invitation_by_token_hash(p_hash TEXT)
RETURNS TABLE(
    id                    TEXT,
    tenant_id             TEXT,
    email                 TEXT,
    normalized_email      TEXT,
    role                  TEXT,
    status                TEXT,
    expires_at            TIMESTAMPTZ,
    acceptance_token_hash TEXT
)
SECURITY DEFINER
STABLE
SET search_path = public
LANGUAGE SQL AS $$
    SELECT
        id,
        tenant_id,
        email,
        normalized_email,
        role,
        status,
        expires_at,
        acceptance_token_hash
    FROM tenant_invitations
    WHERE acceptance_token_hash = p_hash
    LIMIT 1;
$$;
