-- Migration 0195: Security-definer function for cross-tenant principal-to-tenant resolution.
--
-- tenant_users has FORCE ROW LEVEL SECURITY with policy
--   tenant_id = current_setting('app.tenant_id', TRUE).
-- The Console BFF JWT callback must resolve tenant_id from principal_id BEFORE the
-- tenant is known (that is the whole point — resolving it). A context-free SELECT
-- against tenant_users sees zero rows; this function runs with the definer's
-- privileges, bypassing RLS, and returns only the three fields needed to populate
-- token.tenantId. The caller (get_principal_tenant_binding) enforces internal-token
-- auth; this function performs no authentication of its own.
--
-- Rollback: DROP FUNCTION IF EXISTS resolve_principal_tenant(TEXT);

CREATE OR REPLACE FUNCTION resolve_principal_tenant(p_principal_id TEXT)
RETURNS TABLE(
    membership_id TEXT,
    tenant_id     TEXT,
    role          TEXT
)
SECURITY DEFINER
STABLE
SET search_path = public
LANGUAGE SQL AS $$
    SELECT
        id         AS membership_id,
        tenant_id,
        role
    FROM tenant_users
    WHERE principal_id            = p_principal_id
      AND identity_binding_status = 'bound'
      AND active IS TRUE;
$$;
