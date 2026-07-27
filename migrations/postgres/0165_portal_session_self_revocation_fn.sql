-- Migration 0165: portal session self-revocation SECURITY DEFINER function
--
-- Problem
-- -------
-- portal_user_sessions has RLS enabled:
--   USING (tenant_id = current_setting('app.tenant_id', true))
--
-- The self-revocation path (DELETE /portal/named-sessions/self, browser logout)
-- receives only the raw pnu1. bearer token — the tenant_id is unknown at call
-- time. The unscoped DB session has no app.tenant_id set, so the RLS policy hides
-- every row and UPDATE ... WHERE token_fingerprint = :fp returns 0 rows, silently
-- leaving the session active for its remaining Core-side lifetime.
--
-- Solution
-- --------
-- A narrow SECURITY DEFINER function runs as the function owner (table owner),
-- which bypasses RLS (no FORCE ROW LEVEL SECURITY on portal_user_sessions).
-- It performs the UPDATE atomically and returns the resolved tenant_id and
-- portal_user_id so the caller can set app.tenant_id before emitting the audit
-- event (portal_user_audit_events also has RLS).
--
-- The function is intentionally minimal: one table, one WHERE predicate, no
-- joins, no reads of other tables.  The SECURITY DEFINER privilege is bounded
-- to this single operation by SET search_path = public (prevents schema-injection
-- privilege escalation) and by only operating on the fingerprint key.

CREATE OR REPLACE FUNCTION revoke_portal_session_by_fingerprint(p_fingerprint TEXT)
RETURNS TABLE(
    session_id      UUID,
    tenant_id       TEXT,
    portal_user_id  UUID
)
SECURITY DEFINER
SET search_path = public
LANGUAGE plpgsql
VOLATILE
AS $$
BEGIN
    RETURN QUERY
        UPDATE portal_user_sessions
        SET    status     = 'revoked',
               revoked_at = now()
        WHERE  token_fingerprint = p_fingerprint
          AND  status            = 'active'
        RETURNING
               id                 AS session_id,
               tenant_id::TEXT    AS tenant_id,
               portal_user_id     AS portal_user_id;
END;
$$;

COMMENT ON FUNCTION revoke_portal_session_by_fingerprint(TEXT) IS
'Atomically revoke an active portal_user_sessions row by HMAC fingerprint.
Runs SECURITY DEFINER to bypass the tenant-scoped RLS policy, which is
required because self-revocation (browser logout) has no prior tenant
context — the fingerprint IS the credential. Returns the resolved tenant_id
so the caller can set app.tenant_id before writing the audit event.
Never returns rows for unknown, already-revoked, or expired sessions.';
