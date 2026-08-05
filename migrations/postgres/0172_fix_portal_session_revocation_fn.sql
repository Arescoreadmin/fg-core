-- Migration 0172: fix ambiguous column reference in revoke_portal_session_by_fingerprint
--
-- Problem (D-T6-007)
-- ------------------
-- In 0165, the RETURNING clause uses unqualified column references:
--
--     RETURNING
--         id                 AS session_id,
--         tenant_id::TEXT    AS tenant_id,
--         portal_user_id     AS portal_user_id;
--
-- PostgreSQL raises:
--     psycopg.errors.AmbiguousColumn: column reference "tenant_id" is ambiguous
--
-- because PL/pgSQL sees both the RETURNS TABLE column named tenant_id and the
-- portal_user_sessions table column named tenant_id as candidate matches for the
-- unqualified reference.  The function never executes; the BFF fails open (clears
-- the cookie anyway) but leaves the portal_user_sessions row active.  A replayed
-- pnu1. token would still authenticate against Core until the 14-day TTL expires.
--
-- Fix
-- ---
-- Table-qualify all three column references in the RETURNING clause so PostgreSQL
-- resolves each one unambiguously to the portal_user_sessions column.  All other
-- aspects of the function (SECURITY DEFINER, SET search_path = public, logic,
-- WHERE predicate, LANGUAGE, VOLATILE) are identical to 0165.

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
            portal_user_sessions.id                 AS session_id,
            portal_user_sessions.tenant_id::TEXT    AS tenant_id,
            portal_user_sessions.portal_user_id     AS portal_user_id;
END;
$$;

COMMENT ON FUNCTION revoke_portal_session_by_fingerprint(TEXT) IS
'Atomically revoke an active portal_user_sessions row by HMAC fingerprint.
Runs SECURITY DEFINER to bypass the tenant-scoped RLS policy, which is
required because self-revocation (browser logout) has no prior tenant
context — the fingerprint IS the credential. Returns the resolved tenant_id
so the caller can set app.tenant_id before writing the audit event.
Never returns rows for unknown, already-revoked, or expired sessions.
Fixed in 0172: RETURNING clause now uses fully table-qualified column
references to resolve the AmbiguousColumn error introduced in 0165.';
