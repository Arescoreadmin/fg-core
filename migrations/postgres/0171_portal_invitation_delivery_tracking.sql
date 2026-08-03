-- Migration 0171: portal invitation delivery tracking + session lookup function
--
-- Part A: adds delivery state columns to portal_user_invitations.
-- Part B: adds lookup_portal_session_by_fingerprint() SECURITY DEFINER function
--         for the /portal/named-users/me endpoint (same pattern as migration 0165).
--
-- Replay contract: ADD COLUMN IF NOT EXISTS, CREATE OR REPLACE FUNCTION throughout.

-- Part A: delivery tracking
ALTER TABLE portal_user_invitations
    ADD COLUMN IF NOT EXISTS delivery_state VARCHAR(32) NOT NULL DEFAULT 'pending'
        CONSTRAINT pui_delivery_state_valid
        CHECK (delivery_state IN ('pending', 'sent', 'failed', 'skipped')),
    ADD COLUMN IF NOT EXISTS delivery_error_code VARCHAR(128),
    ADD COLUMN IF NOT EXISTS email_message_id VARCHAR(256),
    ADD COLUMN IF NOT EXISTS last_delivery_attempt_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS ix_pui_delivery_state
    ON portal_user_invitations (tenant_id, delivery_state)
    WHERE delivery_state IN ('pending', 'failed');

-- Part B: session lookup SECURITY DEFINER function
-- Problem: /portal/named-users/me receives a pnu1. token with no prior tenant context.
-- portal_user_sessions has tenant-scoped RLS so a plain SELECT hides all rows.
-- Solution: narrow read-only SECURITY DEFINER function (same pattern as 0165).
-- Returns only active, non-expired rows. No joins — caller sets RLS after.

CREATE OR REPLACE FUNCTION lookup_portal_session_by_fingerprint(p_fingerprint TEXT)
RETURNS TABLE(
    session_id            UUID,
    tenant_id             TEXT,
    portal_user_id        UUID,
    portal_membership_id  UUID,
    auth_version_snapshot BIGINT,
    session_type          TEXT,
    status                TEXT,
    expires_at            TIMESTAMPTZ
)
SECURITY DEFINER
SET search_path = public
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    RETURN QUERY
        SELECT
            id::UUID                    AS session_id,
            tenant_id::TEXT             AS tenant_id,
            portal_user_id::UUID        AS portal_user_id,
            portal_membership_id::UUID  AS portal_membership_id,
            auth_version_snapshot::BIGINT AS auth_version_snapshot,
            session_type::TEXT          AS session_type,
            status::TEXT                AS status,
            expires_at                  AS expires_at
        FROM portal_user_sessions
        WHERE token_fingerprint = p_fingerprint
          AND status            = 'active'
          AND expires_at        > now();
END;
$$;

COMMENT ON FUNCTION lookup_portal_session_by_fingerprint(TEXT) IS
'Read-only SECURITY DEFINER lookup of an active portal_user_sessions row by
HMAC fingerprint. Bypasses tenant-scoped RLS so /portal/named-users/me can
resolve the tenant_id before setting app.tenant_id for subsequent queries.
Intentionally minimal: one table, one WHERE predicate, no joins.';
