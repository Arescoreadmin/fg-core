-- Migration 0170: SECURITY DEFINER function for unscoped credential fingerprint lookup
--
-- Problem
-- -------
-- portal_access, connector, and agent_device credentials embed no tenant ID in
-- their key format.  validate_credential() therefore cannot call
-- set_config('app.tenant_id', ...) before querying tenant_credentials.
-- With the fg_app runtime role (NOSUPERUSER, NOBYPASSRLS), the RLS policy
--   USING (tenant_id = current_setting('app.tenant_id', true))
-- filters every row when app.tenant_id is unset → 0 rows → CredentialNotFoundError
-- on every portal, connector, and agent_device authentication attempt.
--
-- Solution
-- --------
-- A narrow SECURITY DEFINER function runs as its owner (postgres superuser,
-- BYPASSRLS), performing the fingerprint lookup across all tenants.
-- The lookup_fingerprint is HMAC-SHA256(secret_part, pepper) — callers cannot
-- enumerate rows without possessing a valid issued secret.
-- Access is granted by _grant_runtime_role_access() in api/db.py, which issues
-- GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO <runtime_role> after each
-- migration run.  Do not hardcode the runtime role name here.
--
-- Column order
-- ------------
-- The RETURNS TABLE matches _RECORD_SELECT_TC + secret_hash + lifecycle_state
-- from api/credential_authority.py exactly.  validate_credential() accesses
-- results by positional index (r[0]..r[22]); the order must not change.
-- If tenant_credentials gains new columns that belong in _RECORD_SELECT, this
-- function must be updated in the same migration.

CREATE OR REPLACE FUNCTION public.credential_fingerprint_lookup(
    _fp    VARCHAR(64),
    _ctype VARCHAR(64)
)
RETURNS TABLE (
    credential_id             UUID,
    tenant_id                 VARCHAR(128),
    credential_type           VARCHAR(64),
    credential_slot           VARCHAR(128),
    generation                INTEGER,
    status                    VARCHAR(16),
    expires_at                TIMESTAMPTZ,
    issued_at                 TIMESTAMPTZ,
    activated_at              TIMESTAMPTZ,
    rotated_at                TIMESTAMPTZ,
    revoked_at                TIMESTAMPTZ,
    replaced_by_credential_id UUID,
    created_by_actor_id       VARCHAR(256),
    request_id                VARCHAR(128),
    idempotency_key           VARCHAR(256),
    last_used_at              TIMESTAMPTZ,
    approximate_use_count     INTEGER,
    scopes_csv                TEXT,
    metadata                  JSONB,
    schema_version            INTEGER,
    record_hash               VARCHAR(64),
    secret_hash               TEXT,
    lifecycle_state           VARCHAR(32)
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
STABLE
AS $$
    SELECT
        tc.credential_id,
        tc.tenant_id,
        tc.credential_type,
        tc.credential_slot,
        tc.generation,
        tc.status,
        tc.expires_at,
        tc.issued_at,
        tc.activated_at,
        tc.rotated_at,
        tc.revoked_at,
        tc.replaced_by_credential_id,
        tc.created_by_actor_id,
        tc.request_id,
        tc.idempotency_key,
        tc.last_used_at,
        tc.approximate_use_count,
        tc.scopes_csv,
        tc.metadata,
        tc.schema_version,
        tc.record_hash,
        tc.secret_hash,
        t.lifecycle_state
    FROM tenant_credentials tc
    JOIN tenants t ON t.tenant_id = tc.tenant_id
    WHERE tc.lookup_fingerprint = _fp
      AND tc.credential_type = _ctype;
$$;

COMMENT ON FUNCTION public.credential_fingerprint_lookup(VARCHAR(64), VARCHAR(64)) IS
'Cross-tenant credential lookup by fingerprint.  Runs SECURITY DEFINER to bypass
the tenant-scoped RLS policy on tenant_credentials, required for credential types
that do not embed tenant ID in their key format (portal_access, connector,
agent_device).  The fingerprint is HMAC-SHA256(secret_part, pepper) — row
enumeration is infeasible without a valid issued secret.  Column order matches
_RECORD_SELECT_TC + secret_hash + lifecycle_state in api/credential_authority.py;
do not reorder.  EXECUTE is granted to the runtime role by _grant_runtime_role_access()
in api/db.py (GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public) — not hardcoded here.';
