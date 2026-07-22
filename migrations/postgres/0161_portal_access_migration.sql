-- migrations/postgres/0161_portal_access_migration.sql
--
-- R4.9 — Portal access credential migration.
--
-- Copies existing portal_grants rows into tenant_credentials as legacy sentinel
-- records so the canonical credential_id exists for all grants (new and old)
-- before the transition window closes.
--
-- SENTINEL DESIGN (Option B from spec):
--   credential_slot  = 'legacy:{client_id}:{engagement_id}:{id}'
--   lookup_fingerprint = 'legacy:{id}'
--
-- A real HMAC-SHA256 fingerprint is a 64-char lowercase hex string (a-f 0-9).
-- The 'legacy:' prefix can never be a valid HMAC output, so sentinel rows are
-- completely invisible to canonical indexed validation.  validate_credential()
-- will never match a sentinel row through the fingerprint lookup.
--
-- Sentinel rows must NOT be used for authentication. The portal_grant_service
-- legacy fallback path (Argon2id scan against portal_grants) handles
-- authentication for existing grants during the transition window.
--
-- REMOVAL CONDITION:
--   Remove the _authenticate_legacy_portal_grant fallback in
--   services/portal_grant_service.py and drop the portal_grants table
--   after all pre-migration grants have expired.
--   Portal grant TTL = 14 days.
--   Removal target: deployment_date + 15 days.
--   Track in: ROADMAP.md R4.9 row, "Legacy fallback removal date" column.
--
-- IDEMPOTENCY:
--   ON CONFLICT (idempotency_key) on tenant_credentials ensures safe re-runs.
--   credential_id uses gen_random_uuid() — not deterministic — so idempotency
--   is keyed on 'legacy-migration:{id}' which is unique per portal_grants row.
--   ON CONFLICT DO NOTHING on credential_slots is likewise idempotent.

BEGIN;

-- Step 1: insert credential_slots rows for each legacy portal_grant.
-- tenant_credentials has a FK to credential_slots(tenant_id, credential_type, credential_slot).
INSERT INTO credential_slots (
    tenant_id,
    credential_type,
    credential_slot,
    current_generation,
    rotation_policy
)
SELECT DISTINCT
    tenant_id,
    'portal_access',
    'legacy:' || client_id || ':' || engagement_id || ':' || id,
    COALESCE(rotation_counter, 0) + 1,
    'immediate'
FROM portal_grants
ON CONFLICT DO NOTHING;

-- Step 2: insert sentinel tenant_credentials rows for each legacy portal_grant.
INSERT INTO tenant_credentials (
    credential_id,
    tenant_id,
    credential_type,
    credential_slot,
    generation,
    lookup_fingerprint,
    lookup_key_version,
    secret_prefix,
    secret_hash,
    hash_algorithm,
    hash_params,
    status,
    expires_at,
    issued_at,
    activated_at,
    rotated_at,
    revoked_at,
    created_by_actor_id,
    request_id,
    idempotency_key,
    scopes_csv,
    metadata,
    schema_version,
    record_hash
)
SELECT
    -- credential_id must be a valid UUID; gen_random_uuid() satisfies the column type.
    -- Idempotency is provided by the unique idempotency_key index, not by a
    -- deterministic credential_id.
    gen_random_uuid(),

    tenant_id,

    'portal_access',

    -- Option B: legacy-namespaced slot prevents collision with new canonical slots
    'legacy:' || client_id || ':' || engagement_id || ':' || id,

    -- Use rotation_counter + 1 as generation (generation is 1-indexed)
    COALESCE(rotation_counter, 0) + 1,

    -- Sentinel fingerprint — can never match a canonical HMAC-SHA256 fingerprint
    'legacy:' || id,

    1,  -- lookup_key_version

    -- Display prefix derived from grant id (display only, not a lookup key)
    substring(encode(sha256(id::bytea), 'hex'), 1, 8),

    -- Preserve existing Argon2id hash. Sentinel rows are not used for
    -- canonical auth, but keeping the real hash means the row is not fabricated.
    grant_hash,

    'argon2id',

    -- Params as stored by portal_grant_service (time_cost=3, memory=64MiB, parallelism=4)
    '{"time_cost": 3, "memory_cost": 65536, "parallelism": 4, "hash_len": 32, "salt_len": 16}'::jsonb,

    -- Map portal_grants status to canonical status
    CASE
        WHEN revoked_at IS NOT NULL                           THEN 'revoked'
        WHEN expires_at::timestamptz < now()                  THEN 'expired'
        ELSE 'active'
    END,

    expires_at::timestamptz,

    created_at::timestamptz,

    created_at::timestamptz,  -- activated_at = created_at (grants are immediately active)

    NULL::timestamptz,  -- rotated_at (rotation produces a new canonical credential)

    CASE WHEN revoked_at IS NOT NULL THEN revoked_at::timestamptz ELSE NULL END,

    created_by,

    NULL,   -- request_id not captured in portal_grants

    -- Idempotency key ensures safe re-runs (unique per portal_grants row)
    'legacy-migration:' || id,

    'credential:use',

    jsonb_build_object(
        'client_id',        client_id,
        'engagement_id',    engagement_id,
        'portal_grant_id',  id,
        'source',           'legacy_portal_grant',
        'validation_mode',  'legacy_fallback_only'
    ),

    1,  -- schema_version

    -- Record hash (tamper detection): sha256 of immutable fields.
    -- credential_id is excluded because it is non-deterministic (gen_random_uuid());
    -- idempotency_key already provides uniqueness per source row.
    encode(sha256((
        tenant_id || E'\n' ||
        'portal_access' || E'\n' ||
        ('legacy:' || client_id || ':' || engagement_id || ':' || id) || E'\n' ||
        (COALESCE(rotation_counter, 0) + 1)::text || E'\n' ||
        created_at
    )::bytea), 'hex')

FROM portal_grants

ON CONFLICT (tenant_id, idempotency_key) DO NOTHING;

COMMIT;
