-- migrations/postgres/0162_connector_credential_authority.sql
--
-- R4.9b — Connector credential authority migration.
--
-- Copies existing active connectors_credentials rows into tenant_credentials as
-- legacy sentinel records so every active connector credential has a canonical
-- credential_id before the transition window closes.
--
-- SENTINEL DESIGN (mirrors 0161_portal_access_migration.sql):
--   credential_slot    = 'legacy:{connector_id}:{id}'
--   lookup_fingerprint = 'legacy:{id}'
--
-- A real HMAC-SHA256 fingerprint is a 64-char lowercase hex string (a-f 0-9).
-- The 'legacy:' prefix can never be a valid HMAC output, so sentinel rows are
-- completely invisible to canonical indexed validation. validate_credential()
-- will never match a sentinel row through the fingerprint lookup.
--
-- Sentinel rows must NOT be used for authentication. The load_connector_secret()
-- legacy fallback path handles authentication for existing connector credentials
-- during the transition window.
--
-- IDEMPOTENCY:
--   ON CONFLICT (tenant_id, idempotency_key) WHERE idempotency_key IS NOT NULL
--   ensures safe re-runs. credential_id uses gen_random_uuid() — not
--   deterministic — so idempotency is keyed on 'legacy-connector-migration:{id}'
--   which is unique per connectors_credentials row.

BEGIN;

-- Step 1: insert credential_slots rows for each active connector credential.
INSERT INTO credential_slots (
    tenant_id,
    credential_type,
    credential_slot,
    current_generation,
    rotation_policy
)
SELECT DISTINCT
    tenant_id,
    'connector',
    'legacy:' || connector_id || ':' || id::text,
    1,
    'immediate'
FROM connectors_credentials
WHERE revoked_at IS NULL
ON CONFLICT DO NOTHING;

-- Step 2: insert sentinel tenant_credentials rows for each active connector credential.
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

    'connector',

    -- Legacy-namespaced slot prevents collision with new canonical slots
    -- Include row id to ensure uniqueness per connectors_credentials row
    -- (prevents ix_tc_slot_generation violation when tenant has multiple
    -- credentials for the same connector_id)
    'legacy:' || connector_id || ':' || id::text,

    1,  -- generation (sentinel rows are generation 1)

    -- Sentinel fingerprint — can never match a canonical HMAC-SHA256 fingerprint.
    -- 'legacy:' prefix is unreachable by HMAC-SHA256(secret, pepper).
    'legacy:' || id::text,

    1,  -- lookup_key_version

    -- Display prefix derived from row id (display only, not a lookup key)
    substring(encode(sha256(id::text::bytea), 'hex'), 1, 8),

    -- Sentinel hash: not a real Argon2id hash — sentinel rows are never used
    -- for canonical auth. A placeholder value prevents NOT NULL constraint violation.
    'sentinel-not-for-auth',

    'argon2id',

    -- Minimal hash params — sentinel rows are not used for verification.
    '{"time_cost": 3, "memory_cost": 65536, "parallelism": 4, "hash_len": 32, "salt_len": 16}'::jsonb,

    -- Status: revoked if revoked_at is set, otherwise active
    CASE
        WHEN revoked_at IS NOT NULL THEN 'revoked'
        ELSE 'active'
    END,

    NULL::timestamptz,  -- connector credentials have no expiry (TTL=0)

    created_at,

    created_at,  -- activated_at = created_at (connector creds are immediately active)

    NULL::timestamptz,  -- rotated_at

    CASE WHEN revoked_at IS NOT NULL THEN revoked_at ELSE NULL END,

    NULL,  -- created_by_actor_id not captured in connectors_credentials

    NULL,  -- request_id not captured in connectors_credentials

    -- Idempotency key ensures safe re-runs (unique per connectors_credentials row)
    'legacy-connector-migration:' || id::text,

    'credential:use',

    jsonb_build_object(
        'connector_id',      connector_id,
        'tenant_id',         tenant_id,
        'credential_id',     credential_id,
        'auth_mode',         auth_mode,
        'source',            'legacy_connector',
        'validation_mode',   'legacy_only'
    ),

    1,  -- schema_version

    -- Record hash (tamper detection): sha256 of immutable fields.
    encode(sha256((
        tenant_id || E'\n' ||
        'connector' || E'\n' ||
        ('legacy:' || connector_id || ':' || id::text) || E'\n' ||
        '1' || E'\n' ||
        created_at::text
    )::bytea), 'hex')

FROM connectors_credentials
WHERE revoked_at IS NULL

ON CONFLICT (tenant_id, idempotency_key) WHERE idempotency_key IS NOT NULL DO NOTHING;

COMMIT;
