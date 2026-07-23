-- migrations/postgres/0163_agent_device_credential_authority.sql
--
-- R4.10 — Agent and Device Credential Authority migration.
--
-- Copies existing active agent_device_keys rows into tenant_credentials as
-- legacy sentinel records so every active agent credential has a canonical
-- credential_id before the transition window closes.
--
-- SENTINEL DESIGN (mirrors 0162_connector_credential_authority.sql):
--   credential_slot    = 'legacy:device:{device_id}:{id}'
--   lookup_fingerprint = 'legacy:{id}'
--
-- A real HMAC-SHA256 fingerprint is a 64-char lowercase hex string (a-f 0-9).
-- The 'legacy:' prefix can never be a valid HMAC output, so sentinel rows are
-- completely invisible to canonical indexed validation. validate_credential()
-- will never match a sentinel row through the fingerprint lookup.
--
-- Sentinel rows must NOT be used for authentication. The legacy agent auth path
-- handles authentication for existing agent device credentials during the
-- transition window.
--
-- IDEMPOTENCY:
--   ON CONFLICT (tenant_id, idempotency_key) WHERE idempotency_key IS NOT NULL
--   ensures safe re-runs. credential_id uses gen_random_uuid() — not
--   deterministic — so idempotency is keyed on 'legacy-agent-migration:{id}'
--   which is unique per agent_device_keys row.

BEGIN;

-- Step 1: insert credential_slots rows for each active agent device key.
INSERT INTO credential_slots (
    tenant_id,
    credential_type,
    credential_slot,
    current_generation,
    rotation_policy
)
SELECT DISTINCT
    adk.tenant_id,
    'agent_device',
    'legacy:device:' || adk.device_id || ':' || adk.id::text,
    1,
    'immediate'
FROM agent_device_keys adk
WHERE adk.enabled = true
ON CONFLICT DO NOTHING;

-- Step 2: insert sentinel tenant_credentials rows for each active agent device key.
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

    adk.tenant_id,

    'agent_device',

    -- Legacy-namespaced slot prevents collision with new canonical slots.
    -- Include row id to ensure uniqueness per agent_device_keys row.
    'legacy:device:' || adk.device_id || ':' || adk.id::text,

    1,  -- generation (sentinel rows are generation 1)

    -- Sentinel fingerprint — can never match a canonical HMAC-SHA256 fingerprint.
    -- 'legacy:' prefix is unreachable by HMAC-SHA256(secret, pepper).
    'legacy:' || adk.id::text,

    1,  -- lookup_key_version

    -- Display prefix derived from row id (display only, not a lookup key)
    substring(encode(sha256(adk.id::text::bytea), 'hex'), 1, 8),

    -- Sentinel hash: not a real Argon2id hash — sentinel rows are never used
    -- for canonical auth. A placeholder value prevents NOT NULL constraint violation.
    'sentinel-not-for-auth',

    'argon2id',

    -- Minimal hash params — sentinel rows are not used for verification.
    '{"time_cost": 3, "memory_cost": 65536, "parallelism": 4, "hash_len": 32, "salt_len": 16}'::jsonb,

    'active',

    NULL::timestamptz,  -- agent device keys have no built-in expiry in legacy schema

    adk.created_at,

    adk.created_at,  -- activated_at = created_at

    NULL::timestamptz,  -- rotated_at

    NULL::timestamptz,  -- revoked_at (only enabled=true rows selected)

    NULL,  -- created_by_actor_id not captured in agent_device_keys

    NULL,  -- request_id not captured in agent_device_keys

    -- Idempotency key ensures safe re-runs (unique per agent_device_keys row)
    'legacy-agent-migration:' || adk.id::text,

    'credential:use',

    jsonb_build_object(
        'device_id',      adk.device_id,
        'tenant_id',      adk.tenant_id,
        'key_prefix',     adk.key_prefix,
        'source',         'legacy_agent_device',
        'validation_mode', 'legacy_only'
    ),

    1,  -- schema_version

    -- Record hash (tamper detection): sha256 of immutable fields.
    encode(sha256((
        adk.tenant_id || E'\n' ||
        'agent_device' || E'\n' ||
        ('legacy:device:' || adk.device_id || ':' || adk.id::text) || E'\n' ||
        '1' || E'\n' ||
        adk.created_at::text
    )::bytea), 'hex')

FROM agent_device_keys adk
WHERE adk.enabled = true

ON CONFLICT (tenant_id, idempotency_key) WHERE idempotency_key IS NOT NULL DO NOTHING;

-- Extend status constraint to include suspension lifecycle state
ALTER TABLE tenant_credentials
    DROP CONSTRAINT IF EXISTS tenant_credentials_status_valid;
ALTER TABLE tenant_credentials
    ADD CONSTRAINT tenant_credentials_status_valid CHECK (
        status IN ('pending', 'active', 'rotated', 'revoked', 'expired', 'suspended')
    );

-- Extend event-type constraint to include suspend/resume audit events
ALTER TABLE tenant_credential_events
    DROP CONSTRAINT IF EXISTS tce_event_type_valid;
ALTER TABLE tenant_credential_events
    ADD CONSTRAINT tce_event_type_valid CHECK (
        event_type IN (
            'issued', 'rotated', 'revoked', 'expired',
            'validated', 'validation_failed', 'denied_tenant_state',
            'suspended', 'resumed'
        )
    );

COMMIT;
