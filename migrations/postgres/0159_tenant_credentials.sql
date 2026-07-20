-- Migration 0159: tenant credentials — R4.2 canonical credential persistence
--
-- Introduces two tables for the R4 Credential Authority.  No application
-- behaviour changes here — this migration is schema-only.  The authority
-- service (api/credential_authority.py) lands in R4.3.
--
-- credential_slots
--   One row per (tenant_id, credential_type, credential_slot) tuple.
--   Owns current_generation and rotation_policy for the slot.
--   Rotation uses a conditional UPDATE on this row (same rowcount=0
--   concurrency guard as R3 tenant_lifecycle_transitions) — so concurrent
--   rotation attempts serialise without an advisory lock.
--
-- tenant_credentials
--   One row per credential generation.  Slot + generation together identify
--   a unique credential within a tenant.
--
--   lookup_fingerprint: HMAC-SHA256(secret_part, pepper).  Indexed for fast
--     candidate lookup.  Not a secret — deterministic and storable.
--   secret_hash: Argon2id hash of the secret.  The verification proof.
--   secret_prefix: first 8 chars of key_lookup hex.  Display-only; never
--     used as a lookup key.
--   record_hash: SHA-256 of immutable fields — tamper-detection fingerprint,
--     same pattern as transition_hash in tenant_lifecycle_transitions.
--
-- Expiration semantics (single expires_at field):
--   pending  → expires_at is the activation deadline (short TTL)
--   active   → expires_at is the validity deadline (NULL = no expiry)
--   terminal → expires_at is historical metadata only
--
-- RLS: both tables are tenant-scoped (tenant_id is a FK scope boundary, not
--   the PK).  The expiration sweep in expire_credentials() must SET LOCAL
--   app.tenant_id per tenant, or run under a BYPASSRLS role.
--
-- Existing keys remain in api_keys throughout R4.7 dual-read.  The api_keys
--   table is not modified by this migration.

-- ── credential_slots ───────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS credential_slots (
    tenant_id           VARCHAR(128)    NOT NULL REFERENCES tenants(tenant_id),
    credential_type     VARCHAR(64)     NOT NULL,
    credential_slot     VARCHAR(128)    NOT NULL,
    current_generation  INTEGER         NOT NULL DEFAULT 0,
    rotation_policy     VARCHAR(32)     NOT NULL DEFAULT 'immediate'
        CONSTRAINT credential_slots_rotation_policy_valid
        CHECK (rotation_policy IN ('immediate', 'bounded_overlap')),
    max_overlap_count   INTEGER         NOT NULL DEFAULT 1
        CONSTRAINT credential_slots_max_overlap_count_valid
        CHECK (max_overlap_count BETWEEN 1 AND 2),
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ     NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant_id, credential_type, credential_slot)
);

ALTER TABLE credential_slots ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS credential_slots_tenant_isolation ON credential_slots;
CREATE POLICY credential_slots_tenant_isolation
    ON credential_slots USING (tenant_id = current_setting('app.tenant_id', true));

-- ── tenant_credentials ─────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS tenant_credentials (
    credential_id           UUID            NOT NULL DEFAULT gen_random_uuid(),
    tenant_id               VARCHAR(128)    NOT NULL REFERENCES tenants(tenant_id),
    credential_type         VARCHAR(64)     NOT NULL,
    credential_slot         VARCHAR(128)    NOT NULL,
    generation              INTEGER         NOT NULL DEFAULT 1,

    -- Lookup and verification material
    lookup_fingerprint      VARCHAR(64)     NOT NULL,
    lookup_key_version      INTEGER         NOT NULL DEFAULT 1,
    secret_prefix           VARCHAR(16)     NOT NULL,
    secret_hash             TEXT            NOT NULL,
    hash_algorithm          VARCHAR(32)     NOT NULL DEFAULT 'argon2id',
    hash_params             JSONB           NOT NULL,

    -- Lifecycle
    status                  VARCHAR(16)     NOT NULL DEFAULT 'pending'
        CONSTRAINT tenant_credentials_status_valid
        CHECK (status IN ('pending', 'active', 'rotated', 'revoked', 'expired')),
    expires_at              TIMESTAMPTZ,
    issued_at               TIMESTAMPTZ     NOT NULL DEFAULT now(),
    activated_at            TIMESTAMPTZ,
    rotated_at              TIMESTAMPTZ,
    revoked_at              TIMESTAMPTZ,
    replaced_by_credential_id UUID REFERENCES tenant_credentials(credential_id),

    -- Provenance
    created_by_actor_id     VARCHAR(256),
    request_id              VARCHAR(128),
    idempotency_key         VARCHAR(256),

    -- Usage metadata (best-effort; never used for authorization)
    last_used_at            TIMESTAMPTZ,
    approximate_use_count   INTEGER         NOT NULL DEFAULT 0,

    -- Policy and typed metadata
    scopes_csv              TEXT,
    metadata                JSONB,

    -- Tamper evidence (same pattern as transition_hash in R3)
    schema_version          INTEGER         NOT NULL DEFAULT 1,
    record_hash             VARCHAR(64),

    PRIMARY KEY (credential_id),
    FOREIGN KEY (tenant_id, credential_type, credential_slot)
        REFERENCES credential_slots(tenant_id, credential_type, credential_slot)
);

ALTER TABLE tenant_credentials ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_credentials_tenant_isolation ON tenant_credentials;
CREATE POLICY tenant_credentials_tenant_isolation
    ON tenant_credentials USING (tenant_id = current_setting('app.tenant_id', true));

-- ── indexes ────────────────────────────────────────────────────────────────

-- Primary validation lookup: fingerprint narrows candidates, hash verifies.
CREATE INDEX IF NOT EXISTS ix_tc_lookup_fingerprint
    ON tenant_credentials (lookup_fingerprint);

-- Unique generation per slot — enforced here and by authority logic.
CREATE UNIQUE INDEX IF NOT EXISTS ix_tc_slot_generation
    ON tenant_credentials (tenant_id, credential_type, credential_slot, generation);

-- Admin listing by tenant and status.
CREATE INDEX IF NOT EXISTS ix_tc_tenant_status
    ON tenant_credentials (tenant_id, status);

-- Expiration sweep: only active/pending rows have meaningful expires_at.
CREATE INDEX IF NOT EXISTS ix_tc_expires_at
    ON tenant_credentials (expires_at)
    WHERE status IN ('pending', 'active');

-- Idempotency check scoped to tenant — same pattern as R3.
-- A key used by tenant-A cannot replay as a no-op against tenant-B.
CREATE UNIQUE INDEX IF NOT EXISTS ix_tc_idempotency_key
    ON tenant_credentials (tenant_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;
