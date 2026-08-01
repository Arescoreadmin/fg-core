-- Migration 0169: tenant identity bindings
--
-- Records the binding between a FrostGate tenant and its identity provider
-- organization (Auth0 Organization in IA-v1). FrostGate is the system of record;
-- Auth0 is a projection. This table tracks provisioning state so failures are
-- recoverable and retryable without data loss.
--
-- Replay/rollback contract:
--   - Forward-only and replay-safe (IF NOT EXISTS throughout).
--   - No credential material is stored here.
--   - provisioning_state drives the retry gate; the tenant itself is not deleted
--     on provider failure.
--   - Introduced by IA-1 per ADR-IA-001.

CREATE TABLE IF NOT EXISTS tenant_identity_bindings (
    id                          UUID            NOT NULL DEFAULT gen_random_uuid(),
    tenant_id                   VARCHAR(128)    NOT NULL
        REFERENCES tenants(tenant_id),
    provider                    VARCHAR(64)     NOT NULL
        CONSTRAINT tib_provider_valid
        CHECK (provider IN ('auth0')),
    provider_org_id             VARCHAR(256),
    provider_org_name           VARCHAR(256),
    provisioning_state          VARCHAR(32)     NOT NULL DEFAULT 'pending'
        CONSTRAINT tib_provisioning_state_valid
        CHECK (provisioning_state IN (
            'pending', 'provisioning', 'active', 'failed',
            'suspended', 'deprovisioning', 'deprovisioned'
        )),
    idempotency_key             VARCHAR(256)    NOT NULL,
    last_sync_at                TIMESTAMPTZ,
    last_error_code             VARCHAR(64),
    last_error_message_redacted TEXT,
    version                     INTEGER         NOT NULL DEFAULT 1,
    created_at                  TIMESTAMPTZ     NOT NULL DEFAULT now(),
    updated_at                  TIMESTAMPTZ     NOT NULL DEFAULT now(),

    PRIMARY KEY (id)
);

-- One binding per tenant per provider
CREATE UNIQUE INDEX IF NOT EXISTS uq_tib_tenant_provider
    ON tenant_identity_bindings (tenant_id, provider);

-- One tenant per provider org (prevents duplicate org binding)
CREATE UNIQUE INDEX IF NOT EXISTS uq_tib_provider_org
    ON tenant_identity_bindings (provider, provider_org_id)
    WHERE provider_org_id IS NOT NULL;

-- Idempotency: same key cannot produce two bindings for the same provider
CREATE UNIQUE INDEX IF NOT EXISTS uq_tib_provider_idempotency
    ON tenant_identity_bindings (provider, idempotency_key);

CREATE INDEX IF NOT EXISTS ix_tib_tenant_id
    ON tenant_identity_bindings (tenant_id);

CREATE INDEX IF NOT EXISTS ix_tib_provisioning_state
    ON tenant_identity_bindings (provisioning_state);

ALTER TABLE tenant_identity_bindings ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_identity_bindings_tenant_isolation ON tenant_identity_bindings;
CREATE POLICY tenant_identity_bindings_tenant_isolation
    ON tenant_identity_bindings
    FOR ALL
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

-- ── tenant_identity_binding_events ──────────────────────────────────────────

CREATE TABLE IF NOT EXISTS tenant_identity_binding_events (
    event_id            UUID            NOT NULL DEFAULT gen_random_uuid(),
    event_type          VARCHAR(64)     NOT NULL
        CONSTRAINT tibe_event_type_valid CHECK (event_type IN (
            'org_provisioning_started',
            'org_provisioned',
            'org_provisioning_failed',
            'org_provisioning_retried',
            'org_suspended',
            'org_deprovisioned'
        )),
    binding_id          UUID            REFERENCES tenant_identity_bindings(id),
    tenant_id           VARCHAR(128)    REFERENCES tenants(tenant_id),
    provider            VARCHAR(64)     NOT NULL,
    provider_org_id     VARCHAR(256),
    actor_id            VARCHAR(256)    NOT NULL,
    request_id          VARCHAR(128),
    outcome             VARCHAR(16)     NOT NULL DEFAULT 'success'
        CONSTRAINT tibe_outcome_valid CHECK (outcome IN ('success', 'failure')),
    error_code          VARCHAR(64),
    occurred_at         TIMESTAMPTZ     NOT NULL DEFAULT now(),
    metadata            JSONB           NOT NULL DEFAULT '{}',
    schema_version      INTEGER         NOT NULL DEFAULT 1,

    PRIMARY KEY (event_id)
);

ALTER TABLE tenant_identity_binding_events ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tibe_tenant_isolation ON tenant_identity_binding_events;
CREATE POLICY tibe_tenant_isolation
    ON tenant_identity_binding_events
    FOR ALL
    USING (
        tenant_id IS NULL
        OR tenant_id = current_setting('app.tenant_id', true)
    )
    WITH CHECK (
        tenant_id IS NULL
        OR tenant_id = current_setting('app.tenant_id', true)
    );

CREATE OR REPLACE FUNCTION tibe_prevent_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION USING
        MESSAGE = 'tenant_identity_binding_events is append-only: '
                  || TG_OP || ' on event_id '
                  || COALESCE(OLD.event_id::TEXT, '(null)') || ' is not permitted',
        ERRCODE = 'restrict_violation';
    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS tibe_no_update_or_delete ON tenant_identity_binding_events;
CREATE TRIGGER tibe_no_update_or_delete
    BEFORE UPDATE OR DELETE ON tenant_identity_binding_events
    FOR EACH ROW EXECUTE FUNCTION tibe_prevent_mutation();

CREATE INDEX IF NOT EXISTS ix_tibe_binding_occurred
    ON tenant_identity_binding_events (binding_id, occurred_at DESC)
    WHERE binding_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS ix_tibe_tenant_occurred
    ON tenant_identity_binding_events (tenant_id, occurred_at DESC)
    WHERE tenant_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS ix_tibe_request_id
    ON tenant_identity_binding_events (request_id)
    WHERE request_id IS NOT NULL;

COMMENT ON TABLE tenant_identity_bindings IS
    'One record per (tenant_id, provider). FrostGate is authoritative; '
    'provider_org_id is a projection. provisioning_state drives retry gate. '
    'No credential material is stored. Introduced by IA-1 per ADR-IA-001.';

COMMENT ON TABLE tenant_identity_binding_events IS
    'Append-only audit events for identity binding lifecycle. '
    'No credential material or PII in event payload. '
    'Introduced by IA-1 per ADR-IA-001.';
