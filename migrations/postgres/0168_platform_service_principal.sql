-- Migration 0168: canonical platform service principal
--
-- PR #586 adds the machine identity layer on top of PR #585's internal
-- platform authority. A platform service principal is the canonical
-- non-human, non-customer, non-portal machine identity used by FrostGate
-- platform workloads acting through the canonical internal platform authority.
--
-- Replay/rollback contract:
--   - Forward-only and replay-safe (IF NOT EXISTS throughout).
--   - No credential material is created in this SQL migration.
--     Application-level bootstrap (bootstrap_platform_service_principal)
--     owns credential issuance.
--   - No customer tenant lifecycle, billing, portal, assessment, report,
--     or artifact ownership is changed.
--   - The stable_key uniqueness index guarantees exactly one canonical
--     active platform service principal per authority+kind combination.

-- ── platform_service_principals ─────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS platform_service_principals (
    id                    UUID            NOT NULL DEFAULT gen_random_uuid(),
    stable_key            VARCHAR(128)    NOT NULL,
    display_name          TEXT            NOT NULL,
    authority_tenant_id   VARCHAR(128)    NOT NULL
        REFERENCES tenants(tenant_id),
    principal_kind        VARCHAR(32)     NOT NULL DEFAULT 'platform_service'
        CONSTRAINT psp_principal_kind_valid
        CHECK (principal_kind IN ('platform_service')),
    lifecycle_state       VARCHAR(32)     NOT NULL DEFAULT 'active'
        CONSTRAINT psp_lifecycle_state_valid
        CHECK (lifecycle_state IN ('active', 'suspended', 'revoked')),
    authority_version     INTEGER         NOT NULL DEFAULT 1,
    credential_slot       VARCHAR(128)    NOT NULL,
    credential_type       VARCHAR(64)     NOT NULL DEFAULT 'tenant_api_key',
    granted_permissions   TEXT            NOT NULL DEFAULT '[]',
    created_at            TIMESTAMPTZ     NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ     NOT NULL DEFAULT now(),
    activated_at          TIMESTAMPTZ,
    suspended_at          TIMESTAMPTZ,
    revoked_at            TIMESTAMPTZ,
    metadata              JSONB           NOT NULL DEFAULT '{}',
    schema_version        INTEGER         NOT NULL DEFAULT 1,

    PRIMARY KEY (id)
);

-- Identity continuity: one stable_key across ALL lifecycle states (non-partial).
-- A revoked canonical PSP is permanently terminal — the identity slot is exhausted.
-- Bootstrapping a new PSP with the same stable_key is not possible after revocation.
-- This prevents silent identity resurrection; recovery requires explicit operator action.
CREATE UNIQUE INDEX IF NOT EXISTS uq_psp_stable_key
    ON platform_service_principals (stable_key);

-- At most one non-revoked PSP per authority tenant + principal_kind.
-- Prevents duplicate canonical active principals even under concurrent bootstrap.
CREATE UNIQUE INDEX IF NOT EXISTS uq_psp_authority_kind_active
    ON platform_service_principals (authority_tenant_id, principal_kind)
    WHERE lifecycle_state != 'revoked';

CREATE INDEX IF NOT EXISTS ix_psp_authority_tenant
    ON platform_service_principals (authority_tenant_id);

ALTER TABLE platform_service_principals ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS platform_service_principals_tenant_isolation ON platform_service_principals;
CREATE POLICY platform_service_principals_tenant_isolation
    ON platform_service_principals
    FOR ALL
    USING (
        authority_tenant_id = current_setting('app.tenant_id', true)
    )
    WITH CHECK (
        authority_tenant_id = current_setting('app.tenant_id', true)
    );

-- ── platform_service_principal_events ───────────────────────────────────────

CREATE TABLE IF NOT EXISTS platform_service_principal_events (
    event_id              UUID            NOT NULL DEFAULT gen_random_uuid(),
    event_type            VARCHAR(64)     NOT NULL
        CONSTRAINT pspe_event_type_valid CHECK (event_type IN (
            'bootstrap_created',
            'bootstrap_reused',
            'bootstrap_conflict',
            'activation',
            'authentication_success',
            'authentication_failure',
            'authorization_allowed',
            'authorization_denied',
            'credential_issued',
            'credential_rotated',
            'credential_revoked',
            'principal_suspended',
            'principal_resumed',
            'principal_revoked',
            'invalid_authority_binding'
        )),
    service_principal_id  UUID,
    stable_key            VARCHAR(128),
    actor_id              VARCHAR(256)    NOT NULL,
    service_id            VARCHAR(128)    NOT NULL,
    authority_tenant_id   VARCHAR(128)    REFERENCES tenants(tenant_id),
    target_tenant_id      VARCHAR(128),
    credential_id         UUID,
    credential_type       VARCHAR(64),
    credential_slot       VARCHAR(128),
    generation            INTEGER,
    request_id            VARCHAR(128),
    permission            VARCHAR(128),
    outcome               VARCHAR(16)     NOT NULL DEFAULT 'success'
        CONSTRAINT pspe_outcome_valid CHECK (outcome IN ('success', 'failure', 'denied')),
    failure_reason        TEXT,
    occurred_at           TIMESTAMPTZ     NOT NULL DEFAULT now(),
    metadata              JSONB           NOT NULL DEFAULT '{}',
    schema_version        INTEGER         NOT NULL DEFAULT 1,

    PRIMARY KEY (event_id)
);

ALTER TABLE platform_service_principal_events ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS platform_service_principal_events_tenant_isolation ON platform_service_principal_events;
CREATE POLICY platform_service_principal_events_tenant_isolation
    ON platform_service_principal_events
    FOR ALL
    USING (
        authority_tenant_id IS NULL
        OR authority_tenant_id = current_setting('app.tenant_id', true)
    )
    WITH CHECK (
        authority_tenant_id IS NULL
        OR authority_tenant_id = current_setting('app.tenant_id', true)
    );

CREATE OR REPLACE FUNCTION pspe_prevent_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION USING
        MESSAGE = 'platform_service_principal_events is append-only: '
                  || TG_OP || ' on event_id '
                  || COALESCE(OLD.event_id::TEXT, '(null)') || ' is not permitted',
        ERRCODE = 'restrict_violation';
    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS pspe_no_update_or_delete ON platform_service_principal_events;
CREATE TRIGGER pspe_no_update_or_delete
    BEFORE UPDATE OR DELETE ON platform_service_principal_events
    FOR EACH ROW EXECUTE FUNCTION pspe_prevent_mutation();

CREATE INDEX IF NOT EXISTS ix_pspe_principal_occurred
    ON platform_service_principal_events (service_principal_id, occurred_at DESC)
    WHERE service_principal_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS ix_pspe_authority_occurred
    ON platform_service_principal_events (authority_tenant_id, occurred_at DESC)
    WHERE authority_tenant_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS ix_pspe_request_id
    ON platform_service_principal_events (request_id)
    WHERE request_id IS NOT NULL;

COMMENT ON TABLE platform_service_principals IS
    'Canonical platform service principals. Exactly one non-revoked record per '
    'authority_tenant_id+principal_kind. No credential material is stored here; '
    'credentials live in tenant_credentials owned by the authority tenant.';

COMMENT ON TABLE platform_service_principal_events IS
    'Append-only audit events for platform service principal lifecycle, '
    'credential rotation, authentication, and authorization. '
    'No credential material (secrets, hashes) is stored. '
    'Created by PR #586. Actor/service/target-tenant attribution extended in PR #587.';
