-- Migration 0167: canonical internal platform authority bootstrap
--
-- PR #585 provisions the first first-class internal platform authority after
-- PR #584 introduced tenant_kind. The canonical identifier is
-- "frostgate-internal". Runtime authorization must still validate authority by
-- tenant_kind -> tenant_authority.py policy, never by tenant_id string matching.
--
-- Replay/rollback contract:
--   - This migration is deterministic and replay-safe.
--   - If an internal_platform tenant already exists, it is reused and no
--     duplicate is created.
--   - If no internal_platform tenant exists, frostgate-internal is inserted.
--   - Existing unknown/customer tenants are not promoted except for the exact
--     canonical frostgate-internal row.
--   - No customer credentials are reused and no credential material is created
--     by this SQL migration; CredentialAuthority issues the operator credential
--     at application bootstrap.
--   - No customer lifecycle, billing, portal, assessment, report, or artifact
--     ownership is changed.

CREATE TABLE IF NOT EXISTS internal_platform_authority_events (
    event_id              UUID            NOT NULL DEFAULT gen_random_uuid(),
    event_type            VARCHAR(64)     NOT NULL
        CONSTRAINT ipae_event_type_valid CHECK (event_type IN (
            'bootstrap_created',
            'bootstrap_reused',
            'credential_issued',
            'credential_reused',
            'credential_rotated',
            'credential_revoked',
            'authority_validated',
            'authority_denied'
        )),
    actor_id              VARCHAR(256)    NOT NULL,
    service_id            VARCHAR(128)    NOT NULL,
    target_tenant_id      VARCHAR(128)    NOT NULL,
    authority_tenant_id   VARCHAR(128)    REFERENCES tenants(tenant_id),
    credential_id         UUID,
    credential_type       VARCHAR(64),
    credential_slot       VARCHAR(128),
    generation            INTEGER,
    request_id            VARCHAR(128),
    occurred_at           TIMESTAMPTZ     NOT NULL DEFAULT now(),
    outcome               VARCHAR(16)     NOT NULL DEFAULT 'success'
        CONSTRAINT ipae_outcome_valid CHECK (outcome IN ('success', 'failure', 'denied')),
    failure_reason        TEXT,
    metadata              JSONB           NOT NULL DEFAULT '{}',
    schema_version        INTEGER         NOT NULL DEFAULT 1,

    PRIMARY KEY (event_id)
);

ALTER TABLE internal_platform_authority_events ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS internal_platform_authority_events_tenant_isolation
    ON internal_platform_authority_events;
CREATE POLICY internal_platform_authority_events_tenant_isolation
    ON internal_platform_authority_events
    FOR ALL
    USING (
        authority_tenant_id IS NULL
        OR authority_tenant_id = current_setting('app.tenant_id', true)
    )
    WITH CHECK (
        authority_tenant_id IS NULL
        OR authority_tenant_id = current_setting('app.tenant_id', true)
    );

CREATE OR REPLACE FUNCTION ipae_prevent_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION USING
        MESSAGE = 'internal_platform_authority_events is append-only: '
                  || TG_OP || ' on event_id ' || COALESCE(OLD.event_id::TEXT, '(null)') || ' is not permitted',
        ERRCODE = 'restrict_violation';
    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS ipae_no_update_or_delete ON internal_platform_authority_events;
CREATE TRIGGER ipae_no_update_or_delete
    BEFORE UPDATE OR DELETE ON internal_platform_authority_events
    FOR EACH ROW EXECUTE FUNCTION ipae_prevent_mutation();

CREATE INDEX IF NOT EXISTS ix_ipae_authority_occurred
    ON internal_platform_authority_events (authority_tenant_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS ix_ipae_target_occurred
    ON internal_platform_authority_events (target_tenant_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS ix_ipae_request_id
    ON internal_platform_authority_events (request_id)
    WHERE request_id IS NOT NULL;

DO $$
DECLARE
    v_existing_internal_tenant_id VARCHAR(128);
    v_bootstrap_status VARCHAR(32);
BEGIN
    SELECT tenant_id
      INTO v_existing_internal_tenant_id
      FROM tenants
     WHERE tenant_kind = 'internal_platform'
     ORDER BY tenant_id
     LIMIT 1;

    IF EXISTS (SELECT 1 FROM tenants WHERE tenant_id = 'frostgate-internal') THEN
        UPDATE tenants
           SET tenant_kind = 'internal_platform',
               display_name = CASE
                   WHEN display_name IS NULL OR display_name = '' THEN 'FrostGate Internal Platform'
                   ELSE display_name
               END,
               metadata = COALESCE(metadata, '{}'::jsonb) || jsonb_build_object(
                   'authority', 'internal_platform',
                   'authority_version', 1,
                   'managed_by', 'frostgate-core',
                   'customer_visible', false,
                   'portal_enabled', false,
                   'billing_eligible', false,
                   'service_principal', false,
                   'created_by_pr', '585'
               ),
               canonical_version = GREATEST(canonical_version, 2),
               migration_source = 'internal_platform_bootstrap',
               migration_version = '0167',
               updated_at = now()
         WHERE tenant_id = 'frostgate-internal';
        v_existing_internal_tenant_id := 'frostgate-internal';
        v_bootstrap_status := 'bootstrap_reused';
    ELSIF v_existing_internal_tenant_id IS NULL THEN
        INSERT INTO tenants (
            tenant_id, display_name, lifecycle_state, tenant_kind,
            created_at, updated_at, created_by, metadata,
            canonical_version, migration_source, migration_version
        ) VALUES (
            'frostgate-internal',
            'FrostGate Internal Platform',
            'active',
            'internal_platform',
            now(),
            now(),
            'migration:0167',
            jsonb_build_object(
                'authority', 'internal_platform',
                'authority_version', 1,
                'managed_by', 'frostgate-core',
                'customer_visible', false,
                'portal_enabled', false,
                'billing_eligible', false,
                'service_principal', false,
                'created_by_pr', '585'
            ),
            2,
            'internal_platform_bootstrap',
            '0167'
        );
        v_existing_internal_tenant_id := 'frostgate-internal';
        v_bootstrap_status := 'bootstrap_created';
    ELSE
        v_bootstrap_status := 'bootstrap_reused';
    END IF;

    INSERT INTO internal_platform_authority_events (
        event_id, event_type, actor_id, service_id, target_tenant_id,
        authority_tenant_id, request_id, occurred_at, outcome, metadata
    ) VALUES (
        '00000000-0000-0000-0000-000000000167',
        v_bootstrap_status,
        'migration:0167',
        'frostgate-core',
        v_existing_internal_tenant_id,
        v_existing_internal_tenant_id,
        'migration-0167',
        now(),
        'success',
        jsonb_build_object('authority_version', 1, 'canonical_tenant_id', 'frostgate-internal')
    ) ON CONFLICT DO NOTHING;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS uq_tenants_single_internal_platform_authority
    ON tenants (tenant_kind)
    WHERE tenant_kind = 'internal_platform';

COMMENT ON TABLE internal_platform_authority_events IS
    'Append-only audit events for internal platform authority bootstrap, validation, and credential lifecycle mirroring. No credential material is stored.';
COMMENT ON COLUMN tenants.tenant_kind IS
    'Canonical tenant authority classification. frostgate-internal is the first canonical internal_platform tenant; policy remains derived from tenant_kind.';
