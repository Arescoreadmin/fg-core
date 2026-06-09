-- Migration 0099: provider-neutral tenant identity governance foundation.
-- New identity tables contain no client secrets, private keys, refresh tokens, or invite tokens.
CREATE TABLE IF NOT EXISTS tenant_identity_configs (
 id VARCHAR(128) PRIMARY KEY, tenant_id VARCHAR(128) NOT NULL UNIQUE,
 identity_mode VARCHAR(32) NOT NULL CHECK (identity_mode IN ('managed','sso','hybrid')),
 maturity_level VARCHAR(32) NOT NULL DEFAULT 'level_0', capability_flags JSONB NOT NULL DEFAULT '{}'::jsonb,
 provider VARCHAR(64) NOT NULL DEFAULT 'auth0', oidc_issuer VARCHAR(512),
 auth0_organization_id VARCHAR(256), auth0_connection_id VARCHAR(256),
 allowed_email_domains JSONB NOT NULL DEFAULT '[]'::jsonb, sso_enforced BOOLEAN NOT NULL DEFAULT FALSE,
 provisioning_status VARCHAR(32) NOT NULL DEFAULT 'not_configured' CHECK (provisioning_status IN ('not_configured','pending','ready','failed','disabled')),
 provisioning_error_code VARCHAR(128), provisioning_error_message TEXT, configured_by_user_id VARCHAR(128), configured_at TIMESTAMPTZ,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE tenant_identity_configs ADD COLUMN IF NOT EXISTS maturity_level VARCHAR(32) NOT NULL DEFAULT 'level_0';
ALTER TABLE tenant_identity_configs ADD COLUMN IF NOT EXISTS capability_flags JSONB NOT NULL DEFAULT '{}'::jsonb;
CREATE INDEX IF NOT EXISTS ix_tenant_identity_configs_status ON tenant_identity_configs(provisioning_status);

CREATE TABLE IF NOT EXISTS tenant_identity_providers (
 id VARCHAR(128) PRIMARY KEY, tenant_id VARCHAR(128) NOT NULL, identity_config_id VARCHAR(128) NOT NULL,
 provider VARCHAR(64) NOT NULL, oidc_issuer VARCHAR(512), organization_id VARCHAR(256), connection_id VARCHAR(256),
 status VARCHAR(32) NOT NULL DEFAULT 'configured', is_primary BOOLEAN NOT NULL DEFAULT FALSE,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 CONSTRAINT uq_tenant_identity_providers_binding UNIQUE (tenant_id,provider,oidc_issuer,organization_id,connection_id)
);
CREATE INDEX IF NOT EXISTS ix_tenant_identity_providers_tenant_status ON tenant_identity_providers(tenant_id,status);
CREATE INDEX IF NOT EXISTS ix_tenant_identity_providers_config ON tenant_identity_providers(identity_config_id);

CREATE TABLE IF NOT EXISTS tenant_identity_domains (
 id VARCHAR(128) PRIMARY KEY, tenant_id VARCHAR(128) NOT NULL, identity_config_id VARCHAR(128) NOT NULL, provider_record_id VARCHAR(128),
 domain VARCHAR(256) NOT NULL, domain_type VARCHAR(32) NOT NULL DEFAULT 'trusted', verification_status VARCHAR(32) NOT NULL DEFAULT 'unverified',
 verified_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 CONSTRAINT uq_tenant_identity_domains_type UNIQUE (tenant_id,domain,domain_type,provider_record_id)
);
CREATE INDEX IF NOT EXISTS ix_tenant_identity_domains_tenant_status ON tenant_identity_domains(tenant_id,verification_status);
CREATE INDEX IF NOT EXISTS ix_tenant_identity_domains_config ON tenant_identity_domains(identity_config_id);

CREATE TABLE IF NOT EXISTS tenant_identity_role_assignments (
 id VARCHAR(128) PRIMARY KEY, tenant_id VARCHAR(128) NOT NULL, membership_id VARCHAR(128) NOT NULL, role VARCHAR(64) NOT NULL,
 assignment_source VARCHAR(32) NOT NULL, approval_source VARCHAR(32), source_reference VARCHAR(256),
 assigned_by_user_id VARCHAR(128), approved_by_user_id VARCHAR(128), assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 revoked_at TIMESTAMPTZ, revoked_by_user_id VARCHAR(128)
);
CREATE INDEX IF NOT EXISTS ix_tenant_identity_roles_membership ON tenant_identity_role_assignments(tenant_id,membership_id);
CREATE INDEX IF NOT EXISTS ix_tenant_identity_roles_active ON tenant_identity_role_assignments(tenant_id,revoked_at);

CREATE TABLE IF NOT EXISTS tenant_invitations (
 id VARCHAR(128) PRIMARY KEY, tenant_id VARCHAR(128) NOT NULL, membership_id VARCHAR(128), email VARCHAR(256) NOT NULL,
 normalized_email VARCHAR(256) NOT NULL, role VARCHAR(32) NOT NULL DEFAULT 'user',
 status VARCHAR(64) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','auth_started','accepted_identity_pending_binding','bound','expired','revoked','failed')),
 identity_mode_at_invite VARCHAR(32) CHECK (identity_mode_at_invite IS NULL OR identity_mode_at_invite IN ('managed','sso','hybrid')), required_provider VARCHAR(64), identity_policy_config_id VARCHAR(128), required_provider_record_id VARCHAR(128), required_connection_id VARCHAR(256), auth0_invitation_id VARCHAR(256),
 expires_at TIMESTAMPTZ, revoked_at TIMESTAMPTZ, revoked_by_user_id VARCHAR(128), accepted_at TIMESTAMPTZ, approved_by_user_id VARCHAR(128), approved_at TIMESTAMPTZ, bound_at TIMESTAMPTZ,
 created_by_user_id VARCHAR(128), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_tenant_invitations_tenant_email ON tenant_invitations(tenant_id, normalized_email);
CREATE INDEX IF NOT EXISTS ix_tenant_invitations_tenant_status ON tenant_invitations(tenant_id, status);
CREATE INDEX IF NOT EXISTS ix_tenant_invitations_status_expiry ON tenant_invitations(status, expires_at);
CREATE INDEX IF NOT EXISTS ix_tenant_invitations_membership ON tenant_invitations(membership_id);

ALTER TABLE tenant_users ADD COLUMN IF NOT EXISTS identity_type VARCHAR(32) NOT NULL DEFAULT 'human';
ALTER TABLE tenant_users ADD COLUMN IF NOT EXISTS identity_provider VARCHAR(64);
ALTER TABLE tenant_users ADD COLUMN IF NOT EXISTS identity_provider_record_id VARCHAR(128);
ALTER TABLE tenant_users ADD COLUMN IF NOT EXISTS identity_policy_config_id VARCHAR(128);
ALTER TABLE tenant_users ADD COLUMN IF NOT EXISTS identity_connection_id VARCHAR(256);
ALTER TABLE tenant_users ADD COLUMN IF NOT EXISTS identity_subject VARCHAR(512);
ALTER TABLE tenant_users ADD COLUMN IF NOT EXISTS identity_issuer VARCHAR(512);
ALTER TABLE tenant_users ADD COLUMN IF NOT EXISTS identity_email VARCHAR(256);
ALTER TABLE tenant_users ADD COLUMN IF NOT EXISTS identity_email_verified BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE tenant_users ADD COLUMN IF NOT EXISTS identity_bound_at TIMESTAMPTZ;
ALTER TABLE tenant_users ADD COLUMN IF NOT EXISTS identity_binding_status VARCHAR(32) NOT NULL DEFAULT 'unbound';
ALTER TABLE tenant_users ADD COLUMN IF NOT EXISTS identity_trust_level VARCHAR(32);
ALTER TABLE tenant_users ADD COLUMN IF NOT EXISTS identity_verification_level VARCHAR(32);
ALTER TABLE tenant_users ADD COLUMN IF NOT EXISTS identity_risk_state VARCHAR(32);
ALTER TABLE tenant_users ADD COLUMN IF NOT EXISTS identity_approved_by_user_id VARCHAR(128);
ALTER TABLE tenant_users ADD COLUMN IF NOT EXISTS identity_approved_at TIMESTAMPTZ;
ALTER TABLE tenant_users ADD COLUMN IF NOT EXISTS identity_revoked_at TIMESTAMPTZ;
ALTER TABLE tenant_users ADD COLUMN IF NOT EXISTS last_identity_login_at TIMESTAMPTZ;
DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='chk_tenant_users_identity_binding_status') THEN ALTER TABLE tenant_users ADD CONSTRAINT chk_tenant_users_identity_binding_status CHECK (identity_binding_status IN ('unbound','pending','bound','disabled','failed')); END IF; END $$;
DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='chk_tenant_users_identity_type') THEN ALTER TABLE tenant_users ADD CONSTRAINT chk_tenant_users_identity_type CHECK (identity_type IN ('human','service','agent','system')); END IF; END $$;
CREATE INDEX IF NOT EXISTS ix_tenant_users_identity_subject ON tenant_users(tenant_id, identity_subject);
CREATE UNIQUE INDEX IF NOT EXISTS uq_tenant_users_bound_identity ON tenant_users(identity_provider, identity_issuer, identity_subject) WHERE identity_binding_status='bound' AND identity_subject IS NOT NULL;

ALTER TABLE tenant_users ENABLE ROW LEVEL SECURITY; ALTER TABLE tenant_users FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_users_tenant_isolation ON tenant_users;
CREATE POLICY tenant_users_tenant_isolation ON tenant_users USING (tenant_id=current_setting('app.tenant_id',TRUE)) WITH CHECK (tenant_id=current_setting('app.tenant_id',TRUE));

CREATE TABLE IF NOT EXISTS tenant_identity_audit_events (
 id VARCHAR(128) PRIMARY KEY, tenant_id VARCHAR(128) NOT NULL, event_type VARCHAR(128) NOT NULL, actor_user_id VARCHAR(128), affected_email VARCHAR(256),
 invitation_id VARCHAR(128), membership_id VARCHAR(128), identity_mode VARCHAR(32), provider VARCHAR(64), connection_id VARCHAR(256), reason_code VARCHAR(128),
 identity_type VARCHAR(32), identity_subject VARCHAR(512), provider_record_id VARCHAR(128), policy_config_id VARCHAR(128), role_assignment_id VARCHAR(128), correlation_id VARCHAR(128),
 previous_event_hash VARCHAR(64), event_hash VARCHAR(64) NOT NULL, details_json JSONB NOT NULL DEFAULT '{}'::jsonb, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE tenant_identity_audit_events ADD COLUMN IF NOT EXISTS identity_type VARCHAR(32);
ALTER TABLE tenant_identity_audit_events ADD COLUMN IF NOT EXISTS identity_subject VARCHAR(512);
ALTER TABLE tenant_identity_audit_events ADD COLUMN IF NOT EXISTS provider_record_id VARCHAR(128);
ALTER TABLE tenant_identity_audit_events ADD COLUMN IF NOT EXISTS policy_config_id VARCHAR(128);
ALTER TABLE tenant_identity_audit_events ADD COLUMN IF NOT EXISTS role_assignment_id VARCHAR(128);
ALTER TABLE tenant_identity_audit_events ADD COLUMN IF NOT EXISTS correlation_id VARCHAR(128);
ALTER TABLE tenant_identity_audit_events ADD COLUMN IF NOT EXISTS previous_event_hash VARCHAR(64);
ALTER TABLE tenant_identity_audit_events ADD COLUMN IF NOT EXISTS event_hash VARCHAR(64);
CREATE INDEX IF NOT EXISTS ix_tenant_identity_audit_tenant_created ON tenant_identity_audit_events(tenant_id, created_at);
CREATE INDEX IF NOT EXISTS ix_tenant_identity_audit_invitation ON tenant_identity_audit_events(invitation_id);
CREATE INDEX IF NOT EXISTS ix_tenant_identity_audit_membership ON tenant_identity_audit_events(membership_id);
CREATE INDEX IF NOT EXISTS ix_tenant_identity_audit_event_type ON tenant_identity_audit_events(tenant_id, event_type);
CREATE INDEX IF NOT EXISTS ix_tenant_identity_audit_event_hash ON tenant_identity_audit_events(event_hash);
DROP TRIGGER IF EXISTS tenant_identity_audit_events_append_only_update ON tenant_identity_audit_events;
CREATE TRIGGER tenant_identity_audit_events_append_only_update BEFORE UPDATE ON tenant_identity_audit_events FOR EACH ROW EXECUTE FUNCTION append_only_guard();
DROP TRIGGER IF EXISTS tenant_identity_audit_events_append_only_delete ON tenant_identity_audit_events;
CREATE TRIGGER tenant_identity_audit_events_append_only_delete BEFORE DELETE ON tenant_identity_audit_events FOR EACH ROW EXECUTE FUNCTION append_only_guard();

-- Repository-evidenced demo tenants only. Unknown tenants receive no guessed policy and fail closed.
INSERT INTO tenant_identity_configs(id,tenant_id,identity_mode,maturity_level,capability_flags,provider,provisioning_status,configured_by_user_id,configured_at,created_at,updated_at)
VALUES ('demo-managed-demo-bank','demo-bank','managed','level_1','{"managed_identities":true}'::jsonb,'auth0','ready','system:migration:0099',NOW(),NOW(),NOW()), ('demo-managed-demo-healthcare','demo-healthcare','managed','level_1','{"managed_identities":true}'::jsonb,'auth0','ready','system:migration:0099',NOW(),NOW(),NOW())
ON CONFLICT (tenant_id) DO NOTHING;
INSERT INTO tenant_identity_providers(id,tenant_id,identity_config_id,provider,oidc_issuer,organization_id,connection_id,status,is_primary,created_at,updated_at)
SELECT 'migration-0099-provider-'||c.tenant_id,c.tenant_id,c.id,c.provider,c.oidc_issuer,c.auth0_organization_id,c.auth0_connection_id,CASE WHEN c.provisioning_status='ready' THEN 'ready' ELSE 'configured' END,TRUE,c.created_at,c.updated_at FROM tenant_identity_configs c
ON CONFLICT (tenant_id,provider,oidc_issuer,organization_id,connection_id) DO NOTHING;
INSERT INTO tenant_identity_domains(id,tenant_id,identity_config_id,provider_record_id,domain,domain_type,verification_status,created_at,updated_at)
SELECT 'migration-0099-domain-'||md5(c.tenant_id||':'||d.domain),c.tenant_id,c.id,p.id,d.domain,'trusted','unverified',c.created_at,c.updated_at
FROM tenant_identity_configs c JOIN tenant_identity_providers p ON p.identity_config_id=c.id AND p.is_primary=TRUE CROSS JOIN LATERAL jsonb_array_elements_text(c.allowed_email_domains::jsonb) AS d(domain)
ON CONFLICT (tenant_id,domain,domain_type,provider_record_id) DO NOTHING;
-- Existing pending invites remain pending; raw tokens are never copied. Existing accepted users remain unbound human identities.
INSERT INTO tenant_invitations(id,tenant_id,membership_id,email,normalized_email,role,status,identity_mode_at_invite,required_provider,identity_policy_config_id,required_provider_record_id,expires_at,created_by_user_id,created_at,updated_at)
SELECT 'legacy-'||md5(u.tenant_id||':'||u.id||':invite'),u.tenant_id,u.id,u.email,lower(trim(u.email)),u.role,'pending',c.identity_mode,c.provider,c.id,p.id,u.invite_expires_at,'system:migration:0099',u.created_at,u.updated_at
FROM tenant_users u LEFT JOIN tenant_identity_configs c ON c.tenant_id=u.tenant_id LEFT JOIN tenant_identity_providers p ON p.identity_config_id=c.id AND p.is_primary=TRUE WHERE u.invite_token IS NOT NULL ON CONFLICT(id) DO NOTHING;
CREATE OR REPLACE FUNCTION tenant_identity_canonical_jsonb(value JSONB)
RETURNS TEXT
LANGUAGE SQL
IMMUTABLE
STRICT
AS $$
SELECT CASE jsonb_typeof(value)
    WHEN 'object' THEN COALESCE(
        (
            SELECT '{' || string_agg(to_json(key)::text || ':' || tenant_identity_canonical_jsonb(item), ',' ORDER BY key) || '}'
            FROM jsonb_each(value) AS entries(key, item)
        ),
        '{}'
    )
    WHEN 'array' THEN COALESCE(
        (
            SELECT '[' || string_agg(tenant_identity_canonical_jsonb(item), ',' ORDER BY ordinal) || ']'
            FROM jsonb_array_elements(value) WITH ORDINALITY AS entries(item, ordinal)
        ),
        '[]'
    )
    ELSE value::text
END
$$;

DO $$
DECLARE
    candidate RECORD;
    previous_hash_value VARCHAR(64);
    event_hash_value VARCHAR(64);
    event_created_at TIMESTAMPTZ;
    hash_payload JSONB;
BEGIN
    FOR candidate IN
        SELECT *
        FROM (
            SELECT
                'migration-0099-config-' || tenant_id AS id,
                tenant_id,
                'tenant.identity_config.created' AS event_type,
                'system:migration:0099' AS actor_user_id,
                NULL::VARCHAR AS affected_email,
                NULL::VARCHAR AS invitation_id,
                NULL::VARCHAR AS membership_id,
                identity_mode,
                provider,
                NULL::VARCHAR AS connection_id,
                NULL::VARCHAR AS reason_code,
                NULL::VARCHAR AS identity_type,
                NULL::VARCHAR AS identity_subject,
                NULL::VARCHAR AS provider_record_id,
                id AS policy_config_id,
                NULL::VARCHAR AS role_assignment_id,
                NULL::VARCHAR AS correlation_id,
                jsonb_build_object(
                    'provisioning_status', provisioning_status,
                    'maturity_level', maturity_level
                ) AS details_json,
                0 AS event_order
            FROM tenant_identity_configs
            WHERE configured_by_user_id = 'system:migration:0099'
            UNION ALL
            SELECT
                'migration-0099-invite-' || id,
                tenant_id,
                'tenant.invite.created',
                'system:migration:0099',
                normalized_email,
                id,
                membership_id,
                identity_mode_at_invite,
                required_provider,
                required_connection_id,
                NULL::VARCHAR,
                NULL::VARCHAR,
                NULL::VARCHAR,
                required_provider_record_id,
                identity_policy_config_id,
                NULL::VARCHAR,
                NULL::VARCHAR,
                jsonb_build_object('invitation_status', status),
                1
            FROM tenant_invitations
            WHERE created_by_user_id = 'system:migration:0099'
        ) AS candidates
        ORDER BY tenant_id, event_order, id
    LOOP
        IF NOT EXISTS (
            SELECT 1 FROM tenant_identity_audit_events WHERE id = candidate.id
        ) THEN
            SELECT event_hash
            INTO previous_hash_value
            FROM tenant_identity_audit_events
            WHERE tenant_id = candidate.tenant_id
            ORDER BY created_at DESC, id DESC
            LIMIT 1;

            event_created_at := clock_timestamp();
            hash_payload := jsonb_build_object(
                'id', candidate.id,
                'tenant_id', candidate.tenant_id,
                'event_type', candidate.event_type,
                'actor_user_id', candidate.actor_user_id,
                'affected_email', candidate.affected_email,
                'invitation_id', candidate.invitation_id,
                'membership_id', candidate.membership_id,
                'identity_mode', candidate.identity_mode,
                'provider', candidate.provider,
                'connection_id', candidate.connection_id,
                'reason_code', candidate.reason_code,
                'identity_type', candidate.identity_type,
                'identity_subject', candidate.identity_subject,
                'provider_record_id', candidate.provider_record_id,
                'policy_config_id', candidate.policy_config_id,
                'role_assignment_id', candidate.role_assignment_id,
                'correlation_id', candidate.correlation_id,
                'details', candidate.details_json,
                'created_at', to_char(event_created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
                'previous_event_hash', previous_hash_value
            );
            event_hash_value := encode(
                sha256(convert_to(tenant_identity_canonical_jsonb(hash_payload), 'UTF8')),
                'hex'
            );

            INSERT INTO tenant_identity_audit_events(
                id, tenant_id, event_type, actor_user_id, affected_email,
                invitation_id, membership_id, identity_mode, provider,
                connection_id, reason_code, identity_type, identity_subject,
                provider_record_id, policy_config_id, role_assignment_id,
                correlation_id, previous_event_hash, event_hash, details_json,
                created_at
            )
            VALUES (
                candidate.id, candidate.tenant_id, candidate.event_type,
                candidate.actor_user_id, candidate.affected_email,
                candidate.invitation_id, candidate.membership_id,
                candidate.identity_mode, candidate.provider,
                candidate.connection_id, candidate.reason_code,
                candidate.identity_type, candidate.identity_subject,
                candidate.provider_record_id, candidate.policy_config_id,
                candidate.role_assignment_id, candidate.correlation_id,
                previous_hash_value, event_hash_value, candidate.details_json,
                event_created_at
            );
        END IF;
    END LOOP;
END $$;

ALTER TABLE tenant_identity_configs ENABLE ROW LEVEL SECURITY; ALTER TABLE tenant_identity_configs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_identity_configs_tenant_isolation ON tenant_identity_configs;
CREATE POLICY tenant_identity_configs_tenant_isolation ON tenant_identity_configs USING (tenant_id=current_setting('app.tenant_id',TRUE)) WITH CHECK (tenant_id=current_setting('app.tenant_id',TRUE));
ALTER TABLE tenant_identity_providers ENABLE ROW LEVEL SECURITY; ALTER TABLE tenant_identity_providers FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_identity_providers_tenant_isolation ON tenant_identity_providers;
CREATE POLICY tenant_identity_providers_tenant_isolation ON tenant_identity_providers USING (tenant_id=current_setting('app.tenant_id',TRUE)) WITH CHECK (tenant_id=current_setting('app.tenant_id',TRUE));
ALTER TABLE tenant_identity_domains ENABLE ROW LEVEL SECURITY; ALTER TABLE tenant_identity_domains FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_identity_domains_tenant_isolation ON tenant_identity_domains;
CREATE POLICY tenant_identity_domains_tenant_isolation ON tenant_identity_domains USING (tenant_id=current_setting('app.tenant_id',TRUE)) WITH CHECK (tenant_id=current_setting('app.tenant_id',TRUE));
ALTER TABLE tenant_identity_role_assignments ENABLE ROW LEVEL SECURITY; ALTER TABLE tenant_identity_role_assignments FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_identity_role_assignments_tenant_isolation ON tenant_identity_role_assignments;
CREATE POLICY tenant_identity_role_assignments_tenant_isolation ON tenant_identity_role_assignments USING (tenant_id=current_setting('app.tenant_id',TRUE)) WITH CHECK (tenant_id=current_setting('app.tenant_id',TRUE));
ALTER TABLE tenant_invitations ENABLE ROW LEVEL SECURITY; ALTER TABLE tenant_invitations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_invitations_tenant_isolation ON tenant_invitations;
CREATE POLICY tenant_invitations_tenant_isolation ON tenant_invitations USING (tenant_id=current_setting('app.tenant_id',TRUE)) WITH CHECK (tenant_id=current_setting('app.tenant_id',TRUE));
ALTER TABLE tenant_identity_audit_events ENABLE ROW LEVEL SECURITY; ALTER TABLE tenant_identity_audit_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_identity_audit_events_tenant_isolation ON tenant_identity_audit_events;
CREATE POLICY tenant_identity_audit_events_tenant_isolation ON tenant_identity_audit_events USING (tenant_id=current_setting('app.tenant_id',TRUE)) WITH CHECK (tenant_id=current_setting('app.tenant_id',TRUE));
