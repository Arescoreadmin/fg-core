-- Migration 0112: Tenant Capability Entitlements (P0-5)
--
-- Introduces the commercial entitlement authority layer.
-- External systems (billing, CRM, provisioning) push explicit capability grants.
-- FrostGate enforces those grants deterministically. No billing logic here.
--
-- Design:
--   - One row per (tenant_id, capability) pair.
--   - expires_at NULL means the grant never expires.
--   - Capability strings are the authoritative unit; products are packaging.
--   - RLS enforced: tenants can only read their own entitlements.
--   - Admin routes bypass RLS by setting the correct tenant context explicitly.
--
-- Enforcement mode is controlled by FG_ENTITLEMENT_ENFORCEMENT env var:
--   false (default) = audit-only; enforcement activates when entitlements are provisioned
--   true            = deny if no explicit grant and not in tier capabilities

CREATE TABLE IF NOT EXISTS tenant_entitlements (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    capability  TEXT NOT NULL,
    granted_by  TEXT NOT NULL DEFAULT 'system',
    granted_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ,
    reason      TEXT,
    UNIQUE (tenant_id, capability)
);

CREATE INDEX IF NOT EXISTS ix_tenant_entitlements_tenant
    ON tenant_entitlements (tenant_id);

CREATE INDEX IF NOT EXISTS ix_tenant_entitlements_capability
    ON tenant_entitlements (tenant_id, capability);

-- RLS: tenants see only their own entitlement records.
-- Admin routes set tenant context explicitly before querying.
DO $$
BEGIN
    IF to_regclass('public.tenant_entitlements') IS NOT NULL THEN
        ALTER TABLE tenant_entitlements ENABLE ROW LEVEL SECURITY;
        ALTER TABLE tenant_entitlements FORCE ROW LEVEL SECURITY;

        DROP POLICY IF EXISTS tenant_entitlements_tenant_isolation
            ON tenant_entitlements;
        CREATE POLICY tenant_entitlements_tenant_isolation
            ON tenant_entitlements
            USING (
                tenant_id IS NOT NULL
                AND current_setting('app.tenant_id', true) IS NOT NULL
                AND tenant_id = current_setting('app.tenant_id', true)
            )
            WITH CHECK (
                tenant_id IS NOT NULL
                AND current_setting('app.tenant_id', true) IS NOT NULL
                AND tenant_id = current_setting('app.tenant_id', true)
            );
    END IF;
END $$;
