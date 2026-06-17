-- Migration 0118: Tenant Policy Bundles + Capability Framework (P1.2)
--
-- Introduces the commercial capability bundle architecture.
-- Bundles are named collections of capabilities; tenants are assigned bundles
-- (or direct capability overrides) via subscriptions or manual admin action.
--
-- Resolution order (in check_capability):
--   1. Registry miss → deny
--   2. Explicit TenantEntitlement grant → allow
--   3. Bundle/capability assignment (this layer) → allow if present
--   4. Tier-based default → allow/deny (backward compat)
--
-- All tables are idempotent (IF NOT EXISTS). TIMESTAMPTZ used on Postgres;
-- SQLite tests use TEXT for timestamps via ORM-level handling.

-- tenant_subscriptions: tracks the commercial subscription type for a tenant
CREATE TABLE IF NOT EXISTS tenant_subscriptions (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    subscription_type TEXT NOT NULL,
    -- 'portal_only'|'portal_remediation'|'portal_ai'|'enterprise'|'government'|'msp'|'trial'|'usage_based'
    status      TEXT NOT NULL DEFAULT 'active',
    -- 'active'|'trial'|'suspended'|'expired'|'cancelled'
    effective_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_tenant_subs_tenant
    ON tenant_subscriptions (tenant_id);
CREATE INDEX IF NOT EXISTS idx_tenant_subs_status
    ON tenant_subscriptions (tenant_id, status);

-- policy_bundles: catalog of named capability bundles (seeded by application)
CREATE TABLE IF NOT EXISTS policy_bundles (
    id              TEXT PRIMARY KEY,
    bundle_key      TEXT NOT NULL UNIQUE,
    bundle_name     TEXT NOT NULL,
    bundle_version  TEXT NOT NULL DEFAULT '1.0',
    active          BOOLEAN NOT NULL DEFAULT TRUE,
    description     TEXT
);

-- capabilities: DB catalog of all known capability strings
-- Mirrors CAPABILITY_REGISTRY; authoritative for admin/UI enumeration.
CREATE TABLE IF NOT EXISTS capabilities (
    id                  TEXT PRIMARY KEY,
    capability_key      TEXT NOT NULL UNIQUE,
    capability_name     TEXT NOT NULL,
    capability_category TEXT NOT NULL,
    description         TEXT,
    active              BOOLEAN NOT NULL DEFAULT TRUE,
    -- billing_category: groups capabilities for invoice line-items (e.g. 'ai', 'portal')
    billing_category    TEXT,
    -- launch_stage: 'alpha'|'beta'|'ga'|'deprecated'
    launch_stage        TEXT NOT NULL DEFAULT 'ga',
    -- visibility: 'public'|'internal'|'hidden'
    visibility          TEXT NOT NULL DEFAULT 'public'
);

-- capability_dependencies: soft prerequisite graph (enforced by resolver/admin, not DB FK loop)
-- capability_id requires requires_id to also be granted before it is usable.
CREATE TABLE IF NOT EXISTS capability_dependencies (
    capability_id   TEXT NOT NULL REFERENCES capabilities(id) ON DELETE CASCADE,
    requires_id     TEXT NOT NULL REFERENCES capabilities(id) ON DELETE CASCADE,
    PRIMARY KEY (capability_id, requires_id)
);
CREATE INDEX IF NOT EXISTS idx_cap_deps_capability
    ON capability_dependencies (capability_id);

-- capability_meter_mappings: maps a capability to a billing meter key
-- One capability can map to multiple meters (e.g. token_meter + document_meter).
CREATE TABLE IF NOT EXISTS capability_meter_mappings (
    id              TEXT PRIMARY KEY,
    capability_id   TEXT NOT NULL REFERENCES capabilities(id) ON DELETE CASCADE,
    meter_key       TEXT NOT NULL,
    UNIQUE (capability_id, meter_key)
);
CREATE INDEX IF NOT EXISTS idx_cap_meters_capability
    ON capability_meter_mappings (capability_id);

-- policy_bundle_capabilities: many-to-many join between bundles and capabilities
CREATE TABLE IF NOT EXISTS policy_bundle_capabilities (
    bundle_id       TEXT NOT NULL REFERENCES policy_bundles(id) ON DELETE CASCADE,
    capability_id   TEXT NOT NULL REFERENCES capabilities(id) ON DELETE CASCADE,
    PRIMARY KEY (bundle_id, capability_id)
);

-- tenant_capability_assignments: per-tenant direct capability overrides
-- source: 'subscription'|'manual'|'trial'|'promotion'|'marketplace'
CREATE TABLE IF NOT EXISTS tenant_capability_assignments (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    capability_id   TEXT NOT NULL REFERENCES capabilities(id),
    source          TEXT NOT NULL,
    assigned_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ,
    assigned_by     TEXT,
    notes           TEXT
);
CREATE INDEX IF NOT EXISTS idx_tca_tenant
    ON tenant_capability_assignments (tenant_id);
CREATE INDEX IF NOT EXISTS idx_tca_tenant_cap
    ON tenant_capability_assignments (tenant_id, capability_id);

-- tenant_bundle_assignments: which bundles a tenant has active
CREATE TABLE IF NOT EXISTS tenant_bundle_assignments (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    bundle_id       TEXT NOT NULL REFERENCES policy_bundles(id),
    subscription_id TEXT REFERENCES tenant_subscriptions(id),
    assigned_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ,
    assigned_by     TEXT,
    UNIQUE (tenant_id, bundle_id)
);
CREATE INDEX IF NOT EXISTS idx_tba_tenant
    ON tenant_bundle_assignments (tenant_id);
