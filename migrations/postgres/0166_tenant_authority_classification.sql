-- Migration 0166: tenant authority classification
--
-- Adds first-class tenant authority classification to the canonical tenants
-- table.  tenant_kind is the durable authority discriminator; operational
-- policy flags such as customer visibility, portal eligibility, billing
-- eligibility, and Console operator authority are derived in application
-- policy code to avoid contradictory persisted combinations.
--
-- Semantics:
--   customer          Ordinary customer tenant.  This is the safe legacy default.
--   internal_platform FrostGate-owned platform/internal authority.  Never inferred.
--   validation        Production validation/test tenant.  Not operator authority.
--   demo              Demo tenant.  Not operator authority and not billable.
--
-- Existing tenants default to customer because that preserves the pre-existing
-- least-surprising behavior and does not auto-promote any customer to platform
-- authority.  The two validation tenants below are exact-ID allowlisted from
-- the post-#583 authority audit; this is deliberately not substring/name
-- inference and does not create an internal platform tenant.
--
-- Rollback/forward compatibility:
--   The migration is additive and replay-safe.  Rolling back code can ignore
--   tenant_kind while the column remains present.  Do not drop tenant_kind
--   after any tenant has been classified internal_platform without a separate
--   governed rollback plan.

ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS tenant_kind VARCHAR(32) NOT NULL DEFAULT 'customer';

UPDATE tenants
SET tenant_kind = 'customer'
WHERE tenant_kind IS NULL OR tenant_kind = '';

UPDATE tenants
SET tenant_kind = 'validation'
WHERE tenant_id IN (
    'frostgate-e2e-validation',
    'frostgate-provisioning-validation'
)
  AND tenant_kind = 'customer';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'chk_tenants_tenant_kind'
    ) THEN
        ALTER TABLE tenants
            ADD CONSTRAINT chk_tenants_tenant_kind
            CHECK (tenant_kind IN ('customer', 'internal_platform', 'validation', 'demo'));
    END IF;
END $$;

COMMENT ON COLUMN tenants.tenant_kind IS
    'Canonical tenant authority classification: customer, internal_platform, validation, or demo. Policy flags are derived from this value.';
