-- Migration 0206: MSP-001 — MSP organization designation and customer-approved
-- MSP service relationships.
--
-- Adds:
--   msp_organizations         — platform designation of an existing canonical tenant
--                               (tenants.tenant_id) as a managed service provider.
--                               It is a designation, not a tenant registry: no tenant
--                               attributes are copied here.
--   msp_service_relationships — one MSP organization serving one customer tenant.
--                               The customer tenant is the data owner and is stored in
--                               tenant_id; msp_tenant_id is the service provider.
--
-- Invariants enforced by the schema (the application enforces the same rules):
--   - An MSP can never relate to itself (no self-relationships, no cycles).
--   - At most one open (proposed / approved / suspended) relationship per
--     (msp_tenant_id, tenant_id) pair, so concurrent proposals or approvals cannot
--     create duplicate active relationships.
--   - Approved or suspended rows always carry the customer approver, the approval
--     time, the authorized capabilities and the effective time.
--   - Revoked rows always carry who revoked them and when.
--   - 'active' and 'expired' are derived (effective_at <= now < expires_at), never
--     stored, so expiry needs no scheduler and cannot be missed.
--
-- Tenant isolation: RLS is forced. A row is visible only to the two parties to the
-- relationship (the customer tenant or the MSP tenant in app.tenant_id). There is no
-- empty-context bypass.
--
-- Safety: additive only. No existing table, row or constraint is changed. No
-- CREATE INDEX CONCURRENTLY (api/db_migrations.py runs in one transaction).

CREATE TABLE IF NOT EXISTS msp_organizations (
    tenant_id                  VARCHAR(128) PRIMARY KEY,
    status                     VARCHAR(16)  NOT NULL
                                   CHECK (status IN ('active', 'suspended')),
    designated_by_subject      TEXT         NOT NULL,
    designated_at              TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    status_changed_by_subject  TEXT         NOT NULL,
    status_changed_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS msp_service_relationships (
    id                         VARCHAR(36)  PRIMARY KEY,
    msp_tenant_id              VARCHAR(128) NOT NULL,
    tenant_id                  VARCHAR(128) NOT NULL,
    status                     VARCHAR(16)  NOT NULL
                                   CHECK (status IN ('proposed', 'approved',
                                                     'suspended', 'revoked')),
    -- Canonical JSON arrays of permission names (sorted, de-duplicated).
    requested_capabilities     TEXT         NOT NULL,
    authorized_capabilities    TEXT,
    proposed_by_subject        TEXT         NOT NULL,
    proposed_at                TIMESTAMPTZ  NOT NULL,
    approved_by_subject        TEXT,
    approved_by_membership_id  VARCHAR(128),
    approved_at                TIMESTAMPTZ,
    effective_at               TIMESTAMPTZ,
    expires_at                 TIMESTAMPTZ,
    suspended_at               TIMESTAMPTZ,
    revoked_at                 TIMESTAMPTZ,
    revoked_by_subject         TEXT,
    revoked_by_party           VARCHAR(16)
                                   CHECK (revoked_by_party IS NULL
                                          OR revoked_by_party IN ('customer', 'msp')),
    version                    INTEGER      NOT NULL DEFAULT 1,
    created_at                 TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at                 TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    CONSTRAINT msp_rel_distinct_parties CHECK (msp_tenant_id <> tenant_id),
    CONSTRAINT msp_rel_approved_complete CHECK (
        status NOT IN ('approved', 'suspended')
        OR (approved_by_subject IS NOT NULL AND approved_at IS NOT NULL
            AND authorized_capabilities IS NOT NULL AND effective_at IS NOT NULL)
    ),
    CONSTRAINT msp_rel_revoked_complete CHECK (
        status <> 'revoked'
        OR (revoked_at IS NOT NULL AND revoked_by_subject IS NOT NULL)
    ),
    CONSTRAINT msp_rel_window_order CHECK (
        expires_at IS NULL OR effective_at IS NULL OR expires_at > effective_at
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_msp_rel_open_pair
    ON msp_service_relationships (msp_tenant_id, tenant_id)
    WHERE status IN ('proposed', 'approved', 'suspended');
CREATE INDEX IF NOT EXISTS ix_msp_rel_msp_status
    ON msp_service_relationships (msp_tenant_id, status);
CREATE INDEX IF NOT EXISTS ix_msp_rel_customer_status
    ON msp_service_relationships (tenant_id, status);

-- ---------------------------------------------------------------------------
-- Row-level security
-- ---------------------------------------------------------------------------

ALTER TABLE msp_organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE msp_organizations FORCE ROW LEVEL SECURITY;
DO $$ BEGIN
    DROP POLICY IF EXISTS msp_organizations_tenant_isolation ON msp_organizations;
    CREATE POLICY msp_organizations_tenant_isolation ON msp_organizations
        USING (tenant_id = current_setting('app.tenant_id', true))
        WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
END $$;

ALTER TABLE msp_service_relationships ENABLE ROW LEVEL SECURITY;
ALTER TABLE msp_service_relationships FORCE ROW LEVEL SECURITY;
DO $$ BEGIN
    DROP POLICY IF EXISTS msp_service_relationships_tenant_isolation
        ON msp_service_relationships;
    CREATE POLICY msp_service_relationships_tenant_isolation
        ON msp_service_relationships
        USING (tenant_id = current_setting('app.tenant_id', true)
               OR msp_tenant_id = current_setting('app.tenant_id', true))
        WITH CHECK (tenant_id = current_setting('app.tenant_id', true)
                    OR msp_tenant_id = current_setting('app.tenant_id', true));
END $$;
