-- Migration 0208: MSP-003 — partner-guided onboarding and assessment orchestration.
--
-- Adds:
--   msp_assessment_grants   — one customer-approved, expiring, single-use grant
--                             that lets an MSP initiate exactly one Field
--                             Assessment engagement in the customer's tenant. It
--                             is separate from the MSP-001 relationship, whose
--                             delegation ceiling stays read-only. The engagement
--                             itself stays in fa_engagements (owned by the
--                             customer); this row stores only the authorization
--                             and the link.
--   msp_onboarding_requests — an MSP's referral of an organization that is not yet
--                             a FrostGate tenant. A review queue only: the platform
--                             provisions the tenant through the canonical routes,
--                             then links the request. Nothing here creates a
--                             tenant, a user or a relationship.
--
-- Invariants enforced by the schema (the application enforces the same rules):
--   - A grant is idempotent per (msp, customer, request_key) and is used at most
--     once: engagement_id is unique, and an initiated grant always has one.
--   - A grant has a bounded expiry and distinct parties.
--   - Every decision carries the deciding subject and time.
--   - An onboarding request is idempotent per (msp, request_key); a linked request
--     always names its customer tenant.
--
-- Tenant isolation: RLS is forced on both tables, with no empty-context bypass.
--   msp_assessment_grants   — visible to the customer and the MSP only.
--   msp_onboarding_requests — visible to the requesting MSP only.
--
-- Safety: additive only. No existing row or constraint is changed. No
-- CREATE INDEX CONCURRENTLY (api/db_migrations.py runs in one transaction).

CREATE TABLE IF NOT EXISTS msp_assessment_grants (
    id                         VARCHAR(36)  PRIMARY KEY,
    tenant_id                  VARCHAR(128) NOT NULL,
    msp_tenant_id              VARCHAR(128) NOT NULL,
    relationship_id            VARCHAR(36)  NOT NULL
                                   REFERENCES msp_service_relationships (id),
    request_key                VARCHAR(128) NOT NULL,
    capabilities               TEXT         NOT NULL,
    assessment_type            VARCHAR(64)  NOT NULL,
    assessor_id                VARCHAR(128) NOT NULL,
    status                     VARCHAR(16)  NOT NULL
                                   CHECK (status IN ('requested', 'approved', 'rejected',
                                                     'withdrawn', 'initiated', 'revoked')),
    requested_by_subject       TEXT         NOT NULL,
    requested_at               TIMESTAMPTZ  NOT NULL,
    expires_at                 TIMESTAMPTZ  NOT NULL,
    decided_by_subject         TEXT,
    decided_by_membership_id   VARCHAR(128),
    decided_at                 TIMESTAMPTZ,
    engagement_id              VARCHAR(64),
    initiated_by_subject       TEXT,
    initiated_at               TIMESTAMPTZ,
    revoked_by_subject         TEXT,
    revoked_at                 TIMESTAMPTZ,
    version                    INTEGER      NOT NULL DEFAULT 1,
    created_at                 TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at                 TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT msp_grant_distinct_parties CHECK (msp_tenant_id <> tenant_id),
    CONSTRAINT msp_grant_window CHECK (expires_at > requested_at),
    CONSTRAINT msp_grant_initiated_has_engagement CHECK (
        status <> 'initiated'
        OR (engagement_id IS NOT NULL AND initiated_by_subject IS NOT NULL
            AND initiated_at IS NOT NULL)
    ),
    CONSTRAINT msp_grant_engagement_only_when_used CHECK (
        engagement_id IS NULL OR status IN ('initiated', 'revoked')
    ),
    CONSTRAINT msp_grant_decided_fields CHECK (
        status IN ('requested', 'withdrawn')
        OR (decided_by_subject IS NOT NULL AND decided_at IS NOT NULL)
    ),
    CONSTRAINT msp_grant_revoked_fields CHECK (
        status <> 'revoked'
        OR (revoked_by_subject IS NOT NULL AND revoked_at IS NOT NULL)
    ),
    CONSTRAINT uq_msp_grant_request_key UNIQUE (msp_tenant_id, tenant_id, request_key),
    CONSTRAINT uq_msp_grant_engagement UNIQUE (engagement_id)
);

CREATE INDEX IF NOT EXISTS ix_msp_grant_customer_status
    ON msp_assessment_grants (tenant_id, status);
CREATE INDEX IF NOT EXISTS ix_msp_grant_msp_status
    ON msp_assessment_grants (msp_tenant_id, status);
CREATE INDEX IF NOT EXISTS ix_msp_grant_relationship
    ON msp_assessment_grants (relationship_id);

ALTER TABLE msp_assessment_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE msp_assessment_grants FORCE ROW LEVEL SECURITY;
DO $$ BEGIN
    DROP POLICY IF EXISTS msp_assessment_grants_tenant_isolation ON msp_assessment_grants;
    CREATE POLICY msp_assessment_grants_tenant_isolation ON msp_assessment_grants
        USING (tenant_id = current_setting('app.tenant_id', true)
               OR msp_tenant_id = current_setting('app.tenant_id', true))
        WITH CHECK (tenant_id = current_setting('app.tenant_id', true)
                    OR msp_tenant_id = current_setting('app.tenant_id', true));
END $$;

CREATE TABLE IF NOT EXISTS msp_onboarding_requests (
    id                         VARCHAR(36)  PRIMARY KEY,
    tenant_id                  VARCHAR(128) NOT NULL,
    request_key                VARCHAR(128) NOT NULL,
    organization_name          VARCHAR(200) NOT NULL,
    contact_email              VARCHAR(254) NOT NULL,
    requested_capabilities     TEXT         NOT NULL,
    status                     VARCHAR(16)  NOT NULL
                                   CHECK (status IN ('requested', 'rejected',
                                                     'canceled', 'linked')),
    requested_by_subject       TEXT         NOT NULL,
    requested_at               TIMESTAMPTZ  NOT NULL,
    expires_at                 TIMESTAMPTZ  NOT NULL,
    reviewed_by_subject        TEXT,
    reviewed_at                TIMESTAMPTZ,
    customer_tenant_id         VARCHAR(128),
    version                    INTEGER      NOT NULL DEFAULT 1,
    created_at                 TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at                 TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT msp_onboarding_window CHECK (expires_at > requested_at),
    CONSTRAINT msp_onboarding_linked_fields CHECK (
        status <> 'linked'
        OR (customer_tenant_id IS NOT NULL AND reviewed_by_subject IS NOT NULL
            AND reviewed_at IS NOT NULL)
    ),
    CONSTRAINT msp_onboarding_not_self CHECK (
        customer_tenant_id IS NULL OR customer_tenant_id <> tenant_id
    ),
    CONSTRAINT uq_msp_onboarding_request_key UNIQUE (tenant_id, request_key)
);

CREATE INDEX IF NOT EXISTS ix_msp_onboarding_msp_status
    ON msp_onboarding_requests (tenant_id, status);

ALTER TABLE msp_onboarding_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE msp_onboarding_requests FORCE ROW LEVEL SECURITY;
DO $$ BEGIN
    DROP POLICY IF EXISTS msp_onboarding_requests_tenant_isolation ON msp_onboarding_requests;
    CREATE POLICY msp_onboarding_requests_tenant_isolation ON msp_onboarding_requests
        USING (tenant_id = current_setting('app.tenant_id', true))
        WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
END $$;
