-- Migration 0209: MSP-007 — customer-controlled, version-bound report sharing.
--
-- Adds:
--   msp_report_shares — one customer decision to let one MSP read one exact,
--                       released Field Assessment report version (report id,
--                       version number and manifest fingerprint), for a bounded
--                       time, under an active MSP-001 relationship. The report
--                       itself stays in governance_reports (owned by the
--                       customer); this row stores only the authorization.
--                       An MSP may ask for a report of an engagement it
--                       initiated under MSP-003 ('requested'); only the
--                       customer's own tenant_admin can make a share active.
--
-- Invariants enforced by the schema (the application enforces the same rules):
--   - Distinct parties; idempotent per (customer, msp, origin, request_key).
--   - An active or revoked share is bound to an exact report id, version and
--     fingerprint, names the deciding subject and time, and has an expiry
--     after the decision.
--   - At most one active share per (customer, msp, report): a concurrent
--     second approval cannot create a duplicate authorization.
--   - A revoked share names who revoked it and when; rows are never deleted,
--     so the access history survives revocation.
--
-- Tenant isolation: RLS is forced, with no empty-context bypass. A share is
-- visible to its customer and its MSP only.
--
-- Safety: additive only. No existing row or constraint is changed. No
-- CREATE INDEX CONCURRENTLY (api/db_migrations.py runs in one transaction).

CREATE TABLE IF NOT EXISTS msp_report_shares (
    id                         VARCHAR(36)  PRIMARY KEY,
    tenant_id                  VARCHAR(128) NOT NULL,
    msp_tenant_id              VARCHAR(128) NOT NULL,
    relationship_id            VARCHAR(36)  NOT NULL
                                   REFERENCES msp_service_relationships (id),
    origin                     VARCHAR(16)  NOT NULL
                                   CHECK (origin IN ('customer', 'msp')),
    request_key                VARCHAR(128) NOT NULL,
    engagement_id              VARCHAR(64)  NOT NULL,
    source_grant_id            VARCHAR(36),
    report_id                  VARCHAR(255),
    report_version             INTEGER,
    manifest_hash              VARCHAR(128),
    status                     VARCHAR(16)  NOT NULL
                                   CHECK (status IN ('requested', 'active', 'rejected',
                                                     'withdrawn', 'revoked')),
    requested_by_subject       TEXT         NOT NULL,
    requested_at               TIMESTAMPTZ  NOT NULL,
    decided_by_subject         TEXT,
    decided_by_membership_id   VARCHAR(128),
    decided_at                 TIMESTAMPTZ,
    expires_at                 TIMESTAMPTZ,
    revoked_by_subject         TEXT,
    revoked_at                 TIMESTAMPTZ,
    version                    INTEGER      NOT NULL DEFAULT 1,
    created_at                 TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at                 TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT msp_share_distinct_parties CHECK (msp_tenant_id <> tenant_id),
    CONSTRAINT msp_share_bound_report CHECK (
        status NOT IN ('active', 'revoked')
        OR (report_id IS NOT NULL AND report_version IS NOT NULL
            AND manifest_hash IS NOT NULL AND decided_by_subject IS NOT NULL
            AND decided_at IS NOT NULL AND expires_at IS NOT NULL
            AND expires_at > decided_at)
    ),
    CONSTRAINT msp_share_rejected_fields CHECK (
        status <> 'rejected'
        OR (decided_by_subject IS NOT NULL AND decided_at IS NOT NULL)
    ),
    CONSTRAINT msp_share_revoked_fields CHECK (
        status <> 'revoked'
        OR (revoked_by_subject IS NOT NULL AND revoked_at IS NOT NULL)
    ),
    CONSTRAINT msp_share_msp_origin_has_grant CHECK (
        origin <> 'msp' OR source_grant_id IS NOT NULL
    ),
    CONSTRAINT uq_msp_share_request_key
        UNIQUE (tenant_id, msp_tenant_id, origin, request_key)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_msp_share_active_report
    ON msp_report_shares (tenant_id, msp_tenant_id, report_id)
    WHERE status = 'active';
CREATE INDEX IF NOT EXISTS ix_msp_share_customer_status
    ON msp_report_shares (tenant_id, status);
CREATE INDEX IF NOT EXISTS ix_msp_share_msp_status
    ON msp_report_shares (msp_tenant_id, status);
CREATE INDEX IF NOT EXISTS ix_msp_share_relationship
    ON msp_report_shares (relationship_id);

ALTER TABLE msp_report_shares ENABLE ROW LEVEL SECURITY;
ALTER TABLE msp_report_shares FORCE ROW LEVEL SECURITY;
DO $$ BEGIN
    DROP POLICY IF EXISTS msp_report_shares_tenant_isolation ON msp_report_shares;
    CREATE POLICY msp_report_shares_tenant_isolation ON msp_report_shares
        USING (tenant_id = current_setting('app.tenant_id', true)
               OR msp_tenant_id = current_setting('app.tenant_id', true))
        WITH CHECK (tenant_id = current_setting('app.tenant_id', true)
                    OR msp_tenant_id = current_setting('app.tenant_id', true));
END $$;
