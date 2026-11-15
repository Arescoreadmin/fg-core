-- Migration 0207: MSP-006 — payer assignments and database isolation for usage.
--
-- Adds:
--   msp_payer_assignments — which party pays for one billable product delivered to
--                           one customer under one MSP relationship. A platform
--                           decision bound to the payer's existing commercial
--                           agreement (subscription_contracts). It is not a billing
--                           engine: usage stays in usage_events, prices in
--                           pricing_versions / tenant_contracts.
--
-- Repairs (MSP-006 audit finding F1):
--   usage_events — existed in Postgres only through ORM create_all, so it never had
--                  row-level security. It now holds MSP charge amounts, so it is
--                  declared here (a no-op where create_all already made it) and its
--                  RLS is enabled and forced.
--
-- Invariants enforced by the schema (the application enforces the same rules):
--   - billing_mode decides the payer: msp_paid means the MSP pays, customer_paid
--     means the customer pays. The payer is never a third party.
--   - At most one active assignment per (customer, product), so payer resolution
--     cannot be ambiguous.
--   - An assignment has a bounded validity window and a platform approver.
--   - Terminated rows always carry who terminated them and when.
--
-- Tenant isolation: RLS is forced on both tables. A payer assignment is visible
-- only to the customer tenant and the payer tenant. In customer_paid mode the MSP
-- does not see it. A usage event is visible only to its own (payer) tenant. There
-- is no empty-context bypass.
--
-- Safety: additive only. No existing row or constraint is changed. No
-- CREATE INDEX CONCURRENTLY (api/db_migrations.py runs in one transaction).

CREATE TABLE IF NOT EXISTS msp_payer_assignments (
    id                         VARCHAR(36)  PRIMARY KEY,
    tenant_id                  VARCHAR(128) NOT NULL,
    msp_tenant_id              VARCHAR(128) NOT NULL,
    relationship_id            VARCHAR(36)  NOT NULL
                                   REFERENCES msp_service_relationships (id),
    payer_tenant_id            VARCHAR(128) NOT NULL,
    billing_mode               VARCHAR(16)  NOT NULL
                                   CHECK (billing_mode IN ('msp_paid', 'customer_paid')),
    product_code               VARCHAR(64)  NOT NULL,
    subscription_contract_id   TEXT         NOT NULL,
    currency                   VARCHAR(3)   NOT NULL,
    status                     VARCHAR(16)  NOT NULL
                                   CHECK (status IN ('active', 'terminated')),
    effective_at               TIMESTAMPTZ  NOT NULL,
    expires_at                 TIMESTAMPTZ  NOT NULL,
    approved_by_subject        TEXT         NOT NULL,
    approved_at                TIMESTAMPTZ  NOT NULL,
    terminated_by_subject      TEXT,
    terminated_at              TIMESTAMPTZ,
    version                    INTEGER      NOT NULL DEFAULT 1,
    created_at                 TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at                 TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT msp_payer_mode_matches_payer CHECK (
        (billing_mode = 'msp_paid' AND payer_tenant_id = msp_tenant_id)
        OR (billing_mode = 'customer_paid' AND payer_tenant_id = tenant_id)
    ),
    CONSTRAINT msp_payer_distinct_parties CHECK (msp_tenant_id <> tenant_id),
    CONSTRAINT msp_payer_window CHECK (expires_at > effective_at),
    CONSTRAINT msp_payer_currency_code CHECK (length(currency) = 3 AND currency = upper(currency)),
    CONSTRAINT msp_payer_terminated_fields CHECK (
        status <> 'terminated'
        OR (terminated_by_subject IS NOT NULL AND terminated_at IS NOT NULL)
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_msp_payer_one_active_per_product
    ON msp_payer_assignments (tenant_id, product_code)
    WHERE status = 'active';
CREATE INDEX IF NOT EXISTS ix_msp_payer_payer_status
    ON msp_payer_assignments (payer_tenant_id, status);
CREATE INDEX IF NOT EXISTS ix_msp_payer_relationship
    ON msp_payer_assignments (relationship_id);

ALTER TABLE msp_payer_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE msp_payer_assignments FORCE ROW LEVEL SECURITY;
DO $$ BEGIN
    DROP POLICY IF EXISTS msp_payer_assignments_tenant_isolation ON msp_payer_assignments;
    CREATE POLICY msp_payer_assignments_tenant_isolation ON msp_payer_assignments
        USING (tenant_id = current_setting('app.tenant_id', true)
               OR payer_tenant_id = current_setting('app.tenant_id', true))
        WITH CHECK (tenant_id = current_setting('app.tenant_id', true)
                    OR payer_tenant_id = current_setting('app.tenant_id', true));
END $$;

-- usage_events: matches api/db_models_billing.py:UsageEvent. create_all runs before
-- migrations (api/db.py), so in a normal start this statement is a no-op.
CREATE TABLE IF NOT EXISTS usage_events (
    id                    TEXT         PRIMARY KEY,
    tenant_id             TEXT         NOT NULL,
    subscription_item_id  TEXT,
    meter_code            TEXT         NOT NULL,
    quantity              TEXT         NOT NULL,
    idempotency_key       TEXT         NOT NULL,
    source                TEXT         NOT NULL DEFAULT 'api',
    occurred_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    reported_at           TIMESTAMPTZ,
    billing_status        TEXT         NOT NULL DEFAULT 'pending',
    provider_event_id     TEXT,
    metadata_json         JSON         NOT NULL DEFAULT '{}',
    CONSTRAINT uq_usage_events_idempotency UNIQUE (tenant_id, idempotency_key)
);
CREATE INDEX IF NOT EXISTS idx_usage_events_tenant ON usage_events (tenant_id);
CREATE INDEX IF NOT EXISTS idx_usage_events_tenant_status
    ON usage_events (tenant_id, billing_status);
CREATE INDEX IF NOT EXISTS idx_usage_events_meter ON usage_events (meter_code);

ALTER TABLE usage_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE usage_events FORCE ROW LEVEL SECURITY;
DO $$ BEGIN
    DROP POLICY IF EXISTS usage_events_tenant_isolation ON usage_events;
    CREATE POLICY usage_events_tenant_isolation ON usage_events
        USING (tenant_id = current_setting('app.tenant_id', true))
        WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
END $$;
