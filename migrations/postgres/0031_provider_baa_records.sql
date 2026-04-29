-- 0031_provider_baa_records.sql
-- Tenant-scoped provider BAA (Business Associate Agreement) records.
--
-- Enforces that regulated AI providers (those processing PHI/ePHI) may only
-- be used by tenants with an active, non-expired BAA. Used by the provider
-- BAA enforcement boundary (services/provider_baa/policy.py) to gate all
-- provider routing decisions before dispatch.
--
-- Design: one authoritative row per (tenant_id, provider_id).
-- History is intentionally NOT modeled here — update the row, rely on
-- audit logs for change history. If historical rows become required, add
-- a separate audit_provider_baa_history table rather than creating
-- ambiguous multi-row semantics here.

CREATE TABLE IF NOT EXISTS provider_baa_records (
    id              BIGSERIAL    PRIMARY KEY,
    tenant_id       TEXT         NOT NULL,
    provider_id     TEXT         NOT NULL,
    baa_status      TEXT         NOT NULL
        CHECK (baa_status IN ('active', 'expired', 'missing', 'revoked', 'pending')),
    expiry_date     DATE,                          -- NULL = no expiry clause
    signed_at       TIMESTAMPTZ,                   -- when the BAA was executed
    document_ref    TEXT,                          -- opaque reference (no raw text)
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_provider_baa_records_tenant_provider
        UNIQUE (tenant_id, provider_id)
);

CREATE INDEX IF NOT EXISTS ix_provider_baa_records_tenant_provider
    ON provider_baa_records (tenant_id, provider_id);

CREATE INDEX IF NOT EXISTS ix_provider_baa_records_tenant_status
    ON provider_baa_records (tenant_id, baa_status);

ALTER TABLE IF EXISTS provider_baa_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS provider_baa_records FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename   = 'provider_baa_records'
          AND policyname  = 'provider_baa_records_tenant_isolation'
    ) THEN
        CREATE POLICY provider_baa_records_tenant_isolation
            ON provider_baa_records
            USING  (tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
    END IF;
END $$;
