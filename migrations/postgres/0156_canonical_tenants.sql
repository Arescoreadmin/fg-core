-- Migration 0156: canonical tenants table
-- Establishes Postgres as the authoritative source for tenant identity.
-- Before this migration, tenant identity lived in state/tenants.json on the
-- API server filesystem. See docs/ai/R1_AUTHORITY_AUDIT.md for context.
--
-- R3 will add richer lifecycle semantics; R7 only needs enough to migrate
-- and operate safely.
--
-- No RLS: tenants is a platform-level table, not a per-tenant resource.
-- The tenant_id IS the tenant identity, not a scope boundary.

CREATE TABLE IF NOT EXISTS tenants (
    tenant_id           VARCHAR(128)    PRIMARY KEY,
    display_name        TEXT            NOT NULL,
    lifecycle_state     VARCHAR(32)     NOT NULL DEFAULT 'active',
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ     NOT NULL DEFAULT now(),
    created_by          TEXT,
    metadata            JSONB           NOT NULL DEFAULT '{}',
    canonical_version   INTEGER         NOT NULL DEFAULT 1,
    last_reconciled_at  TIMESTAMPTZ,
    archived_at         TIMESTAMPTZ,
    migration_source    VARCHAR(32),
    migration_version   VARCHAR(32)
);

CREATE INDEX IF NOT EXISTS ix_tenants_lifecycle_state
    ON tenants (lifecycle_state);
CREATE INDEX IF NOT EXISTS ix_tenants_created_at
    ON tenants (created_at);

-- tenant_migration_ledger: append-only record of each migrate_to_postgres.py run
CREATE TABLE IF NOT EXISTS tenant_migration_ledger (
    ledger_id           VARCHAR(64)     PRIMARY KEY,
    run_at              TIMESTAMPTZ     NOT NULL DEFAULT now(),
    source              VARCHAR(32)     NOT NULL,
    source_checksum     VARCHAR(64),
    tenants_found       INTEGER         NOT NULL DEFAULT 0,
    tenants_created     INTEGER         NOT NULL DEFAULT 0,
    tenants_skipped     INTEGER         NOT NULL DEFAULT 0,
    tenants_failed      INTEGER         NOT NULL DEFAULT 0,
    warnings            JSONB           NOT NULL DEFAULT '[]',
    status              VARCHAR(32)     NOT NULL DEFAULT 'running',
    completed_at        TIMESTAMPTZ
);
