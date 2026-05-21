-- Migration: create governance_assets table + add provenance columns
-- Root cause repair (PR 8 CI regression):
--   PR 3.5 introduced governance_assets via ORM only — no SQL migration was
--   ever written for the table.  Base.metadata.create_all() masked the gap in
--   SQLite.  Migration 0062 attempted ALTER TABLE governance_assets ADD COLUMN
--   on a table that had never been created by any prior migration, causing
--   Docker Compose frostgate-migrate to exit 1 on a fresh Postgres database.
--
-- This migration:
--   1. Creates governance_assets for fresh PostgreSQL databases (idempotent).
--   2. Adds provenance columns for databases where the table already existed
--      without them (created by create_all in dev/staging environments).
--   3. Creates all indexes with IF NOT EXISTS so replay is safe in every state.
--
-- Idempotency guarantees:
--   - Fresh Postgres replay from zero: CREATE TABLE runs; ALTERs are no-ops.
--   - Existing DB without provenance cols: CREATE TABLE is no-op; ALTERs add cols.
--   - Existing DB with provenance cols:    all are no-ops; indexes upserted safely.

BEGIN;

CREATE TABLE IF NOT EXISTS governance_assets (
    asset_id                TEXT        NOT NULL,
    tenant_id               TEXT        NOT NULL,
    asset_type              TEXT        NOT NULL,
    name                    TEXT        NOT NULL,
    description             TEXT,
    status                  TEXT        NOT NULL DEFAULT 'active',
    risk_tier               TEXT        NOT NULL DEFAULT 'unclassified',
    risk_score              INTEGER     NOT NULL DEFAULT 0,
    discovery_source        TEXT        NOT NULL DEFAULT 'declared',
    external_id             TEXT,
    metadata_json           JSONB       NOT NULL DEFAULT '{}',
    current_version_hash    TEXT,
    schema_version          TEXT        NOT NULL DEFAULT '1.0',
    created_at              TEXT        NOT NULL,
    updated_at              TEXT        NOT NULL,
    created_by_email        TEXT        NOT NULL,
    source_scan_result_id   TEXT,
    source_engagement_id    TEXT,
    PRIMARY KEY (asset_id)
);

-- Handles databases where the table existed before this migration without provenance cols
ALTER TABLE governance_assets
    ADD COLUMN IF NOT EXISTS source_scan_result_id TEXT;

ALTER TABLE governance_assets
    ADD COLUMN IF NOT EXISTS source_engagement_id TEXT;

CREATE INDEX IF NOT EXISTS ix_ga_assets_tenant_id
    ON governance_assets (tenant_id);

CREATE INDEX IF NOT EXISTS ix_ga_assets_tenant_type
    ON governance_assets (tenant_id, asset_type);

CREATE INDEX IF NOT EXISTS ix_ga_assets_tenant_status
    ON governance_assets (tenant_id, status);

CREATE INDEX IF NOT EXISTS ix_ga_assets_tenant_risk_tier
    ON governance_assets (tenant_id, risk_tier);

CREATE INDEX IF NOT EXISTS ix_ga_assets_tenant_discovery
    ON governance_assets (tenant_id, discovery_source);

CREATE INDEX IF NOT EXISTS ix_ga_assets_external_id
    ON governance_assets (tenant_id, external_id);

CREATE INDEX IF NOT EXISTS ix_ga_assets_current_version_hash
    ON governance_assets (current_version_hash);

CREATE INDEX IF NOT EXISTS ix_ga_assets_source_scan
    ON governance_assets (tenant_id, source_scan_result_id)
    WHERE source_scan_result_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS ix_ga_assets_source_engagement
    ON governance_assets (tenant_id, source_engagement_id)
    WHERE source_engagement_id IS NOT NULL;

COMMIT;
