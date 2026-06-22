-- Migration: create governance_promotions table
-- PR 8: the promotion record is the authoritative signal that a tenant has
-- graduated from assessment-only to continuous governance.  One record per
-- engagement; unique constraint enforces idempotency.

BEGIN;

CREATE TABLE IF NOT EXISTS governance_promotions (
    id                      TEXT        PRIMARY KEY,
    tenant_id               TEXT        NOT NULL,
    engagement_id           TEXT        NOT NULL,
    status                  TEXT        NOT NULL DEFAULT 'pending',
    promoted_at             TEXT        NOT NULL,
    completed_at            TEXT,
    asset_count             INTEGER     NOT NULL DEFAULT 0,
    workflow_count          INTEGER     NOT NULL DEFAULT 0,
    corpus_entries_added    INTEGER     NOT NULL DEFAULT 0,
    baseline_readiness_score INTEGER    NOT NULL DEFAULT 0,
    gate_snapshot_json      TEXT        NOT NULL DEFAULT '{}',
    error_detail            TEXT,
    schema_version          TEXT        NOT NULL DEFAULT '1.0'
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_governance_promotions_engagement
    ON governance_promotions (tenant_id, engagement_id);

CREATE INDEX IF NOT EXISTS ix_governance_promotions_tenant_status
    ON governance_promotions (tenant_id, status);

COMMIT;
