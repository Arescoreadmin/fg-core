-- Migration 0103: Identity Governance Actions Ledger
-- Append-only table recording governance decisions on recommendations.
-- Each row is a decision event; current state per dimension = latest row.
-- SCHEMA CHANGE — must be called out.

CREATE TABLE IF NOT EXISTS tenant_identity_governance_actions (
    id                  TEXT        PRIMARY KEY,
    tenant_id           TEXT        NOT NULL,
    dimension           TEXT        NOT NULL,
    action_state        TEXT        NOT NULL,   -- accepted|rejected|deferred|implemented
    actor_id            TEXT,
    actor_email         TEXT,
    actor_role          TEXT,
    reason              TEXT,
    outcome             TEXT,
    deferred_until      TEXT,                   -- ISO date; populated when action_state='deferred'
    snapshot_id         TEXT,                   -- optional ref to governance snapshot at time of action
    previous_action_id  TEXT,                   -- linked-list pointer to prior action on same dimension
    created_at          TEXT        NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_tiga_tenant_dim
    ON tenant_identity_governance_actions (tenant_id, dimension, created_at DESC);

CREATE INDEX IF NOT EXISTS ix_tiga_tenant_created
    ON tenant_identity_governance_actions (tenant_id, created_at DESC);
