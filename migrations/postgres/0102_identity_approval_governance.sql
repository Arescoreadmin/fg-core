-- Migration 0102: Identity Approval Workflow + Governance Snapshots
-- PR7: Approval state columns on tenant_invitations; historical posture snapshot table.
--
-- Replay-safe: ADD COLUMN IF NOT EXISTS; CREATE TABLE IF NOT EXISTS.

ALTER TABLE tenant_invitations
    ADD COLUMN IF NOT EXISTS approval_required BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS approval_state    TEXT    NOT NULL DEFAULT 'not_required',
    ADD COLUMN IF NOT EXISTS approval_reason   TEXT;

-- Historical governance snapshots for posture trending
CREATE TABLE IF NOT EXISTS tenant_identity_governance_snapshots (
    id            TEXT    PRIMARY KEY,
    tenant_id     TEXT    NOT NULL,
    score         INTEGER NOT NULL,
    max_score     INTEGER NOT NULL,
    percent       REAL    NOT NULL,
    grade         TEXT    NOT NULL,
    dimensions    TEXT    NOT NULL DEFAULT '{}',
    created_at    TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_igov_snapshots_tenant_created
    ON tenant_identity_governance_snapshots (tenant_id, created_at DESC);
