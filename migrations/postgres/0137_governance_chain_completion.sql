-- PR 17.6A: Governance Chain Completion — health snapshot v2 fields

ALTER TABLE fa_governance_health_snapshots
    ADD COLUMN IF NOT EXISTS governance_momentum DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS governance_stability DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS governance_confidence DOUBLE PRECISION;
