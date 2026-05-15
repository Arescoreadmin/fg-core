-- 0049_deployment_manager_hardening.sql
-- PR 80 follow-up — Deployment Manager Hardening.
-- Touching schema — flagged explicitly per CLAUDE.md.
--
-- Adds columns to the four tables created in 0048:
--
--   deployment_records:
--     approval_granted_at      — timestamp when approval was recorded
--     approval_reason          — free-text reason supplied by approver
--     approval_policy_version  — policy bundle version at approval time
--     spec_image_digest        — immutable image digest at deploy creation
--     spec_commit_sha          — commit SHA at deploy creation
--     spec_contract_hash       — contract hash at deploy creation
--     spec_topology_hash       — topology hash at deploy creation
--     spec_policy_bundle_version — policy bundle version at creation
--     spec_migration_fingerprint — migration set fingerprint at creation
--     state_version            — optimistic-lock counter (increments on each state change)
--
--   deployment_events:
--     event_hash               — SHA-256 of canonical event fields
--     previous_event_hash      — SHA-256 of prior event (tamper-evident chaining)
--
--   deployment_health_records:
--     expires_at               — optional TTL for retention enforcement
--
-- All additions are idempotent (ADD COLUMN IF NOT EXISTS).
-- Downgrade: columns can be dropped safely.

-- ─── deployment_records additions ────────────────────────────────────────────

ALTER TABLE deployment_records
    ADD COLUMN IF NOT EXISTS approval_granted_at       TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS approval_reason           TEXT,
    ADD COLUMN IF NOT EXISTS approval_policy_version   TEXT,
    ADD COLUMN IF NOT EXISTS spec_image_digest         TEXT,
    ADD COLUMN IF NOT EXISTS spec_commit_sha           TEXT,
    ADD COLUMN IF NOT EXISTS spec_contract_hash        TEXT,
    ADD COLUMN IF NOT EXISTS spec_topology_hash        TEXT,
    ADD COLUMN IF NOT EXISTS spec_policy_bundle_version TEXT,
    ADD COLUMN IF NOT EXISTS spec_migration_fingerprint TEXT,
    ADD COLUMN IF NOT EXISTS state_version             INTEGER NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS ix_deploy_record_state_version
    ON deployment_records (deployment_id, state_version);

-- ─── deployment_events additions ─────────────────────────────────────────────

ALTER TABLE deployment_events
    ADD COLUMN IF NOT EXISTS event_hash          TEXT,
    ADD COLUMN IF NOT EXISTS previous_event_hash TEXT;

CREATE INDEX IF NOT EXISTS ix_deploy_event_hash
    ON deployment_events (event_hash);

-- ─── deployment_health_records additions ─────────────────────────────────────

ALTER TABLE deployment_health_records
    ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS ix_deploy_health_expires_at
    ON deployment_health_records (expires_at)
    WHERE expires_at IS NOT NULL;
