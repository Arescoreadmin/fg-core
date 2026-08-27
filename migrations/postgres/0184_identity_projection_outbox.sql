-- 0184_identity_projection_outbox
-- AUTH-ROLE-001B: Transactional outbox for FrostGate→Auth0 app_metadata projection.
--
-- Depends on:
--   0181 tenant_users.principal_id
--   0183 bound_membership_principal_integrity
--
-- This table stores pending projection events so that FrostGate identity state
-- (principal_id, roles, membership_version) converges into Auth0 app_metadata
-- without making Auth0 an authority. The outbox is consumed by projection_worker.py.
--
-- Auth0 tokens/credentials are never stored in this table.
--
-- Stale-write safety: projection_revision (= membership_version) is compared
-- against the existing app_metadata.projection_revision before any write.
-- Workers skip rows whose revision ≤ the revision already in Auth0.
--
-- Rollback:
--   DROP TABLE IF EXISTS identity_projection_outbox;

CREATE TABLE IF NOT EXISTS identity_projection_outbox (
    id                  UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    principal_id        UUID            NOT NULL,
    membership_id       TEXT            NOT NULL,
    tenant_id           TEXT            NOT NULL,
    provider            TEXT            NOT NULL,
    provider_subject    TEXT            NOT NULL,
    roles               JSONB           NOT NULL,
    projection_revision BIGINT          NOT NULL,
    status              TEXT            NOT NULL DEFAULT 'pending'
                            CHECK (status IN ('pending','processing','done','failed')),
    attempt_count       INT             NOT NULL DEFAULT 0,
    next_attempt_at     TIMESTAMPTZ     NOT NULL DEFAULT now(),
    last_error_code     TEXT,
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT now(),
    processed_at        TIMESTAMPTZ
);

-- Index for worker: grab pending rows ordered by next_attempt_at
CREATE INDEX IF NOT EXISTS ix_identity_projection_outbox_pending
    ON identity_projection_outbox (next_attempt_at)
    WHERE status IN ('pending', 'processing');

-- Index for tenant isolation queries
CREATE INDEX IF NOT EXISTS ix_identity_projection_outbox_tenant
    ON identity_projection_outbox (tenant_id);

-- Row-Level Security
ALTER TABLE identity_projection_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity_projection_outbox FORCE ROW LEVEL SECURITY;

DO $do$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE tablename = 'identity_projection_outbox'
          AND policyname = 'identity_projection_outbox_tenant_isolation'
    ) THEN
        CREATE POLICY identity_projection_outbox_tenant_isolation
            ON identity_projection_outbox
            USING (tenant_id = current_setting('app.tenant_id', true));
    END IF;
END
$do$;
