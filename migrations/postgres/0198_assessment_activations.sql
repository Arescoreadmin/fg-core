-- Migration 0198: Assessment activation tokens for secure post-payment identity binding.
-- L14-PORTAL-HANDOFF-001: One-time activation tokens embedded in Stripe success URL.
-- Token hash stored (HMAC-SHA256 + pepper), raw token returned once at checkout creation.
-- Single-use enforced by used_at IS NULL predicate on UPDATE.

CREATE TABLE IF NOT EXISTS assessment_activations (
    id              TEXT NOT NULL PRIMARY KEY,
    assessment_id   TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    token_hash      TEXT NOT NULL UNIQUE,
    email_hint      TEXT,
    expires_at      TIMESTAMPTZ NOT NULL,
    used_at         TIMESTAMPTZ,
    state           TEXT NOT NULL DEFAULT 'pending',
    provisioned_tenant_id TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_activation_state CHECK (state IN ('pending','claimed','expired','revoked'))
);

CREATE INDEX IF NOT EXISTS ix_assessment_activations_assessment_id
    ON assessment_activations (assessment_id);

CREATE INDEX IF NOT EXISTS ix_assessment_activations_pending
    ON assessment_activations (token_hash)
    WHERE used_at IS NULL;

-- RLS: unclaimed rows (provisioned_tenant_id IS NULL) are visible in any context
-- (required for public pre-auth activation endpoint). Claimed rows are scoped
-- to the provisioned tenant.
ALTER TABLE assessment_activations ENABLE ROW LEVEL SECURITY;
CREATE POLICY assessment_activations_tenant_isolation ON assessment_activations
    USING (
        provisioned_tenant_id IS NULL
        OR provisioned_tenant_id = current_setting('app.tenant_id', TRUE)
    );
