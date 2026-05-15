-- 0050_tenant_provisioning.sql
-- PR 81 — Enterprise Tenant Provisioning & Organization Onboarding Foundation.
-- Touching schema — flagged explicitly per CLAUDE.md.
--
-- Adds three tables:
--   provisioning_organizations  — org lifecycle records (platform + tenant-linked)
--   provisioning_workflows      — per-org provisioning workflow runs
--   provisioning_audit_events   — append-only audit trail (hash-chained)
--
-- Security posture:
--   - No secrets, credentials, or raw error messages stored.
--   - tenant_id nullable: NULL = platform-level org, non-NULL = tenant-linked.
--   - provisioning_audit_events enforced append-only via Postgres rules.
--   - All tables are fully idempotent (CREATE TABLE IF NOT EXISTS).
--
-- Downgrade: tables can be dropped safely — no foreign keys to existing tables.

-- ─── Provisioning Organizations ──────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS provisioning_organizations (
    organization_id          TEXT         PRIMARY KEY,
    tenant_id                TEXT,
    org_name                 TEXT         NOT NULL,
    slug                     TEXT         NOT NULL UNIQUE,
    lifecycle_status         TEXT         NOT NULL DEFAULT 'pending',
    compliance_classification TEXT        NOT NULL DEFAULT 'standard',
    deployment_tier          TEXT         NOT NULL DEFAULT 'shared',
    onboarding_state         TEXT         NOT NULL DEFAULT 'not_started',
    env_assignment_id        TEXT,
    region                   TEXT,
    idempotency_key          TEXT,
    metadata_json            TEXT         NOT NULL DEFAULT '{}',
    created_by               TEXT         NOT NULL,
    created_at               TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    activated_at             TIMESTAMPTZ,
    suspended_at             TIMESTAMPTZ,
    archived_at              TIMESTAMPTZ,
    state_version            INTEGER      NOT NULL DEFAULT 0,

    CONSTRAINT chk_prov_org_lifecycle CHECK (
        lifecycle_status IN ('pending', 'provisioning', 'active', 'suspended', 'archived', 'failed')
    ),
    CONSTRAINT chk_prov_org_compliance CHECK (
        compliance_classification IN ('standard', 'regulated', 'hipaa', 'fedramp', 'govcon')
    ),
    CONSTRAINT chk_prov_org_tier CHECK (
        deployment_tier IN ('shared', 'dedicated', 'regulated_dedicated')
    ),
    CONSTRAINT chk_prov_org_onboarding CHECK (
        onboarding_state IN ('not_started', 'in_progress', 'pending_activation', 'completed', 'failed')
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS ix_prov_org_slug
    ON provisioning_organizations (slug);

CREATE INDEX IF NOT EXISTS ix_prov_org_tenant
    ON provisioning_organizations (tenant_id);

-- Tenant-scoped idempotency: (tenant_id, idempotency_key) unique within a tenant;
-- platform-level orgs (tenant_id IS NULL) share a separate namespace.
CREATE UNIQUE INDEX IF NOT EXISTS ix_prov_org_idem_tenant
    ON provisioning_organizations (tenant_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL AND tenant_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS ix_prov_org_idem_platform
    ON provisioning_organizations (idempotency_key)
    WHERE idempotency_key IS NOT NULL AND tenant_id IS NULL;

CREATE INDEX IF NOT EXISTS ix_prov_org_lifecycle
    ON provisioning_organizations (lifecycle_status);

CREATE INDEX IF NOT EXISTS ix_prov_org_state_version
    ON provisioning_organizations (state_version);

-- ─── Provisioning Workflows ───────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS provisioning_workflows (
    provisioning_id              TEXT         PRIMARY KEY,
    organization_id              TEXT         NOT NULL,
    tenant_id                    TEXT,
    workflow_state               TEXT         NOT NULL DEFAULT 'pending',
    current_step                 TEXT,
    idempotency_key              TEXT,
    parent_provisioning_id       TEXT,
    env_target                   TEXT,
    retry_count                  INTEGER      NOT NULL DEFAULT 0,
    max_retries                  INTEGER      NOT NULL DEFAULT 3,
    failure_reason               TEXT,
    failure_category             TEXT,
    validation_results_json      TEXT         NOT NULL DEFAULT '{}',
    orchestration_metadata_json  TEXT         NOT NULL DEFAULT '{}',
    initiated_by                 TEXT         NOT NULL,
    started_at                   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    completed_at                 TIMESTAMPTZ,
    last_updated_at              TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    state_version                INTEGER      NOT NULL DEFAULT 0,

    CONSTRAINT chk_prov_wf_state CHECK (
        workflow_state IN ('pending', 'running', 'completed', 'failed', 'cancelled')
    ),
    CONSTRAINT chk_prov_wf_failure_category CHECK (
        failure_category IS NULL OR failure_category IN (
            'retryable', 'terminal', 'validation', 'orchestration_interrupted',
            'env_incompatible', 'approval_failure', 'compliance_failure'
        )
    )
);

CREATE INDEX IF NOT EXISTS ix_prov_wf_org
    ON provisioning_workflows (organization_id);

CREATE INDEX IF NOT EXISTS ix_prov_wf_tenant
    ON provisioning_workflows (tenant_id);

CREATE INDEX IF NOT EXISTS ix_prov_wf_state
    ON provisioning_workflows (workflow_state);

CREATE INDEX IF NOT EXISTS ix_prov_wf_parent
    ON provisioning_workflows (parent_provisioning_id)
    WHERE parent_provisioning_id IS NOT NULL;

-- Tenant-scoped workflow idempotency: same semantics as org idempotency above.
CREATE UNIQUE INDEX IF NOT EXISTS ix_prov_wf_idem_tenant
    ON provisioning_workflows (tenant_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL AND tenant_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS ix_prov_wf_idem_platform
    ON provisioning_workflows (idempotency_key)
    WHERE idempotency_key IS NOT NULL AND tenant_id IS NULL;

-- ─── Provisioning Audit Events ────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS provisioning_audit_events (
    event_id          TEXT         PRIMARY KEY,
    organization_id   TEXT         NOT NULL,
    provisioning_id   TEXT,
    tenant_id         TEXT,
    env_id            TEXT,
    event_type        TEXT         NOT NULL,
    actor             TEXT         NOT NULL,
    outcome           TEXT         NOT NULL DEFAULT 'success',
    workflow_state    TEXT,
    failure_reason    TEXT,
    details_json      TEXT         NOT NULL DEFAULT '{}',
    event_hash        TEXT,
    previous_event_hash TEXT,
    timestamp         TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_prov_audit_outcome CHECK (
        outcome IN ('success', 'failure', 'pending')
    )
);

CREATE INDEX IF NOT EXISTS ix_prov_audit_org
    ON provisioning_audit_events (organization_id);

CREATE INDEX IF NOT EXISTS ix_prov_audit_provisioning
    ON provisioning_audit_events (provisioning_id);

CREATE INDEX IF NOT EXISTS ix_prov_audit_tenant
    ON provisioning_audit_events (tenant_id);

CREATE INDEX IF NOT EXISTS ix_prov_audit_timestamp
    ON provisioning_audit_events (timestamp);

-- Append-only enforcement (same pattern as deployment_events in 0048)
CREATE OR REPLACE RULE provisioning_audit_events_no_update AS
  ON UPDATE TO provisioning_audit_events DO INSTEAD NOTHING;

CREATE OR REPLACE RULE provisioning_audit_events_no_delete AS
  ON DELETE TO provisioning_audit_events DO INSTEAD NOTHING;
