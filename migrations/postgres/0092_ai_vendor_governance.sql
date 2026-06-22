-- Migration 0092: PR 4 — Third-Party AI Governance Workflow Engine
-- Creates fa_ai_vendor_governance_records and fa_ai_vendor_governance_decisions
-- with append-only DB triggers on the decisions table.
--
-- Safe to replay: all DDL uses IF NOT EXISTS / IF EXISTS guards.

-- -------------------------------------------------------------------------
-- Governance records table
-- -------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS fa_ai_vendor_governance_records (
    id                          VARCHAR(64)     PRIMARY KEY,
    tenant_id                   VARCHAR(255)    NOT NULL,
    engagement_id               VARCHAR(64)     NOT NULL,
    vendor                      VARCHAR(255)    NOT NULL,
    tool_name                   VARCHAR(255)    NOT NULL,
    tool_id                     VARCHAR(255),
    target_type                 VARCHAR(64)     NOT NULL DEFAULT 'ai_tool',
    workflow_state              VARCHAR(32)     NOT NULL DEFAULT 'discovered',

    -- Ownership
    business_owner              VARCHAR(255),
    technical_owner             VARCHAR(255),
    executive_sponsor           VARCHAR(255),

    -- Business context
    business_justification      TEXT,
    business_process            VARCHAR(255),
    department                  VARCHAR(255),
    criticality                 VARCHAR(32)     NOT NULL DEFAULT 'unknown',

    -- Data governance
    data_processed              JSONB           NOT NULL DEFAULT '[]',
    sensitive_data_types        JSONB           NOT NULL DEFAULT '[]',
    regulated_data_present      BOOLEAN         NOT NULL DEFAULT FALSE,
    data_residency_notes        TEXT,

    -- Contract governance
    contract_status             VARCHAR(32)     NOT NULL DEFAULT 'unknown',
    contract_owner              VARCHAR(255),
    contract_expiration         VARCHAR(64),
    renewal_date                VARCHAR(64),

    -- DPA governance
    dpa_required                BOOLEAN         NOT NULL DEFAULT FALSE,
    dpa_status                  VARCHAR(32)     NOT NULL DEFAULT 'unknown',
    dpa_review_date             VARCHAR(64),

    -- Healthcare (BAA)
    baa_required                BOOLEAN         NOT NULL DEFAULT FALSE,
    baa_status                  VARCHAR(32)     NOT NULL DEFAULT 'unknown',
    baa_review_date             VARCHAR(64),

    -- Security review
    security_review_status      VARCHAR(32)     NOT NULL DEFAULT 'not_started',
    security_review_date        VARCHAR(64),
    security_reviewer           VARCHAR(255),

    -- Privacy review
    privacy_review_status       VARCHAR(32)     NOT NULL DEFAULT 'not_started',
    privacy_review_date         VARCHAR(64),
    privacy_reviewer            VARCHAR(255),

    -- Compliance evidence
    soc2_available              BOOLEAN         NOT NULL DEFAULT FALSE,
    soc2_reviewed               BOOLEAN         NOT NULL DEFAULT FALSE,
    soc2_review_date            VARCHAR(64),
    iso27001_available          BOOLEAN         NOT NULL DEFAULT FALSE,
    iso27001_reviewed           BOOLEAN         NOT NULL DEFAULT FALSE,
    iso_review_date             VARCHAR(64),

    -- Risk governance
    risk_acceptance_required    BOOLEAN         NOT NULL DEFAULT FALSE,
    risk_acceptance_status      VARCHAR(32)     NOT NULL DEFAULT 'unknown',
    risk_acceptance_owner       VARCHAR(255),
    risk_acceptance_expiration  VARCHAR(64),

    -- Lifecycle governance
    review_due_date             VARCHAR(64),
    last_review_date            VARCHAR(64),
    renewal_due_date            VARCHAR(64),
    retirement_date             VARCHAR(64),

    -- Governance readiness (deterministic, recomputed each run)
    governance_readiness        VARCHAR(32)     NOT NULL DEFAULT 'unknown',

    -- Source cross-references (PR 1/2/3)
    pr1_scan_result_id          VARCHAR(64),
    pr2_scan_result_id          VARCHAR(64),
    pr3_risk_record_id          VARCHAR(64),
    risk_score                  VARCHAR(32)     NOT NULL DEFAULT 'unknown',
    risk_categories             JSONB           NOT NULL DEFAULT '[]',
    regulatory_flags            JSONB           NOT NULL DEFAULT '[]',

    -- Evidence / finding cross-references
    evidence_refs               JSONB           NOT NULL DEFAULT '[]',
    finding_refs                JSONB           NOT NULL DEFAULT '[]',

    -- Graph-ready identifiers
    graph_node_id               VARCHAR(255),
    vendor_node_id              VARCHAR(255),
    owner_node_id               VARCHAR(255),
    contract_node_id            VARCHAR(255),
    evidence_node_id            VARCHAR(255),
    decision_node_id            VARCHAR(255),
    governance_node_id          VARCHAR(255),

    -- Source scan traceability
    source_scan_result_id       VARCHAR(64),

    -- Timestamps
    created_at                  VARCHAR(64)     NOT NULL,
    updated_at                  VARCHAR(64)     NOT NULL,
    last_reviewed_at            VARCHAR(64),

    CONSTRAINT uq_fa_ai_vendor_gov_tool
        UNIQUE (engagement_id, tenant_id, tool_name)
);

CREATE INDEX IF NOT EXISTS ix_fa_ai_vendor_gov_tenant_eng
    ON fa_ai_vendor_governance_records (tenant_id, engagement_id);

CREATE INDEX IF NOT EXISTS ix_fa_ai_vendor_gov_tenant_state
    ON fa_ai_vendor_governance_records (tenant_id, workflow_state);

CREATE INDEX IF NOT EXISTS ix_fa_ai_vendor_gov_tenant_readiness
    ON fa_ai_vendor_governance_records (tenant_id, governance_readiness);

CREATE INDEX IF NOT EXISTS ix_fa_ai_vendor_gov_tenant_risk
    ON fa_ai_vendor_governance_records (tenant_id, risk_score);

-- -------------------------------------------------------------------------
-- Governance decisions table (append-only)
-- -------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS fa_ai_vendor_governance_decisions (
    decision_id             VARCHAR(64)     PRIMARY KEY,
    tenant_id               VARCHAR(255)    NOT NULL,
    engagement_id           VARCHAR(64)     NOT NULL,
    governance_record_id    VARCHAR(64)     NOT NULL,

    -- Tool identity (duplicated for auditability — survives record changes)
    vendor                  VARCHAR(255)    NOT NULL,
    tool_name               VARCHAR(255)    NOT NULL,
    target_type             VARCHAR(64)     NOT NULL DEFAULT 'ai_tool',

    -- Decision
    decision                VARCHAR(64)     NOT NULL,
    reason                  TEXT            NOT NULL,
    previous_state          VARCHAR(32),
    new_state               VARCHAR(32),

    -- Actor attribution
    actor_id                VARCHAR(255),
    actor_name              VARCHAR(255)    NOT NULL,
    actor_email             VARCHAR(255),

    -- Evidence and context
    evidence_refs           JSONB           NOT NULL DEFAULT '[]',
    notes                   TEXT,
    exception_expiration    VARCHAR(64),

    created_at              VARCHAR(64)     NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_fa_ai_vendor_gov_dec_tenant_eng
    ON fa_ai_vendor_governance_decisions (tenant_id, engagement_id);

CREATE INDEX IF NOT EXISTS ix_fa_ai_vendor_gov_dec_record
    ON fa_ai_vendor_governance_decisions (governance_record_id);

-- -------------------------------------------------------------------------
-- Append-only DB triggers on governance decisions
-- No UPDATE or DELETE permitted — any attempt raises an exception.
-- -------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION fg_prevent_vendor_gov_decision_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION
        'fa_ai_vendor_governance_decisions rows are append-only — '
        'create a new decision record instead of modifying this one';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_prevent_vendor_gov_decision_update
    ON fa_ai_vendor_governance_decisions;
CREATE TRIGGER trg_prevent_vendor_gov_decision_update
    BEFORE UPDATE ON fa_ai_vendor_governance_decisions
    FOR EACH ROW EXECUTE FUNCTION fg_prevent_vendor_gov_decision_mutation();

DROP TRIGGER IF EXISTS trg_prevent_vendor_gov_decision_delete
    ON fa_ai_vendor_governance_decisions;
CREATE TRIGGER trg_prevent_vendor_gov_decision_delete
    BEFORE DELETE ON fa_ai_vendor_governance_decisions
    FOR EACH ROW EXECUTE FUNCTION fg_prevent_vendor_gov_decision_mutation();

-- -------------------------------------------------------------------------
-- Extend fa_scan_jobs scanner_type constraint
-- -------------------------------------------------------------------------

ALTER TABLE fa_scan_jobs DROP CONSTRAINT IF EXISTS fa_scan_jobs_scanner_type_check;
ALTER TABLE fa_scan_jobs
    ADD CONSTRAINT fa_scan_jobs_scanner_type_check
    CHECK (scanner_type IN (
        'msgraph', 'network_scan', 'dns_email', 'web_headers',
        'oauth_inventory', 'oauth_risk', 'endpoint_inventory',
        'entra_governance', 'sharepoint',
        'ai_tool_discovery', 'ai_data_access_mapping',
        'external_ai_risk_register', 'ai_vendor_governance'
    ));
