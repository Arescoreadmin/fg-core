-- Migration 0091: PR 3 Addendum — Governance Intelligence & Regulatory Hardening
--
-- Extends fa_external_ai_risk_records with:
--   Addition 1  — Ownership model (risk_owner, owner_type)
--   Addition 2  — Governance state (governance_state)
--   Addition 3  — Decision linkage (decision_refs, risk_acceptance_refs, exception_refs, approval_refs)
--   Addition 4  — Vendor governance status (vendor_review_status, vendor_dpa_status,
--                  vendor_baa_status, vendor_security_review_status, vendor_last_reviewed_at)
--   Addition 5  — Regulatory impact flags (regulatory_flags)
--   Addition 6  — Risk aging (risk_age_days, first_detected_at, last_observed_at, last_reviewed_at)
--   Addition 7  — Remediation tracking (remediation_status, remediation_target_date, remediation_completed_at)
--   Addition 10 — Graph-ready node identifiers (risk_node_id, owner_node_id, vendor_node_id,
--                  decision_node_id, governance_node_id)

-- Addition 1 — Ownership model
ALTER TABLE fa_external_ai_risk_records
    ADD COLUMN IF NOT EXISTS risk_owner            VARCHAR(255),
    ADD COLUMN IF NOT EXISTS owner_type            VARCHAR(64)  NOT NULL DEFAULT 'Unknown';

-- Addition 2 — Governance state
ALTER TABLE fa_external_ai_risk_records
    ADD COLUMN IF NOT EXISTS governance_state      VARCHAR(32)  NOT NULL DEFAULT 'unknown';

-- Addition 3 — Decision linkage (JSON arrays; default empty)
ALTER TABLE fa_external_ai_risk_records
    ADD COLUMN IF NOT EXISTS decision_refs         JSONB        NOT NULL DEFAULT '[]',
    ADD COLUMN IF NOT EXISTS risk_acceptance_refs  JSONB        NOT NULL DEFAULT '[]',
    ADD COLUMN IF NOT EXISTS exception_refs        JSONB        NOT NULL DEFAULT '[]',
    ADD COLUMN IF NOT EXISTS approval_refs         JSONB        NOT NULL DEFAULT '[]';

-- Addition 4 — Vendor governance status
ALTER TABLE fa_external_ai_risk_records
    ADD COLUMN IF NOT EXISTS vendor_review_status          VARCHAR(32)  NOT NULL DEFAULT 'not_reviewed',
    ADD COLUMN IF NOT EXISTS vendor_dpa_status             VARCHAR(32)  NOT NULL DEFAULT 'unknown',
    ADD COLUMN IF NOT EXISTS vendor_baa_status             VARCHAR(32)  NOT NULL DEFAULT 'unknown',
    ADD COLUMN IF NOT EXISTS vendor_security_review_status VARCHAR(32)  NOT NULL DEFAULT 'unknown',
    ADD COLUMN IF NOT EXISTS vendor_last_reviewed_at       VARCHAR(64);

-- Addition 5 — Regulatory impact flags
ALTER TABLE fa_external_ai_risk_records
    ADD COLUMN IF NOT EXISTS regulatory_flags      JSONB        NOT NULL DEFAULT '[]';

-- Addition 6 — Risk aging
ALTER TABLE fa_external_ai_risk_records
    ADD COLUMN IF NOT EXISTS risk_age_days         INTEGER,
    ADD COLUMN IF NOT EXISTS first_detected_at     VARCHAR(64),
    ADD COLUMN IF NOT EXISTS last_observed_at      VARCHAR(64),
    ADD COLUMN IF NOT EXISTS last_reviewed_at      VARCHAR(64);

-- Addition 7 — Remediation tracking
ALTER TABLE fa_external_ai_risk_records
    ADD COLUMN IF NOT EXISTS remediation_status        VARCHAR(32)  NOT NULL DEFAULT 'not_started',
    ADD COLUMN IF NOT EXISTS remediation_target_date   VARCHAR(64),
    ADD COLUMN IF NOT EXISTS remediation_completed_at  VARCHAR(64);

-- Addition 10 — Graph-ready node identifiers
ALTER TABLE fa_external_ai_risk_records
    ADD COLUMN IF NOT EXISTS risk_node_id          VARCHAR(255),
    ADD COLUMN IF NOT EXISTS owner_node_id         VARCHAR(255),
    ADD COLUMN IF NOT EXISTS vendor_node_id        VARCHAR(255),
    ADD COLUMN IF NOT EXISTS decision_node_id      VARCHAR(255),
    ADD COLUMN IF NOT EXISTS governance_node_id    VARCHAR(255);

-- Indexes for executive dashboard queries and autonomous governance
CREATE INDEX IF NOT EXISTS ix_fa_ext_ai_risk_tenant_gov
    ON fa_external_ai_risk_records (tenant_id, governance_state);

CREATE INDEX IF NOT EXISTS ix_fa_ext_ai_risk_tenant_remediation
    ON fa_external_ai_risk_records (tenant_id, remediation_status);
