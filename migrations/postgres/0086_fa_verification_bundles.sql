-- Migration 0086: Verification Bundle table (PR 52)
--
-- fa_verification_bundles stores immutable records of verification bundle
-- generation. Each generation run produces one row. The bundle captures
-- SHA-256 hashes of all 9 engagement components and runs tamper detection
-- at generation time. Rows are never updated or deleted (append-only).

CREATE TABLE IF NOT EXISTS fa_verification_bundles (
    id                   VARCHAR(64)  PRIMARY KEY,
    tenant_id            VARCHAR(255) NOT NULL,
    engagement_id        VARCHAR(64)  NOT NULL,
    bundle_hash          VARCHAR(64)  NOT NULL,
    manifest_hash        VARCHAR(64)  NOT NULL,
    verification_status  VARCHAR(32)  NOT NULL,
    generated_by         VARCHAR(255) NOT NULL,
    generated_at         VARCHAR(64)  NOT NULL,
    finding_count        INTEGER      NOT NULL DEFAULT 0,
    evidence_count       INTEGER      NOT NULL DEFAULT 0,
    interview_count      INTEGER      NOT NULL DEFAULT 0,
    decision_count       INTEGER      NOT NULL DEFAULT 0,
    risk_acceptance_count INTEGER     NOT NULL DEFAULT 0,
    exception_count      INTEGER      NOT NULL DEFAULT 0,
    audit_event_count    INTEGER      NOT NULL DEFAULT 0,
    has_report           BOOLEAN      NOT NULL DEFAULT FALSE,
    tamper_details       TEXT,
    component_summary    TEXT         NOT NULL,
    bundle_json          TEXT         NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_fa_vbundles_tenant_eng
    ON fa_verification_bundles (tenant_id, engagement_id);

CREATE INDEX IF NOT EXISTS ix_fa_vbundles_engagement_time
    ON fa_verification_bundles (engagement_id, generated_at);
