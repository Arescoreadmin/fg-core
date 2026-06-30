-- PR 18.1: Enterprise Assessment Report Authority
-- Creates:
--   fa_report              — canonical report entity
--   fa_report_audit_events — append-only audit trail
--   fa_report_bundles      — export bundle records

-- fa_report
CREATE TABLE IF NOT EXISTS fa_report (
    id                          VARCHAR(64)  PRIMARY KEY,
    tenant_id                   VARCHAR(255) NOT NULL,
    report_ref                  VARCHAR(512) NOT NULL,
    report_type                 VARCHAR(64)  NOT NULL,
    lifecycle_state             VARCHAR(32)  NOT NULL DEFAULT 'DRAFT',
    schema_version              VARCHAR(32)  NOT NULL DEFAULT '1.0',
    assessment_id               VARCHAR(64),
    title                       TEXT         NOT NULL,
    scope                       TEXT,
    objectives                  TEXT,
    assessor_id                 VARCHAR(255),
    reviewer_id                 VARCHAR(255),
    generator_id                VARCHAR(255),
    quality_score               DOUBLE PRECISION,
    evidence_coverage_score     DOUBLE PRECISION,
    verification_coverage_score DOUBLE PRECISION,
    freshness_score             DOUBLE PRECISION,
    confidence_score            DOUBLE PRECISION,
    completeness_score          DOUBLE PRECISION,
    quality_grade               VARCHAR(32),
    report_hash_sha256          VARCHAR(128),
    report_hash_sha512          VARCHAR(256),
    manifest_hash               VARCHAR(128),
    manifest_hash_sha256        VARCHAR(128),
    manifest_hash_sha512        VARCHAR(256),
    transparency_root           VARCHAR(256),
    merkle_root                 VARCHAR(256),
    signing_algorithm           VARCHAR(64),
    signature                   TEXT,
    report_version              VARCHAR(64)  NOT NULL DEFAULT '1.0.0-r0',
    major_version               INTEGER      NOT NULL DEFAULT 1,
    minor_version               INTEGER      NOT NULL DEFAULT 0,
    patch_version               INTEGER      NOT NULL DEFAULT 0,
    report_revision             INTEGER      NOT NULL DEFAULT 0,
    branding_config             TEXT,
    regulatory_profile          VARCHAR(64),
    generator_version           VARCHAR(64),
    provider_version            VARCHAR(128),
    export_version              VARCHAR(32),
    manifest_schema_version     VARCHAR(32),
    has_pdf                     INTEGER      NOT NULL DEFAULT 0,
    has_html                    INTEGER      NOT NULL DEFAULT 0,
    has_json                    INTEGER      NOT NULL DEFAULT 0,
    created_at                  VARCHAR(64)  NOT NULL,
    updated_at                  VARCHAR(64)  NOT NULL,
    published_at                VARCHAR(64),
    superseded_at               VARCHAR(64),
    archived_at                 VARCHAR(64),
    generation_started_at       VARCHAR(64),
    generation_completed_at     VARCHAR(64)
);

CREATE INDEX IF NOT EXISTS ix_fa_report_tenant_id         ON fa_report (tenant_id);
CREATE INDEX IF NOT EXISTS ix_fa_report_tenant_state      ON fa_report (tenant_id, lifecycle_state);
CREATE INDEX IF NOT EXISTS ix_fa_report_tenant_assessment ON fa_report (tenant_id, assessment_id);
CREATE INDEX IF NOT EXISTS ix_fa_report_created_at        ON fa_report (created_at);

-- Row-level security for tenant isolation
ALTER TABLE fa_report ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename  = 'fa_report'
          AND policyname = 'fa_report_tenant_isolation'
    ) THEN
        CREATE POLICY fa_report_tenant_isolation ON fa_report
            USING (tenant_id = current_setting('app.tenant_id', true));
    END IF;
END $$;

-- fa_report_audit_events (append-only)
CREATE TABLE IF NOT EXISTS fa_report_audit_events (
    id             VARCHAR(64)  PRIMARY KEY,
    tenant_id      VARCHAR(255) NOT NULL,
    report_id      VARCHAR(64)  NOT NULL,
    event_type     VARCHAR(64)  NOT NULL,
    actor_id       VARCHAR(255),
    actor_type     VARCHAR(32),
    from_state     VARCHAR(32),
    to_state       VARCHAR(32),
    reason         TEXT,
    event_metadata TEXT,
    created_at     VARCHAR(64)  NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_fa_report_audit_tenant  ON fa_report_audit_events (tenant_id);
CREATE INDEX IF NOT EXISTS ix_fa_report_audit_report  ON fa_report_audit_events (report_id);
CREATE INDEX IF NOT EXISTS ix_fa_report_audit_created ON fa_report_audit_events (created_at);

ALTER TABLE fa_report_audit_events ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename  = 'fa_report_audit_events'
          AND policyname = 'fa_report_audit_tenant_isolation'
    ) THEN
        CREATE POLICY fa_report_audit_tenant_isolation ON fa_report_audit_events
            USING (tenant_id = current_setting('app.tenant_id', true));
    END IF;
END $$;

-- Append-only enforcement at DB level
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_rules
        WHERE tablename = 'fa_report_audit_events'
          AND rulename  = 'fa_report_audit_no_update'
    ) THEN
        CREATE RULE fa_report_audit_no_update
            AS ON UPDATE TO fa_report_audit_events DO INSTEAD NOTHING;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_rules
        WHERE tablename = 'fa_report_audit_events'
          AND rulename  = 'fa_report_audit_no_delete'
    ) THEN
        CREATE RULE fa_report_audit_no_delete
            AS ON DELETE TO fa_report_audit_events DO INSTEAD NOTHING;
    END IF;
END $$;

-- fa_report_bundles
CREATE TABLE IF NOT EXISTS fa_report_bundles (
    id                                 VARCHAR(64)  PRIMARY KEY,
    tenant_id                          VARCHAR(255) NOT NULL,
    report_id                          VARCHAR(64)  NOT NULL,
    bundle_state                       VARCHAR(32)  NOT NULL DEFAULT 'PENDING',
    bundle_hash_sha256                 VARCHAR(128),
    bundle_hash_sha512                 VARCHAR(256),
    bundle_signature                   TEXT,
    contains_pdf                       INTEGER      NOT NULL DEFAULT 0,
    contains_html                      INTEGER      NOT NULL DEFAULT 0,
    contains_json                      INTEGER      NOT NULL DEFAULT 0,
    contains_manifest                  INTEGER      NOT NULL DEFAULT 1,
    contains_trust_manifest            INTEGER      NOT NULL DEFAULT 0,
    contains_transparency_proof        INTEGER      NOT NULL DEFAULT 0,
    contains_evidence_index            INTEGER      NOT NULL DEFAULT 0,
    contains_verification_instructions INTEGER      NOT NULL DEFAULT 1,
    file_size_bytes                    INTEGER,
    created_at                         VARCHAR(64)  NOT NULL,
    updated_at                         VARCHAR(64)  NOT NULL,
    expires_at                         VARCHAR(64)
);

CREATE INDEX IF NOT EXISTS ix_fa_report_bundles_tenant ON fa_report_bundles (tenant_id);
CREATE INDEX IF NOT EXISTS ix_fa_report_bundles_report ON fa_report_bundles (report_id);

ALTER TABLE fa_report_bundles ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename  = 'fa_report_bundles'
          AND policyname = 'fa_report_bundles_tenant_isolation'
    ) THEN
        CREATE POLICY fa_report_bundles_tenant_isolation ON fa_report_bundles
            USING (tenant_id = current_setting('app.tenant_id', true));
    END IF;
END $$;
