-- 0032_assessment_and_reports.sql
-- Customer-facing AI governance assessment and report tables.
-- These tables power the onboarding wizard, assessment wizard, and report viewer.
-- tenant_id is stored for dashboard correlation but these tables intentionally
-- do NOT enforce RLS — assessments are accessed by UUID (unguessable) for the
-- customer-facing flow. Tenant-level reporting is a Stage 2 hardening item.

CREATE TABLE IF NOT EXISTS org_profiles (
    id              BIGSERIAL    PRIMARY KEY,
    org_id          TEXT         NOT NULL UNIQUE DEFAULT gen_random_uuid()::text,
    tenant_id       TEXT         NOT NULL DEFAULT 'public',
    org_name        TEXT         NOT NULL,
    industry        TEXT         NOT NULL DEFAULT 'other',
    employee_count  TEXT         NOT NULL DEFAULT '',
    revenue         TEXT         NOT NULL DEFAULT '',
    profile_type    TEXT         NOT NULL DEFAULT 'smb_basic'
        CHECK (profile_type IN ('smb_basic','smb_growth','midmarket','enterprise','regulated','govcon')),
    handles_phi     BOOLEAN      NOT NULL DEFAULT FALSE,
    handles_cui     BOOLEAN      NOT NULL DEFAULT FALSE,
    is_dod_contractor BOOLEAN    NOT NULL DEFAULT FALSE,
    fedramp_required  BOOLEAN    NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_org_profiles_tenant_id  ON org_profiles(tenant_id);
CREATE INDEX IF NOT EXISTS ix_org_profiles_org_id     ON org_profiles(org_id);
CREATE INDEX IF NOT EXISTS ix_org_profiles_profile    ON org_profiles(profile_type);

-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS assessment_schemas (
    id              BIGSERIAL    PRIMARY KEY,
    schema_version  TEXT         NOT NULL UNIQUE,
    profile_type    TEXT         NOT NULL,
    questions       JSONB        NOT NULL DEFAULT '[]',
    is_current      BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_assessment_schemas_profile ON assessment_schemas(profile_type, is_current);

-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS assessments (
    id              TEXT         PRIMARY KEY DEFAULT gen_random_uuid()::text,
    tenant_id       TEXT         NOT NULL DEFAULT 'public',
    org_profile_id  BIGINT       REFERENCES org_profiles(id) ON DELETE SET NULL,
    org_id          TEXT         NOT NULL DEFAULT '',
    schema_version  TEXT         NOT NULL DEFAULT 'v2025.1-base',
    profile_type    TEXT         NOT NULL DEFAULT 'smb_basic',
    status          TEXT         NOT NULL DEFAULT 'draft'
        CHECK (status IN ('draft','in_progress','submitted','scored')),
    responses       JSONB        NOT NULL DEFAULT '{}',
    scores          JSONB,
    overall_score   NUMERIC(5,2),
    risk_band       TEXT         CHECK (risk_band IN ('critical','high','medium','low')),
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    submitted_at    TIMESTAMPTZ,
    scored_at       TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS ix_assessments_tenant_id     ON assessments(tenant_id);
CREATE INDEX IF NOT EXISTS ix_assessments_org_id        ON assessments(org_id);
CREATE INDEX IF NOT EXISTS ix_assessments_org_profile   ON assessments(org_profile_id);
CREATE INDEX IF NOT EXISTS ix_assessments_status        ON assessments(status);

-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS prompt_versions (
    id                   BIGSERIAL  PRIMARY KEY,
    prompt_key           TEXT       NOT NULL,
    version              TEXT       NOT NULL,
    system_prompt        TEXT       NOT NULL,
    user_prompt_template TEXT       NOT NULL,
    is_active            BOOLEAN    NOT NULL DEFAULT FALSE,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (prompt_key, version)
);

CREATE INDEX IF NOT EXISTS ix_prompt_versions_key_active ON prompt_versions(prompt_key, is_active);

-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS reports (
    id              TEXT         PRIMARY KEY DEFAULT gen_random_uuid()::text,
    tenant_id       TEXT         NOT NULL DEFAULT 'public',
    assessment_id   TEXT         REFERENCES assessments(id) ON DELETE SET NULL,
    org_id          TEXT         NOT NULL DEFAULT '',
    org_profile_id  BIGINT       REFERENCES org_profiles(id) ON DELETE SET NULL,
    status          TEXT         NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','generating','complete','failed')),
    prompt_type     TEXT         NOT NULL DEFAULT 'executive',
    content         JSONB,
    error_message   TEXT,
    pdf_storage_key TEXT,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS ix_reports_tenant_id     ON reports(tenant_id);
CREATE INDEX IF NOT EXISTS ix_reports_assessment_id ON reports(assessment_id);
CREATE INDEX IF NOT EXISTS ix_reports_org_id        ON reports(org_id);
CREATE INDEX IF NOT EXISTS ix_reports_status        ON reports(status);
