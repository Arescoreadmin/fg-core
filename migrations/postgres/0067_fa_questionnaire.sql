-- PR 26: NIST AI RMF Questionnaire
-- Adds two tables for structured per-control manual evidence capture.
--
-- fa_questionnaires      — one per engagement+framework; tracks lifecycle status
-- fa_questionnaire_responses — one row per control, pre-seeded on questionnaire creation
--
-- Tenant isolation: all queries must include tenant_id predicate.
-- Status lifecycle: draft → submitted → finalized (no backward transitions).

CREATE TABLE IF NOT EXISTS fa_questionnaires (
    id              VARCHAR(64)     PRIMARY KEY,
    tenant_id       VARCHAR(255)    NOT NULL,
    engagement_id   VARCHAR(64)     NOT NULL,
    framework       VARCHAR(64)     NOT NULL DEFAULT 'nist_ai_rmf',
    framework_version VARCHAR(32)   NOT NULL DEFAULT '1.0',
    status          VARCHAR(32)     NOT NULL DEFAULT 'draft',
    submitted_at    VARCHAR(64),
    submitted_by    VARCHAR(128),
    schema_version  VARCHAR(16)     NOT NULL DEFAULT '1.0',
    created_at      VARCHAR(64)     NOT NULL,
    updated_at      VARCHAR(64)     NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_fa_questionnaire_engagement_framework
    ON fa_questionnaires (tenant_id, engagement_id, framework);

CREATE INDEX IF NOT EXISTS ix_fa_questionnaires_engagement_tenant
    ON fa_questionnaires (engagement_id, tenant_id);

CREATE TABLE IF NOT EXISTS fa_questionnaire_responses (
    id                  VARCHAR(64)     PRIMARY KEY,
    questionnaire_id    VARCHAR(64)     NOT NULL REFERENCES fa_questionnaires(id) ON DELETE CASCADE,
    tenant_id           VARCHAR(255)    NOT NULL,
    engagement_id       VARCHAR(64)     NOT NULL,
    control_id          VARCHAR(64)     NOT NULL,
    category            VARCHAR(64)     NOT NULL,
    control_name        TEXT            NOT NULL,
    response_status     VARCHAR(32)     NOT NULL DEFAULT 'not_assessed',
    evidence_text       TEXT,
    confidence_score    REAL,
    assessor_id         VARCHAR(128),
    schema_version      VARCHAR(16)     NOT NULL DEFAULT '1.0',
    created_at          VARCHAR(64)     NOT NULL,
    updated_at          VARCHAR(64)     NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_fa_questionnaire_response_control
    ON fa_questionnaire_responses (questionnaire_id, control_id);

CREATE INDEX IF NOT EXISTS ix_fa_qresponses_questionnaire
    ON fa_questionnaire_responses (questionnaire_id);

CREATE INDEX IF NOT EXISTS ix_fa_qresponses_engagement_tenant
    ON fa_questionnaire_responses (engagement_id, tenant_id);

CREATE INDEX IF NOT EXISTS ix_fa_qresponses_control_id
    ON fa_questionnaire_responses (control_id);
