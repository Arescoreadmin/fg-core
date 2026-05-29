-- 0071_tenant_keywords.sql
-- Per-tenant keyword triggers for AI query classification (PR 37)

CREATE TABLE IF NOT EXISTS tenant_keywords (
    id              TEXT        PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    tenant_id       TEXT        NOT NULL,
    keyword         TEXT        NOT NULL,
    match_type      TEXT        NOT NULL DEFAULT 'contains',
    -- contains | exact | word_boundary | prefix | regex
    case_sensitive  BOOLEAN     NOT NULL DEFAULT FALSE,
    flag_value      TEXT        NOT NULL,
    -- maps to a sensitivity_flag or subject_category value
    flag_type       TEXT        NOT NULL DEFAULT 'sensitivity',
    -- sensitivity | subject | custom
    action          TEXT        NOT NULL DEFAULT 'flag',
    -- flag | block | escalate
    description     TEXT,
    created_by      TEXT,
    active          BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_tenant_keyword
    ON tenant_keywords (tenant_id, keyword, flag_value)
    WHERE active = TRUE;

CREATE INDEX IF NOT EXISTS idx_tenant_keyword_tenant
    ON tenant_keywords (tenant_id, active);
