-- additive AI plane extension tables

CREATE TABLE IF NOT EXISTS ai_model_catalog (
    model_id TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    model_name TEXT NOT NULL,
    risk_tier TEXT NOT NULL,
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS tenant_ai_policy (
    tenant_id TEXT PRIMARY KEY,
    max_prompt_chars INTEGER NOT NULL DEFAULT 2000,
    blocked_topics_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    require_human_review BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ai_inference_records (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    inference_id TEXT NOT NULL UNIQUE,
    model_id TEXT NOT NULL REFERENCES ai_model_catalog(model_id),
    prompt_sha256 TEXT NOT NULL,
    response_text TEXT NOT NULL,
    context_refs_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at_utc TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ai_governance_reviews (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    review_id TEXT NOT NULL UNIQUE,
    inference_id TEXT NOT NULL,
    reviewer TEXT NOT NULL,
    decision TEXT NOT NULL,
    notes TEXT,
    created_at_utc TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
