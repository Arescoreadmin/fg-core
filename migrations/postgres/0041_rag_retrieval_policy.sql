-- 0041_rag_retrieval_policy.sql
-- Touching schema — flagged explicitly per CLAUDE.md.
--
-- Adds tenant_retrieval_policies: DB-backed, tenant-scoped retrieval policy
-- persistence.  One row per tenant.  Upserted via PUT /rag/retrieval-policy.
--
-- Fields map 1:1 to AiRagRules (services/ai/policy.py) plus audit metadata.
-- Defaults match _default_rules() so that a freshly-created row is safe.

CREATE TABLE IF NOT EXISTS tenant_retrieval_policies (
    id                           SERIAL       PRIMARY KEY,
    tenant_id                    TEXT         NOT NULL UNIQUE,
    rag_enabled                  BOOLEAN      NOT NULL DEFAULT TRUE,
    allowed_corpus_ids           JSONB        NOT NULL DEFAULT '[]',
    denied_corpus_ids            JSONB        NOT NULL DEFAULT '[]',
    max_top_k                    INTEGER      NOT NULL DEFAULT 4,
    allowed_retrieval_strategies JSONB        NOT NULL DEFAULT '["lexical"]',
    require_grounded_response    BOOLEAN      NOT NULL DEFAULT TRUE,
    no_answer_on_ungrounded      BOOLEAN      NOT NULL DEFAULT TRUE,
    require_grounded_context     BOOLEAN      NOT NULL DEFAULT FALSE,
    allow_lexical_fallback       BOOLEAN      NOT NULL DEFAULT FALSE,
    allow_semantic               BOOLEAN      NOT NULL DEFAULT FALSE,
    allow_no_context_answer      BOOLEAN      NOT NULL DEFAULT TRUE,
    reranking_enabled            BOOLEAN      NOT NULL DEFAULT FALSE,
    policy_version               INTEGER      NOT NULL DEFAULT 1,
    updated_by                   TEXT,
    updated_at                   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_tenant_retrieval_policies_tenant
    ON tenant_retrieval_policies (tenant_id);
