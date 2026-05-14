-- 0042_provider_governance.sql
-- Touching schema — flagged explicitly per CLAUDE.md.
--
-- PR 53: Provider Governance UI + Retrieval Evaluation Foundation
--
-- Adds two tables:
--   provider_governance_records — tenant-scoped provider governance state
--   retrieval_evaluation_runs   — tenant-scoped retrieval evaluation substrate
--
-- Neither table stores raw prompts, completions, API keys, or PII.
-- All governance state must originate from authoritative backend truth.

-- ─── Provider Governance ─────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS provider_governance_records (
    id                   SERIAL       PRIMARY KEY,
    tenant_id            TEXT         NOT NULL,
    provider_id          TEXT         NOT NULL,
    -- healthy | degraded | unavailable | blocked | restricted | maintenance
    operational_state    TEXT         NOT NULL DEFAULT 'healthy',
    -- approved | restricted | blocked | pending_review
    governance_state     TEXT         NOT NULL DEFAULT 'approved',
    -- trusted | regulated | untrusted | unknown
    trust_classification TEXT         NOT NULL DEFAULT 'unknown',
    routing_eligible     BOOLEAN      NOT NULL DEFAULT TRUE,
    failover_eligible    BOOLEAN      NOT NULL DEFAULT FALSE,
    restrictions_json    JSONB        NOT NULL DEFAULT '[]',
    blocked_at           TIMESTAMPTZ,
    block_reason         TEXT,
    policy_version       INTEGER      NOT NULL DEFAULT 1,
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_provider_governance_tenant_provider UNIQUE (tenant_id, provider_id)
);

CREATE INDEX IF NOT EXISTS ix_provider_governance_tenant_provider
    ON provider_governance_records (tenant_id, provider_id);

CREATE INDEX IF NOT EXISTS ix_provider_governance_tenant_opstate
    ON provider_governance_records (tenant_id, operational_state);

-- ─── Retrieval Evaluation Foundation ─────────────────────────────────────────

CREATE TABLE IF NOT EXISTS retrieval_evaluation_runs (
    id                           SERIAL       PRIMARY KEY,
    tenant_id                    TEXT         NOT NULL,
    run_ref                      TEXT         NOT NULL,
    corpus_id                    TEXT,
    -- pending | running | completed | failed
    status                       TEXT         NOT NULL DEFAULT 'pending',
    started_at                   TIMESTAMPTZ,
    completed_at                 TIMESTAMPTZ,
    query_count                  INTEGER      NOT NULL DEFAULT 0,
    -- Structural indicators only — no fabricated scores
    relevance_indicators_json    JSONB        NOT NULL DEFAULT '{}',
    coverage_indicators_json     JSONB        NOT NULL DEFAULT '{}',
    correctness_indicators_json  JSONB        NOT NULL DEFAULT '{}',
    evaluator_ref                TEXT,
    evaluation_metadata_json     JSONB        NOT NULL DEFAULT '{}',
    created_at                   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at                   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_retrieval_eval_tenant_run_ref UNIQUE (tenant_id, run_ref)
);

CREATE INDEX IF NOT EXISTS ix_retrieval_eval_tenant_run
    ON retrieval_evaluation_runs (tenant_id, run_ref);

CREATE INDEX IF NOT EXISTS ix_retrieval_eval_tenant_status
    ON retrieval_evaluation_runs (tenant_id, status);

CREATE INDEX IF NOT EXISTS ix_retrieval_eval_tenant_corpus
    ON retrieval_evaluation_runs (tenant_id, corpus_id);
