-- 0069: ai_query_log — per-query audit record with user attribution and classification
-- Every AI workspace query is written here after completion.
-- subject_category, work_relevance, sensitivity_flags are populated by the
-- async classification pipeline; initially NULL until classified.

CREATE TABLE IF NOT EXISTS ai_query_log (
    id                  TEXT PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    tenant_id           TEXT NOT NULL,
    user_id             TEXT,           -- tenant_users.id; NULL if query came from operator/API
    user_email          TEXT,           -- denormalised for query speed
    session_id          TEXT,           -- correlates a conversation thread
    query_text          TEXT NOT NULL,
    response_text       TEXT,
    provider            TEXT,
    model               TEXT,
    prompt_tokens       INTEGER NOT NULL DEFAULT 0,
    completion_tokens   INTEGER NOT NULL DEFAULT 0,
    policy_decision     TEXT NOT NULL DEFAULT 'allow',  -- allow | block | redact
    subject_category    TEXT,           -- classified: legal | financial | hr | technical |
                                        --   personal | competitor | medical | compliance | other
    work_relevance      TEXT,           -- on_task | tangential | personal
    sensitivity_flags   JSONB NOT NULL DEFAULT '[]'::JSONB,  -- ["contains_pii","competitor_mention",...]
    risk_signals        JSONB NOT NULL DEFAULT '{}'::JSONB,   -- computed per-query signal map
    classified_at       TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_ai_query_log_tenant_id     ON ai_query_log (tenant_id);
CREATE INDEX IF NOT EXISTS ix_ai_query_log_user_id       ON ai_query_log (user_id)
    WHERE user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_ai_query_log_tenant_created ON ai_query_log (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_ai_query_log_user_created  ON ai_query_log (user_id, created_at DESC)
    WHERE user_id IS NOT NULL;
