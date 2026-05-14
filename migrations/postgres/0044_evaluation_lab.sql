-- 0044_evaluation_lab.sql
-- Touching schema — flagged explicitly per CLAUDE.md.
--
-- PR 54: Evaluation Lab UI
--
-- Adds two tables:
--   evaluation_query_sets  — tenant-scoped operator query set metadata
--   evaluation_query_items — tenant-scoped expected source/chunk references per query
--
-- Neither table stores raw query text, completions, API keys, or PII.
-- Query identity is by item_ref UUID. Expected source hashes enable
-- retrieval precision measurement without raw prompt exposure.

-- ─── Evaluation Query Sets ───────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS evaluation_query_sets (
    id                        SERIAL       PRIMARY KEY,
    tenant_id                 TEXT         NOT NULL,
    set_ref                   TEXT         NOT NULL,
    name                      TEXT         NOT NULL,
    corpus_id                 TEXT,
    description               TEXT,
    operator_notes_json       JSONB        NOT NULL DEFAULT '[]',
    export_safe_metadata_json JSONB        NOT NULL DEFAULT '{}',
    created_at                TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at                TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_eval_query_set_tenant_ref UNIQUE (tenant_id, set_ref),
    CONSTRAINT chk_eval_query_set_name_nonempty CHECK (LENGTH(TRIM(name)) > 0),
    CONSTRAINT chk_eval_query_set_ref_nonempty  CHECK (LENGTH(TRIM(set_ref)) > 0)
);

CREATE INDEX IF NOT EXISTS ix_eval_query_set_tenant_ref
    ON evaluation_query_sets (tenant_id, set_ref);

CREATE INDEX IF NOT EXISTS ix_eval_query_set_tenant_corpus
    ON evaluation_query_sets (tenant_id, corpus_id);

ALTER TABLE evaluation_query_sets ENABLE ROW LEVEL SECURITY;
ALTER TABLE evaluation_query_sets FORCE ROW LEVEL SECURITY;

CREATE POLICY eval_query_sets_tenant_isolation
    ON evaluation_query_sets
    USING (tenant_id = current_setting('app.tenant_id'));

-- ─── Evaluation Query Items ──────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS evaluation_query_items (
    id                          SERIAL       PRIMARY KEY,
    tenant_id                   TEXT         NOT NULL,
    set_ref                     TEXT         NOT NULL,
    item_ref                    TEXT         NOT NULL,
    query_category              TEXT,
    expected_source_ids_json    JSONB        NOT NULL DEFAULT '[]',
    expected_chunk_ids_json     JSONB        NOT NULL DEFAULT '[]',
    expected_source_hashes_json JSONB        NOT NULL DEFAULT '[]',
    expected_provenance_ids_json JSONB       NOT NULL DEFAULT '[]',
    retrieval_expectations_json JSONB        NOT NULL DEFAULT '{}',
    operator_notes              TEXT,
    created_at                  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at                  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_eval_query_item_tenant_set_ref
        UNIQUE (tenant_id, set_ref, item_ref),
    CONSTRAINT chk_eval_query_item_ref_nonempty
        CHECK (LENGTH(TRIM(item_ref)) > 0),
    CONSTRAINT chk_eval_query_item_set_ref_nonempty
        CHECK (LENGTH(TRIM(set_ref)) > 0)
);

CREATE INDEX IF NOT EXISTS ix_eval_query_item_tenant_set
    ON evaluation_query_items (tenant_id, set_ref);

CREATE INDEX IF NOT EXISTS ix_eval_query_item_tenant_ref
    ON evaluation_query_items (tenant_id, item_ref);

ALTER TABLE evaluation_query_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE evaluation_query_items FORCE ROW LEVEL SECURITY;

CREATE POLICY eval_query_items_tenant_isolation
    ON evaluation_query_items
    USING (tenant_id = current_setting('app.tenant_id'));
