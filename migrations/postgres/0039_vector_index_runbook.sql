-- 0039_vector_index_runbook.sql
-- Touching schema — flagged explicitly per CLAUDE.md.
--
-- Adds the vector_index_registry table.  This is the operator runbook for
-- tracking ANN index readiness before semantic retrieval can be enabled.
--
-- WHY this migration exists:
--   Semantic retrieval requires a fixed-dimension ANN index (ivfflat or HNSW)
--   on embedding_vectors.embedding.  ivfflat/HNSW indexes cannot be created
--   safely in a migration because they:
--     (a) require a minimum row count to tune list/m parameters effectively,
--     (b) require knowing the exact model dimension in advance, and
--     (c) for large tables must be built CONCURRENTLY outside a transaction.
--
--   The application layer (services/embeddings/config.py) reads this registry
--   to gate semantic retrieval.  Prod startup FAILS CLOSED if no ready entry
--   exists and FG_EMBEDDINGS_ANN_INDEX_STATUS != "ready".
--
-- OPERATOR RUNBOOK — when ready to enable semantic retrieval:
-- ─────────────────────────────────────────────────────────────
-- Step 1. Choose the primary model and confirm dimensions:
--   SELECT model, dimensions, COUNT(*) FROM embedding_vectors GROUP BY model, dimensions;
--
-- Step 2. Create the ANN index CONCURRENTLY (outside this migration):
--   CREATE INDEX CONCURRENTLY ix_ev_ann_ada_1536
--       ON embedding_vectors USING ivfflat (embedding vector_cosine_ops)
--       WITH (lists = 100)
--       WHERE model = 'openai/text-embedding-ada-002';
--
--   Tune: lists ≈ sqrt(row_count); minimum ~1 000 rows per list recommended.
--   For HNSW (better recall, slower build):
--   CREATE INDEX CONCURRENTLY ix_ev_hnsw_ada_1536
--       ON embedding_vectors USING hnsw (embedding vector_cosine_ops)
--       WITH (m = 16, ef_construction = 64)
--       WHERE model = 'openai/text-embedding-ada-002';
--
-- Step 3. Register the index:
--   INSERT INTO vector_index_registry
--       (id, model, dimensions, index_type, index_name, notes)
--   VALUES
--       (gen_random_uuid()::text, 'openai/text-embedding-ada-002', 1536,
--        'ivfflat', 'ix_ev_ann_ada_1536', 'production index for ada-002');
--
-- Step 4. Set FG_EMBEDDINGS_ANN_INDEX_STATUS=ready in the deployment env.
--
-- Step 5. Restart — the application startup check will now pass.
-- ─────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS vector_index_registry (
    id           TEXT        NOT NULL PRIMARY KEY,
    model        TEXT        NOT NULL,
    dimensions   INTEGER     NOT NULL,
    index_type   TEXT        NOT NULL CHECK (index_type IN ('ivfflat', 'hnsw', 'exact')),
    index_name   TEXT        NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    notes        TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_vector_index_registry_model_type
    ON vector_index_registry (model, index_type);

CREATE INDEX IF NOT EXISTS ix_vector_index_registry_model
    ON vector_index_registry (model);
