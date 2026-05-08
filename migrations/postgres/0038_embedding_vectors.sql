-- 0038_embedding_vectors.sql
-- Touching contracts/schema — flagged explicitly per CLAUDE.md.
--
-- Adds pgvector extension and the embedding_vectors table for persisting
-- chunk embeddings.  Storage only — no retrieval, no ANN search, no AI calls.
--
-- Requires pgvector extension (https://github.com/pgvector/pgvector).
-- In production/staging the application layer will fail closed at startup if
-- the extension is not present (see services/embeddings/persistence.py).
--
-- Vector column uses `vector` without a fixed-dimension constraint because
-- different models produce vectors of different lengths (768–3072).  Dimension
-- consistency is enforced at the application layer before persistence.
--
-- IVFFlat / HNSW ANN indexes are intentionally omitted here.  They require:
--   (a) a fixed dimension per index, and
--   (b) a minimum row count to tune list counts effectively.
-- Per-model ANN indexes should be added in a follow-up migration once a single
-- model is selected for production and the table has sufficient data.

-- ─── Extension ───────────────────────────────────────────────────────────────

CREATE EXTENSION IF NOT EXISTS vector;

-- ─── embedding_vectors ───────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS embedding_vectors (
    id           TEXT        NOT NULL PRIMARY KEY,
    tenant_id    TEXT        NOT NULL,
    corpus_id    TEXT        NOT NULL,
    document_id  TEXT        NOT NULL,
    chunk_id     TEXT        NOT NULL,
    model        TEXT        NOT NULL,
    dimensions   INTEGER     NOT NULL,
    embedding    vector      NOT NULL,
    content_hash TEXT        NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Uniqueness: exactly one embedding per (tenant, corpus, chunk, model, hash).
-- Prevents duplicate inserts for the same chunk content without upsert logic.
CREATE UNIQUE INDEX IF NOT EXISTS uq_embedding_vectors_identity
    ON embedding_vectors (tenant_id, corpus_id, chunk_id, model, content_hash);

-- ─── Tenant-scoped B-tree indexes ────────────────────────────────────────────

-- Primary tenant scope — all queries start here.
CREATE INDEX IF NOT EXISTS ix_embedding_vectors_tenant
    ON embedding_vectors (tenant_id);

-- Corpus listing (list_embeddings_for_corpus).
CREATE INDEX IF NOT EXISTS ix_embedding_vectors_tenant_corpus
    ON embedding_vectors (tenant_id, corpus_id);

-- Chunk lookup (get_embedding_for_chunk, embedding_exists).
CREATE INDEX IF NOT EXISTS ix_embedding_vectors_tenant_chunk
    ON embedding_vectors (tenant_id, chunk_id);

-- Model-scoped queries (future: model-specific ANN index prerequisite).
CREATE INDEX IF NOT EXISTS ix_embedding_vectors_tenant_model
    ON embedding_vectors (tenant_id, model);
