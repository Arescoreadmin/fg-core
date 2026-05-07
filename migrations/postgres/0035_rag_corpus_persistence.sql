-- 0035_rag_corpus_persistence.sql
-- Tenant-scoped corpus persistence tables: rag_corpora, rag_documents, rag_chunks.
-- Persistence only — no retrieval, no embeddings, no vector DB, no AI changes.
-- All three tables enforce tenant_id on every row and every query path.

-- ─── rag_corpora ─────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS rag_corpora (
    corpus_id   TEXT        NOT NULL PRIMARY KEY,
    tenant_id   TEXT        NOT NULL,
    name        TEXT        NOT NULL,
    description TEXT,
    metadata    JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_rag_corpora_tenant_corpus
    ON rag_corpora (tenant_id, corpus_id);

-- ─── rag_documents ───────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS rag_documents (
    document_id TEXT        NOT NULL PRIMARY KEY,
    corpus_id   TEXT        NOT NULL REFERENCES rag_corpora (corpus_id),
    tenant_id   TEXT        NOT NULL,
    title       TEXT        NOT NULL,
    source      TEXT,
    metadata    JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_rag_documents_tenant_corpus
    ON rag_documents (tenant_id, corpus_id);

CREATE INDEX IF NOT EXISTS ix_rag_documents_tenant_document
    ON rag_documents (tenant_id, document_id);

-- ─── rag_chunks ──────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS rag_chunks (
    chunk_id    TEXT        NOT NULL PRIMARY KEY,
    document_id TEXT        NOT NULL REFERENCES rag_documents (document_id),
    corpus_id   TEXT        NOT NULL,
    tenant_id   TEXT        NOT NULL,
    text        TEXT        NOT NULL,
    ordinal     INTEGER     NOT NULL,
    metadata    JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_rag_chunks_tenant_corpus
    ON rag_chunks (tenant_id, corpus_id);

CREATE INDEX IF NOT EXISTS ix_rag_chunks_tenant_document
    ON rag_chunks (tenant_id, document_id);
