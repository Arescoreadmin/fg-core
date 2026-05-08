-- 0037_rag_chunk_embedding_state.sql
-- Touching contracts/schema — flagged explicitly per CLAUDE.md.
--
-- Adds content_hash and embedding_state to rag_chunks.
--
-- content_hash: SHA-256 of the canonical UTF-8 chunk text.
--   Required for idempotent embedding generation (PR 21) and vector
--   deduplication (PR 20).  Was intentionally omitted from 0035 because
--   embeddings were out of scope at that time.
--
-- embedding_state: drives the embedding pipeline state machine.
--   Valid values are enforced by CHECK; the application-level EmbeddingState
--   enum in api/embeddings/state.py is the authoritative source of truth.
--
-- These columns are additive — no existing rows or indexes are modified.
-- content_hash is nullable on existing rows; the pipeline will backfill.

ALTER TABLE rag_chunks
    ADD COLUMN IF NOT EXISTS content_hash    TEXT,
    ADD COLUMN IF NOT EXISTS embedding_state TEXT NOT NULL DEFAULT 'pending'
        CHECK (embedding_state IN ('pending', 'processing', 'completed', 'failed', 'skipped'));

-- Partial index: drives efficient polling by the embedding worker (PR 21).
-- Only indexes rows in states the worker needs to pick up.
CREATE INDEX IF NOT EXISTS ix_rag_chunks_pending_embedding
    ON rag_chunks (tenant_id, created_at)
    WHERE embedding_state IN ('pending', 'failed');

-- Lookup index for the persistence layer (PR 20): find a chunk's embedding
-- state by chunk_id without a full table scan.
CREATE INDEX IF NOT EXISTS ix_rag_chunks_chunk_embedding_state
    ON rag_chunks (chunk_id, embedding_state);
