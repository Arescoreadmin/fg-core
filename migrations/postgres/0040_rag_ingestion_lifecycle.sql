-- 0040_rag_ingestion_lifecycle.sql
-- PR 29 ingestion pipeline hardening.
--
-- Additive lifecycle/versioning metadata only. Existing rows default to
-- indexed/current so retrieval behavior remains backward compatible while new
-- ingestion paths can fail closed on quarantined, failed, or superseded rows.

ALTER TABLE rag_documents
    ADD COLUMN IF NOT EXISTS version_id TEXT,
    ADD COLUMN IF NOT EXISTS source_hash TEXT,
    ADD COLUMN IF NOT EXISTS normalized_source_hash TEXT,
    ADD COLUMN IF NOT EXISTS version_number INTEGER NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS is_current BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS ingestion_status TEXT NOT NULL DEFAULT 'indexed',
    ADD COLUMN IF NOT EXISTS quarantine_reason TEXT,
    ADD COLUMN IF NOT EXISTS failure_reason TEXT,
    ADD COLUMN IF NOT EXISTS indexed_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS superseded_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS superseded_by_version_id TEXT;

ALTER TABLE rag_chunks
    ADD COLUMN IF NOT EXISTS document_version_id TEXT,
    ADD COLUMN IF NOT EXISTS source_hash TEXT,
    ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'ck_rag_documents_ingestion_status'
    ) THEN
        ALTER TABLE rag_documents
            ADD CONSTRAINT ck_rag_documents_ingestion_status
            CHECK (
                ingestion_status IN (
                    'received',
                    'validating',
                    'duplicate',
                    'quarantined',
                    'chunking',
                    'embedding',
                    'indexed',
                    'failed',
                    'superseded',
                    'reindexing'
                )
            );
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS ix_rag_documents_tenant_source_hash
    ON rag_documents (tenant_id, corpus_id, source_hash);

CREATE INDEX IF NOT EXISTS ix_rag_documents_tenant_status
    ON rag_documents (tenant_id, corpus_id, ingestion_status, is_current);

CREATE INDEX IF NOT EXISTS ix_rag_documents_tenant_version
    ON rag_documents (tenant_id, corpus_id, document_id, version_id);

CREATE INDEX IF NOT EXISTS ix_rag_chunks_tenant_version_active
    ON rag_chunks (tenant_id, document_version_id, is_active);

CREATE INDEX IF NOT EXISTS ix_rag_chunks_tenant_source_hash
    ON rag_chunks (tenant_id, corpus_id, source_hash);
