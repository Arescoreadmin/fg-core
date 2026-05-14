-- 0045_pdf_ingestion.sql
-- PR 55 — Enterprise PDF Ingestion Pipeline.
--
-- Additive columns only. Existing rows default to NULL (non-PDF documents).
-- All new columns are nullable so retrieval and non-PDF ingestion remain
-- backward compatible.

ALTER TABLE rag_chunks
    ADD COLUMN IF NOT EXISTS source_page INTEGER,
    ADD COLUMN IF NOT EXISTS extraction_version TEXT;

-- Allow rag_documents to record the original content_type for provenance.
ALTER TABLE rag_documents
    ADD COLUMN IF NOT EXISTS content_type TEXT;

-- Constrain ingestion_status to allow 'pdf_validating' as a transient state.
-- We add it to the existing check constraint via DROP + re-ADD (idempotent).
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'ck_rag_documents_ingestion_status'
    ) THEN
        ALTER TABLE rag_documents
            DROP CONSTRAINT ck_rag_documents_ingestion_status;
    END IF;

    ALTER TABLE rag_documents
        ADD CONSTRAINT ck_rag_documents_ingestion_status
        CHECK (
            ingestion_status IN (
                'received',
                'validating',
                'pdf_validating',
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
END $$;

-- Index for page-level provenance lookups.
CREATE INDEX IF NOT EXISTS ix_rag_chunks_tenant_document_page
    ON rag_chunks (tenant_id, document_id, source_page)
    WHERE source_page IS NOT NULL;

-- Index for retrieval trace / citation rendering by page.
CREATE INDEX IF NOT EXISTS ix_rag_chunks_tenant_corpus_page
    ON rag_chunks (tenant_id, corpus_id, source_page)
    WHERE source_page IS NOT NULL;

-- Index for content_type filter on document list.
CREATE INDEX IF NOT EXISTS ix_rag_documents_tenant_content_type
    ON rag_documents (tenant_id, corpus_id, content_type)
    WHERE content_type IS NOT NULL;
