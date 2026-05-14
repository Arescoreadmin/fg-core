-- 0046_docx_ingestion.sql
-- PR 56 — Enterprise DOCX Ingestion Pipeline.
--
-- No new columns are required: source_page (paragraph position), extraction_version,
-- and content_type were already added by 0045_pdf_ingestion.sql and are reused
-- for DOCX chunks with the same _table_columns guard pattern.
--
-- This migration extends the ingestion_status constraint to allow
-- 'docx_validating' as a transient validation state, and adds an index
-- for paragraph-level provenance lookups on DOCX documents.

-- Extend ingestion_status constraint to include 'docx_validating'.
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
                'docx_validating',
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

-- Index for DOCX content_type filter (reuses ix_rag_documents_tenant_content_type
-- created in 0045; no new index needed here).
-- Paragraph-level provenance uses ix_rag_chunks_tenant_document_page
-- created in 0045 (source_page holds paragraph_number for DOCX chunks).
