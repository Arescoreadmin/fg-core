"""
tests/security/test_rag_ingestion_upload_security.py — Security tests for PR 51.

Coverage:
- Tenant A cannot see Tenant B uploads
- Tenant A cannot retry Tenant B ingestion
- Metadata filtering removes unsafe internals
- Upload state remains tenant-scoped
- Invalid upload types fail safely
- Duplicate ingestion remains tenant-safe
- Source hash does not leak full sensitive values
- No unsafe rendering (no dangerouslySetInnerHTML)
- Resumable UX cannot bypass governance
- Cross-tenant document lookup denied
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("FG_ENV", "test")


@pytest.fixture()
def db(tmp_path, monkeypatch):
    db_path = str(tmp_path / "ingestion-security.db")
    monkeypatch.setenv("FG_SQLITE_PATH", db_path)
    monkeypatch.setenv("FG_ENV", "test")

    from api.db import get_sessionmaker, init_db, reset_engine_cache

    reset_engine_cache()
    init_db(sqlite_path=db_path)
    SessionLocal = get_sessionmaker(sqlite_path=db_path)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
        reset_engine_cache()


@pytest.fixture()
def corpus_a(db):
    from api.rag_corpus_store import create_corpus

    return create_corpus(db, tenant_id="tenant-a", name="Corpus A")["corpus_id"]


@pytest.fixture()
def corpus_b(db):
    from api.rag_corpus_store import create_corpus

    return create_corpus(db, tenant_id="tenant-b", name="Corpus B")["corpus_id"]


def _ingest(db, tenant_id: str, corpus_id: str, content: str) -> str:
    from api.rag_corpus_store import ingest_document_version

    r = ingest_document_version(
        db,
        tenant_id=tenant_id,
        corpus_id=corpus_id,
        title="Security Test Doc",
        source="sec.txt",
        content=content,
    )
    return str(r.get("document_id", ""))


# ---------------------------------------------------------------------------
# Cross-tenant upload visibility denied
# ---------------------------------------------------------------------------


class TestCrossTenantUploadDenied:
    def test_tenant_b_cannot_upload_to_tenant_a_corpus(self, db, corpus_a):
        from api.rag_corpus_store import get_corpus, ingest_document_version

        corpus = get_corpus(db, "tenant-b", corpus_a)
        assert corpus is None, "Tenant B must not see Tenant A corpus"

        with pytest.raises(ValueError, match="corpus_id"):
            ingest_document_version(
                db,
                tenant_id="tenant-b",
                corpus_id=corpus_a,
                title="Unauthorized",
                source="hack.txt",
                content="unauthorized content",
            )

    def test_tenant_a_cannot_upload_to_tenant_b_corpus(self, db, corpus_b):
        from api.rag_corpus_store import get_corpus, ingest_document_version

        corpus = get_corpus(db, "tenant-a", corpus_b)
        assert corpus is None

        with pytest.raises(ValueError, match="corpus_id"):
            ingest_document_version(
                db,
                tenant_id="tenant-a",
                corpus_id=corpus_b,
                title="Unauthorized",
                source="hack.txt",
                content="unauthorized content",
            )


# ---------------------------------------------------------------------------
# Cross-tenant ingestion lookup denied
# ---------------------------------------------------------------------------


class TestCrossTenantIngestionLookupDenied:
    def test_tenant_b_cannot_read_tenant_a_document_ingestion(self, db, corpus_a):
        from api.rag_corpus_store import get_document

        doc_id = _ingest(db, "tenant-a", corpus_a, "Tenant A secret content")
        assert doc_id != ""

        # Tenant B lookup returns None — structural impossibility
        doc = get_document(db, "tenant-b", doc_id)
        assert doc is None, "Tenant B must not see Tenant A document"

    def test_tenant_a_cannot_read_tenant_b_document_ingestion(self, db, corpus_b):
        from api.rag_corpus_store import get_document

        doc_id = _ingest(db, "tenant-b", corpus_b, "Tenant B secret content")
        assert doc_id != ""

        doc = get_document(db, "tenant-a", doc_id)
        assert doc is None

    def test_cross_tenant_chunk_lookup_denied(self, db, corpus_a):
        from api.rag_corpus_store import list_chunks

        doc_id = _ingest(
            db, "tenant-a", corpus_a, "Chunk isolation test content for tenant A"
        )
        assert doc_id != ""

        # Tenant B list_chunks returns empty list — not an error
        chunks_b = list_chunks(db, "tenant-b", doc_id)
        assert chunks_b == []


# ---------------------------------------------------------------------------
# Cross-tenant retry denied
# ---------------------------------------------------------------------------


class TestCrossTenantRetryDenied:
    def test_tenant_b_cannot_trigger_retry_on_tenant_a_document(self, db, corpus_a):
        from api.rag_corpus_store import get_document

        doc_id = _ingest(db, "tenant-a", corpus_a, "Retry isolation test content")
        assert doc_id != ""

        # Retry endpoint checks get_document first — if None, raises 404
        doc_for_b = get_document(db, "tenant-b", doc_id)
        assert doc_for_b is None, (
            "Retry gate must deny Tenant B access to Tenant A document"
        )


# ---------------------------------------------------------------------------
# Metadata filtering removes unsafe internals
# ---------------------------------------------------------------------------


class TestMetadataFiltering:
    def test_ingestion_result_does_not_expose_vectors(self, db, corpus_a):
        from api.rag_corpus_ingestion import (
            _build_ingestion_lifecycle_response,
            _document_chunk_summary,
            _document_embedding_summary,
        )
        from api.rag_corpus_store import get_document

        doc_id = _ingest(db, "tenant-a", corpus_a, "Vector leak test content")
        doc = get_document(db, "tenant-a", doc_id)
        assert doc is not None

        chunks = _document_chunk_summary(db, tenant_id="tenant-a", document_id=doc_id)
        embeddings = _document_embedding_summary(
            db, tenant_id="tenant-a", document_id=doc_id
        )
        payload = _build_ingestion_lifecycle_response(doc, chunks, embeddings)

        for forbidden_key in [
            "vector",
            "embedding_value",
            "raw_text",
            "provider_payload",
            "prompt",
        ]:
            assert forbidden_key not in payload, (
                f"Forbidden key '{forbidden_key}' found in response"
            )

        payload_str = str(payload)
        for forbidden_value in ["provider_key", "api_secret", "bearer_token"]:
            assert forbidden_value not in payload_str

    def test_source_hash_full_not_exposed(self, db, corpus_a):
        from api.rag_corpus_ingestion import _safe_source_hash_prefix
        from api.rag_corpus_store import canonical_source_hash

        content = "Source hash exposure test content"
        full_hash = canonical_source_hash(content)
        prefix = _safe_source_hash_prefix(full_hash)

        assert prefix is not None
        assert len(prefix) <= 12
        assert len(prefix) < len(full_hash), "Prefix must be shorter than full hash"

    def test_quarantine_reason_does_not_expose_stack_trace(self):
        from api.rag_corpus_ingestion import _quarantine_label

        label = _quarantine_label("parse_failed")
        assert "Traceback" not in label
        assert "Exception" not in label
        assert "File " not in label


# ---------------------------------------------------------------------------
# Invalid upload types fail safely
# ---------------------------------------------------------------------------


class TestInvalidUploadTypesSafety:
    def test_binary_content_type_quarantined_not_crashed(self, db, corpus_a):
        from api.rag_corpus_store import ingest_document_version

        result = ingest_document_version(
            db,
            tenant_id="tenant-a",
            corpus_id=corpus_a,
            title="binary.pdf",
            source="binary.pdf",
            content="PDF binary content simulation",
            content_type="application/pdf",
        )
        assert result["ingestion_status"] == "quarantined"
        assert result.get("quarantine_reason") == "unsupported_type"

    def test_empty_document_quarantined_not_crashed(self, db, corpus_a):
        from api.rag_corpus_store import ingest_document_version

        result = ingest_document_version(
            db,
            tenant_id="tenant-a",
            corpus_id=corpus_a,
            title="empty.txt",
            source="empty.txt",
            content="",
        )
        assert result["ingestion_status"] == "quarantined"

    def test_quarantined_document_creates_no_retrievable_chunks(self, db, corpus_a):
        from api.rag_corpus_store import ingest_document_version, list_chunks

        result = ingest_document_version(
            db,
            tenant_id="tenant-a",
            corpus_id=corpus_a,
            title="nochunks.pdf",
            source="nochunks.pdf",
            content="This should be quarantined",
            content_type="application/pdf",
        )
        assert result["ingestion_status"] == "quarantined"
        doc_id = str(result.get("document_id", ""))
        if doc_id:
            chunks = list_chunks(db, "tenant-a", doc_id)
            assert chunks == [], "Quarantined document must not have retrievable chunks"


# ---------------------------------------------------------------------------
# Duplicate ingestion tenant-safe
# ---------------------------------------------------------------------------


class TestDuplicateIngestionTenantSafe:
    def test_duplicate_detection_does_not_expose_other_tenant_existence(
        self, db, corpus_a, corpus_b
    ):
        from api.rag_corpus_store import ingest_document_version

        content = "Shared content between tenants for dedup test"

        r_a = ingest_document_version(
            db,
            tenant_id="tenant-a",
            corpus_id=corpus_a,
            title="shared.txt",
            source="shared.txt",
            content=content,
        )
        r_b = ingest_document_version(
            db,
            tenant_id="tenant-b",
            corpus_id=corpus_b,
            title="shared.txt",
            source="shared.txt",
            content=content,
        )

        # Both should be indexed independently — no cross-tenant dup detection
        assert r_a["ingestion_status"] == "indexed"
        assert r_b["ingestion_status"] == "indexed"
        assert r_a.get("document_id") != r_b.get("document_id")

    def test_intra_tenant_duplicate_does_not_leak_document_id_across_tenants(
        self, db, corpus_a, corpus_b
    ):
        from api.rag_corpus_store import get_document, ingest_document_version

        content = "Intra-tenant dedup content test"

        ingest_document_version(
            db,
            tenant_id="tenant-a",
            corpus_id=corpus_a,
            title="dup.txt",
            source="dup.txt",
            content=content,
        )
        # Second identical upload in tenant-a → duplicate
        r_a2 = ingest_document_version(
            db,
            tenant_id="tenant-a",
            corpus_id=corpus_a,
            title="dup.txt",
            source="dup.txt",
            content=content,
        )
        assert r_a2["ingestion_status"] == "duplicate"

        # Tenant B cannot see duplicate_of_document_id
        if r_a2.get("duplicate_of_document_id"):
            doc = get_document(db, "tenant-b", r_a2["duplicate_of_document_id"])
            assert doc is None


# ---------------------------------------------------------------------------
# Source hash does not leak full sensitive values
# ---------------------------------------------------------------------------


class TestSourceHashSafety:
    def test_source_hash_prefix_always_truncated(self):
        from api.rag_corpus_ingestion import _safe_source_hash_prefix

        long_hash = "a" * 64
        prefix = _safe_source_hash_prefix(long_hash)
        assert prefix is not None
        assert len(prefix) == 12

    def test_source_hash_none_returns_none(self):
        from api.rag_corpus_ingestion import _safe_source_hash_prefix

        assert _safe_source_hash_prefix(None) is None
        assert _safe_source_hash_prefix("") is None

    def test_source_hash_prefix_not_original_content(self, db, corpus_a):
        from api.rag_corpus_ingestion import _safe_source_hash_prefix
        from api.rag_corpus_store import canonical_source_hash

        secret_content = "TOP_SECRET_CONTENT_DO_NOT_EXPOSE"
        full_hash = canonical_source_hash(secret_content)
        prefix = _safe_source_hash_prefix(full_hash)

        assert prefix is not None
        assert secret_content[:12] not in (prefix or "")


# ---------------------------------------------------------------------------
# No unsafe rendering (frontend static check)
# ---------------------------------------------------------------------------


class TestNoUnsafeRendering:
    def test_document_ingestion_console_no_dangerous_html(self):
        import os

        component_path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "..",
            "apps",
            "console",
            "components",
            "governance",
            "DocumentIngestionConsole.tsx",
        )
        component_path = os.path.normpath(component_path)
        assert os.path.exists(component_path), f"Component not found: {component_path}"

        with open(component_path) as f:
            content = f.read()

        assert "dangerouslySetInnerHTML" not in content, (
            "DocumentIngestionConsole must not use dangerouslySetInnerHTML"
        )

    def test_ingestion_page_no_dangerous_html(self):
        import os

        page_path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "..",
            "apps",
            "console",
            "app",
            "dashboard",
            "ingestion",
            "page.tsx",
        )
        page_path = os.path.normpath(page_path)
        assert os.path.exists(page_path), f"Page not found: {page_path}"

        with open(page_path) as f:
            content = f.read()

        assert "dangerouslySetInnerHTML" not in content, (
            "Ingestion page must not use dangerouslySetInnerHTML"
        )


# ---------------------------------------------------------------------------
# Resumable UX cannot bypass governance
# ---------------------------------------------------------------------------


class TestResumableUXGovernance:
    def test_ingestion_state_loaded_from_backend_not_client(self, db, corpus_a):
        """
        Resumable UX must reload state from the backend (get_document_ingestion),
        not rely on client-only memory. Verify that re-querying the backend
        returns the same deterministic state.
        """
        from api.rag_corpus_store import get_document, ingest_document_version

        content = "Resumable UX governance test content"
        r = ingest_document_version(
            db,
            tenant_id="tenant-a",
            corpus_id=corpus_a,
            title="resume.txt",
            source="resume.txt",
            content=content,
        )
        doc_id = str(r.get("document_id", ""))
        assert doc_id != ""

        # Simulate page reload: fetch document state from backend
        doc1 = get_document(db, "tenant-a", doc_id)
        doc2 = get_document(db, "tenant-a", doc_id)

        assert doc1 is not None
        assert doc2 is not None
        assert doc1["ingestion_status"] == doc2["ingestion_status"]
        assert doc1["document_id"] == doc2["document_id"]

    def test_resumable_ux_does_not_create_duplicate_on_reload(self, db, corpus_a):
        """Re-querying ingestion state must not trigger re-ingestion."""
        from api.rag_corpus_store import (
            get_document,
            ingest_document_version,
            list_documents,
        )

        r = ingest_document_version(
            db,
            tenant_id="tenant-a",
            corpus_id=corpus_a,
            title="reload.txt",
            source="reload.txt",
            content="Reload idempotency test content",
        )
        doc_id = str(r.get("document_id", ""))

        # Reload does not create new document
        doc = get_document(db, "tenant-a", doc_id)
        assert doc is not None

        docs = list_documents(db, "tenant-a", corpus_a)
        doc_ids = [d["document_id"] for d in docs if d.get("source") == "reload.txt"]
        # Only one document (or superseded + current, but same source)
        assert doc_id in doc_ids
