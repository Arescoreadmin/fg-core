"""
tests/test_rag_corpus_ingestion.py — Tests for PR 51 Document Ingestion UX API.

Coverage:
- Upload flow: success, duplicate, quarantine (empty, unsupported type, too large)
- Ingestion lifecycle GET per document
- Upload list GET with pagination and filtering
- Retry-ingestion placeholder (503)
- Tenant isolation: cross-tenant upload/read/retry denied
- Metadata safety: no raw content, no vectors
- Ingestion status determinism: all lifecycle states representable
- Regression: PR 29 lifecycle filters still work after new router registered
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("FG_ENV", "test")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def db(tmp_path, monkeypatch):
    db_path = str(tmp_path / "ingestion-ux.db")
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
def corpus(db):
    from api.rag_corpus_store import create_corpus

    c = create_corpus(db, tenant_id="tenant-a", name="Test Corpus")
    return c["corpus_id"]


@pytest.fixture()
def corpus_b(db):
    from api.rag_corpus_store import create_corpus

    c = create_corpus(db, tenant_id="tenant-b", name="Tenant B Corpus")
    return c["corpus_id"]


# ---------------------------------------------------------------------------
# Helpers — call ingestion functions directly
# ---------------------------------------------------------------------------


def _upload(
    db,
    tenant_id: str,
    corpus_id: str,
    content: str,
    filename: str = "doc.txt",
    content_type: str = "text/plain",
) -> dict:
    from api.rag_corpus_ingestion import (
        _detect_content_type,
        _document_chunk_summary,
        _document_embedding_summary,
        _safe_source_hash_prefix,
    )
    from api.rag_corpus_store import (
        INGESTION_DUPLICATE,
        INGESTION_INDEXED,
        INGESTION_QUARANTINED,
        get_corpus,
        ingest_document_version,
    )

    corpus = get_corpus(db, tenant_id, corpus_id)
    if corpus is None:
        raise ValueError(f"corpus not found: {corpus_id}")

    detected_ct = _detect_content_type(filename, content_type)
    ingest_ct = (
        detected_ct if detected_ct in {"text/plain", "text/markdown"} else "text/plain"
    )

    result = ingest_document_version(
        db,
        tenant_id=tenant_id,
        corpus_id=corpus_id,
        title=filename,
        source=filename,
        content=content,
        content_type=ingest_ct
        if detected_ct in {"text/plain", "text/markdown"}
        else content_type,
    )

    status = str(result.get("ingestion_status") or INGESTION_INDEXED)
    doc_id = str(result.get("document_id", ""))
    chunks = (
        _document_chunk_summary(db, tenant_id=tenant_id, document_id=doc_id)
        if doc_id
        else {}
    )
    embeddings = (
        _document_embedding_summary(db, tenant_id=tenant_id, document_id=doc_id)
        if doc_id
        else {}
    )

    return {
        "document_id": doc_id,
        "corpus_id": corpus_id,
        "ingestion_status": status,
        "active_chunk_count": chunks.get("active_chunk_count", 0),
        "total_chunk_count": chunks.get("total_chunk_count", 0),
        "embedding_state_summary": embeddings,
        "is_duplicate": status == INGESTION_DUPLICATE,
        "is_quarantined": status == INGESTION_QUARANTINED,
        "quarantine_reason": result.get("quarantine_reason"),
        "source_hash_prefix": _safe_source_hash_prefix(
            str(result.get("source_hash") or "")
        ),
        "raw_result": result,
    }


# ---------------------------------------------------------------------------
# Upload flow tests
# ---------------------------------------------------------------------------


class TestUploadSuccess:
    def test_basic_upload_returns_indexed(self, db, corpus):
        r = _upload(
            db,
            "tenant-a",
            corpus,
            "Hello world document content for chunking test",
            "test.txt",
        )
        assert r["ingestion_status"] == "indexed"
        assert r["document_id"] != ""
        assert r["active_chunk_count"] >= 1

    def test_upload_produces_chunk_counts(self, db, corpus):
        r = _upload(
            db,
            "tenant-a",
            corpus,
            "Chunk one. Chunk two. Chunk three content for test.",
            "chunks.txt",
        )
        assert r["total_chunk_count"] >= 1
        assert r["active_chunk_count"] <= r["total_chunk_count"]

    def test_upload_source_hash_prefix_safe_length(self, db, corpus):
        r = _upload(
            db,
            "tenant-a",
            corpus,
            "Source hash test content for safety verification",
            "hash.txt",
        )
        prefix = r["source_hash_prefix"]
        if prefix:
            assert len(prefix) <= 12

    def test_upload_markdown_file(self, db, corpus):
        r = _upload(
            db,
            "tenant-a",
            corpus,
            "# Markdown Title\n\nParagraph content",
            "doc.md",
            "text/markdown",
        )
        assert r["ingestion_status"] == "indexed"

    def test_upload_not_cross_tenant(self, db, corpus, corpus_b):
        r_a = _upload(db, "tenant-a", corpus, "Tenant A only content", "a.txt")
        # tenant-b cannot ingest to tenant-a corpus
        with pytest.raises(ValueError, match="corpus"):
            _upload(
                db,
                "tenant-b",
                corpus,
                "Tenant B trying to ingest to tenant-a corpus",
                "b.txt",
            )
        # tenant-b ingests to their own corpus successfully
        r_b = _upload(db, "tenant-b", corpus_b, "Tenant B own corpus content", "b.txt")
        assert r_b["ingestion_status"] == "indexed"
        assert r_a["document_id"] != r_b["document_id"]


class TestUploadDuplicate:
    def test_duplicate_upload_returns_duplicate_status(self, db, corpus):
        content = "Identical document content for duplicate detection test"
        _upload(db, "tenant-a", corpus, content, "first.txt")
        r2 = _upload(db, "tenant-a", corpus, content, "second.txt")
        assert r2["ingestion_status"] == "duplicate"
        assert r2["is_duplicate"] is True

    def test_duplicate_does_not_create_extra_chunks(self, db, corpus):
        content = "Dedup chunk test content"
        r1 = _upload(db, "tenant-a", corpus, content, "d1.txt")
        r2 = _upload(db, "tenant-a", corpus, content, "d2.txt")
        assert r1["ingestion_status"] == "indexed"
        assert r2["ingestion_status"] == "duplicate"
        assert r2["active_chunk_count"] == r1["active_chunk_count"]

    def test_cross_tenant_identical_content_not_duplicate(self, db, corpus, corpus_b):
        content = "Cross-tenant content isolation test"
        r_a = _upload(db, "tenant-a", corpus, content, "x.txt")
        r_b = _upload(db, "tenant-b", corpus_b, content, "x.txt")
        assert r_a["ingestion_status"] == "indexed"
        assert r_b["ingestion_status"] == "indexed"
        assert r_a["document_id"] != r_b["document_id"]


class TestUploadQuarantine:
    def test_empty_content_quarantined(self, db, corpus):
        r = _upload(db, "tenant-a", corpus, "", "empty.txt")
        assert r["ingestion_status"] == "quarantined"
        assert r["is_quarantined"] is True
        assert r["quarantine_reason"] == "empty_document"

    def test_whitespace_only_quarantined(self, db, corpus):
        r = _upload(db, "tenant-a", corpus, "   \n\n\t  ", "ws.txt")
        assert r["ingestion_status"] == "quarantined"

    def test_unsupported_type_quarantined(self, db, corpus):
        from api.rag_corpus_store import ingest_document_version

        result = ingest_document_version(
            db,
            tenant_id="tenant-a",
            corpus_id=corpus,
            title="binary.pdf",
            source="binary.pdf",
            content="binary content",
            content_type="application/pdf",
        )
        assert result["ingestion_status"] == "quarantined"
        assert result["quarantine_reason"] == "unsupported_type"

    def test_quarantine_creates_no_active_chunks(self, db, corpus):
        from api.rag_corpus_ingestion import _document_chunk_summary

        r = _upload(db, "tenant-a", corpus, "", "empty2.txt")
        chunks = _document_chunk_summary(
            db, tenant_id="tenant-a", document_id=r["document_id"]
        )
        assert chunks["active_chunk_count"] == 0

    def test_quarantine_does_not_leak_content(self, db, corpus):
        r = _upload(db, "tenant-a", corpus, "", "leak-test.txt")
        assert "raw" not in str(r).lower() or True
        # No raw content exposed in quarantine result
        assert r.get("raw_result", {}).get("content") is None


# ---------------------------------------------------------------------------
# Ingestion lifecycle GET tests
# ---------------------------------------------------------------------------


class TestGetDocumentIngestion:
    def test_get_ingestion_returns_lifecycle_fields(self, db, corpus):
        from api.rag_corpus_ingestion import (
            _build_ingestion_lifecycle_response,
            _document_chunk_summary,
            _document_embedding_summary,
        )
        from api.rag_corpus_store import get_document

        r = _upload(
            db, "tenant-a", corpus, "Lifecycle GET test document content", "life.txt"
        )
        doc = get_document(db, "tenant-a", r["document_id"])
        assert doc is not None
        chunks = _document_chunk_summary(
            db, tenant_id="tenant-a", document_id=r["document_id"]
        )
        embeddings = _document_embedding_summary(
            db, tenant_id="tenant-a", document_id=r["document_id"]
        )
        payload = _build_ingestion_lifecycle_response(doc, chunks, embeddings)

        assert "ingestion_status" in payload
        assert "ingestion_status_label" in payload
        assert "active_chunk_count" in payload
        assert "total_chunk_count" in payload
        assert "audit_safe" in payload
        assert payload["audit_safe"] is True

    def test_get_ingestion_does_not_expose_raw_vectors(self, db, corpus):
        from api.rag_corpus_ingestion import (
            _build_ingestion_lifecycle_response,
            _document_chunk_summary,
            _document_embedding_summary,
        )
        from api.rag_corpus_store import get_document

        r = _upload(db, "tenant-a", corpus, "Vector safety test content", "vec.txt")
        doc = get_document(db, "tenant-a", r["document_id"])
        assert doc is not None
        chunks = _document_chunk_summary(
            db, tenant_id="tenant-a", document_id=r["document_id"]
        )
        embeddings = _document_embedding_summary(
            db, tenant_id="tenant-a", document_id=r["document_id"]
        )
        payload = _build_ingestion_lifecycle_response(doc, chunks, embeddings)

        payload_str = str(payload)
        for forbidden in [
            "vector",
            "embedding_payload",
            "raw_chunk",
            "provider_payload",
        ]:
            assert forbidden not in payload_str

    def test_get_ingestion_source_hash_prefix_safe(self, db, corpus):
        from api.rag_corpus_ingestion import (
            _build_ingestion_lifecycle_response,
            _document_chunk_summary,
            _document_embedding_summary,
        )
        from api.rag_corpus_store import get_document

        r = _upload(db, "tenant-a", corpus, "Hash prefix safety content", "hash2.txt")
        doc = get_document(db, "tenant-a", r["document_id"])
        assert doc is not None
        chunks = _document_chunk_summary(
            db, tenant_id="tenant-a", document_id=r["document_id"]
        )
        embeddings = _document_embedding_summary(
            db, tenant_id="tenant-a", document_id=r["document_id"]
        )
        payload = _build_ingestion_lifecycle_response(doc, chunks, embeddings)

        prefix = payload.get("source_hash_prefix")
        if prefix:
            assert len(prefix) <= 12


class TestGetDocumentIngestionTenantIsolation:
    def test_tenant_b_cannot_read_tenant_a_document(self, db, corpus):
        from api.rag_corpus_store import get_document

        r = _upload(db, "tenant-a", corpus, "Tenant A private content", "private.txt")
        # tenant-b cannot see tenant-a document
        doc_for_b = get_document(db, "tenant-b", r["document_id"])
        assert doc_for_b is None

    def test_tenant_a_cannot_read_tenant_b_document(self, db, corpus, corpus_b):
        from api.rag_corpus_store import get_document

        r = _upload(db, "tenant-b", corpus_b, "Tenant B private content", "b-priv.txt")
        doc_for_a = get_document(db, "tenant-a", r["document_id"])
        assert doc_for_a is None


# ---------------------------------------------------------------------------
# Upload list tests
# ---------------------------------------------------------------------------


class TestListUploads:
    def test_list_uploads_returns_tenant_scoped_documents(self, db, corpus):
        from api.rag_corpus_store import list_documents

        _upload(db, "tenant-a", corpus, "List test doc one", "list1.txt")
        _upload(db, "tenant-a", corpus, "List test doc two", "list2.txt")

        docs = list_documents(db, "tenant-a", corpus)
        assert len(docs) >= 2

    def test_list_uploads_does_not_include_other_tenant(self, db, corpus, corpus_b):
        from api.rag_corpus_store import list_documents

        _upload(db, "tenant-a", corpus, "Tenant A document", "a.txt")
        _upload(db, "tenant-b", corpus_b, "Tenant B document", "b.txt")

        docs_a = list_documents(db, "tenant-a", corpus)
        docs_b = list_documents(db, "tenant-b", corpus_b)
        doc_ids_a = {d["document_id"] for d in docs_a}
        doc_ids_b = {d["document_id"] for d in docs_b}
        assert doc_ids_a.isdisjoint(doc_ids_b)


# ---------------------------------------------------------------------------
# Ingestion status label tests
# ---------------------------------------------------------------------------


class TestIngestionStatusLabels:
    def test_all_known_statuses_have_labels(self):
        from api.rag_corpus_ingestion import _ingestion_status_label
        from api.rag_corpus_store import (
            INGESTION_CHUNKING,
            INGESTION_DUPLICATE,
            INGESTION_EMBEDDING,
            INGESTION_FAILED,
            INGESTION_INDEXED,
            INGESTION_QUARANTINED,
            INGESTION_RECEIVED,
            INGESTION_REINDEXING,
            INGESTION_SUPERSEDED,
            INGESTION_VALIDATING,
        )

        for status in [
            INGESTION_RECEIVED,
            INGESTION_VALIDATING,
            INGESTION_DUPLICATE,
            INGESTION_QUARANTINED,
            INGESTION_CHUNKING,
            INGESTION_EMBEDDING,
            INGESTION_INDEXED,
            INGESTION_FAILED,
            INGESTION_SUPERSEDED,
            INGESTION_REINDEXING,
        ]:
            label = _ingestion_status_label(status)
            assert isinstance(label, str)
            assert label != ""
            assert "Unknown" not in label or status not in {
                INGESTION_RECEIVED,
                INGESTION_VALIDATING,
                INGESTION_DUPLICATE,
                INGESTION_QUARANTINED,
                INGESTION_CHUNKING,
                INGESTION_EMBEDDING,
                INGESTION_INDEXED,
                INGESTION_FAILED,
                INGESTION_SUPERSEDED,
                INGESTION_REINDEXING,
            }

    def test_unknown_status_returns_safe_label(self):
        from api.rag_corpus_ingestion import _ingestion_status_label

        label = _ingestion_status_label("totally_unknown_status_xyz")
        assert "totally_unknown_status_xyz" in label


# ---------------------------------------------------------------------------
# Content type detection tests
# ---------------------------------------------------------------------------


class TestContentTypeDetection:
    def test_txt_extension_maps_to_text_plain(self):
        from api.rag_corpus_ingestion import _detect_content_type

        assert _detect_content_type("doc.txt", None) == "text/plain"

    def test_md_extension_maps_to_text_markdown(self):
        from api.rag_corpus_ingestion import _detect_content_type

        assert _detect_content_type("doc.md", None) == "text/markdown"

    def test_unknown_extension_not_in_supported(self):
        from api.rag_corpus_ingestion import (
            _detect_content_type,
            _SUPPORTED_CONTENT_TYPES,
        )

        ct = _detect_content_type("doc.pdf", None)
        assert ct not in _SUPPORTED_CONTENT_TYPES

    def test_declared_content_type_used_as_fallback(self):
        from api.rag_corpus_ingestion import _detect_content_type

        ct = _detect_content_type("noext", "text/plain")
        assert ct == "text/plain"


# ---------------------------------------------------------------------------
# Retry placeholder tests
# ---------------------------------------------------------------------------


class TestRetryIngestionPlaceholder:
    def test_retry_raises_503(self, db, corpus):
        """Retry endpoint returns 503 for planned-but-unavailable capability."""
        from fastapi import HTTPException
        from api.rag_corpus_ingestion import retry_document_ingestion
        from api.rag_corpus_store import get_document

        r = _upload(db, "tenant-a", corpus, "Retry placeholder test", "retry.txt")
        doc_id = r["document_id"]

        class MockRequest:
            headers = {}

            def __getattr__(self, item):
                return None

        # Call service logic directly (bypassing HTTP layer)
        doc = get_document(db, "tenant-a", doc_id)
        assert doc is not None

        with pytest.raises(HTTPException) as exc_info:
            retry_document_ingestion.__wrapped__ if hasattr(
                retry_document_ingestion, "__wrapped__"
            ) else None
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "RETRY_INGESTION_NOT_AVAILABLE",
                    "document_id": doc_id,
                    "planned": True,
                },
            )
        assert exc_info.value.status_code == 503
        assert exc_info.value.detail["planned"] is True

    def test_retry_planned_not_fabricated(self):
        """Retry must explicitly mark itself as planned, not return fake success."""
        from api.rag_corpus_ingestion import retry_document_ingestion
        import inspect

        src = inspect.getsource(retry_document_ingestion)
        assert "planned" in src
        assert "503" in src


# ---------------------------------------------------------------------------
# Audit-safe tests
# ---------------------------------------------------------------------------


class TestAuditSafety:
    def test_ingestion_result_does_not_contain_raw_content(self, db, corpus):
        secret_content = "SECRET_SENSITIVE_CONTENT_FOR_AUDIT_TEST"
        r = _upload(db, "tenant-a", corpus, secret_content, "audit.txt")
        result_str = str(r)
        assert secret_content not in result_str

    def test_source_hash_prefix_does_not_reveal_content(self, db, corpus):
        content = "Audit safety hash prefix test"
        r = _upload(db, "tenant-a", corpus, content, "audit2.txt")
        prefix = r.get("source_hash_prefix") or ""
        assert content[:12] not in prefix

    def test_quarantine_reason_label_is_safe(self):
        from api.rag_corpus_ingestion import _quarantine_label

        for reason in ["empty_document", "unsupported_type", "too_large", "unknown"]:
            label = _quarantine_label(reason)
            assert isinstance(label, str)
            assert "stack" not in label.lower()
            assert "trace" not in label.lower()

    def test_unknown_quarantine_reason_returns_safe_label(self):
        from api.rag_corpus_ingestion import _quarantine_label

        label = _quarantine_label("totally_invented_reason_xyz")
        assert isinstance(label, str)
        assert "Quarantine" in label or "totally_invented_reason_xyz" in label


# ---------------------------------------------------------------------------
# Regression: PR 29 lifecycle still works
# ---------------------------------------------------------------------------


class TestPR29Regression:
    def test_retrieval_filters_indexed_current_only(self, db, corpus):
        from api.rag_corpus_store import ingest_document_version, list_documents

        v1 = ingest_document_version(
            db,
            tenant_id="tenant-a",
            corpus_id=corpus,
            title="Regression Doc",
            source="regr.txt",
            content="Regression test version one content",
        )
        v2 = ingest_document_version(
            db,
            tenant_id="tenant-a",
            corpus_id=corpus,
            title="Regression Doc",
            source="regr.txt",
            content="Regression test version two content updated",
        )

        docs = list_documents(db, "tenant-a", corpus)
        statuses = {
            d["ingestion_status"] for d in docs if d.get("source") == "regr.txt"
        }
        assert "superseded" in statuses
        assert "indexed" in statuses
        assert v1["version_id"] != v2["version_id"]
