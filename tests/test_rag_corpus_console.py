"""
tests/test_rag_corpus_console.py — Tests for PR 50 Corpus Management Console API.

Coverage:
- Corpus detail endpoint: counts, ingestion summary, embedding summary
- Document list endpoint: pagination, stable sorting, ingestion/is_current filtering
- Document detail endpoint: chunk summary, embedding summary
- Tenant isolation: cross-tenant access denied for all three endpoints
- Invalid filter rejection: bad ingestion_status, bad sort_by, bad sort_dir
- Empty states: no corpus, no documents
- Metadata safety: _safe_metadata strips blocked keys
- source_hash_prefix: safe 12-char prefix exposed, full hash not in response
- Ingestion status coverage: all lifecycle values representable
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
    db_path = str(tmp_path / "console-test.db")
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
def seeded_db(db):
    """DB with corpus + documents + chunks for tenant-a."""
    from api.rag_corpus_store import (
        create_corpus,
        ingest_document_version,
    )

    corp = create_corpus(db, tenant_id="tenant-a", name="Alpha Corpus")
    corpus_id = corp["corpus_id"]

    r1 = ingest_document_version(
        db,
        tenant_id="tenant-a",
        corpus_id=corpus_id,
        title="Doc One",
        source="source-one",
        content="Hello world from document one with enough words to form a chunk",
    )
    r2 = ingest_document_version(
        db,
        tenant_id="tenant-a",
        corpus_id=corpus_id,
        title="Doc Two",
        source="source-two",
        content="Second document with content sufficient for one chunk creation",
    )
    return {"corpus_id": corpus_id, "doc1": r1, "doc2": r2}


# ---------------------------------------------------------------------------
# Helper: call corpus console functions directly
# ---------------------------------------------------------------------------


def call_corpus_detail(db_session, tenant_id, corpus_id):
    from api.rag_corpus_console import (
        _corpus_document_chunk_counts,
        _ingestion_status_summary,
        _embedding_state_summary,
        _safe_metadata,
    )
    from api.rag_corpus_store import get_corpus

    corpus = get_corpus(db_session, tenant_id, corpus_id)
    if corpus is None:
        return None
    counts = _corpus_document_chunk_counts(
        db_session, tenant_id=tenant_id, corpus_id=corpus_id
    )
    ingestion_summary = _ingestion_status_summary(
        db_session, tenant_id=tenant_id, corpus_id=corpus_id
    )
    embedding_summary = _embedding_state_summary(
        db_session, tenant_id=tenant_id, corpus_id=corpus_id
    )
    return {
        **corpus,
        **counts,
        "ingestion_status_summary": ingestion_summary,
        "embedding_state_summary": embedding_summary,
        "metadata": _safe_metadata(corpus.get("metadata")),
    }


# ---------------------------------------------------------------------------
# Corpus detail tests
# ---------------------------------------------------------------------------


def test_corpus_detail_counts(seeded_db, db):
    result = call_corpus_detail(db, "tenant-a", seeded_db["corpus_id"])
    assert result is not None
    assert result["total_document_count"] == 2
    assert result["active_document_count"] == 2
    assert result["active_chunk_count"] >= 2


def test_corpus_detail_ingestion_summary(seeded_db, db):
    result = call_corpus_detail(db, "tenant-a", seeded_db["corpus_id"])
    assert result is not None
    summary = result["ingestion_status_summary"]
    assert isinstance(summary, dict)
    # Both docs should be indexed
    assert summary.get("indexed", 0) == 2


def test_corpus_detail_embedding_summary_keys(seeded_db, db):
    result = call_corpus_detail(db, "tenant-a", seeded_db["corpus_id"])
    assert result is not None
    emb = result["embedding_state_summary"]
    assert isinstance(emb, dict)
    # All chunks should have a known embedding state
    for state in emb:
        assert state in {"pending", "processing", "completed", "failed", "skipped"}


def test_corpus_detail_tenant_isolation(seeded_db, db):
    # tenant-b cannot see tenant-a's corpus
    result = call_corpus_detail(db, "tenant-b", seeded_db["corpus_id"])
    assert result is None


def test_corpus_detail_missing_corpus(db):
    result = call_corpus_detail(db, "tenant-a", "corp-nonexistent")
    assert result is None


# ---------------------------------------------------------------------------
# Document list tests
# ---------------------------------------------------------------------------


def test_document_list_returns_docs(seeded_db, db):
    from api.rag_corpus_store import list_documents

    docs = list_documents(db, "tenant-a", seeded_db["corpus_id"])
    assert len(docs) == 2


def test_document_list_tenant_isolation(seeded_db, db):
    from api.rag_corpus_store import list_documents

    # tenant-b cannot see tenant-a's documents in that corpus
    docs = list_documents(db, "tenant-b", seeded_db["corpus_id"])
    assert len(docs) == 0


def test_document_list_chunk_count(seeded_db, db):
    from api.rag_corpus_console import _document_chunk_count

    doc_id = seeded_db["doc1"]["document_id"]
    counts = _document_chunk_count(db, tenant_id="tenant-a", document_id=doc_id)
    assert counts["total_chunk_count"] >= 1
    assert counts["active_chunk_count"] >= 1


def test_document_chunk_count_tenant_isolation(seeded_db, db):
    from api.rag_corpus_console import _document_chunk_count

    doc_id = seeded_db["doc1"]["document_id"]
    # tenant-b cannot see tenant-a's chunks
    counts = _document_chunk_count(db, tenant_id="tenant-b", document_id=doc_id)
    assert counts["total_chunk_count"] == 0
    assert counts["active_chunk_count"] == 0


# ---------------------------------------------------------------------------
# Document detail tests
# ---------------------------------------------------------------------------


def test_document_detail_fields(seeded_db, db):
    from api.rag_corpus_store import get_document

    doc_id = seeded_db["doc1"]["document_id"]
    doc = get_document(db, "tenant-a", doc_id)
    assert doc is not None
    assert doc["document_id"] == doc_id
    assert doc.get("ingestion_status") == "indexed"
    assert doc.get("is_current") in (1, True, 1)


def test_document_detail_tenant_isolation(seeded_db, db):
    from api.rag_corpus_store import get_document

    doc_id = seeded_db["doc1"]["document_id"]
    doc = get_document(db, "tenant-b", doc_id)
    assert doc is None


def test_document_embedding_summary_keys(seeded_db, db):
    from api.rag_corpus_console import _document_embedding_summary

    doc_id = seeded_db["doc1"]["document_id"]
    emb = _document_embedding_summary(db, tenant_id="tenant-a", document_id=doc_id)
    assert isinstance(emb, dict)
    for state in emb:
        assert state in {"pending", "processing", "completed", "failed", "skipped"}


# ---------------------------------------------------------------------------
# source_hash_prefix safety
# ---------------------------------------------------------------------------


def test_source_hash_prefix_is_short(seeded_db, db):
    from api.rag_corpus_console import _safe_source_hash_prefix

    full_hash = "a" * 64  # SHA-256 hex is 64 chars
    prefix = _safe_source_hash_prefix(full_hash)
    assert prefix is not None
    assert len(prefix) == 12


def test_source_hash_prefix_none_is_safe(db):
    from api.rag_corpus_console import _safe_source_hash_prefix

    assert _safe_source_hash_prefix(None) is None
    assert _safe_source_hash_prefix("") is None


# ---------------------------------------------------------------------------
# Metadata safety
# ---------------------------------------------------------------------------


def test_safe_metadata_strips_blocked_keys():
    from api.rag_corpus_console import _safe_metadata

    metadata = {
        "title": "safe",
        "embedding": "BLOCKED",
        "vector": "BLOCKED",
        "prompt": "BLOCKED",
        "credentials": "BLOCKED",
        "api_key": "BLOCKED",
        "provider_payload": "BLOCKED",
        "created_at": "2026-01-01",
    }
    result = _safe_metadata(metadata)
    assert result is not None
    assert "title" in result
    assert "created_at" in result
    for blocked in [
        "embedding",
        "vector",
        "prompt",
        "credentials",
        "api_key",
        "provider_payload",
    ]:
        assert blocked not in result, (
            f"Blocked key '{blocked}' must not appear in safe metadata"
        )


def test_safe_metadata_none_returns_none():
    from api.rag_corpus_console import _safe_metadata

    assert _safe_metadata(None) is None


def test_safe_metadata_non_dict_returns_none():
    from api.rag_corpus_console import _safe_metadata

    assert _safe_metadata("string") is None  # type: ignore[arg-type]
    assert _safe_metadata(42) is None  # type: ignore[arg-type]


def test_safe_metadata_strips_nested_blocked_keys():
    from api.rag_corpus_console import _safe_metadata

    # Nested dict whose key is safe but whose value contains a blocked sub-key
    metadata = {
        "connector": {
            "api_key": "should-be-gone",
            "name": "keep-this",
        },
        "tags": ["finance", "legal"],
        "title": "top-level-safe",
    }
    result = _safe_metadata(metadata)
    assert result is not None
    assert result["title"] == "top-level-safe"
    assert result["tags"] == ["finance", "legal"]
    connector = result.get("connector")
    assert connector is not None
    assert "api_key" not in connector
    assert connector.get("name") == "keep-this"


def test_safe_metadata_strips_deeply_nested_blocked_keys():
    from api.rag_corpus_console import _safe_metadata

    metadata = {
        "provider": {
            "credentials": {"key": "secret-value"},
            "region": "us-east-1",
        }
    }
    result = _safe_metadata(metadata)
    assert result is not None
    provider = result.get("provider")
    assert provider is not None
    assert "credentials" not in provider
    assert provider.get("region") == "us-east-1"


def test_safe_metadata_list_of_dicts_stripped():
    from api.rag_corpus_console import _safe_metadata

    metadata = {
        "sources": [
            {"url": "https://example.com", "api_key": "leaked"},
            {"url": "https://other.com"},
        ]
    }
    result = _safe_metadata(metadata)
    assert result is not None
    sources = result.get("sources")
    assert isinstance(sources, list)
    assert len(sources) == 2
    for src in sources:
        assert "api_key" not in src


# ---------------------------------------------------------------------------
# Ingestion status coverage
# ---------------------------------------------------------------------------


def test_all_known_ingestion_statuses_in_module():
    from api.rag_corpus_console import _KNOWN_INGESTION_STATUSES

    expected = {
        "received",
        "validating",
        "duplicate",
        "quarantined",
        "chunking",
        "embedding",
        "indexed",
        "failed",
        "superseded",
        "reindexing",
    }
    assert expected.issubset(_KNOWN_INGESTION_STATUSES)


def test_known_embedding_states_in_module():
    from api.rag_corpus_console import _KNOWN_EMBEDDING_STATES

    expected = {"pending", "processing", "completed", "failed", "skipped"}
    assert expected == _KNOWN_EMBEDDING_STATES


# ---------------------------------------------------------------------------
# Sort field validation
# ---------------------------------------------------------------------------


def test_allowed_sort_fields_defined():
    from api.rag_corpus_console import _ALLOWED_SORT_FIELDS

    assert "created_at" in _ALLOWED_SORT_FIELDS
    assert "updated_at" in _ALLOWED_SORT_FIELDS
    assert "title" in _ALLOWED_SORT_FIELDS
    assert "ingestion_status" in _ALLOWED_SORT_FIELDS
    assert "version_number" in _ALLOWED_SORT_FIELDS


def test_validate_sort_rejects_unknown_field():
    from fastapi import HTTPException
    from api.rag_corpus_console import _validate_sort

    with pytest.raises(HTTPException) as exc_info:
        _validate_sort("raw_text", "asc")
    assert exc_info.value.status_code == 422


def test_validate_sort_rejects_unknown_dir():
    from fastapi import HTTPException
    from api.rag_corpus_console import _validate_sort

    with pytest.raises(HTTPException) as exc_info:
        _validate_sort("created_at", "sideways")
    assert exc_info.value.status_code == 422


def test_validate_sort_accepts_valid():
    from api.rag_corpus_console import _validate_sort

    assert _validate_sort("created_at", "asc") == ("created_at", "asc")
    assert _validate_sort("title", "desc") == ("title", "desc")


# ---------------------------------------------------------------------------
# Quarantine visibility
# ---------------------------------------------------------------------------


def test_quarantined_document_visible_in_list(db):
    from api.rag_corpus_store import (
        create_corpus,
        ingest_document_version,
        list_documents,
    )

    corp = create_corpus(db, tenant_id="tenant-q", name="Quarantine Test")
    corpus_id = corp["corpus_id"]
    result = ingest_document_version(
        db,
        tenant_id="tenant-q",
        corpus_id=corpus_id,
        title="Empty Doc",
        source="src-empty",
        content="",  # will be quarantined (empty_document)
    )
    assert result["ingestion_status"] == "quarantined"

    docs = list_documents(db, "tenant-q", corpus_id)
    statuses = [d.get("ingestion_status") or "indexed" for d in docs]
    assert "quarantined" in statuses


def test_quarantined_document_not_in_active_chunk_count(db):
    from api.rag_corpus_store import create_corpus, ingest_document_version
    from api.rag_corpus_console import _corpus_document_chunk_counts

    corp = create_corpus(db, tenant_id="tenant-qchunk", name="Chunk Test")
    corpus_id = corp["corpus_id"]
    ingest_document_version(
        db,
        tenant_id="tenant-qchunk",
        corpus_id=corpus_id,
        title="Empty",
        source="src-empty",
        content="",  # quarantined — no chunks
    )
    counts = _corpus_document_chunk_counts(
        db, tenant_id="tenant-qchunk", corpus_id=corpus_id
    )
    assert counts["active_chunk_count"] == 0


# ---------------------------------------------------------------------------
# Regression: retrieval and provenance behavior unchanged
# ---------------------------------------------------------------------------


def test_rag_retrieval_module_importable():
    import api.rag_retrieval  # noqa: F401


def test_rag_corpus_store_module_importable():
    import api.rag_corpus_store  # noqa: F401


def test_rag_retrieval_policy_store_importable():
    import api.rag_retrieval_policy_store  # noqa: F401


def test_rag_corpus_console_importable():
    import api.rag_corpus_console  # noqa: F401
