from __future__ import annotations

import logging

import pytest
from sqlalchemy import text

from api.rag_context import RagContextRequest
from api.rag_corpus_store import (
    INGESTION_DUPLICATE,
    INGESTION_INDEXED,
    INGESTION_QUARANTINED,
    INGESTION_SUPERSEDED,
    QUARANTINE_EMPTY_DOCUMENT,
    QUARANTINE_UNSUPPORTED_TYPE,
    canonical_source_hash,
    create_corpus,
    ingest_document_version,
    list_chunks,
    list_documents,
    reindex_document_version,
)
from api.rag_retrieval import retrieve_rag_context


@pytest.fixture()
def db_session(tmp_path, monkeypatch):
    db_path = str(tmp_path / "ingestion-hardening.db")
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


def _corpus(db_session, tenant_id: str = "tenant-a") -> str:
    return str(
        create_corpus(db_session, tenant_id=tenant_id, name="Hardening")["corpus_id"]
    )


def test_document_versioning_preserves_old_and_retrieves_only_current(
    db_session,
) -> None:
    corpus_id = _corpus(db_session)

    v1 = ingest_document_version(
        db_session,
        tenant_id="tenant-a",
        corpus_id=corpus_id,
        title="Runbook",
        source="runbook.md",
        content="old authentication runbook version one",
    )
    v2 = ingest_document_version(
        db_session,
        tenant_id="tenant-a",
        corpus_id=corpus_id,
        title="Runbook",
        source="runbook.md",
        content="new authentication runbook version two",
    )

    docs = list_documents(db_session, tenant_id="tenant-a", corpus_id=corpus_id)
    assert len(docs) == 2
    assert {doc["ingestion_status"] for doc in docs} == {
        INGESTION_SUPERSEDED,
        INGESTION_INDEXED,
    }
    assert v1["version_id"] != v2["version_id"]
    assert v2["version_number"] == 2

    response = retrieve_rag_context(
        db_session,
        RagContextRequest(
            tenant_id="tenant-a",
            corpus_ids=[corpus_id],
            query="old new authentication runbook",
            top_k=10,
        ),
    )

    assert response.chunks
    assert all("version one" not in chunk.text for chunk in response.chunks)
    assert any("version two" in chunk.text for chunk in response.chunks)


def test_same_tenant_duplicate_is_deterministic_and_does_not_add_chunks(
    db_session,
) -> None:
    corpus_id = _corpus(db_session)
    first = ingest_document_version(
        db_session,
        tenant_id="tenant-a",
        corpus_id=corpus_id,
        title="A",
        source="a.txt",
        content="duplicate ingestion content",
    )
    duplicate = ingest_document_version(
        db_session,
        tenant_id="tenant-a",
        corpus_id=corpus_id,
        title="B",
        source="different-name.txt",
        content="duplicate ingestion content",
    )

    assert duplicate["ingestion_status"] == INGESTION_DUPLICATE
    assert duplicate["duplicate_of_document_id"] == first["document_id"]
    docs = list_documents(db_session, tenant_id="tenant-a", corpus_id=corpus_id)
    assert len(docs) == 1
    chunks = list_chunks(
        db_session, tenant_id="tenant-a", document_id=first["document_id"]
    )
    assert len(chunks) == first["chunk_count"]


def test_cross_tenant_identical_content_does_not_leak_or_dedupe(db_session) -> None:
    corpus_a = _corpus(db_session, "tenant-a")
    corpus_b = _corpus(db_session, "tenant-b")

    a = ingest_document_version(
        db_session,
        tenant_id="tenant-a",
        corpus_id=corpus_a,
        title="Shared",
        source="shared.txt",
        content="same content across tenants",
    )
    b = ingest_document_version(
        db_session,
        tenant_id="tenant-b",
        corpus_id=corpus_b,
        title="Shared",
        source="shared.txt",
        content="same content across tenants",
    )

    assert a["ingestion_status"] == INGESTION_INDEXED
    assert b["ingestion_status"] == INGESTION_INDEXED
    assert a["document_id"] != b["document_id"]


def test_quarantined_documents_are_not_retrievable_and_create_no_chunks(
    db_session,
) -> None:
    corpus_id = _corpus(db_session)

    quarantined = ingest_document_version(
        db_session,
        tenant_id="tenant-a",
        corpus_id=corpus_id,
        title="Empty",
        source="empty.txt",
        content=" ",
    )

    assert quarantined["ingestion_status"] == INGESTION_QUARANTINED
    assert quarantined["quarantine_reason"] == QUARANTINE_EMPTY_DOCUMENT
    assert quarantined["chunk_count"] == 0
    assert (
        list_chunks(
            db_session, tenant_id="tenant-a", document_id=quarantined["document_id"]
        )
        == []
    )
    response = retrieve_rag_context(
        db_session,
        RagContextRequest(
            tenant_id="tenant-a",
            corpus_ids=[corpus_id],
            query="empty",
            top_k=10,
        ),
    )
    assert response.chunks == []


def test_unsupported_type_quarantine_is_safe_and_audited(
    db_session, caplog: pytest.LogCaptureFixture
) -> None:
    corpus_id = _corpus(db_session)
    caplog.set_level(logging.INFO, logger="frostgate.rag_corpus_store")
    result = ingest_document_version(
        db_session,
        tenant_id="tenant-a",
        corpus_id=corpus_id,
        title="Binary",
        source="binary.pdf",
        content="raw secret document body",
        content_type="application/pdf",
    )

    assert result["ingestion_status"] == INGESTION_QUARANTINED
    assert result["quarantine_reason"] == QUARANTINE_UNSUPPORTED_TYPE
    audit_text = " ".join(str(record.__dict__) for record in caplog.records)
    assert "raw secret document body" not in audit_text
    assert "document_quarantined" in audit_text


def test_reindex_current_version_is_idempotent_and_preserves_source_hash(
    db_session,
) -> None:
    corpus_id = _corpus(db_session)
    content = "reindex authentication source proof"
    indexed = ingest_document_version(
        db_session,
        tenant_id="tenant-a",
        corpus_id=corpus_id,
        title="Reindex",
        source="reindex.txt",
        content=content,
    )

    first = reindex_document_version(
        db_session,
        tenant_id="tenant-a",
        corpus_id=corpus_id,
        document_id=indexed["document_id"],
        version_id=indexed["version_id"],
        content=content,
    )
    second = reindex_document_version(
        db_session,
        tenant_id="tenant-a",
        corpus_id=corpus_id,
        document_id=indexed["document_id"],
        version_id=indexed["version_id"],
        content=content,
    )

    assert first["ingestion_status"] == INGESTION_INDEXED
    assert second["ingestion_status"] == INGESTION_INDEXED
    chunks = list_chunks(
        db_session, tenant_id="tenant-a", document_id=indexed["document_id"]
    )
    assert len(chunks) == second["chunk_count"]
    assert all(
        chunk["source_hash"] == canonical_source_hash(content) for chunk in chunks
    )
    assert all(
        chunk["document_version_id"] == indexed["version_id"] for chunk in chunks
    )


def test_reindex_superseded_version_rejected_and_stale_chunks_hidden(
    db_session,
) -> None:
    corpus_id = _corpus(db_session)
    v1 = ingest_document_version(
        db_session,
        tenant_id="tenant-a",
        corpus_id=corpus_id,
        title="Runbook",
        source="runbook.md",
        content="stale source content",
    )
    ingest_document_version(
        db_session,
        tenant_id="tenant-a",
        corpus_id=corpus_id,
        title="Runbook",
        source="runbook.md",
        content="fresh source content",
    )

    with pytest.raises(ValueError, match="current indexed"):
        reindex_document_version(
            db_session,
            tenant_id="tenant-a",
            corpus_id=corpus_id,
            document_id=v1["document_id"],
            version_id=v1["version_id"],
            content="stale source content",
        )

    stale_rows = (
        db_session.execute(
            text(
                "SELECT COUNT(*) AS count FROM rag_chunks "
                "WHERE document_id=:document_id AND COALESCE(is_active, 1)=1"
            ),
            {"document_id": v1["document_id"]},
        )
        .mappings()
        .first()
    )
    assert stale_rows is not None
    assert stale_rows["count"] == 0


def test_reindex_cross_tenant_rejected(db_session) -> None:
    corpus_a = _corpus(db_session, "tenant-a")
    indexed = ingest_document_version(
        db_session,
        tenant_id="tenant-a",
        corpus_id=corpus_a,
        title="Tenant A",
        source="a.txt",
        content="tenant a only",
    )

    with pytest.raises(ValueError, match="document version not found"):
        reindex_document_version(
            db_session,
            tenant_id="tenant-b",
            corpus_id=corpus_a,
            document_id=indexed["document_id"],
            version_id=indexed["version_id"],
            content="tenant a only",
        )


def test_source_hash_mismatch_fails_closed(db_session) -> None:
    corpus_id = _corpus(db_session)
    indexed = ingest_document_version(
        db_session,
        tenant_id="tenant-a",
        corpus_id=corpus_id,
        title="Hash",
        source="hash.txt",
        content="original hash content",
    )

    with pytest.raises(ValueError, match="source_hash mismatch"):
        reindex_document_version(
            db_session,
            tenant_id="tenant-a",
            corpus_id=corpus_id,
            document_id=indexed["document_id"],
            version_id=indexed["version_id"],
            content="tampered hash content",
        )
