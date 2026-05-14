from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text

from api.knowledge_facts import (
    ERR_EMPTY_OBJECT,
    ERR_EMPTY_PREDICATE,
    ERR_EMPTY_SUBJECT,
    ERR_INVALID_CONFIDENCE,
    ERR_MISSING_SOURCE_CHUNK,
    ERR_MISSING_SOURCE_DOC,
    ERR_MISSING_SOURCE_HASH,
    ERR_SOURCE_HASH_MISMATCH,
    ERR_SOURCE_NOT_CURRENT,
    ERR_SOURCE_NOT_FOUND,
    ERR_SOURCE_QUARANTINED,
    KnowledgeFactError,
    VerifiedFactInput,
    create_verified_fact,
    inspect_fact_proof,
    list_current_facts,
    list_historical_facts,
    list_retrieval_safe_current_facts,
)
from api.rag_corpus_store import (
    INGESTION_QUARANTINED,
    canonical_source_hash,
    create_corpus,
    ingest_document_version,
)


@pytest.fixture()
def db_session(tmp_path, monkeypatch):
    db_path = str(tmp_path / "knowledge-facts.db")
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


def _source(db_session, tenant_id: str = "tenant-a", content: str = "Alice is CISO"):
    corpus = create_corpus(db_session, tenant_id=tenant_id, name=f"Corpus {tenant_id}")
    doc = ingest_document_version(
        db_session,
        tenant_id=tenant_id,
        corpus_id=corpus["corpus_id"],
        title="Source",
        source=f"{tenant_id}.txt",
        content=content,
    )
    chunk = (
        db_session.execute(
            text(
                """
                SELECT chunk_id, source_hash
                FROM rag_chunks
                WHERE tenant_id = :tenant_id AND document_id = :document_id
                """
            ),
            {"tenant_id": tenant_id, "document_id": doc["document_id"]},
        )
        .mappings()
        .one()
    )
    return corpus, doc, dict(chunk)


def _fact_input(doc: dict, chunk: dict, **overrides) -> VerifiedFactInput:
    payload = {
        "tenant_id": doc["tenant_id"],
        "subject": "Alice",
        "predicate": "role",
        "object": "CISO",
        "confidence": 0.91,
        "source_doc_id": doc["document_id"],
        "source_chunk_id": chunk["chunk_id"],
        "source_hash": chunk["source_hash"],
    }
    payload.update(overrides)
    return VerifiedFactInput(**payload)


def _assert_rejected(db_session, fact: VerifiedFactInput, code: str) -> None:
    with pytest.raises(KnowledgeFactError) as exc:
        create_verified_fact(db_session, fact)
    assert exc.value.code == code
    assert (
        db_session.execute(text("SELECT COUNT(*) FROM knowledge_facts")).scalar_one()
        == 0
    )


def test_fact_requires_complete_source_proof(db_session) -> None:
    _, doc, chunk = _source(db_session)

    _assert_rejected(
        db_session, _fact_input(doc, chunk, source_doc_id=" "), ERR_MISSING_SOURCE_DOC
    )
    _assert_rejected(
        db_session,
        _fact_input(doc, chunk, source_chunk_id=" "),
        ERR_MISSING_SOURCE_CHUNK,
    )
    _assert_rejected(
        db_session, _fact_input(doc, chunk, source_hash=" "), ERR_MISSING_SOURCE_HASH
    )

    fact = create_verified_fact(db_session, _fact_input(doc, chunk))
    assert fact["source_doc_id"] == doc["document_id"]
    assert fact["source_chunk_id"] == chunk["chunk_id"]
    assert fact["source_hash"] == chunk["source_hash"]


def test_fact_rejects_empty_fields_and_invalid_confidence(db_session) -> None:
    _, doc, chunk = _source(db_session)

    _assert_rejected(
        db_session, _fact_input(doc, chunk, subject=" "), ERR_EMPTY_SUBJECT
    )
    _assert_rejected(
        db_session, _fact_input(doc, chunk, predicate=" "), ERR_EMPTY_PREDICATE
    )
    _assert_rejected(db_session, _fact_input(doc, chunk, object=" "), ERR_EMPTY_OBJECT)
    _assert_rejected(
        db_session, _fact_input(doc, chunk, confidence=-0.01), ERR_INVALID_CONFIDENCE
    )
    _assert_rejected(
        db_session, _fact_input(doc, chunk, confidence=1.01), ERR_INVALID_CONFIDENCE
    )


def test_source_hash_and_cross_tenant_binding_are_rejected(db_session) -> None:
    _, doc_a, chunk_a = _source(db_session, "tenant-a")
    _, doc_b, chunk_b = _source(db_session, "tenant-b")

    _assert_rejected(
        db_session,
        _fact_input(doc_a, chunk_a, source_hash="not-the-source-hash"),
        ERR_SOURCE_HASH_MISMATCH,
    )
    _assert_rejected(
        db_session,
        _fact_input(
            doc_a,
            chunk_a,
            source_doc_id=doc_b["document_id"],
            source_chunk_id=chunk_b["chunk_id"],
            source_hash=chunk_b["source_hash"],
        ),
        ERR_SOURCE_NOT_FOUND,
    )
    _assert_rejected(
        db_session,
        _fact_input(doc_a, chunk_a, source_chunk_id=chunk_b["chunk_id"]),
        ERR_SOURCE_NOT_FOUND,
    )


def test_quarantined_and_superseded_sources_cannot_create_current_facts(
    db_session,
) -> None:
    corpus = create_corpus(db_session, tenant_id="tenant-a", name="Quarantine")
    quarantined = ingest_document_version(
        db_session,
        tenant_id="tenant-a",
        corpus_id=corpus["corpus_id"],
        title="Empty",
        source="empty.txt",
        content=" ",
    )
    assert quarantined["ingestion_status"] == INGESTION_QUARANTINED
    db_session.execute(
        text(
            """
            INSERT INTO rag_chunks (
                chunk_id, document_id, corpus_id, tenant_id, text, ordinal,
                source_hash, is_active, created_at
            )
            VALUES ('ck-quarantined', :document_id, :corpus_id, 'tenant-a',
                    'quarantined evidence', 0, :source_hash, 1, :created_at)
            """
        ),
        {
            "document_id": quarantined["document_id"],
            "corpus_id": corpus["corpus_id"],
            "source_hash": canonical_source_hash(" "),
            "created_at": datetime.now(timezone.utc).isoformat(),
        },
    )
    db_session.commit()

    _assert_rejected(
        db_session,
        VerifiedFactInput(
            tenant_id="tenant-a",
            subject="A",
            predicate="B",
            object="C",
            confidence=0.8,
            source_doc_id=quarantined["document_id"],
            source_chunk_id="ck-quarantined",
            source_hash=canonical_source_hash(" "),
        ),
        ERR_SOURCE_QUARANTINED,
    )

    _, v1, chunk_v1 = _source(db_session, "tenant-a", "Old source value")
    ingest_document_version(
        db_session,
        tenant_id="tenant-a",
        corpus_id=v1["corpus_id"],
        title="Source",
        source="tenant-a.txt",
        content="New source value",
    )
    _assert_rejected(db_session, _fact_input(v1, chunk_v1), ERR_SOURCE_NOT_CURRENT)


def test_expired_and_historical_fact_lookup_remain_tenant_scoped(db_session) -> None:
    _, doc_a, chunk_a = _source(db_session, "tenant-a")
    _, doc_b, chunk_b = _source(db_session, "tenant-b")
    now = datetime.now(timezone.utc)

    expired = create_verified_fact(
        db_session,
        _fact_input(
            doc_a,
            chunk_a,
            valid_from=now - timedelta(days=2),
            valid_to=now - timedelta(days=1),
        ),
    )
    create_verified_fact(db_session, _fact_input(doc_b, chunk_b))

    assert list_current_facts(db_session, tenant_id="tenant-a") == []
    historical = list_historical_facts(db_session, tenant_id="tenant-a")
    assert [fact["id"] for fact in historical] == [expired["id"]]
    assert all(fact["tenant_id"] == "tenant-a" for fact in historical)


def test_contradiction_detection_and_non_overlapping_windows(db_session) -> None:
    _, doc, chunk = _source(db_session)
    now = datetime.now(timezone.utc)
    first = create_verified_fact(
        db_session,
        _fact_input(
            doc,
            chunk,
            object="CISO",
            valid_from=now,
            valid_to=now + timedelta(days=10),
        ),
    )
    contradicted = create_verified_fact(
        db_session,
        _fact_input(
            doc,
            chunk,
            object="CFO",
            valid_from=now + timedelta(days=1),
            valid_to=now + timedelta(days=2),
        ),
    )
    non_overlapping = create_verified_fact(
        db_session,
        _fact_input(
            doc,
            chunk,
            object="CTO",
            valid_from=now + timedelta(days=20),
            valid_to=now + timedelta(days=30),
        ),
    )

    assert first["review_status"] == "active"
    assert contradicted["review_status"] == "needs_review"
    assert contradicted["contradiction_of_fact_id"] == first["id"]
    assert non_overlapping["review_status"] == "active"


def test_same_fact_from_same_source_is_idempotent(db_session) -> None:
    _, doc, chunk = _source(db_session)

    first = create_verified_fact(db_session, _fact_input(doc, chunk))
    second = create_verified_fact(
        db_session,
        _fact_input(doc, chunk, subject=" alice ", predicate=" ROLE ", object=" ciso "),
    )

    assert first["id"] == second["id"]
    assert (
        db_session.execute(text("SELECT COUNT(*) FROM knowledge_facts")).scalar_one()
        == 1
    )


def test_retrieval_safe_lookup_revalidates_source_hash_and_status(db_session) -> None:
    _, doc, chunk = _source(db_session)
    fact = create_verified_fact(db_session, _fact_input(doc, chunk))
    assert [
        item["id"]
        for item in list_retrieval_safe_current_facts(db_session, tenant_id="tenant-a")
    ] == [fact["id"]]

    db_session.execute(
        text(
            "UPDATE rag_chunks SET source_hash = 'tampered' "
            "WHERE tenant_id = 'tenant-a' AND chunk_id = :chunk_id"
        ),
        {"chunk_id": chunk["chunk_id"]},
    )
    db_session.commit()

    assert list_retrieval_safe_current_facts(db_session, tenant_id="tenant-a") == []
    proof = inspect_fact_proof(db_session, tenant_id="tenant-a", fact_id=fact["id"])
    assert proof is not None
    assert proof["source_valid"] is False
    assert proof["reason_code"] == ERR_SOURCE_HASH_MISMATCH
