from __future__ import annotations

import pytest
from sqlalchemy import text

from api.knowledge_facts import (
    ERR_SOURCE_HASH_MISMATCH,
    ERR_SOURCE_NOT_FOUND,
    ERR_SOURCE_POLICY_DENIED,
    KnowledgeFactError,
    VerifiedFactInput,
    create_verified_fact,
    list_current_facts,
    list_retrieval_safe_current_facts,
)
from api.rag_corpus_store import create_corpus, ingest_document_version


@pytest.fixture()
def db_session(tmp_path, monkeypatch):
    db_path = str(tmp_path / "knowledge-facts-security.db")
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


def _source(db_session, tenant_id: str, corpus_name: str):
    corpus = create_corpus(db_session, tenant_id=tenant_id, name=corpus_name)
    doc = ingest_document_version(
        db_session,
        tenant_id=tenant_id,
        corpus_id=corpus["corpus_id"],
        title="Tenant Evidence",
        source=f"{tenant_id}.txt",
        content=f"{tenant_id} verified control evidence",
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


def _input(doc: dict, chunk: dict, **overrides) -> VerifiedFactInput:
    payload = {
        "tenant_id": doc["tenant_id"],
        "subject": "Control",
        "predicate": "owner",
        "object": "Security",
        "confidence": 0.9,
        "source_doc_id": doc["document_id"],
        "source_chunk_id": chunk["chunk_id"],
        "source_hash": chunk["source_hash"],
    }
    payload.update(overrides)
    return VerifiedFactInput(**payload)


def test_cross_tenant_document_and_chunk_binding_fails_closed(db_session) -> None:
    _, doc_a, chunk_a = _source(db_session, "tenant-a", "A")
    _, doc_b, chunk_b = _source(db_session, "tenant-b", "B")

    with pytest.raises(KnowledgeFactError) as exc:
        create_verified_fact(
            db_session,
            _input(
                doc_a,
                chunk_a,
                source_doc_id=doc_b["document_id"],
                source_chunk_id=chunk_b["chunk_id"],
                source_hash=chunk_b["source_hash"],
            ),
        )
    assert exc.value.code == ERR_SOURCE_NOT_FOUND
    assert list_current_facts(db_session, tenant_id="tenant-a") == []
    assert list_current_facts(db_session, tenant_id="tenant-b") == []


def test_caller_source_hash_is_revalidated_not_trusted(db_session) -> None:
    _, doc, chunk = _source(db_session, "tenant-a", "A")

    with pytest.raises(KnowledgeFactError) as exc:
        create_verified_fact(db_session, _input(doc, chunk, source_hash="caller-fake"))

    assert exc.value.code == ERR_SOURCE_HASH_MISMATCH
    assert list_current_facts(db_session, tenant_id="tenant-a") == []


def test_retrieval_safe_facts_enforce_corpus_policy(db_session) -> None:
    corpus_allowed, doc_allowed, chunk_allowed = _source(
        db_session, "tenant-a", "Allowed"
    )
    corpus_denied, doc_denied, chunk_denied = _source(db_session, "tenant-a", "Denied")
    allowed_fact = create_verified_fact(db_session, _input(doc_allowed, chunk_allowed))
    create_verified_fact(
        db_session,
        _input(
            doc_denied,
            chunk_denied,
            subject="Denied Control",
            object="Denied Owner",
        ),
    )

    safe = list_retrieval_safe_current_facts(
        db_session,
        tenant_id="tenant-a",
        allowed_corpus_ids=[corpus_allowed["corpus_id"]],
    )

    assert [fact["id"] for fact in safe] == [allowed_fact["id"]]
    safe_from_generator = list_retrieval_safe_current_facts(
        db_session,
        tenant_id="tenant-a",
        allowed_corpus_ids=(corpus_id for corpus_id in [corpus_allowed["corpus_id"]]),
    )
    assert [fact["id"] for fact in safe_from_generator] == [allowed_fact["id"]]

    with pytest.raises(KnowledgeFactError) as exc:
        create_verified_fact(
            db_session,
            _input(
                doc_denied,
                chunk_denied,
                subject="Blocked",
                object="Blocked Owner",
                allowed_corpus_ids=(corpus_allowed["corpus_id"],),
            ),
        )
    assert exc.value.code == ERR_SOURCE_POLICY_DENIED
    assert corpus_denied["corpus_id"] != corpus_allowed["corpus_id"]
