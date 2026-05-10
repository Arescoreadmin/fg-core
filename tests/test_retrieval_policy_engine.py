from __future__ import annotations

import logging
from typing import Any, cast

import pytest

from services.ai.policy import AiRagRules
from services.ai.rag_context import (
    RagContextResult,
    RagContextError,
    retrieve_persisted_rag_context,
)
from services.ai.retrieval_policy import (
    RETRIEVAL_POLICY_LEXICAL_FALLBACK,
    RETRIEVAL_POLICY_NO_CONTEXT_DENIED,
    RETRIEVAL_POLICY_STRATEGY_DENIED,
    evaluate_retrieval_policy,
)


@pytest.fixture()
def db_session(tmp_path, monkeypatch):
    db_path = str(tmp_path / "retrieval-policy-test.db")
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


def _rules(**overrides: Any) -> AiRagRules:
    values = {
        "enabled": True,
        "require_grounded_response": True,
        "no_answer_on_ungrounded": True,
        "allowed_corpus_ids": (),
        "denied_corpus_ids": (),
        "max_top_k": 4,
        "allowed_retrieval_strategies": ("lexical",),
        "require_grounded_context": True,
        "allow_lexical_fallback": False,
        "allow_semantic": False,
        "allow_no_context_answer": False,
    }
    values.update(overrides)
    return AiRagRules(
        enabled=cast(bool, values["enabled"]),
        require_grounded_response=cast(bool, values["require_grounded_response"]),
        no_answer_on_ungrounded=cast(bool, values["no_answer_on_ungrounded"]),
        allowed_corpus_ids=cast(tuple[str, ...], values["allowed_corpus_ids"]),
        denied_corpus_ids=cast(tuple[str, ...], values["denied_corpus_ids"]),
        max_top_k=cast(int, values["max_top_k"]),
        allowed_retrieval_strategies=cast(
            tuple[str, ...], values["allowed_retrieval_strategies"]
        ),
        require_grounded_context=cast(bool, values["require_grounded_context"]),
        allow_lexical_fallback=cast(bool, values["allow_lexical_fallback"]),
        allow_semantic=cast(bool, values["allow_semantic"]),
        allow_no_context_answer=cast(bool, values["allow_no_context_answer"]),
    )


def _policy_metadata(result: RagContextResult) -> dict[str, object]:
    assert result.retrieval_policy_metadata is not None
    return result.retrieval_policy_metadata


def _seed_document(
    db_session,
    *,
    tenant_id: str,
    corpus_name: str,
    text: str,
) -> dict[str, str]:
    from api.rag_corpus_store import create_corpus, create_document, store_chunks

    corpus = create_corpus(db_session, tenant_id=tenant_id, name=corpus_name)
    document = create_document(
        db_session,
        tenant_id=tenant_id,
        corpus_id=corpus["corpus_id"],
        title=f"{corpus_name} guide",
    )
    chunks = store_chunks(
        db_session,
        tenant_id=tenant_id,
        document_id=document["document_id"],
        corpus_id=corpus["corpus_id"],
        chunks=[{"text": text, "ordinal": 0}],
    )
    return {
        "corpus_id": str(corpus["corpus_id"]),
        "document_id": str(document["document_id"]),
        "chunk_id": str(chunks[0]["chunk_id"]),
    }


def test_allowed_corpus_policy_passes(db_session) -> None:
    allowed = _seed_document(
        db_session,
        tenant_id="tenant-a",
        corpus_name="Allowed",
        text="retrieval policy allowed corpus evidence",
    )
    _seed_document(
        db_session,
        tenant_id="tenant-a",
        corpus_name="Other",
        text="retrieval policy other corpus evidence",
    )

    result = retrieve_persisted_rag_context(
        db=db_session,
        tenant_id="tenant-a",
        query_text="retrieval policy evidence",
        limit=4,
        phi_detected=False,
        corpus_ids=[allowed["corpus_id"]],
        rag_rules=_rules(allowed_corpus_ids=(allowed["corpus_id"],)),
    )

    assert result.chunk_count == 1
    assert result.chunks[0].chunk_id == allowed["chunk_id"]
    assert _policy_metadata(result)["effective_corpus_count"] == 1


def test_denied_corpus_policy_blocks_without_broadening(db_session) -> None:
    denied = _seed_document(
        db_session,
        tenant_id="tenant-a",
        corpus_name="Denied",
        text="blocked corpus policy evidence",
    )
    _seed_document(
        db_session,
        tenant_id="tenant-a",
        corpus_name="Allowed",
        text="blocked corpus policy evidence",
    )

    with pytest.raises(RagContextError) as exc:
        retrieve_persisted_rag_context(
            db=db_session,
            tenant_id="tenant-a",
            query_text="blocked corpus policy evidence",
            limit=4,
            phi_detected=False,
            corpus_ids=[denied["corpus_id"]],
            rag_rules=_rules(denied_corpus_ids=(denied["corpus_id"],)),
        )

    assert exc.value.error_code == RETRIEVAL_POLICY_NO_CONTEXT_DENIED


def test_unknown_corpus_returns_empty_when_no_context_allowed(db_session) -> None:
    _seed_document(
        db_session,
        tenant_id="tenant-a",
        corpus_name="Known",
        text="unknown corpus must not broaden",
    )

    result = retrieve_persisted_rag_context(
        db=db_session,
        tenant_id="tenant-a",
        query_text="unknown corpus",
        limit=4,
        phi_detected=False,
        corpus_ids=["corp-does-not-exist"],
        rag_rules=_rules(
            require_grounded_context=False,
            allow_no_context_answer=True,
        ),
    )

    assert result.chunk_count == 0
    assert _policy_metadata(result)["effective_corpus_count"] == 0


def test_policy_clamps_top_k(db_session) -> None:
    corpus = _seed_document(
        db_session,
        tenant_id="tenant-a",
        corpus_name="Clamp",
        text="policy clamp shared evidence one",
    )
    from api.rag_corpus_store import store_chunks

    store_chunks(
        db_session,
        tenant_id="tenant-a",
        document_id=corpus["document_id"],
        corpus_id=corpus["corpus_id"],
        chunks=[
            {"text": "policy clamp shared evidence two", "ordinal": 1},
            {"text": "policy clamp shared evidence three", "ordinal": 2},
        ],
    )

    result = retrieve_persisted_rag_context(
        db=db_session,
        tenant_id="tenant-a",
        query_text="policy clamp shared evidence",
        limit=4,
        phi_detected=False,
        rag_rules=_rules(max_top_k=1),
    )

    assert result.chunk_count == 1
    metadata = _policy_metadata(result)
    assert metadata["requested_top_k"] == 4
    assert metadata["effective_top_k"] == 1


def test_semantic_disabled_policy_denies_semantic_strategy(db_session) -> None:
    decision = evaluate_retrieval_policy(
        db_session,
        tenant_id="tenant-a",
        corpus_ids=[],
        top_k=4,
        requested_strategy="hybrid",
        rag_rules=_rules(),
    )

    assert decision.allowed is False
    assert decision.reason_code == RETRIEVAL_POLICY_STRATEGY_DENIED


def test_lexical_fallback_policy_uses_lexical_strategy(db_session) -> None:
    _seed_document(
        db_session,
        tenant_id="tenant-a",
        corpus_name="Fallback",
        text="lexical fallback policy evidence",
    )

    result = retrieve_persisted_rag_context(
        db=db_session,
        tenant_id="tenant-a",
        query_text="lexical fallback evidence",
        limit=4,
        phi_detected=False,
        requested_strategy="hybrid",
        rag_rules=_rules(allow_lexical_fallback=True),
    )

    assert result.chunk_count == 1
    assert result.retrieval_policy_reason_code == RETRIEVAL_POLICY_LEXICAL_FALLBACK
    assert _policy_metadata(result)["lexical_fallback_used"] is True


def test_require_grounded_context_blocks_no_context_answer(db_session) -> None:
    _seed_document(
        db_session,
        tenant_id="tenant-a",
        corpus_name="Grounded",
        text="available grounded evidence",
    )

    with pytest.raises(RagContextError) as exc:
        retrieve_persisted_rag_context(
            db=db_session,
            tenant_id="tenant-a",
            query_text="no matching context",
            limit=4,
            phi_detected=False,
            rag_rules=_rules(),
        )

    assert exc.value.error_code == RETRIEVAL_POLICY_NO_CONTEXT_DENIED


def test_policy_preserves_tenant_isolation_for_foreign_corpus(db_session) -> None:
    foreign = _seed_document(
        db_session,
        tenant_id="tenant-b",
        corpus_name="Foreign",
        text="foreign tenant policy evidence",
    )
    _seed_document(
        db_session,
        tenant_id="tenant-a",
        corpus_name="Local",
        text="foreign tenant policy evidence",
    )

    result = retrieve_persisted_rag_context(
        db=db_session,
        tenant_id="tenant-a",
        query_text="foreign tenant policy evidence",
        limit=4,
        phi_detected=False,
        corpus_ids=[foreign["corpus_id"]],
        rag_rules=_rules(
            require_grounded_context=False,
            allow_no_context_answer=True,
        ),
    )

    assert result.chunk_count == 0
    assert _policy_metadata(result)["effective_corpus_count"] == 0


def test_policy_decision_audited_without_chunk_text(db_session, caplog) -> None:
    secret_text = "retrieval policy audit raw chunk secret 123-45-6789"
    _seed_document(
        db_session,
        tenant_id="tenant-a",
        corpus_name="Audit",
        text=secret_text,
    )
    caplog.set_level(logging.INFO, logger="frostgate.ai.retrieval_policy")

    result = retrieve_persisted_rag_context(
        db=db_session,
        tenant_id="tenant-a",
        query_text="retrieval policy audit",
        limit=4,
        phi_detected=False,
        rag_rules=_rules(),
    )

    assert result.chunk_count == 1
    records = [
        record
        for record in caplog.records
        if record.name == "frostgate.ai.retrieval_policy"
    ]
    assert records
    assert any(record.reason_code == "RETRIEVAL_POLICY_ALLOWED" for record in records)
    for record in records:
        assert secret_text not in str(record.__dict__)
        assert "123-45-6789" not in str(record.__dict__)
