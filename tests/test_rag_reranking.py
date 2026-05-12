from __future__ import annotations

import logging
import socket
from typing import Any, cast

import pytest

from api.rag_context import (
    RagChunkProvenance,
    RagContextChunk,
    RagContextRequest,
    RagContextResponse,
    RagRetrievalTrace,
)
from api.rag_reranking import (
    DeterministicLocalReranker,
    RerankConfig,
    rerank_response,
)
from services.ai.policy import AiRagRules
from services.ai.provenance import PROVENANCE_VALID, validate_answer_provenance
from services.ai.rag_context import retrieve_persisted_rag_context
from services.ai.response_validation import ResponseValidationResult


@pytest.fixture()
def db_session(tmp_path, monkeypatch):
    db_path = str(tmp_path / "reranking-test.db")
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


def _chunk(
    *,
    chunk_id: str,
    text: str,
    score: float,
    corpus_id: str = "corp-a",
    document_id: str = "doc-a",
    ordinal: int = 0,
) -> RagContextChunk:
    return RagContextChunk(
        text=text,
        score=score,
        combined_score=score,
        lexical_score=score,
        provenance=RagChunkProvenance(
            corpus_id=corpus_id,
            document_id=document_id,
            chunk_id=chunk_id,
            ordinal=ordinal,
        ),
        why_this_chunk={
            "score_components": {
                "lexical_score": score,
                "semantic_score": None,
                "combined_score": score,
            }
        },
    )


def _response(chunks: list[RagContextChunk]) -> RagContextResponse:
    return RagContextResponse(
        query="mfa recovery controls",
        chunks=chunks,
        retrieval_trace=RagRetrievalTrace(
            retrieval_trace_id="rt-rerank",
            retrieval_strategy="lexical",
            candidate_count=len(chunks),
            returned_count=len(chunks),
            duration_ms=1,
            confidence=0.5,
            confidence_reason="test",
        ),
    )


def _rules(**overrides: Any) -> AiRagRules:
    values = {
        "enabled": True,
        "require_grounded_response": True,
        "no_answer_on_ungrounded": True,
        "allowed_corpus_ids": (),
        "denied_corpus_ids": (),
        "max_top_k": 4,
        "allowed_retrieval_strategies": ("lexical",),
        "require_grounded_context": False,
        "allow_lexical_fallback": False,
        "allow_semantic": False,
        "allow_no_context_answer": True,
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


def _seed_document(
    db_session,
    *,
    tenant_id: str,
    corpus_name: str,
    chunks: list[dict[str, Any]],
) -> dict[str, str]:
    from api.rag_corpus_store import create_corpus, create_document, store_chunks

    corpus = create_corpus(db_session, tenant_id=tenant_id, name=corpus_name)
    document = create_document(
        db_session,
        tenant_id=tenant_id,
        corpus_id=corpus["corpus_id"],
        title=f"{corpus_name} doc",
    )
    stored = store_chunks(
        db_session,
        tenant_id=tenant_id,
        document_id=document["document_id"],
        corpus_id=corpus["corpus_id"],
        chunks=chunks,
    )
    return {
        "corpus_id": str(corpus["corpus_id"]),
        "document_id": str(document["document_id"]),
        "chunk_id": str(stored[0]["chunk_id"]),
    }


def test_reranker_improves_ordering_and_preserves_original_scores() -> None:
    response = _response(
        [
            _chunk(chunk_id="ck-bad", text="mfa overview", score=0.95, ordinal=0),
            _chunk(
                chunk_id="ck-good",
                text="mfa recovery controls require approval and recovery controls",
                score=0.70,
                ordinal=1,
            ),
        ]
    )

    reranked = rerank_response(response, query="mfa recovery controls")

    assert [chunk.provenance.chunk_id for chunk in reranked.chunks] == [
        "ck-good",
        "ck-bad",
    ]
    assert reranked.chunks[0].score == 0.70
    assert reranked.chunks[0].combined_score == 0.70
    assert reranked.chunks[0].rerank_score is not None
    assert reranked.chunks[0].final_score is not None
    assert reranked.chunks[0].rerank_reason == "query_term_coverage_density"


def test_rerank_top_n_limit_enforced() -> None:
    response = _response(
        [
            _chunk(chunk_id="ck-1", text="mfa", score=0.9, ordinal=0),
            _chunk(chunk_id="ck-2", text="mfa recovery controls", score=0.5, ordinal=1),
            _chunk(chunk_id="ck-3", text="mfa recovery controls", score=0.1, ordinal=2),
        ]
    )

    reranked = rerank_response(
        response,
        query="mfa recovery controls",
        config=RerankConfig(max_rerank_candidates=2),
    )

    assert [chunk.provenance.chunk_id for chunk in reranked.chunks] == [
        "ck-2",
        "ck-1",
        "ck-3",
    ]
    assert reranked.chunks[2].rerank_score is None


def test_rerank_results_are_deterministic() -> None:
    response_1 = _response(
        [
            _chunk(chunk_id="ck-1", text="mfa recovery", score=0.8, ordinal=0),
            _chunk(chunk_id="ck-2", text="mfa controls", score=0.8, ordinal=1),
        ]
    )
    response_2 = _response(
        [
            _chunk(chunk_id="ck-1", text="mfa recovery", score=0.8, ordinal=0),
            _chunk(chunk_id="ck-2", text="mfa controls", score=0.8, ordinal=1),
        ]
    )

    first = rerank_response(response_1, query="mfa recovery controls")
    second = rerank_response(response_2, query="mfa recovery controls")

    assert [c.provenance.chunk_id for c in first.chunks] == [
        c.provenance.chunk_id for c in second.chunks
    ]
    assert [c.final_score for c in first.chunks] == [
        c.final_score for c in second.chunks
    ]


def test_rerank_stable_tie_ordering_uses_required_keys() -> None:
    response = _response(
        [
            _chunk(
                chunk_id="ck-b",
                text="mfa recovery",
                score=0.5,
                corpus_id="corp-b",
                document_id="doc-b",
                ordinal=2,
            ),
            _chunk(
                chunk_id="ck-a",
                text="mfa recovery",
                score=0.5,
                corpus_id="corp-a",
                document_id="doc-a",
                ordinal=1,
            ),
        ]
    )

    reranked = rerank_response(response, query="mfa recovery")

    assert [chunk.provenance.chunk_id for chunk in reranked.chunks] == ["ck-a", "ck-b"]


def test_reranker_unavailable_falls_back_to_original_order() -> None:
    class BrokenReranker:
        def score(self, **_kwargs):
            raise RuntimeError("unavailable")

    response = _response(
        [
            _chunk(chunk_id="ck-1", text="mfa", score=0.9, ordinal=0),
            _chunk(chunk_id="ck-2", text="mfa recovery controls", score=0.1, ordinal=1),
        ]
    )

    reranked = rerank_response(
        response,
        query="mfa recovery controls",
        reranker=cast(DeterministicLocalReranker, BrokenReranker()),
    )

    assert [chunk.provenance.chunk_id for chunk in reranked.chunks] == ["ck-1", "ck-2"]
    assert all(
        chunk.rerank_reason == "reranker_unavailable" for chunk in reranked.chunks
    )


def test_reranker_makes_no_network_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fail_socket(*_args, **_kwargs):
        raise AssertionError("network calls are forbidden")

    monkeypatch.setattr(socket, "socket", _fail_socket)
    response = _response([_chunk(chunk_id="ck-1", text="mfa recovery", score=0.7)])

    reranked = rerank_response(response, query="mfa recovery")

    assert reranked.chunks[0].final_score is not None


def test_rerank_audit_has_no_raw_chunk_text(caplog) -> None:
    secret_text = "mfa recovery controls secret mrn12345"
    response = _response([_chunk(chunk_id="ck-1", text=secret_text, score=0.7)])

    with caplog.at_level(logging.INFO, logger="frostgate.rag_reranking"):
        rerank_response(response, query="mfa recovery controls mrn12345")

    audit_text = " ".join(str(record.__dict__) for record in caplog.records)
    assert "rag_reranking.completed" in audit_text
    assert secret_text not in audit_text
    assert "mrn12345" not in audit_text


def test_persisted_rerank_preserves_policy_and_tenant_isolation(db_session) -> None:
    local = _seed_document(
        db_session,
        tenant_id="tenant-a",
        corpus_name="Local",
        chunks=[
            {"text": "mfa evidence", "ordinal": 0},
            {"text": "mfa recovery controls evidence", "ordinal": 1},
        ],
    )
    _seed_document(
        db_session,
        tenant_id="tenant-b",
        corpus_name="Foreign",
        chunks=[{"text": "mfa recovery controls evidence foreign", "ordinal": 0}],
    )

    result = retrieve_persisted_rag_context(
        db=db_session,
        tenant_id="tenant-a",
        query_text="mfa recovery controls",
        limit=4,
        phi_detected=False,
        corpus_ids=[local["corpus_id"]],
        rag_rules=_rules(allowed_corpus_ids=(local["corpus_id"],), max_top_k=2),
    )

    assert result.chunk_count == 2
    assert result.retrieval_policy_metadata is not None
    assert result.retrieval_policy_metadata["effective_top_k"] == 2
    assert {chunk.chunk_id for chunk in result.chunks} <= set(
        result.retrieved_source_chunk_ids
    )
    assert all("foreign" not in chunk.text for chunk in result.chunks)
    assert result.chunks[0].why_this_chunk is not None
    assert result.chunks[0].why_this_chunk["rerank_reason"] == (
        "query_term_coverage_density"
    )


def test_provenance_enforcement_still_passes_after_rerank(db_session) -> None:
    seeded = _seed_document(
        db_session,
        tenant_id="tenant-a",
        corpus_name="Provenance",
        chunks=[{"text": "mfa recovery controls cited evidence", "ordinal": 0}],
    )

    result = retrieve_persisted_rag_context(
        db=db_session,
        tenant_id="tenant-a",
        query_text="mfa recovery controls",
        limit=4,
        phi_detected=False,
        corpus_ids=[seeded["corpus_id"]],
        rag_rules=_rules(allowed_corpus_ids=(seeded["corpus_id"],)),
    )
    validation = ResponseValidationResult(
        grounded=True,
        final_text=f"Answer cites chunk_id={result.chunks[0].chunk_id}",
        reason_code="RESPONSE_GROUNDED",
        citation_source_ids=(result.chunks[0].chunk_id,),
        validator_version="test",
        evidence_count=1,
    )

    updated, provenance = validate_answer_provenance(
        response_text=validation.final_text,
        rag_context=result,
        response_validation=validation,
    )

    assert updated.provenance_valid is True
    assert provenance.reason_code == PROVENANCE_VALID


def test_lexical_route_still_uses_lexical_retriever_with_rerank(
    db_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    import services.ai.rag_context as rag_context_mod

    calls: list[str] = []

    def _lexical(_db, request: RagContextRequest) -> RagContextResponse:
        calls.append("lexical")
        return _response(
            [
                _chunk(chunk_id="ck-1", text="mfa", score=0.9, ordinal=0),
                _chunk(
                    chunk_id="ck-2",
                    text="mfa recovery controls",
                    score=0.2,
                    ordinal=1,
                ),
            ]
        )

    monkeypatch.setattr(rag_context_mod, "retrieve_persisted_context", _lexical)

    result = retrieve_persisted_rag_context(
        db=db_session,
        tenant_id="tenant-a",
        query_text="mfa recovery controls",
        limit=4,
        phi_detected=False,
        rag_rules=_rules(max_top_k=2),
    )

    assert calls == ["lexical"]
    assert result.retrieval_strategy == "lexical"
    assert result.chunks[0].chunk_id == "ck-2"
