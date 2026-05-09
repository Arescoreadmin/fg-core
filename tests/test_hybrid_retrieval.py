from __future__ import annotations

import importlib
import math
import os
from datetime import datetime, timezone
from typing import Any

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.sql import text as sqltext

os.environ.setdefault("FG_ENV", "test")

from api.embeddings.contracts import (  # noqa: E402
    ChunkEmbeddingRecord,
    EmbeddingMetadata,
    EmbeddingRequest,
    EmbeddingResponse,
    canonical_content_hash,
)
from api.embeddings.providers import EmbeddingModel  # noqa: E402
from api.rag_context import RagContextRequest  # noqa: E402
from api.rag_corpus_store import create_corpus, create_document, store_chunks  # noqa: E402
from api.rag_hybrid_retrieval import (  # noqa: E402
    DEFAULT_RRF_K,
    HybridRetrievalConfig,
    retrieve_rag_context_hybrid_rrf,
)
from services.embeddings import ensure_sqlite_schema, upsert_embedding  # noqa: E402

_TENANT_A = "tenant-hybrid-a"
_TENANT_B = "tenant-hybrid-b"
_MODEL = EmbeddingModel.INSTRUCTOR_XL
_DIMENSIONS = 768


class StaticQueryProvider:
    def __init__(self, vector: tuple[float, ...]) -> None:
        self._vector = vector

    @property
    def model(self) -> EmbeddingModel:
        return _MODEL

    @property
    def dimensions(self) -> int:
        return _DIMENSIONS

    def embed(self, request: EmbeddingRequest) -> EmbeddingResponse:
        return EmbeddingResponse(
            chunk_id=request.chunk_id,
            tenant_id=request.tenant_id,
            vector=self._vector,
            metadata=EmbeddingMetadata(
                model=_MODEL,
                dimensions=_DIMENSIONS,
                corpus_id=request.corpus_id,
                chunk_id=request.chunk_id,
                content_hash=request.content_hash,
            ),
        )

    def embed_batch(self, requests: list[EmbeddingRequest]) -> list[EmbeddingResponse]:
        return [self.embed(request) for request in requests]

    def is_available(self) -> bool:
        return True


@pytest.fixture()
def engine(tmp_path):
    from api.db import init_db, reset_engine_cache

    db_path = str(tmp_path / "hybrid-test.db")
    reset_engine_cache()
    init_db(sqlite_path=db_path)
    e = create_engine(f"sqlite:///{db_path}")
    ensure_sqlite_schema(e)
    return e


@pytest.fixture()
def db(engine):
    with Session(engine) as session:
        yield session
        session.rollback()


@pytest.fixture()
def provider() -> StaticQueryProvider:
    return StaticQueryProvider(_vector(1.0, 0.0))


def _vector(first: float, second: float) -> tuple[float, ...]:
    return (first, second, *([0.0] * (_DIMENSIONS - 2)))


def _seed(
    db: Session,
    *,
    tenant_id: str = _TENANT_A,
    corpus_name: str = "Hybrid",
    chunks: list[dict[str, Any]],
) -> tuple[dict, dict, list[dict]]:
    corpus = create_corpus(db, tenant_id=tenant_id, name=corpus_name)
    document = create_document(
        db,
        tenant_id=tenant_id,
        corpus_id=corpus["corpus_id"],
        title=f"{corpus_name} Doc",
        source=f"https://example.test/{corpus_name.lower()}",
    )
    stored = store_chunks(
        db,
        tenant_id=tenant_id,
        document_id=document["document_id"],
        corpus_id=corpus["corpus_id"],
        chunks=chunks,
    )
    return corpus, document, stored


def _persist_vector(
    db: Session,
    *,
    tenant_id: str,
    corpus_id: str,
    document_id: str,
    chunk_id: str,
    text: str,
    vector: tuple[float, ...],
) -> None:
    upsert_embedding(
        db,
        ChunkEmbeddingRecord(
            tenant_id=tenant_id,
            corpus_id=corpus_id,
            document_id=document_id,
            chunk_id=chunk_id,
            content_hash=canonical_content_hash(text),
            embedding_model=_MODEL,
            dimensions=_DIMENSIONS,
            vector=vector,
            created_at=datetime.now(timezone.utc),
        ),
    )


def _request(
    query: str,
    *,
    tenant_id: str = _TENANT_A,
    corpus_ids: list[str] | None = None,
    top_k: int = 10,
) -> RagContextRequest:
    return RagContextRequest(
        query=query,
        tenant_id=tenant_id,
        corpus_ids=corpus_ids or [],
        top_k=top_k,
    )


def test_hybrid_rrf_lexical_only_hits_survive(db, provider):
    _seed(
        db,
        chunks=[
            {"text": "alpha retention policy", "ordinal": 0},
            {"text": "invoice billing schedule", "ordinal": 1},
        ],
    )

    response = retrieve_rag_context_hybrid_rrf(
        db, _request("alpha retention"), provider=provider
    )

    assert [chunk.text for chunk in response.chunks] == ["alpha retention policy"]
    chunk = response.chunks[0]
    assert chunk.lexical_score is not None and chunk.lexical_score > 0.0
    assert chunk.semantic_score == 0.0
    assert chunk.retrieval_strategy == "hybrid_rrf"


def test_hybrid_rrf_semantic_only_hits_survive(db, provider):
    corpus, document, stored = _seed(
        db,
        chunks=[
            {"text": "alpha lexical policy", "ordinal": 0},
            {"text": "semantically adjacent control", "ordinal": 1},
        ],
    )
    _persist_vector(
        db,
        tenant_id=_TENANT_A,
        corpus_id=corpus["corpus_id"],
        document_id=document["document_id"],
        chunk_id=stored[1]["chunk_id"],
        text="semantically adjacent control",
        vector=_vector(1.0, 0.0),
    )

    response = retrieve_rag_context_hybrid_rrf(db, _request("alpha"), provider=provider)

    texts = [chunk.text for chunk in response.chunks]
    assert "alpha lexical policy" in texts
    assert "semantically adjacent control" in texts
    semantic_only = next(
        chunk
        for chunk in response.chunks
        if chunk.text == "semantically adjacent control"
    )
    assert semantic_only.lexical_score == 0.0
    assert semantic_only.semantic_score == 1.0


def test_hybrid_rrf_improves_ranking_stability(db, provider):
    corpus, document, stored = _seed(
        db,
        chunks=[
            {"text": "alpha first", "ordinal": 0},
            {"text": "alpha second", "ordinal": 1},
            {"text": "semantic third", "ordinal": 2},
        ],
    )
    for index, chunk in enumerate(stored):
        _persist_vector(
            db,
            tenant_id=_TENANT_A,
            corpus_id=corpus["corpus_id"],
            document_id=document["document_id"],
            chunk_id=chunk["chunk_id"],
            text=chunk["text"],
            vector=_vector(1.0, float(index)),
        )

    response_1 = retrieve_rag_context_hybrid_rrf(
        db, _request("alpha"), provider=provider
    )
    response_2 = retrieve_rag_context_hybrid_rrf(
        db, _request("alpha"), provider=provider
    )

    assert [c.provenance.chunk_id for c in response_1.chunks] == [
        c.provenance.chunk_id for c in response_2.chunks
    ]
    assert response_1.chunks[0].rrf_score is not None
    assert response_1.chunks[0].combined_score == response_1.chunks[0].rrf_score


def test_hybrid_rrf_duplicate_candidates_merge_by_chunk_id(db, provider):
    corpus, document, stored = _seed(
        db,
        chunks=[{"text": "alpha duplicated candidate", "ordinal": 0}],
    )
    _persist_vector(
        db,
        tenant_id=_TENANT_A,
        corpus_id=corpus["corpus_id"],
        document_id=document["document_id"],
        chunk_id=stored[0]["chunk_id"],
        text="alpha duplicated candidate",
        vector=_vector(1.0, 0.0),
    )

    response = retrieve_rag_context_hybrid_rrf(db, _request("alpha"), provider=provider)

    assert len(response.chunks) == 1
    chunk = response.chunks[0]
    assert chunk.lexical_score is not None and chunk.lexical_score > 0.0
    assert chunk.semantic_score == 1.0
    assert chunk.rrf_score == pytest.approx(2 / (DEFAULT_RRF_K + 1))


def test_hybrid_rrf_filters_stale_embedding_content_hashes(db):
    provider = StaticQueryProvider(_vector(1.0, 0.0))
    corpus, document, stored = _seed(
        db,
        chunks=[{"text": "legacy semantic text", "ordinal": 0}],
    )
    chunk = stored[0]
    _persist_vector(
        db,
        tenant_id=_TENANT_A,
        corpus_id=corpus["corpus_id"],
        document_id=document["document_id"],
        chunk_id=chunk["chunk_id"],
        text="legacy semantic text",
        vector=_vector(1.0, 0.0),
    )
    db.execute(
        sqltext("UPDATE rag_chunks SET text = :text WHERE chunk_id = :chunk_id"),
        {
            "text": "current semantic text",
            "chunk_id": chunk["chunk_id"],
        },
    )
    db.commit()
    _persist_vector(
        db,
        tenant_id=_TENANT_A,
        corpus_id=corpus["corpus_id"],
        document_id=document["document_id"],
        chunk_id=chunk["chunk_id"],
        text="current semantic text",
        vector=_vector(0.0, 1.0),
    )

    response = retrieve_rag_context_hybrid_rrf(
        db,
        _request(
            "no lexical overlap",
            top_k=1,
        ),
        provider=provider,
    )

    assert len(response.chunks) == 1
    chunk_result = response.chunks[0]
    assert chunk_result.text == "current semantic text"
    assert chunk_result.lexical_score == 0.0
    assert chunk_result.semantic_score == pytest.approx(0.5)


def test_hybrid_rrf_top_k_respected(db, provider):
    _seed(
        db,
        chunks=[
            {"text": "alpha one", "ordinal": 0},
            {"text": "alpha two", "ordinal": 1},
            {"text": "alpha three", "ordinal": 2},
        ],
    )

    response = retrieve_rag_context_hybrid_rrf(
        db, _request("alpha", top_k=2), provider=provider
    )

    assert len(response.chunks) == 2
    assert response.context_count == 2


def test_hybrid_rrf_deterministic_ordering_tie_break(db, provider):
    _seed(
        db,
        chunks=[
            {"text": "alpha tie one", "ordinal": 1},
            {"text": "alpha tie zero", "ordinal": 0},
        ],
    )

    response = retrieve_rag_context_hybrid_rrf(
        db,
        _request("alpha tie"),
        provider=provider,
        config=HybridRetrievalConfig(semantic_weight=0.0),
    )

    assert [chunk.text for chunk in response.chunks] == [
        "alpha tie zero",
        "alpha tie one",
    ]


def test_hybrid_rrf_tenant_isolation(db, provider):
    corpus_a, document_a, stored_a = _seed(
        db,
        tenant_id=_TENANT_A,
        chunks=[{"text": "alpha tenant secret", "ordinal": 0}],
    )
    _persist_vector(
        db,
        tenant_id=_TENANT_A,
        corpus_id=corpus_a["corpus_id"],
        document_id=document_a["document_id"],
        chunk_id=stored_a[0]["chunk_id"],
        text="alpha tenant secret",
        vector=_vector(1.0, 0.0),
    )

    response = retrieve_rag_context_hybrid_rrf(
        db, _request("alpha tenant secret", tenant_id=_TENANT_B), provider=provider
    )

    assert response.chunks == []
    assert response.context_count == 0


def test_hybrid_rrf_respects_corpus_filters(db, provider):
    allowed, _, _ = _seed(
        db,
        corpus_name="Allowed",
        chunks=[{"text": "alpha allowed corpus", "ordinal": 0}],
    )
    _seed(
        db,
        corpus_name="Blocked",
        chunks=[{"text": "alpha blocked corpus", "ordinal": 0}],
    )

    response = retrieve_rag_context_hybrid_rrf(
        db,
        _request("alpha", corpus_ids=[allowed["corpus_id"]]),
        provider=provider,
    )

    assert len(response.chunks) == 1
    assert response.chunks[0].provenance.corpus_id == allowed["corpus_id"]
    assert "allowed" in response.chunks[0].text


def test_hybrid_rrf_scores_are_finite(db, provider):
    corpus, document, stored = _seed(
        db,
        chunks=[{"text": "alpha finite score", "ordinal": 0}],
    )
    _persist_vector(
        db,
        tenant_id=_TENANT_A,
        corpus_id=corpus["corpus_id"],
        document_id=document["document_id"],
        chunk_id=stored[0]["chunk_id"],
        text="alpha finite score",
        vector=_vector(1.0, 0.0),
    )

    response = retrieve_rag_context_hybrid_rrf(db, _request("alpha"), provider=provider)

    for chunk in response.chunks:
        assert math.isfinite(chunk.score)
        assert chunk.lexical_score is not None and math.isfinite(chunk.lexical_score)
        assert chunk.semantic_score is not None and math.isfinite(chunk.semantic_score)
        assert chunk.rrf_score is not None and math.isfinite(chunk.rrf_score)
        assert chunk.combined_score is not None and math.isfinite(chunk.combined_score)


def test_hybrid_rrf_empty_corpus_behavior(db, provider):
    create_corpus(db, tenant_id=_TENANT_A, name="Empty")

    response = retrieve_rag_context_hybrid_rrf(
        db, _request("anything"), provider=provider
    )

    assert response.chunks == []
    assert response.context_count == 0
    assert response.used_retrieval is False


def test_hybrid_rrf_no_provider_routing_changes():
    spec = importlib.util.find_spec("api.rag_hybrid_retrieval")
    assert spec is not None and spec.origin is not None
    with open(spec.origin) as fh:
        source = fh.read()

    forbidden = ("ring_router", "AIPlaneService", "dispatch_to_provider")
    assert all(token not in source for token in forbidden)


def test_hybrid_rrf_no_ui_changes():
    spec = importlib.util.find_spec("api.rag_hybrid_retrieval")
    assert spec is not None and spec.origin is not None
    with open(spec.origin) as fh:
        source = fh.read()

    forbidden = ("APIRouter", "fastapi.routing", "from api.main import", "Depends(")
    assert all(token not in source for token in forbidden)
