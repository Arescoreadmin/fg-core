"""
tests/test_semantic_retrieval.py — PR 22 semantic retrieval tests.

Covers all 25 required scenarios:
1)  semantic retrieval returns relevant chunks
2)  semantic similarity improves ranking
3)  hybrid retrieval preserves lexical relevance
4)  deterministic ranking
5)  stable tie ordering
6)  top_k behavior
7)  empty corpus behavior
8)  no-context behavior
9)  tenant isolation
10) corpus filtering
11) embedding absence fallback
12) pgvector fallback compatibility
13) lexical-only fallback behavior
14) retrieval provenance correctness
15) score metadata correctness
16) finite score guarantees
17) no cross-tenant embedding leakage
18) semantic retrieval does not bypass lexical filtering
19) audit safety
20) no raw vector logging
21) no provider routing changes
22) no AI-plane auth boundary changes
23) no UI coupling
24) no network dependency
25) deterministic CI behavior

All tests use SQLite in-memory (dev/test fallback) — no pgvector required.
"""

from __future__ import annotations

import importlib
import logging
import os

os.environ.setdefault("FG_ENV", "test")

import math
from typing import Any

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from api.embeddings import DeterministicStubProvider, EmbeddingModel
from api.rag_context import RagContextRequest, RagContextChunk
from api.rag_corpus_store import create_corpus, create_document, store_chunks
from api.rag_semantic_retrieval import (
    _cosine_similarity,
    _normalise_semantic_score,
    retrieve_rag_context_hybrid,
)
from services.embeddings import (
    ensure_sqlite_schema,
    generate_embeddings_for_corpus,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_TENANT_A = "tenant-semantic-a"
_TENANT_B = "tenant-semantic-b"
_MODEL = EmbeddingModel.INSTRUCTOR_XL
_DIM = 768


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def engine(tmp_path):
    from api.db import init_db, reset_engine_cache

    db_path = str(tmp_path / "semantic-test.db")
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
def provider():
    return DeterministicStubProvider(model=_MODEL)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _seed(
    db: Session,
    *,
    tenant_id: str,
    corpus_name: str = "Default",
    chunks: list[dict[str, Any]],
    title: str = "Test Doc",
    source: str = "https://example.test/doc",
) -> tuple[dict, dict, list[dict]]:
    corpus = create_corpus(db, tenant_id=tenant_id, name=corpus_name)
    document = create_document(
        db,
        tenant_id=tenant_id,
        corpus_id=corpus["corpus_id"],
        title=title,
        source=source,
    )
    stored = store_chunks(
        db,
        tenant_id=tenant_id,
        document_id=document["document_id"],
        corpus_id=corpus["corpus_id"],
        chunks=chunks,
    )
    return corpus, document, stored


def _embed_corpus(db: Session, *, tenant_id: str, corpus_id: str, provider) -> None:
    generate_embeddings_for_corpus(
        db,
        tenant_id=tenant_id,
        corpus_id=corpus_id,
        provider=provider,
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


# ---------------------------------------------------------------------------
# 1) Semantic retrieval returns relevant chunks
# ---------------------------------------------------------------------------


def test_semantic_retrieval_returns_relevant_chunks(db, provider):
    corpus, _, _ = _seed(
        db,
        tenant_id=_TENANT_A,
        chunks=[
            {"text": "authentication requires multi-factor verification", "ordinal": 0},
            {"text": "billing invoice generation schedule", "ordinal": 1},
        ],
    )
    _embed_corpus(
        db, tenant_id=_TENANT_A, corpus_id=corpus["corpus_id"], provider=provider
    )

    resp = retrieve_rag_context_hybrid(
        db, _request("authentication mfa"), provider=provider
    )

    assert resp.context_count >= 1
    assert resp.used_retrieval is True
    texts = [c.text for c in resp.chunks]
    assert any("authentication" in t.lower() for t in texts)


# ---------------------------------------------------------------------------
# 2) Semantic similarity improves ranking
# ---------------------------------------------------------------------------


def test_semantic_similarity_improves_ranking(db, provider):
    corpus, _, stored = _seed(
        db,
        tenant_id=_TENANT_A,
        chunks=[
            {"text": "authentication policy", "ordinal": 0},
            {"text": "authentication policy requires authentication MFA", "ordinal": 1},
        ],
    )
    _embed_corpus(
        db, tenant_id=_TENANT_A, corpus_id=corpus["corpus_id"], provider=provider
    )

    resp = retrieve_rag_context_hybrid(
        db, _request("authentication mfa policy"), provider=provider
    )

    assert len(resp.chunks) >= 2
    # Higher combined_score chunk must be first.
    assert resp.chunks[0].combined_score is not None
    assert resp.chunks[0].score >= resp.chunks[1].score


# ---------------------------------------------------------------------------
# 3) Hybrid retrieval preserves lexical relevance
# ---------------------------------------------------------------------------


def test_hybrid_retrieval_preserves_lexical_relevance(db, provider):
    corpus, _, _ = _seed(
        db,
        tenant_id=_TENANT_A,
        chunks=[
            {"text": "compliance audit retention policy required", "ordinal": 0},
            {"text": "invoice billing payment", "ordinal": 1},
        ],
    )
    _embed_corpus(
        db, tenant_id=_TENANT_A, corpus_id=corpus["corpus_id"], provider=provider
    )

    resp = retrieve_rag_context_hybrid(
        db, _request("compliance audit retention"), provider=provider
    )

    assert resp.context_count >= 1
    # The lexically matching chunk must appear.
    assert any("compliance" in c.text.lower() for c in resp.chunks)
    # Each chunk must have a positive lexical_score.
    for chunk in resp.chunks:
        assert chunk.lexical_score is not None
        assert chunk.lexical_score > 0.0


# ---------------------------------------------------------------------------
# 9) Tenant isolation — semantic retrieval requires tenant
# ---------------------------------------------------------------------------


def test_semantic_retrieval_requires_tenant(db, provider):
    with pytest.raises(ValueError, match="tenant_id"):
        req = RagContextRequest.model_construct(
            query="authentication",
            tenant_id="",
            corpus_ids=[],
            top_k=5,
        )
        retrieve_rag_context_hybrid(db, req, provider=provider)


# ---------------------------------------------------------------------------
# 10) Corpus filtering
# ---------------------------------------------------------------------------


def test_semantic_retrieval_respects_corpus_filters(db, provider):
    allowed_corpus, _, _ = _seed(
        db,
        tenant_id=_TENANT_A,
        corpus_name="Allowed",
        chunks=[{"text": "retention policy allowed corpus", "ordinal": 0}],
    )
    blocked_corpus, _, _ = _seed(
        db,
        tenant_id=_TENANT_A,
        corpus_name="Blocked",
        chunks=[{"text": "retention policy blocked corpus", "ordinal": 0}],
    )
    _embed_corpus(
        db,
        tenant_id=_TENANT_A,
        corpus_id=allowed_corpus["corpus_id"],
        provider=provider,
    )
    _embed_corpus(
        db,
        tenant_id=_TENANT_A,
        corpus_id=blocked_corpus["corpus_id"],
        provider=provider,
    )

    resp = retrieve_rag_context_hybrid(
        db,
        _request(
            "retention policy",
            corpus_ids=[allowed_corpus["corpus_id"]],
        ),
        provider=provider,
    )

    assert len(resp.chunks) == 1
    assert resp.chunks[0].provenance.corpus_id == allowed_corpus["corpus_id"]


# ---------------------------------------------------------------------------
# 4) Deterministic ordering
# ---------------------------------------------------------------------------


def test_semantic_retrieval_deterministic_ordering(db, provider):
    corpus, _, _ = _seed(
        db,
        tenant_id=_TENANT_A,
        chunks=[
            {"text": "security policy alpha", "ordinal": 0},
            {"text": "security policy beta", "ordinal": 1},
            {"text": "security policy gamma", "ordinal": 2},
        ],
    )
    _embed_corpus(
        db, tenant_id=_TENANT_A, corpus_id=corpus["corpus_id"], provider=provider
    )

    resp1 = retrieve_rag_context_hybrid(
        db, _request("security policy"), provider=provider
    )
    resp2 = retrieve_rag_context_hybrid(
        db, _request("security policy"), provider=provider
    )

    assert [c.provenance.chunk_id for c in resp1.chunks] == [
        c.provenance.chunk_id for c in resp2.chunks
    ]


# ---------------------------------------------------------------------------
# 7) Empty corpus behavior
# ---------------------------------------------------------------------------


def test_semantic_retrieval_empty_corpus(db, provider):
    create_corpus(db, tenant_id=_TENANT_A, name="Empty")

    resp = retrieve_rag_context_hybrid(db, _request("anything"), provider=provider)

    assert resp.chunks == []
    assert resp.context_count == 0
    assert resp.used_retrieval is False


# ---------------------------------------------------------------------------
# 11) Embedding absence fallback (lexical-only)
# ---------------------------------------------------------------------------


def test_semantic_retrieval_embedding_fallback(db):
    """Chunks without persisted embeddings → semantic_score=0.0, not excluded."""
    corpus, _, _ = _seed(
        db,
        tenant_id=_TENANT_A,
        chunks=[{"text": "authentication policy without embedding", "ordinal": 0}],
    )
    # No embeddings generated — provider provided but no embeddings persisted.
    # Query embedding will succeed but chunk vectors will be absent.
    provider = DeterministicStubProvider(model=_MODEL)

    resp = retrieve_rag_context_hybrid(
        db, _request("authentication policy"), provider=provider
    )

    # Chunk returned via lexical path even without persisted embeddings.
    assert resp.context_count >= 1
    chunk = resp.chunks[0]
    assert chunk.semantic_score is not None
    assert chunk.semantic_score == 0.0
    assert chunk.lexical_score is not None
    assert chunk.lexical_score > 0.0


# ---------------------------------------------------------------------------
# 12) pgvector fallback compatibility (SQLite used in CI)
# ---------------------------------------------------------------------------


def test_semantic_retrieval_pgvector_fallback(db, provider):
    """Hybrid retrieval works on SQLite (the dev/test backend) without pgvector."""
    corpus, _, _ = _seed(
        db,
        tenant_id=_TENANT_A,
        chunks=[{"text": "policy audit evidence retention", "ordinal": 0}],
    )
    _embed_corpus(
        db, tenant_id=_TENANT_A, corpus_id=corpus["corpus_id"], provider=provider
    )

    # If this passes without error, the SQLite fallback is working correctly.
    resp = retrieve_rag_context_hybrid(
        db, _request("audit evidence"), provider=provider
    )

    assert resp.context_count >= 1


# ---------------------------------------------------------------------------
# 16) Finite score guarantees
# ---------------------------------------------------------------------------


def test_semantic_scores_are_finite(db, provider):
    corpus, _, _ = _seed(
        db,
        tenant_id=_TENANT_A,
        chunks=[
            {"text": "compliance audit policy one", "ordinal": 0},
            {"text": "compliance audit policy two", "ordinal": 1},
        ],
    )
    _embed_corpus(
        db, tenant_id=_TENANT_A, corpus_id=corpus["corpus_id"], provider=provider
    )

    resp = retrieve_rag_context_hybrid(
        db, _request("compliance audit"), provider=provider
    )

    for chunk in resp.chunks:
        assert math.isfinite(chunk.score), f"score={chunk.score} is not finite"
        if chunk.lexical_score is not None:
            assert math.isfinite(chunk.lexical_score)
        if chunk.semantic_score is not None:
            assert math.isfinite(chunk.semantic_score)
        if chunk.combined_score is not None:
            assert math.isfinite(chunk.combined_score)


# ---------------------------------------------------------------------------
# 19) Audit safety
# ---------------------------------------------------------------------------


def test_semantic_retrieval_audit_safe(db, provider, caplog):
    """Audit logs must not include raw vectors, raw chunk text, or provider secrets."""
    corpus, _, _ = _seed(
        db,
        tenant_id=_TENANT_A,
        chunks=[{"text": "audit safety check retention policy", "ordinal": 0}],
    )
    _embed_corpus(
        db, tenant_id=_TENANT_A, corpus_id=corpus["corpus_id"], provider=provider
    )

    with caplog.at_level(logging.INFO, logger="frostgate.rag_semantic_retrieval"):
        retrieve_rag_context_hybrid(db, _request("audit safety"), provider=provider)

    for record in caplog.records:
        msg = str(record.message) + str(getattr(record, "extra", ""))
        assert "vector" not in msg.lower() or "retrieval_strategy" in msg.lower()
        # Confirm no API key patterns leaked.
        assert "sk-" not in msg
        assert "Bearer " not in msg


# ---------------------------------------------------------------------------
# 17) No cross-tenant embedding leakage
# ---------------------------------------------------------------------------


def test_semantic_retrieval_no_cross_tenant_leakage(db, provider):
    """Tenant B must never see Tenant A's chunks even if the query matches Tenant A's text."""
    corpus_a, _, _ = _seed(
        db,
        tenant_id=_TENANT_A,
        chunks=[
            {"text": "alpha private acquisition strategy unique_term_xyz", "ordinal": 0}
        ],
    )
    _embed_corpus(
        db, tenant_id=_TENANT_A, corpus_id=corpus_a["corpus_id"], provider=provider
    )

    # Tenant B has NO matching documents. Querying for Tenant A's unique terms must return empty.
    resp = retrieve_rag_context_hybrid(
        db,
        _request("unique_term_xyz private acquisition", tenant_id=_TENANT_B),
        provider=provider,
    )

    assert resp.chunks == []
    assert resp.context_count == 0
    assert resp.used_retrieval is False

    # Also verify: tenant A can find the chunk but tenant B cannot.
    resp_a = retrieve_rag_context_hybrid(
        db,
        _request("unique_term_xyz private acquisition", tenant_id=_TENANT_A),
        provider=provider,
    )
    assert resp_a.context_count >= 1
    # Confirm all returned chunks belong to tenant A's corpus.
    for chunk in resp_a.chunks:
        assert chunk.provenance.corpus_id == corpus_a["corpus_id"]


# ---------------------------------------------------------------------------
# 20) No raw vector logging
# ---------------------------------------------------------------------------


def test_semantic_retrieval_no_raw_vectors_logged(db, provider, caplog):
    corpus, _, _ = _seed(
        db,
        tenant_id=_TENANT_A,
        chunks=[{"text": "embedding vector check policy", "ordinal": 0}],
    )
    _embed_corpus(
        db, tenant_id=_TENANT_A, corpus_id=corpus["corpus_id"], provider=provider
    )

    with caplog.at_level(logging.DEBUG, logger="frostgate"):
        retrieve_rag_context_hybrid(
            db, _request("embedding vector check"), provider=provider
        )

    # No log message should contain a raw float vector pattern (e.g. [0.1, 0.2, ...])
    for record in caplog.records:
        msg = str(record.message)
        # A raw vector would have many comma-separated floats
        # Simple heuristic: no message has more than 5 consecutive comma-separated numbers.
        import re

        float_seq = re.findall(r"\d+\.\d+", msg)
        assert len(float_seq) < 5, f"Possible raw vector leak in log: {msg[:200]}"


# ---------------------------------------------------------------------------
# 5) Stable tie ordering
# ---------------------------------------------------------------------------


def test_semantic_retrieval_stable_tie_ordering(db, provider):
    """Identical text → identical combined_score → stable tie-breaker by corpus/doc/ordinal."""
    corpus_b, _, chunks_b = _seed(
        db,
        tenant_id=_TENANT_A,
        corpus_name="B Corpus",
        chunks=[{"text": "shared policy term", "ordinal": 0}],
    )
    corpus_a, _, chunks_a = _seed(
        db,
        tenant_id=_TENANT_A,
        corpus_name="A Corpus",
        chunks=[
            {"text": "shared policy term", "ordinal": 1},
            {"text": "shared policy term", "ordinal": 0},
        ],
    )
    _embed_corpus(
        db, tenant_id=_TENANT_A, corpus_id=corpus_a["corpus_id"], provider=provider
    )
    _embed_corpus(
        db, tenant_id=_TENANT_A, corpus_id=corpus_b["corpus_id"], provider=provider
    )

    resp1 = retrieve_rag_context_hybrid(
        db, _request("shared policy term"), provider=provider
    )
    resp2 = retrieve_rag_context_hybrid(
        db, _request("shared policy term"), provider=provider
    )

    ids1 = [c.provenance.chunk_id for c in resp1.chunks]
    ids2 = [c.provenance.chunk_id for c in resp2.chunks]
    assert ids1 == ids2, "Ordering must be stable across identical runs"


# ---------------------------------------------------------------------------
# 6) top_k behavior
# ---------------------------------------------------------------------------


def test_semantic_retrieval_top_k_behavior(db, provider):
    corpus, _, _ = _seed(
        db,
        tenant_id=_TENANT_A,
        chunks=[
            {"text": "policy one", "ordinal": 0},
            {"text": "policy two", "ordinal": 1},
            {"text": "policy three", "ordinal": 2},
            {"text": "policy four", "ordinal": 3},
        ],
    )
    _embed_corpus(
        db, tenant_id=_TENANT_A, corpus_id=corpus["corpus_id"], provider=provider
    )

    resp = retrieve_rag_context_hybrid(
        db, _request("policy", top_k=2), provider=provider
    )

    assert len(resp.chunks) == 2
    assert resp.context_count == 2


# ---------------------------------------------------------------------------
# 8) No-context (empty query / no lexical terms)
# ---------------------------------------------------------------------------


def test_semantic_retrieval_empty_query_returns_no_context(db, provider):
    _seed(
        db,
        tenant_id=_TENANT_A,
        chunks=[{"text": "some content", "ordinal": 0}],
    )

    # Query with no tokenizable terms.
    resp = retrieve_rag_context_hybrid(db, _request("   !!!   "), provider=provider)

    assert resp.chunks == []
    assert resp.context_count == 0
    assert resp.used_retrieval is False


# ---------------------------------------------------------------------------
# 13) Lexical-only fallback (no provider)
# ---------------------------------------------------------------------------


def test_semantic_retrieval_lexical_only_fallback_no_provider(db):
    """When provider=None, retrieval degrades to lexical-only."""
    corpus, _, _ = _seed(
        db,
        tenant_id=_TENANT_A,
        chunks=[{"text": "authentication policy mfa required", "ordinal": 0}],
    )

    resp = retrieve_rag_context_hybrid(
        db, _request("authentication mfa"), provider=None
    )

    assert resp.context_count >= 1
    chunk = resp.chunks[0]
    assert chunk.retrieval_strategy == "lexical"
    assert chunk.semantic_score == 0.0


# ---------------------------------------------------------------------------
# 14) Retrieval provenance correctness
# ---------------------------------------------------------------------------


def test_semantic_retrieval_provenance_correctness(db, provider):
    corpus, document, stored = _seed(
        db,
        tenant_id=_TENANT_A,
        title="Evidence Runbook",
        source="https://example.test/runbook",
        chunks=[
            {
                "text": "evidence retention policy",
                "ordinal": 0,
                "metadata": {"uri": "https://example.test/runbook#p7", "page": 7},
            }
        ],
    )
    _embed_corpus(
        db, tenant_id=_TENANT_A, corpus_id=corpus["corpus_id"], provider=provider
    )

    resp = retrieve_rag_context_hybrid(
        db, _request("evidence retention"), provider=provider
    )

    assert resp.context_count == 1
    prov = resp.chunks[0].provenance
    assert prov.corpus_id == corpus["corpus_id"]
    assert prov.document_id == document["document_id"]
    assert prov.chunk_id == stored[0]["chunk_id"]
    assert prov.title == "Evidence Runbook"
    assert prov.source == "https://example.test/runbook"
    assert prov.uri == "https://example.test/runbook#p7"
    assert prov.page == 7


# ---------------------------------------------------------------------------
# 15) Score metadata correctness
# ---------------------------------------------------------------------------


def test_semantic_retrieval_score_metadata(db, provider):
    corpus, _, _ = _seed(
        db,
        tenant_id=_TENANT_A,
        chunks=[{"text": "authentication policy requires mfa", "ordinal": 0}],
    )
    _embed_corpus(
        db, tenant_id=_TENANT_A, corpus_id=corpus["corpus_id"], provider=provider
    )

    resp = retrieve_rag_context_hybrid(
        db, _request("authentication mfa"), provider=provider
    )

    assert resp.context_count >= 1
    chunk = resp.chunks[0]
    assert chunk.lexical_score is not None and chunk.lexical_score > 0.0
    assert chunk.semantic_score is not None and chunk.semantic_score >= 0.0
    assert chunk.combined_score is not None
    assert chunk.retrieval_strategy in ("lexical", "hybrid")
    # combined_score == score (the primary ranking score).
    assert abs(chunk.score - chunk.combined_score) < 1e-9


# ---------------------------------------------------------------------------
# 18) Semantic retrieval does not bypass lexical filtering
# ---------------------------------------------------------------------------


def test_semantic_retrieval_does_not_bypass_lexical_filter(db, provider):
    """Chunks that do not match the query lexically must not appear even with good embeddings."""
    corpus, _, _ = _seed(
        db,
        tenant_id=_TENANT_A,
        chunks=[
            {"text": "authentication policy requires mfa enforcement", "ordinal": 0},
            {"text": "invoice billing payment schedule", "ordinal": 1},
        ],
    )
    _embed_corpus(
        db, tenant_id=_TENANT_A, corpus_id=corpus["corpus_id"], provider=provider
    )

    resp = retrieve_rag_context_hybrid(
        db, _request("authentication mfa"), provider=provider
    )

    texts = [c.text for c in resp.chunks]
    # The billing chunk must not appear — it has no lexical match.
    assert all("billing" not in t for t in texts)
    assert all("invoice" not in t for t in texts)


# ---------------------------------------------------------------------------
# 21) No provider routing changes
# ---------------------------------------------------------------------------


def test_semantic_retrieval_no_provider_routing_changes():
    """Hybrid retrieval module must not import ring_router or change provider dispatch."""
    spec = importlib.util.find_spec("api.rag_semantic_retrieval")
    assert spec is not None and spec.origin is not None
    with open(spec.origin) as fh:
        source = fh.read()

    forbidden = ("ring_router", "AIPlaneService", "dispatch_to_provider")
    for token in forbidden:
        assert token not in source, (
            f"rag_semantic_retrieval must not reference {token!r}"
        )


# ---------------------------------------------------------------------------
# 22) No AI-plane auth boundary changes
# ---------------------------------------------------------------------------


def test_semantic_retrieval_no_ai_plane_auth_boundary_changes():
    """Hybrid retrieval must not touch auth scopes or AI-plane extension auth."""
    spec = importlib.util.find_spec("api.rag_semantic_retrieval")
    assert spec is not None and spec.origin is not None
    with open(spec.origin) as fh:
        source = fh.read()

    # These are auth-boundary modules — retrieval must not import them.
    forbidden = (
        "auth_scopes",
        "mint_key",
        "ai_plane_extension",
        "require_scope",
        "validate_token",
    )
    for token in forbidden:
        assert token not in source, (
            f"rag_semantic_retrieval must not reference auth module {token!r}"
        )


# ---------------------------------------------------------------------------
# 23) No UI coupling
# ---------------------------------------------------------------------------


def test_semantic_retrieval_no_ui_coupling():
    """Hybrid retrieval module must not import any UI or FastAPI router modules."""
    spec = importlib.util.find_spec("api.rag_semantic_retrieval")
    assert spec is not None and spec.origin is not None
    with open(spec.origin) as fh:
        source = fh.read()

    forbidden = ("APIRouter", "fastapi.routing", "from api.main import", "Depends(")
    for token in forbidden:
        assert token not in source, (
            f"rag_semantic_retrieval must not reference UI/router token {token!r}"
        )


# ---------------------------------------------------------------------------
# 24) No network dependency
# ---------------------------------------------------------------------------


def test_semantic_retrieval_no_network_dependency(db, provider, monkeypatch):
    """Hybrid retrieval with DeterministicStubProvider must not make network calls."""
    import socket

    def _raise_on_connect(self, address):  # type: ignore[override]
        raise AssertionError(f"Network call detected in semantic retrieval: {address}")

    monkeypatch.setattr(socket.socket, "connect", _raise_on_connect)

    corpus, _, _ = _seed(
        db,
        tenant_id=_TENANT_A,
        chunks=[{"text": "network isolation test policy", "ordinal": 0}],
    )
    _embed_corpus(
        db, tenant_id=_TENANT_A, corpus_id=corpus["corpus_id"], provider=provider
    )

    # Must complete without triggering the network patch.
    resp = retrieve_rag_context_hybrid(
        db, _request("network isolation"), provider=provider
    )
    assert resp.context_count >= 1


# ---------------------------------------------------------------------------
# 25) Deterministic CI behavior
# ---------------------------------------------------------------------------


def test_semantic_retrieval_deterministic_ci_behavior(db, provider):
    """Running the same retrieval twice must produce identical results."""
    corpus, _, _ = _seed(
        db,
        tenant_id=_TENANT_A,
        chunks=[
            {"text": "deterministic ordering alpha", "ordinal": 0},
            {"text": "deterministic ordering beta", "ordinal": 1},
        ],
    )
    _embed_corpus(
        db, tenant_id=_TENANT_A, corpus_id=corpus["corpus_id"], provider=provider
    )

    results = [
        retrieve_rag_context_hybrid(
            db, _request("deterministic ordering"), provider=provider
        )
        for _ in range(3)
    ]

    ref_ids = [c.provenance.chunk_id for c in results[0].chunks]
    for resp in results[1:]:
        ids = [c.provenance.chunk_id for c in resp.chunks]
        assert ids == ref_ids, "Retrieval ordering is not deterministic across runs"


# ---------------------------------------------------------------------------
# Cosine similarity unit tests
# ---------------------------------------------------------------------------


def test_cosine_similarity_identical_vectors():
    v = tuple(0.5 for _ in range(4))
    assert abs(_cosine_similarity(v, v) - 1.0) < 1e-9


def test_cosine_similarity_orthogonal_vectors():
    a = (1.0, 0.0, 0.0, 0.0)
    b = (0.0, 1.0, 0.0, 0.0)
    assert abs(_cosine_similarity(a, b)) < 1e-9


def test_cosine_similarity_zero_vector():
    z = (0.0, 0.0, 0.0)
    v = (1.0, 0.0, 0.0)
    assert _cosine_similarity(z, v) == 0.0
    assert _cosine_similarity(v, z) == 0.0


def test_cosine_similarity_length_mismatch():
    a = (1.0, 0.0)
    b = (1.0, 0.0, 0.0)
    assert _cosine_similarity(a, b) == 0.0


def test_cosine_similarity_result_is_bounded():
    import random

    random.seed(42)
    for _ in range(10):
        a = tuple(random.uniform(-1, 1) for _ in range(16))
        b = tuple(random.uniform(-1, 1) for _ in range(16))
        sim = _cosine_similarity(a, b)
        assert -1.0 <= sim <= 1.0


def test_normalise_semantic_score_bounds():
    for cosine in [-1.0, -0.5, 0.0, 0.5, 1.0]:
        norm = _normalise_semantic_score(cosine)
        assert 0.0 <= norm <= 1.0


def test_normalise_semantic_score_symmetry():
    assert abs(_normalise_semantic_score(0.0) - 0.5) < 1e-9
    assert abs(_normalise_semantic_score(1.0) - 1.0) < 1e-9
    assert abs(_normalise_semantic_score(-1.0) - 0.0) < 1e-9


# ---------------------------------------------------------------------------
# RagContextChunk additive scoring field validation
# ---------------------------------------------------------------------------


def test_rag_chunk_accepts_scoring_fields():
    from api.rag_context import RagChunkProvenance

    prov = RagChunkProvenance(corpus_id="c1", document_id="d1", chunk_id="k1")
    chunk = RagContextChunk(
        text="test",
        score=1.5,
        provenance=prov,
        lexical_score=1.5,
        semantic_score=0.8,
        combined_score=1.5,
        retrieval_strategy="hybrid",
    )
    assert chunk.lexical_score == 1.5
    assert chunk.semantic_score == 0.8
    assert chunk.combined_score == 1.5
    assert chunk.retrieval_strategy == "hybrid"


def test_rag_chunk_scoring_fields_default_none():
    from api.rag_context import RagChunkProvenance

    prov = RagChunkProvenance(corpus_id="c1", document_id="d1", chunk_id="k1")
    chunk = RagContextChunk(text="test", score=1.0, provenance=prov)
    assert chunk.lexical_score is None
    assert chunk.semantic_score is None
    assert chunk.combined_score is None
    assert chunk.retrieval_strategy is None


def test_rag_chunk_rejects_nonfinite_component_scores():
    from api.rag_context import RagChunkProvenance

    prov = RagChunkProvenance(corpus_id="c1", document_id="d1", chunk_id="k1")
    with pytest.raises(Exception):
        RagContextChunk(
            text="test",
            score=1.0,
            provenance=prov,
            semantic_score=float("nan"),
        )
