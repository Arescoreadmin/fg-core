"""
api/rag_hybrid_retrieval.py — Tenant-scoped lexical + semantic RRF retrieval.

Production hybrid retrieval over persisted RAG chunks and persisted embeddings.
No live answer generation, no provider routing, no reranking, no external vector
database, and no UI coupling.
"""

from __future__ import annotations

import json
import logging
import math
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Optional

from sqlalchemy import bindparam, text
from sqlalchemy.orm import Session

from api.rag_context import (
    RagChunkProvenance,
    RagContextChunk,
    RagContextRequest,
    RagContextResponse,
)
from api.rag_retrieval import (
    _decode_metadata,
    _escape_like_term,
    _metadata_int,
    _metadata_string,
    _normalise_corpus_ids,
    _require_tenant,
    _score_text,
    _tokenize,
)
from api.rag_semantic_retrieval import (
    _cosine_similarity,
    _embed_query,
    _normalise_semantic_score,
)

if TYPE_CHECKING:
    from api.embeddings.providers import EmbeddingProvider

logger = logging.getLogger("frostgate.rag_hybrid_retrieval")

DEFAULT_RRF_K: int = 60
DEFAULT_LEXICAL_WEIGHT: float = 1.0
DEFAULT_SEMANTIC_WEIGHT: float = 1.0
DEFAULT_LEXICAL_CANDIDATE_LIMIT: int = 100
DEFAULT_SEMANTIC_CANDIDATE_LIMIT: int = 100


@dataclass(frozen=True)
class HybridRetrievalConfig:
    """Configurable bounds and weights for hybrid RRF retrieval."""

    lexical_weight: float = DEFAULT_LEXICAL_WEIGHT
    semantic_weight: float = DEFAULT_SEMANTIC_WEIGHT
    rrf_k: int = DEFAULT_RRF_K
    lexical_candidate_limit: int = DEFAULT_LEXICAL_CANDIDATE_LIMIT
    semantic_candidate_limit: int = DEFAULT_SEMANTIC_CANDIDATE_LIMIT

    def __post_init__(self) -> None:
        _require_finite_non_negative("lexical_weight", self.lexical_weight)
        _require_finite_non_negative("semantic_weight", self.semantic_weight)
        if self.lexical_weight == 0.0 and self.semantic_weight == 0.0:
            raise ValueError("at least one retrieval weight must be positive")
        if self.rrf_k <= 0:
            raise ValueError("rrf_k must be positive")
        if self.lexical_candidate_limit <= 0:
            raise ValueError("lexical_candidate_limit must be positive")
        if self.semantic_candidate_limit <= 0:
            raise ValueError("semantic_candidate_limit must be positive")


@dataclass(frozen=True)
class _Candidate:
    chunk_id: str
    document_id: str
    corpus_id: str
    text: str
    ordinal: int
    chunk_metadata: dict[str, Any]
    document_metadata: dict[str, Any]
    title: str | None
    source: str | None
    lexical_score: float = 0.0
    semantic_score: float = 0.0

    @property
    def stable_key(self) -> tuple[str, str, int, str]:
        return (self.corpus_id, self.document_id, self.ordinal, self.chunk_id)


@dataclass(frozen=True)
class _RankedCandidate:
    candidate: _Candidate
    lexical_rank: int | None = None
    semantic_rank: int | None = None
    rrf_score: float = 0.0
    combined_score: float = 0.0


def _require_finite_non_negative(name: str, value: float) -> None:
    if not math.isfinite(value) or value < 0.0:
        raise ValueError(f"{name} must be a finite non-negative number")


def _decode_vector(raw: object) -> tuple[float, ...] | None:
    if isinstance(raw, str):
        try:
            decoded = json.loads(raw)
        except (json.JSONDecodeError, TypeError, ValueError):
            return None
        if isinstance(decoded, list):
            try:
                return tuple(float(value) for value in decoded)
            except (TypeError, ValueError):
                return None
    if isinstance(raw, (list, tuple)):
        try:
            return tuple(float(value) for value in raw)
        except (TypeError, ValueError):
            return None
    return None


def _row_to_candidate(
    row: dict[str, Any],
    *,
    lexical_score: float = 0.0,
    semantic_score: float = 0.0,
) -> _Candidate:
    return _Candidate(
        chunk_id=str(row["chunk_id"]),
        document_id=str(row["document_id"]),
        corpus_id=str(row["corpus_id"]),
        text=str(row["text"]),
        ordinal=int(row["ordinal"]),
        chunk_metadata=_decode_metadata(row.get("chunk_metadata")),
        document_metadata=_decode_metadata(row.get("document_metadata")),
        title=row.get("title"),
        source=row.get("source"),
        lexical_score=lexical_score,
        semantic_score=semantic_score,
    )


def _lexical_candidates(
    db: Session,
    *,
    tenant_id: str,
    query_terms: list[str],
    corpus_ids: list[str],
    invalid_explicit_filter: bool,
    limit: int,
) -> list[_Candidate]:
    if not query_terms or invalid_explicit_filter:
        return []

    unique_query_terms = list(dict.fromkeys(query_terms))
    like_clauses = []
    params: dict[str, Any] = {
        "tenant_id": tenant_id,
        "use_corpus_filter": 1 if corpus_ids else 0,
        "corpus_ids": corpus_ids or ["__unused__"],
    }
    for index, term in enumerate(unique_query_terms):
        param_name = f"term_{index}"
        like_clauses.append(f"LOWER(c.text) LIKE :{param_name} ESCAPE '\\'")
        params[param_name] = f"%{_escape_like_term(term)}%"

    stmt = text(
        f"""
        SELECT
            c.chunk_id,
            c.document_id,
            c.corpus_id,
            c.text,
            c.ordinal,
            c.metadata AS chunk_metadata,
            d.title,
            d.source,
            d.metadata AS document_metadata
        FROM rag_chunks c
        JOIN rag_documents d
          ON d.document_id = c.document_id
         AND d.corpus_id = c.corpus_id
         AND d.tenant_id = c.tenant_id
        JOIN rag_corpora corp
          ON corp.corpus_id = c.corpus_id
         AND corp.tenant_id = c.tenant_id
        WHERE c.tenant_id = :tenant_id
          AND (:use_corpus_filter = 0 OR c.corpus_id IN :corpus_ids)
          AND ({" OR ".join(like_clauses)})
        ORDER BY c.corpus_id ASC, c.document_id ASC, c.ordinal ASC, c.chunk_id ASC
        """
    ).bindparams(bindparam("corpus_ids", expanding=True))

    candidates: list[_Candidate] = []
    for row in db.execute(stmt, params).mappings():
        row_dict = dict(row)
        lexical_score = _score_text(query_terms, str(row_dict["text"]))
        if lexical_score <= 0.0:
            continue
        candidates.append(_row_to_candidate(row_dict, lexical_score=lexical_score))

    candidates.sort(
        key=lambda candidate: (
            -candidate.lexical_score,
            candidate.corpus_id,
            candidate.document_id,
            candidate.ordinal,
            candidate.chunk_id,
        )
    )
    return candidates[:limit]


def _semantic_candidates(
    db: Session,
    *,
    tenant_id: str,
    query_vector: tuple[float, ...] | None,
    corpus_ids: list[str],
    invalid_explicit_filter: bool,
    model: str | None,
    limit: int,
) -> list[_Candidate]:
    if query_vector is None or invalid_explicit_filter:
        return []

    params: dict[str, Any] = {
        "tenant_id": tenant_id,
        "use_corpus_filter": 1 if corpus_ids else 0,
        "corpus_ids": corpus_ids or ["__unused__"],
        "use_model_filter": 1 if model else 0,
        "model": model or "__unused__",
    }
    stmt = text(
        """
        SELECT
            c.chunk_id,
            c.document_id,
            c.corpus_id,
            c.text,
            c.ordinal,
            c.metadata AS chunk_metadata,
            d.title,
            d.source,
            d.metadata AS document_metadata,
            e.embedding
        FROM embedding_vectors e
        JOIN rag_chunks c
          ON c.chunk_id = e.chunk_id
         AND c.document_id = e.document_id
         AND c.corpus_id = e.corpus_id
         AND c.tenant_id = e.tenant_id
        JOIN rag_documents d
          ON d.document_id = c.document_id
         AND d.corpus_id = c.corpus_id
         AND d.tenant_id = c.tenant_id
        JOIN rag_corpora corp
          ON corp.corpus_id = c.corpus_id
         AND corp.tenant_id = c.tenant_id
        WHERE e.tenant_id = :tenant_id
          AND (:use_corpus_filter = 0 OR c.corpus_id IN :corpus_ids)
          AND (:use_model_filter = 0 OR e.model = :model)
        ORDER BY c.corpus_id ASC, c.document_id ASC, c.ordinal ASC, c.chunk_id ASC
        """
    ).bindparams(bindparam("corpus_ids", expanding=True))

    best_by_chunk: dict[str, _Candidate] = {}
    for row in db.execute(stmt, params).mappings():
        row_dict = dict(row)
        chunk_vector = _decode_vector(row_dict.get("embedding"))
        if chunk_vector is None:
            continue
        semantic_score = _normalise_semantic_score(
            _cosine_similarity(query_vector, chunk_vector)
        )
        if semantic_score <= 0.0:
            continue
        candidate = _row_to_candidate(row_dict, semantic_score=semantic_score)
        existing = best_by_chunk.get(candidate.chunk_id)
        if existing is None or (
            -candidate.semantic_score,
            candidate.stable_key,
        ) < (-existing.semantic_score, existing.stable_key):
            best_by_chunk[candidate.chunk_id] = candidate

    candidates = list(best_by_chunk.values())
    candidates.sort(
        key=lambda candidate: (
            -candidate.semantic_score,
            candidate.corpus_id,
            candidate.document_id,
            candidate.ordinal,
            candidate.chunk_id,
        )
    )
    return candidates[:limit]


def _merge_candidates(
    lexical: list[_Candidate],
    semantic: list[_Candidate],
    *,
    config: HybridRetrievalConfig,
) -> list[_RankedCandidate]:
    merged: dict[str, _Candidate] = {}
    lexical_ranks: dict[str, int] = {}
    semantic_ranks: dict[str, int] = {}

    for rank, candidate in enumerate(lexical, start=1):
        lexical_ranks[candidate.chunk_id] = rank
        merged[candidate.chunk_id] = candidate

    for rank, candidate in enumerate(semantic, start=1):
        semantic_ranks[candidate.chunk_id] = rank
        existing = merged.get(candidate.chunk_id)
        if existing is None:
            merged[candidate.chunk_id] = candidate
            continue
        merged[candidate.chunk_id] = _Candidate(
            chunk_id=existing.chunk_id,
            document_id=existing.document_id,
            corpus_id=existing.corpus_id,
            text=existing.text,
            ordinal=existing.ordinal,
            chunk_metadata=existing.chunk_metadata,
            document_metadata=existing.document_metadata,
            title=existing.title,
            source=existing.source,
            lexical_score=existing.lexical_score,
            semantic_score=candidate.semantic_score,
        )

    ranked: list[_RankedCandidate] = []
    for chunk_id, candidate in merged.items():
        lexical_rank = lexical_ranks.get(chunk_id)
        semantic_rank = semantic_ranks.get(chunk_id)
        rrf_score = 0.0
        if lexical_rank is not None:
            rrf_score += config.lexical_weight / (config.rrf_k + lexical_rank)
        if semantic_rank is not None:
            rrf_score += config.semantic_weight / (config.rrf_k + semantic_rank)
        combined_score = rrf_score
        ranked.append(
            _RankedCandidate(
                candidate=candidate,
                lexical_rank=lexical_rank,
                semantic_rank=semantic_rank,
                rrf_score=rrf_score,
                combined_score=combined_score,
            )
        )

    ranked.sort(
        key=lambda item: (
            -item.combined_score,
            -item.rrf_score,
            -item.candidate.semantic_score,
            -item.candidate.lexical_score,
            item.candidate.corpus_id,
            item.candidate.document_id,
            item.candidate.ordinal,
            item.candidate.chunk_id,
        )
    )
    return ranked


def _to_chunk(item: _RankedCandidate) -> RagContextChunk:
    candidate = item.candidate
    uri = _metadata_string(candidate.chunk_metadata, "uri", "source_uri")
    if uri is None:
        uri = _metadata_string(candidate.document_metadata, "uri", "source_uri")
    page = _metadata_int(candidate.chunk_metadata, "page", "source_page")
    if page is None:
        page = _metadata_int(candidate.document_metadata, "page", "source_page")

    return RagContextChunk(
        text=candidate.text,
        score=item.combined_score,
        provenance=RagChunkProvenance(
            corpus_id=candidate.corpus_id,
            document_id=candidate.document_id,
            chunk_id=candidate.chunk_id,
            source=candidate.source,
            title=candidate.title,
            uri=uri,
            page=page,
        ),
        lexical_score=candidate.lexical_score,
        semantic_score=candidate.semantic_score,
        rrf_score=item.rrf_score,
        combined_score=item.combined_score,
        retrieval_strategy="hybrid_rrf",
    )


def retrieve_rag_context_hybrid_rrf(
    db: Session,
    request: RagContextRequest,
    *,
    provider: Optional["EmbeddingProvider"] = None,
    embedding_model: Optional[str] = None,
    config: HybridRetrievalConfig | None = None,
) -> RagContextResponse:
    """Return tenant-scoped hybrid retrieval results fused with RRF.

    RRF uses ``sum(1 / (k + rank))`` with default ``k=60``. Component weights
    are configurable and multiply each ranked list's RRF contribution.
    """
    start = time.monotonic()
    tenant_id = _require_tenant(request.tenant_id)
    query_terms = _tokenize(request.query)
    if not query_terms:
        return RagContextResponse(query=request.query, chunks=[])

    resolved_config = config or HybridRetrievalConfig()
    corpus_ids, invalid_explicit_filter = _normalise_corpus_ids(request.corpus_ids)
    if invalid_explicit_filter:
        return RagContextResponse(query=request.query, chunks=[])

    query_vector: tuple[float, ...] | None = None
    resolved_embedding_model = embedding_model
    if provider is not None and resolved_config.semantic_weight > 0.0:
        context_corpus = corpus_ids[0] if corpus_ids else ""
        query_vector = _embed_query(
            provider,
            tenant_id=tenant_id,
            corpus_id=context_corpus,
            query=request.query,
        )
        if query_vector is not None and resolved_embedding_model is None:
            resolved_embedding_model = provider.model.value

    lexical = _lexical_candidates(
        db,
        tenant_id=tenant_id,
        query_terms=query_terms,
        corpus_ids=corpus_ids,
        invalid_explicit_filter=invalid_explicit_filter,
        limit=resolved_config.lexical_candidate_limit,
    )
    semantic = _semantic_candidates(
        db,
        tenant_id=tenant_id,
        query_vector=query_vector,
        corpus_ids=corpus_ids,
        invalid_explicit_filter=invalid_explicit_filter,
        model=resolved_embedding_model,
        limit=resolved_config.semantic_candidate_limit,
    )
    ranked = _merge_candidates(lexical, semantic, config=resolved_config)
    chunks = [_to_chunk(item) for item in ranked[: request.top_k]]

    _audit_retrieval(
        tenant_id=tenant_id,
        corpus_count=len(corpus_ids),
        lexical_candidate_count=len(lexical),
        semantic_candidate_count=len(semantic),
        returned_count=len(chunks),
        semantic_available=query_vector is not None,
        rrf_k=resolved_config.rrf_k,
        duration_ms=int((time.monotonic() - start) * 1000),
    )
    return RagContextResponse(query=request.query, chunks=chunks)


def _audit_retrieval(
    *,
    tenant_id: str,
    corpus_count: int,
    lexical_candidate_count: int,
    semantic_candidate_count: int,
    returned_count: int,
    semantic_available: bool,
    rrf_k: int,
    duration_ms: int,
) -> None:
    logger.info(
        "rag_hybrid_retrieval.retrieved",
        extra={
            "event": "rag_hybrid_retrieval.retrieved",
            "tenant_id": tenant_id,
            "retrieval_strategy": "hybrid_rrf",
            "corpus_count": corpus_count,
            "lexical_candidate_count": lexical_candidate_count,
            "semantic_candidate_count": semantic_candidate_count,
            "returned_count": returned_count,
            "semantic_available": semantic_available,
            "rrf_k": rrf_k,
            "duration_ms": duration_ms,
        },
    )
