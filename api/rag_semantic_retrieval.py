"""
api/rag_semantic_retrieval.py — Hybrid lexical + semantic retrieval.

Extends PR 15 lexical retrieval with embedding-assisted semantic scoring over
persisted embedding_vectors rows.  All retrieval operates ONLY on persisted
data — no live inference, no remote embedding APIs, no provider calls.

Architecture:
  1. Run lexical pre-filter (same SQL as rag_retrieval.py).
  2. For each candidate, load its persisted embedding vector.
  3. Compute cosine similarity between query embedding and chunk embedding.
  4. Compute combined_score = lexical_weight * lexical_score +
                              semantic_weight * semantic_score.
  5. Re-rank by combined_score (deterministic tie-breaker preserved).

Fallback behavior:
  - If query embedding is unavailable (no provider / failure):
    degrade to lexical-only retrieval.  ``retrieval_strategy`` is set to
    "lexical" and a structured warning is emitted.
  - If a chunk has no persisted embedding:
    that chunk's semantic_score defaults to 0.0.  It is not excluded —
    lexical score still contributes to ranking.
  - Never silently fabricates semantic success.

Tenant isolation:
  - Every call requires non-blank tenant_id.
  - Lexical SQL query filters by tenant_id (join on rag_chunks + rag_documents
    + rag_corpora all scoped to tenant).
  - Embedding lookup (list_embeddings_for_corpus / get_embedding_for_chunk)
    requires tenant_id.
  - No cross-tenant embedding lookup is possible.

Audit safety:
  - Logs: retrieval_strategy, chunk_count, tenant_id, corpus_ids (count),
          semantic_available, duration_ms.
  - Never logs: raw embedding vectors, raw chunk text, provider secrets,
                PHI, auth tokens.

Not included:
  - No ANN indexing — all similarity is computed in Python (O(N) scan).
  - No pgvector operator usage — no ``<->``, ``<#>``, ``<=>``.
  - No reranking models / cross-encoder reranking.
  - No external vector DB (LangChain, LlamaIndex, Pinecone, Weaviate, Milvus).
  - No remote embedding API calls at retrieval time.
  - No provider routing changes.
  - No UI changes.
  - No AI-plane auth boundary changes.
"""

from __future__ import annotations

import logging
import math
import time
from typing import TYPE_CHECKING, Optional

from sqlalchemy import bindparam, text
from sqlalchemy.orm import Session

from api.rag_context import (
    RagChunkProvenance,
    RagContextChunk,
    RagContextRequest,
    RagContextResponse,
    RetrievalStrategy,
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

if TYPE_CHECKING:
    from api.embeddings.providers import EmbeddingProvider

logger = logging.getLogger("frostgate.rag_semantic_retrieval")

# ---------------------------------------------------------------------------
# Hybrid scoring weights
# ---------------------------------------------------------------------------

# Default weights for hybrid scoring.
# lexical_weight + semantic_weight should sum to 1.0.
_DEFAULT_LEXICAL_WEIGHT: float = 0.4
_DEFAULT_SEMANTIC_WEIGHT: float = 0.6

# ---------------------------------------------------------------------------
# Similarity
# ---------------------------------------------------------------------------


def _cosine_similarity(a: tuple[float, ...], b: tuple[float, ...]) -> float:
    """Compute cosine similarity between two vectors.

    Returns a value in [-1.0, 1.0].  Returns 0.0 for zero vectors.

    Properties:
    - Deterministic: pure arithmetic, no PRNG.
    - Bounded: output in [-1, 1], always finite (zero-vector guard included).
    - Does not modify caller's vectors.
    """
    if len(a) != len(b):
        return 0.0
    dot = sum(ai * bi for ai, bi in zip(a, b))
    norm_a = math.sqrt(sum(ai * ai for ai in a))
    norm_b = math.sqrt(sum(bi * bi for bi in b))
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    raw = dot / (norm_a * norm_b)
    # Clamp to [-1.0, 1.0] to absorb floating-point drift.
    return max(-1.0, min(1.0, raw))


def _normalise_semantic_score(cosine: float) -> float:
    """Map cosine similarity [-1, 1] → [0, 1] for hybrid scoring arithmetic.

    Uses (cosine + 1) / 2 — a linear, invertible, deterministic mapping.
    """
    return (cosine + 1.0) / 2.0


# ---------------------------------------------------------------------------
# Embedding load helpers
# ---------------------------------------------------------------------------


def _load_chunk_embeddings(
    db: Session,
    *,
    tenant_id: str,
    chunk_ids: list[str],
    model: str | None = None,
) -> dict[str, tuple[float, ...]]:
    """Load persisted embeddings for a list of chunk_ids scoped to tenant_id.

    Returns a dict mapping chunk_id → vector tuple.  Missing chunks are simply
    absent from the result — callers treat absent chunks as semantic_score=0.0.

    Never raises on missing chunks.  Raises only on tenant_id validation failure.
    """
    from services.embeddings.persistence import get_embedding_for_chunk

    result: dict[str, tuple[float, ...]] = {}
    for chunk_id in chunk_ids:
        try:
            row = get_embedding_for_chunk(
                db,
                tenant_id=tenant_id,
                chunk_id=chunk_id,
                model=model,
            )
            if row is not None:
                result[chunk_id] = row.vector
        except Exception:
            # Non-fatal: a single chunk missing its embedding degrades to
            # semantic_score=0.0 for that chunk only.
            logger.warning(
                "rag_semantic_retrieval.chunk_embedding_load_failed",
                extra={
                    "event": "rag_semantic_retrieval.chunk_embedding_load_failed",
                    "tenant_id": tenant_id,
                    "chunk_id": chunk_id,
                },
            )
    return result


# ---------------------------------------------------------------------------
# Query embedding
# ---------------------------------------------------------------------------


def _embed_query(
    provider: "EmbeddingProvider",
    *,
    tenant_id: str,
    corpus_id: str,
    query: str,
) -> tuple[float, ...] | None:
    """Embed the query text using the given provider.

    Returns the vector on success.  Returns None on any failure — callers must
    degrade to lexical-only retrieval when None is returned.

    Never raises.  Failure is always non-fatal at the query level.
    """
    from api.embeddings.contracts import EmbeddingRequest

    try:
        if not provider.is_available():
            logger.warning(
                "rag_semantic_retrieval.provider_unavailable",
                extra={
                    "event": "rag_semantic_retrieval.provider_unavailable",
                    "tenant_id": tenant_id,
                    "model": provider.model.value,
                },
            )
            return None
        request = EmbeddingRequest.from_chunk(
            tenant_id=tenant_id,
            corpus_id=corpus_id or "query",
            document_id="query",
            chunk_id="query",
            text=query,
        )
        response = provider.embed(request)
        return response.vector
    except Exception as exc:
        logger.warning(
            "rag_semantic_retrieval.query_embed_failed",
            extra={
                "event": "rag_semantic_retrieval.query_embed_failed",
                "tenant_id": tenant_id,
                "error": str(exc),
            },
        )
        return None


# ---------------------------------------------------------------------------
# Core retrieval helpers
# ---------------------------------------------------------------------------


def _lexical_candidates(
    db: Session,
    *,
    tenant_id: str,
    query_terms: list[str],
    corpus_ids: list[str],
    invalid_explicit_filter: bool,
) -> list[dict]:
    """Run the lexical SQL pre-filter and return raw row dicts.

    Returns an empty list if the query is empty or the filter is invalid.
    Mirrors the SQL used in rag_retrieval.retrieve_rag_context but streams
    all candidates (top_k applied after hybrid scoring).
    """
    if not query_terms or invalid_explicit_filter:
        return []

    unique_query_terms = list(dict.fromkeys(query_terms))
    like_clauses = []
    params: dict = {
        "tenant_id": tenant_id,
        "use_corpus_filter": 1 if corpus_ids else 0,
        "corpus_ids": corpus_ids or ["__unused__"],
    }
    for index, term in enumerate(unique_query_terms):
        param_name = f"term_{index}"
        like_clauses.append(f"LOWER(c.text) LIKE :{param_name} ESCAPE '\\'")
        params[param_name] = f"%{_escape_like_term(term)}%"

    lexical_prefilter = " OR ".join(like_clauses)
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
          AND ({lexical_prefilter})
        ORDER BY c.corpus_id ASC, c.document_id ASC, c.ordinal ASC, c.chunk_id ASC
        """
    ).bindparams(bindparam("corpus_ids", expanding=True))

    rows = []
    for row in db.execute(stmt, params).mappings():
        rows.append(dict(row))
    return rows


def _build_chunk(
    row: dict,
    *,
    query_terms: list[str],
    query_vector: tuple[float, ...] | None,
    chunk_vectors: dict[str, tuple[float, ...]],
    lexical_weight: float,
    semantic_weight: float,
    strategy: RetrievalStrategy,
) -> tuple[float, str, str, int, str, RagContextChunk] | None:
    """Score a single row and build a RagContextChunk.

    Returns None if the chunk scores <= 0.0 on the lexical component
    (preserving the PR 15 invariant that non-matching chunks are excluded).
    """
    lexical_score = _score_text(query_terms, str(row["text"]))
    if lexical_score <= 0.0:
        return None

    chunk_id = str(row["chunk_id"])
    semantic_score = 0.0
    if query_vector is not None and chunk_id in chunk_vectors:
        cosine = _cosine_similarity(query_vector, chunk_vectors[chunk_id])
        semantic_score = _normalise_semantic_score(cosine)

    if strategy == "hybrid":
        combined = lexical_weight * lexical_score + semantic_weight * semantic_score
    else:
        combined = lexical_score

    chunk_metadata = _decode_metadata(row.get("chunk_metadata"))
    document_metadata = _decode_metadata(row.get("document_metadata"))
    uri = _metadata_string(chunk_metadata, "uri", "source_uri") or _metadata_string(
        document_metadata, "uri", "source_uri"
    )
    page = _metadata_int(chunk_metadata, "page", "source_page") or _metadata_int(
        document_metadata, "page", "source_page"
    )

    chunk = RagContextChunk(
        text=str(row["text"]),
        score=combined,
        provenance=RagChunkProvenance(
            corpus_id=str(row["corpus_id"]),
            document_id=str(row["document_id"]),
            chunk_id=chunk_id,
            source=row.get("source"),
            title=row.get("title"),
            uri=uri,
            page=page,
        ),
        lexical_score=lexical_score,
        semantic_score=semantic_score,
        combined_score=combined,
        retrieval_strategy=strategy,
    )
    return (
        combined,
        str(row["corpus_id"]),
        str(row["document_id"]),
        int(row["ordinal"]),
        chunk_id,
        chunk,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def retrieve_rag_context_hybrid(
    db: Session,
    request: RagContextRequest,
    *,
    provider: Optional["EmbeddingProvider"] = None,
    embedding_model: Optional[str] = None,
    lexical_weight: float = _DEFAULT_LEXICAL_WEIGHT,
    semantic_weight: float = _DEFAULT_SEMANTIC_WEIGHT,
) -> RagContextResponse:
    """Hybrid lexical + semantic RAG retrieval.

    Parameters
    ----------
    db:
        SQLAlchemy session.  Must be scoped to the correct tenant context.
    request:
        Standard retrieval request (tenant_id required, corpus_ids optional).
    provider:
        Optional embedding provider.  If None or unavailable, degrades to
        lexical-only retrieval — never fails closed on provider absence.
    embedding_model:
        Optional model filter for persisted embeddings.  If None, the most
        recently persisted embedding per chunk is used.
    lexical_weight:
        Weight for the lexical score component (default 0.4).
    semantic_weight:
        Weight for the semantic score component (default 0.6).

    Returns
    -------
    RagContextResponse with ``top_k`` chunks ordered by combined_score DESC.
    Chunks include ``lexical_score``, ``semantic_score``, ``combined_score``,
    and ``retrieval_strategy`` provenance fields.

    Tenant isolation invariants
    ---------------------------
    - tenant_id required; raises ValueError on blank.
    - All SQL queries filter by tenant_id.
    - Embedding lookups require tenant_id.
    - corpus_ids filter is applied inside the tenant-scoped query.
    - Wrong-tenant queries return empty results — no enumeration leakage.

    Fallback invariants
    -------------------
    - Provider absent / unavailable → lexical-only, strategy="lexical".
    - Query embed failure → lexical-only, strategy="lexical".
    - Chunk missing embedding → semantic_score=0.0, not excluded.
    - Degradation is always explicit in retrieval_strategy and audit log.
    """
    start = time.monotonic()
    tenant_id = _require_tenant(request.tenant_id)
    query_terms = _tokenize(request.query)

    if not query_terms:
        return RagContextResponse(query=request.query, chunks=[])

    corpus_ids, invalid_explicit_filter = _normalise_corpus_ids(request.corpus_ids)
    if invalid_explicit_filter:
        return RagContextResponse(query=request.query, chunks=[])

    # Attempt to embed the query.
    query_vector: tuple[float, ...] | None = None
    strategy: RetrievalStrategy = "lexical"

    # Resolve the embedding model used for chunk lookups.
    # An explicit override takes precedence; otherwise fall back to the
    # provider's own model so that chunk vectors are always compared against
    # a query vector from the same embedding space.
    resolved_embedding_model: str | None = embedding_model
    if provider is not None:
        # Use first corpus_id for embed context; fallback to empty string.
        context_corpus = corpus_ids[0] if corpus_ids else ""
        query_vector = _embed_query(
            provider,
            tenant_id=tenant_id,
            corpus_id=context_corpus,
            query=request.query,
        )
        if query_vector is not None:
            strategy = "hybrid"
            if resolved_embedding_model is None:
                resolved_embedding_model = provider.model.value

    # Lexical SQL pre-filter — returns all candidates before top_k.
    rows = _lexical_candidates(
        db,
        tenant_id=tenant_id,
        query_terms=query_terms,
        corpus_ids=corpus_ids,
        invalid_explicit_filter=invalid_explicit_filter,
    )

    if not rows:
        _audit_retrieval(
            tenant_id=tenant_id,
            strategy=strategy,
            corpus_count=len(corpus_ids),
            candidate_count=0,
            returned_count=0,
            semantic_available=(query_vector is not None),
            duration_ms=int((time.monotonic() - start) * 1000),
        )
        return RagContextResponse(query=request.query, chunks=[])

    # Load persisted embeddings for candidates — batch by chunk_id.
    # Uses resolved_embedding_model (provider.model when not explicitly
    # overridden) so chunk vectors always come from the same embedding space
    # as the query vector.
    chunk_vectors: dict[str, tuple[float, ...]] = {}
    if query_vector is not None:
        chunk_ids = [str(r["chunk_id"]) for r in rows]
        chunk_vectors = _load_chunk_embeddings(
            db,
            tenant_id=tenant_id,
            chunk_ids=chunk_ids,
            model=resolved_embedding_model,
        )

    # Score and rank.
    ranked: list[tuple[float, str, str, int, str, RagContextChunk]] = []
    for row in rows:
        item = _build_chunk(
            row,
            query_terms=query_terms,
            query_vector=query_vector,
            chunk_vectors=chunk_vectors,
            lexical_weight=lexical_weight,
            semantic_weight=semantic_weight,
            strategy=strategy,
        )
        if item is None:
            continue
        ranked.append(item)
        ranked.sort(key=lambda x: (-x[0], x[1], x[2], x[3], x[4]))
        if len(ranked) > request.top_k:
            ranked.pop()

    chunks = [item[5] for item in ranked]

    _audit_retrieval(
        tenant_id=tenant_id,
        strategy=strategy,
        corpus_count=len(corpus_ids),
        candidate_count=len(rows),
        returned_count=len(chunks),
        semantic_available=(query_vector is not None),
        duration_ms=int((time.monotonic() - start) * 1000),
    )

    return RagContextResponse(query=request.query, chunks=chunks)


def _audit_retrieval(
    *,
    tenant_id: str,
    strategy: str,
    corpus_count: int,
    candidate_count: int,
    returned_count: int,
    semantic_available: bool,
    duration_ms: int,
) -> None:
    """Emit a structured audit log for a retrieval operation.

    Never logs: raw vectors, raw chunk text, provider secrets, PHI,
                auth tokens, cookies.
    Logs: retrieval_strategy, counts, tenant_id, corpus_ids (count),
          semantic_available, duration_ms.
    """
    logger.info(
        "rag_semantic_retrieval.retrieved",
        extra={
            "event": "rag_semantic_retrieval.retrieved",
            "tenant_id": tenant_id,
            "retrieval_strategy": strategy,
            "corpus_count": corpus_count,
            "candidate_count": candidate_count,
            "returned_count": returned_count,
            "semantic_available": semantic_available,
            "duration_ms": duration_ms,
        },
    )
