"""
api/rag_reranking.py — deterministic local reranking for retrieved RAG chunks.

Reranking is a post-retrieval step only.  It never fetches additional chunks,
never crosses tenant/corpus boundaries, never calls a network service, and
never logs raw chunk text, prompts, vectors, or provider data.
"""

from __future__ import annotations

import logging
import math
import time
from dataclasses import dataclass
from typing import Protocol

from api.rag_context import RagContextChunk, RagContextResponse
from api.rag_retrieval import _tokenize

logger = logging.getLogger("frostgate.rag_reranking")

DEFAULT_MAX_RERANK_CANDIDATES = 8
DEFAULT_RERANK_TIMEOUT_MS = 25


@dataclass(frozen=True)
class RerankConfig:
    enabled: bool = True
    max_rerank_candidates: int = DEFAULT_MAX_RERANK_CANDIDATES
    timeout_ms: int = DEFAULT_RERANK_TIMEOUT_MS

    def __post_init__(self) -> None:
        if not isinstance(self.enabled, bool):
            raise ValueError("enabled must be a boolean")
        if (
            not isinstance(self.max_rerank_candidates, int)
            or isinstance(self.max_rerank_candidates, bool)
            or self.max_rerank_candidates < 1
        ):
            raise ValueError("max_rerank_candidates must be a positive integer")
        if (
            not isinstance(self.timeout_ms, int)
            or isinstance(self.timeout_ms, bool)
            or self.timeout_ms < 1
        ):
            raise ValueError("timeout_ms must be a positive integer")


class Reranker(Protocol):
    def score(
        self,
        *,
        query: str,
        chunk: RagContextChunk,
        original_rank: int,
    ) -> tuple[float, str]:
        """Return a bounded rerank score and safe reason code."""


class DeterministicLocalReranker:
    """Local lexical coverage reranker used by CI and default runtime wiring."""

    def score(
        self,
        *,
        query: str,
        chunk: RagContextChunk,
        original_rank: int,
    ) -> tuple[float, str]:
        _ = original_rank
        query_terms = tuple(dict.fromkeys(_tokenize(query)))
        if not query_terms:
            return 0.0, "no_query_terms"

        chunk_terms = _tokenize(chunk.text)
        if not chunk_terms:
            return 0.0, "empty_chunk"

        chunk_term_set = set(chunk_terms)
        matched = [term for term in query_terms if term in chunk_term_set]
        coverage = len(matched) / len(query_terms)
        density = sum(1 for term in chunk_terms if term in set(query_terms)) / (
            len(chunk_terms) + 1
        )
        score = (0.80 * coverage) + (0.20 * density)
        return _bounded_score(score), "query_term_coverage_density"


def rerank_response(
    response: RagContextResponse,
    *,
    query: str,
    reranker: Reranker | None = None,
    config: RerankConfig | None = None,
) -> RagContextResponse:
    """Rerank only the top-N chunks already present in a response.

    Original retrieval scores remain on ``score`` and component score fields.
    Rerank output is additive: ``rerank_score``, ``final_score``, and
    ``rerank_reason``.
    """
    resolved_config = config or RerankConfig()
    if not resolved_config.enabled or not response.chunks:
        return response

    resolved_reranker = reranker or DeterministicLocalReranker()
    start = time.monotonic()
    rerank_count = min(len(response.chunks), resolved_config.max_rerank_candidates)
    reranked: list[RagContextChunk] = []
    untouched = list(response.chunks[rerank_count:])

    try:
        for index, chunk in enumerate(response.chunks[:rerank_count], start=1):
            elapsed_ms = int((time.monotonic() - start) * 1000)
            if elapsed_ms > resolved_config.timeout_ms:
                return _fallback(response, "timeout")
            rerank_score, reason = resolved_reranker.score(
                query=query,
                chunk=chunk,
                original_rank=index,
            )
            chunk.rerank_score = _bounded_score(rerank_score)
            chunk.final_score = _final_score(chunk)
            chunk.rerank_reason = reason
            _annotate_why_this_chunk(chunk)
            reranked.append(chunk)
    except Exception:
        logger.warning(
            "rag_reranking.unavailable",
            extra={
                "event": "rag_reranking.unavailable",
                "returned_count": len(response.chunks),
                "rerank_candidate_count": rerank_count,
            },
        )
        return _fallback(response, "unavailable")

    reranked.sort(key=_sort_key)
    response.chunks = [*reranked, *untouched]
    _sync_trace_counts(response)
    logger.info(
        "rag_reranking.completed",
        extra={
            "event": "rag_reranking.completed",
            "retrieval_trace_id": response.retrieval_trace.retrieval_trace_id
            if response.retrieval_trace is not None
            else None,
            "rerank_candidate_count": rerank_count,
            "returned_count": len(response.chunks),
            "timeout_ms": resolved_config.timeout_ms,
        },
    )
    return response


def _fallback(response: RagContextResponse, reason: str) -> RagContextResponse:
    for chunk in response.chunks:
        if chunk.rerank_score is None:
            chunk.rerank_score = 0.0
        if chunk.final_score is None:
            chunk.final_score = _base_score(chunk)
        if chunk.rerank_reason is None:
            chunk.rerank_reason = f"reranker_{reason}"
        _annotate_why_this_chunk(chunk)
    _sync_trace_counts(response)
    return response


def _final_score(chunk: RagContextChunk) -> float:
    return _bounded_score(
        (0.65 * (chunk.rerank_score or 0.0)) + (0.35 * _base_score(chunk))
    )


def _base_score(chunk: RagContextChunk) -> float:
    score = chunk.combined_score if chunk.combined_score is not None else chunk.score
    if not math.isfinite(score):
        return 0.0
    return max(0.0, float(score))


def _bounded_score(value: float) -> float:
    if not math.isfinite(value):
        return 0.0
    return max(0.0, min(1.0, float(value)))


def _sort_key(chunk: RagContextChunk) -> tuple[float, float, float, str, str, int, str]:
    ordinal = chunk.provenance.ordinal if chunk.provenance.ordinal is not None else 0
    return (
        -(chunk.final_score or 0.0),
        -(chunk.rerank_score or 0.0),
        -_base_score(chunk),
        chunk.provenance.corpus_id,
        chunk.provenance.document_id,
        ordinal,
        chunk.provenance.chunk_id,
    )


def _sync_trace_counts(response: RagContextResponse) -> None:
    returned_count = len(response.chunks)
    if response.retrieval_trace is not None:
        response.retrieval_trace.returned_count = returned_count
    for chunk in response.chunks:
        chunk.returned_count = returned_count


def _annotate_why_this_chunk(chunk: RagContextChunk) -> None:
    if chunk.why_this_chunk is None:
        chunk.why_this_chunk = {}
    score_components = chunk.why_this_chunk.get("score_components")
    if not isinstance(score_components, dict):
        score_components = {}
    score_components["rerank_score"] = chunk.rerank_score
    score_components["final_score"] = chunk.final_score
    chunk.why_this_chunk["score_components"] = score_components
    chunk.why_this_chunk["rerank_reason"] = chunk.rerank_reason
