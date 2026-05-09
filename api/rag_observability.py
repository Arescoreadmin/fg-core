"""
api/rag_observability.py — Audit-safe retrieval trace and explanation helpers.

No persistence, no provider routing, no ranking decisions. Helpers here only
derive safe metadata from already-ranked retrieval results.
"""

from __future__ import annotations

import math
import uuid
from typing import Any


def new_retrieval_trace_id() -> str:
    return f"rt-{uuid.uuid4().hex}"


def confidence_from_scores(scores: list[float]) -> tuple[float, str]:
    finite_scores = [score for score in scores if math.isfinite(score) and score > 0.0]
    if not finite_scores:
        return 0.0, "no_positive_scores"

    ordered = sorted(finite_scores, reverse=True)
    top = ordered[0]
    strength = top / (top + 1.0)
    if len(ordered) == 1:
        confidence = strength
        reason = "single_result_score_strength"
    else:
        second = ordered[1]
        gap = max(0.0, top - second) / (abs(top) + abs(second) + 1.0)
        confidence = (0.7 * strength) + (0.3 * gap)
        reason = "score_strength_and_top_gap"
    return max(0.0, min(1.0, float(confidence))), reason


def matched_terms(query_terms: list[str], chunk_text: str) -> list[str]:
    chunk_terms = set(term.lower() for term in query_terms_from_text(chunk_text))
    return [term for term in dict.fromkeys(query_terms) if term in chunk_terms]


def query_terms_from_text(value: str) -> list[str]:
    from api.rag_retrieval import _tokenize

    return _tokenize(value)


def _term_category(term: str) -> str:
    if term.isdigit():
        return "numeric"
    if any(char.isdigit() for char in term) and any(char.isalpha() for char in term):
        return "letters_digits"
    if term.isalpha():
        return "letters"
    return "token"


def why_this_chunk(
    *,
    matched_query_terms: list[str],
    lexical_score: float | None,
    semantic_score: float | None,
    combined_score: float | None,
    rank_reason: str,
    corpus_id: str,
    document_id: str,
    chunk_id: str,
) -> dict[str, Any]:
    matched_categories = sorted(
        set(_term_category(term) for term in matched_query_terms)
    )
    return {
        "matched_term_count": len(matched_query_terms),
        "matched_term_categories": matched_categories,
        "score_components": {
            "lexical_score": lexical_score,
            "semantic_score": semantic_score,
            "combined_score": combined_score,
        },
        "rank_reason": rank_reason,
        "corpus_id": corpus_id,
        "document_id": document_id,
        "chunk_id": chunk_id,
    }
