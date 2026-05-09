"""
api/rag_context.py — Typed RAG context request/response/provenance contract.

Defines the wire-stable models that future retrieval and AI-plane wiring will
use to pass context between the retrieval layer and the AI plane.

No retrieval implementation.  No persistence.  No database.  No AI answer
changes.  Internal models only — no FastAPI router.
"""

from __future__ import annotations

import math
from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


class RagContextRequest(BaseModel):
    """Request to retrieve RAG context chunks for a query."""

    query: str = Field(..., min_length=1)
    tenant_id: str = Field(..., min_length=1)
    corpus_ids: list[str] = Field(default_factory=list)
    top_k: int = Field(default=5, ge=1, le=100)


class RagChunkProvenance(BaseModel):
    """Provenance metadata for a single retrieved RAG chunk."""

    corpus_id: str = Field(..., min_length=1)
    document_id: str = Field(..., min_length=1)
    chunk_id: str = Field(..., min_length=1)
    source: Optional[str] = None
    title: Optional[str] = None
    uri: Optional[str] = None
    page: Optional[int] = None


# Stable set of retrieval strategy identifiers.
RetrievalStrategy = Literal["lexical", "hybrid", "semantic", "hybrid_rrf"]


class RagContextChunk(BaseModel):
    """A single retrieved RAG chunk with its relevance score and provenance.

    ``score`` is always the primary relevance score used for ranking.
    For hybrid retrieval it equals ``combined_score``.
    For lexical-only retrieval it equals ``lexical_score``.

    Scoring fields are additive — existing callers that only consume ``score``
    continue to work unchanged.  New callers may inspect the component scores
    and ``retrieval_strategy`` for provenance.
    """

    text: str = Field(..., min_length=1)
    score: float
    provenance: RagChunkProvenance

    # Additive scoring fields (PR 22 — semantic retrieval provenance).
    # Default to None so that pure-lexical callers are unaffected.
    lexical_score: Optional[float] = None
    semantic_score: Optional[float] = None
    rrf_score: Optional[float] = None
    combined_score: Optional[float] = None
    retrieval_strategy: Optional[RetrievalStrategy] = None

    @field_validator("score")
    @classmethod
    def score_must_be_finite(cls, v: float) -> float:
        if not math.isfinite(v):
            raise ValueError("score must be a finite number")
        return v

    @field_validator(
        "lexical_score",
        "semantic_score",
        "rrf_score",
        "combined_score",
        mode="before",
    )
    @classmethod
    def optional_scores_must_be_finite(cls, v: Optional[float]) -> Optional[float]:
        if v is not None and not math.isfinite(v):
            raise ValueError("score components must be finite numbers")
        return v


class RagContextResponse(BaseModel):
    """Response containing retrieved RAG context chunks for a query.

    ``context_count`` and ``used_retrieval`` are always derived from
    ``chunks`` after construction — caller-supplied values are normalised.
    This prevents a non-empty chunk list from producing
    ``context_count == 0`` or ``used_retrieval == False``.
    """

    query: str
    chunks: list[RagContextChunk] = Field(default_factory=list)
    context_count: int = 0
    used_retrieval: bool = False

    @model_validator(mode="after")
    def _derive_counts(self) -> "RagContextResponse":
        self.context_count = len(self.chunks)
        self.used_retrieval = bool(self.chunks)
        return self
