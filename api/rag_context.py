"""
api/rag_context.py — Typed RAG context request/response/provenance contract.

Defines the wire-stable models that future retrieval and AI-plane wiring will
use to pass context between the retrieval layer and the AI plane.

No retrieval implementation.  No persistence.  No database.  No AI answer
changes.  Internal models only — no FastAPI router.
"""

from __future__ import annotations

import math
from typing import Optional

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


class RagContextChunk(BaseModel):
    """A single retrieved RAG chunk with its relevance score and provenance."""

    text: str = Field(..., min_length=1)
    score: float
    provenance: RagChunkProvenance

    @field_validator("score")
    @classmethod
    def score_must_be_finite(cls, v: float) -> float:
        if not math.isfinite(v):
            raise ValueError("score must be a finite number")
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
