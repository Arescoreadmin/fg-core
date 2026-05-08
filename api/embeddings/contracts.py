"""
api/embeddings/contracts.py — Embedding request/response/record contracts.

All types here are stable wire contracts.  Changing field names or removing
fields is a breaking change — add a new field with a default instead.

No I/O, no provider calls, no database access.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from api.embeddings.providers import EmbeddingModel

# ---------------------------------------------------------------------------
# Error codes (stable — never change meaning once published)
# ---------------------------------------------------------------------------

EMBED_ERR_MISSING_TENANT = "EMBED_E001"
EMBED_ERR_MISSING_CHUNK = "EMBED_E002"
EMBED_ERR_EMPTY_TEXT = "EMBED_E003"
EMBED_ERR_MISSING_HASH = "EMBED_E004"
EMBED_ERR_DIMENSION_MISMATCH = "EMBED_E005"
EMBED_ERR_EMPTY_VECTOR = "EMBED_E006"
EMBED_ERR_MISSING_CORPUS = "EMBED_E007"
EMBED_ERR_MISSING_DOCUMENT = "EMBED_E008"
EMBED_ERR_HASH_MISMATCH = "EMBED_E009"

# ---------------------------------------------------------------------------
# Canonical hash helper
# ---------------------------------------------------------------------------

_CANONICAL_ENCODING = "utf-8"


def canonical_content_hash(text: str) -> str:
    """SHA-256 hex digest of *text* encoded as canonical UTF-8.

    This is the one authoritative function for computing content hashes in the
    embedding pipeline.  All callers (ingest, chunking, provider adapters) must
    use this to guarantee hash consistency across the stack.
    """
    return hashlib.sha256(text.encode(_CANONICAL_ENCODING)).hexdigest()


# ---------------------------------------------------------------------------
# EmbeddingRequest
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EmbeddingRequest:
    """Input to the embedding pipeline for a single corpus chunk.

    ``tenant_id`` MUST come from the caller's trusted execution context —
    never from query text, client payload, or chunk metadata.

    ``content_hash`` MUST be produced by :func:`canonical_content_hash`.
    Callers should prefer the :meth:`from_chunk` factory which enforces this.
    """

    tenant_id: str
    corpus_id: str
    document_id: str
    chunk_id: str
    text: str
    content_hash: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.tenant_id or not self.tenant_id.strip():
            raise ValueError(f"{EMBED_ERR_MISSING_TENANT}: tenant_id required")
        if not self.corpus_id or not self.corpus_id.strip():
            raise ValueError(f"{EMBED_ERR_MISSING_CORPUS}: corpus_id required")
        if not self.document_id or not self.document_id.strip():
            raise ValueError(f"{EMBED_ERR_MISSING_DOCUMENT}: document_id required")
        if not self.chunk_id or not self.chunk_id.strip():
            raise ValueError(f"{EMBED_ERR_MISSING_CHUNK}: chunk_id required")
        if not self.text or not self.text.strip():
            raise ValueError(f"{EMBED_ERR_EMPTY_TEXT}: text must not be blank")
        if not self.content_hash or not self.content_hash.strip():
            raise ValueError(f"{EMBED_ERR_MISSING_HASH}: content_hash required")

    @classmethod
    def from_chunk(
        cls,
        *,
        tenant_id: str,
        corpus_id: str,
        document_id: str,
        chunk_id: str,
        text: str,
        metadata: dict[str, Any] | None = None,
    ) -> "EmbeddingRequest":
        """Canonical constructor.

        Computes ``content_hash`` from *text* using :func:`canonical_content_hash`
        so callers never risk hash/text mismatches.
        """
        return cls(
            tenant_id=tenant_id,
            corpus_id=corpus_id,
            document_id=document_id,
            chunk_id=chunk_id,
            text=text,
            content_hash=canonical_content_hash(text),
            metadata=metadata or {},
        )

    def verify_hash(self) -> bool:
        """Return True if content_hash matches the canonical hash of text."""
        return self.content_hash == canonical_content_hash(self.text)


# ---------------------------------------------------------------------------
# EmbeddingMetadata
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EmbeddingMetadata:
    """Provenance attached to every embedding response.

    ``created_at`` is always UTC.  Consumers must not mutate it.
    """

    model: EmbeddingModel
    dimensions: int
    corpus_id: str
    chunk_id: str
    content_hash: str
    created_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def __post_init__(self) -> None:
        if self.dimensions <= 0:
            raise ValueError("dimensions must be a positive integer")
        if not self.corpus_id or not self.corpus_id.strip():
            raise ValueError(f"{EMBED_ERR_MISSING_CORPUS}: corpus_id required")
        if not self.chunk_id or not self.chunk_id.strip():
            raise ValueError(f"{EMBED_ERR_MISSING_CHUNK}: chunk_id required")
        if not self.content_hash or not self.content_hash.strip():
            raise ValueError(f"{EMBED_ERR_MISSING_HASH}: content_hash required")
        if self.created_at.tzinfo is None:
            raise ValueError("created_at must be timezone-aware (UTC)")


# ---------------------------------------------------------------------------
# EmbeddingResponse
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EmbeddingResponse:
    """Output from an embedding provider for a single chunk.

    ``vector`` length MUST equal ``metadata.dimensions``.  The response is
    considered invalid otherwise and the pipeline must reject it before
    persisting.
    """

    chunk_id: str
    tenant_id: str
    vector: tuple[float, ...]
    metadata: EmbeddingMetadata

    def __post_init__(self) -> None:
        if not self.chunk_id or not self.chunk_id.strip():
            raise ValueError(f"{EMBED_ERR_MISSING_CHUNK}: chunk_id required")
        if not self.tenant_id or not self.tenant_id.strip():
            raise ValueError(f"{EMBED_ERR_MISSING_TENANT}: tenant_id required")
        if not self.vector:
            raise ValueError(f"{EMBED_ERR_EMPTY_VECTOR}: vector must not be empty")
        if len(self.vector) != self.metadata.dimensions:
            raise ValueError(
                f"{EMBED_ERR_DIMENSION_MISMATCH}: "
                f"vector length {len(self.vector)} != declared dimensions "
                f"{self.metadata.dimensions}"
            )


# ---------------------------------------------------------------------------
# ChunkEmbeddingRecord
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ChunkEmbeddingRecord:
    """Full embedding record as it lands in the persistence layer.

    This is the stable contract between the embedding pipeline (PR 21) and the
    vector persistence layer (PR 20).  Both sides must agree on this shape —
    changing it is a migration event.

    ``tenant_id`` is always present.  Persistence layer MUST reject any record
    where tenant_id is missing or blank.
    """

    tenant_id: str
    corpus_id: str
    document_id: str
    chunk_id: str
    content_hash: str
    embedding_model: EmbeddingModel
    dimensions: int
    vector: tuple[float, ...]
    created_at: datetime

    def __post_init__(self) -> None:
        if not self.tenant_id or not self.tenant_id.strip():
            raise ValueError(f"{EMBED_ERR_MISSING_TENANT}: tenant_id required")
        if not self.corpus_id or not self.corpus_id.strip():
            raise ValueError(f"{EMBED_ERR_MISSING_CORPUS}: corpus_id required")
        if not self.document_id or not self.document_id.strip():
            raise ValueError(f"{EMBED_ERR_MISSING_DOCUMENT}: document_id required")
        if not self.chunk_id or not self.chunk_id.strip():
            raise ValueError(f"{EMBED_ERR_MISSING_CHUNK}: chunk_id required")
        if not self.content_hash or not self.content_hash.strip():
            raise ValueError(f"{EMBED_ERR_MISSING_HASH}: content_hash required")
        if self.dimensions <= 0:
            raise ValueError("dimensions must be a positive integer")
        if len(self.vector) != self.dimensions:
            raise ValueError(
                f"{EMBED_ERR_DIMENSION_MISMATCH}: "
                f"vector length {len(self.vector)} != declared dimensions "
                f"{self.dimensions}"
            )
        if self.created_at.tzinfo is None:
            raise ValueError("created_at must be timezone-aware (UTC)")

    @classmethod
    def from_response(
        cls,
        response: EmbeddingResponse,
        *,
        corpus_id: str,
        document_id: str,
    ) -> "ChunkEmbeddingRecord":
        """Build a persistence record from a validated EmbeddingResponse."""
        return cls(
            tenant_id=response.tenant_id,
            corpus_id=corpus_id,
            document_id=document_id,
            chunk_id=response.chunk_id,
            content_hash=response.metadata.content_hash,
            embedding_model=response.metadata.model,
            dimensions=response.metadata.dimensions,
            vector=response.vector,
            created_at=response.metadata.created_at,
        )
