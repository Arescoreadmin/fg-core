"""
api/embeddings — Embedding architecture contracts.

Public surface for the embedding subsystem.  Import from here, not from
sub-modules, to keep the internal layout changeable without breaking callers.
"""

from api.embeddings.contracts import (
    EMBED_ERR_DIMENSION_MISMATCH,
    EMBED_ERR_EMPTY_TEXT,
    EMBED_ERR_EMPTY_VECTOR,
    EMBED_ERR_HASH_MISMATCH,
    EMBED_ERR_MISSING_CHUNK,
    EMBED_ERR_MISSING_CORPUS,
    EMBED_ERR_MISSING_DOCUMENT,
    EMBED_ERR_MISSING_HASH,
    EMBED_ERR_MISSING_TENANT,
    ChunkEmbeddingRecord,
    EmbeddingMetadata,
    EmbeddingRequest,
    EmbeddingResponse,
    canonical_content_hash,
)
from api.embeddings.providers import (
    KNOWN_DIMENSIONS,
    EmbeddingModel,
    EmbeddingProvider,
    expected_dimensions,
)
from api.embeddings.state import EmbeddingState
from api.embeddings.stub_provider import DeterministicStubProvider

__all__ = [
    # contracts
    "canonical_content_hash",
    "ChunkEmbeddingRecord",
    "EmbeddingMetadata",
    "EmbeddingRequest",
    "EmbeddingResponse",
    # error codes
    "EMBED_ERR_DIMENSION_MISMATCH",
    "EMBED_ERR_EMPTY_TEXT",
    "EMBED_ERR_EMPTY_VECTOR",
    "EMBED_ERR_HASH_MISMATCH",
    "EMBED_ERR_MISSING_CHUNK",
    "EMBED_ERR_MISSING_CORPUS",
    "EMBED_ERR_MISSING_DOCUMENT",
    "EMBED_ERR_MISSING_HASH",
    "EMBED_ERR_MISSING_TENANT",
    # providers
    "EmbeddingModel",
    "EmbeddingProvider",
    "KNOWN_DIMENSIONS",
    "expected_dimensions",
    # state
    "EmbeddingState",
    # stub
    "DeterministicStubProvider",
]
