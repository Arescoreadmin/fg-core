"""
api/embeddings/providers.py — Provider-neutral embedding interface.

Defines EmbeddingModel (stable enum) and EmbeddingProvider (Protocol).
No provider implementations — those land in PR 21.
"""

from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from api.embeddings.contracts import EmbeddingRequest, EmbeddingResponse


# ---------------------------------------------------------------------------
# Model registry
# ---------------------------------------------------------------------------


class EmbeddingModel(str, Enum):
    """Canonical embedding model identifiers.

    Format: ``provider/model-name``.  Adding a new model here is a contract
    change — bump the model registry version and document dimensions below.
    """

    # OpenAI
    OPENAI_ADA_002 = "openai/text-embedding-ada-002"
    OPENAI_3_SMALL = "openai/text-embedding-3-small"
    OPENAI_3_LARGE = "openai/text-embedding-3-large"

    # Voyage AI
    VOYAGE_2 = "voyage/voyage-2"
    VOYAGE_LARGE_2 = "voyage/voyage-large-2"
    VOYAGE_CODE_2 = "voyage/voyage-code-2"

    # Local / open-source
    BGE_LARGE_EN = "local/bge-large-en"
    BGE_M3 = "local/bge-m3"
    INSTRUCTOR_XL = "local/instructor-xl"

    # Ollama-served
    OLLAMA_NOMIC_EMBED = "ollama/nomic-embed-text"


# Canonical output dimensions per model.
# PR 20 uses this to enforce column dimension at migration time.
# PR 21 validates provider output against this before persisting.
KNOWN_DIMENSIONS: dict[EmbeddingModel, int] = {
    EmbeddingModel.OPENAI_ADA_002: 1536,
    EmbeddingModel.OPENAI_3_SMALL: 1536,
    EmbeddingModel.OPENAI_3_LARGE: 3072,
    EmbeddingModel.VOYAGE_2: 1024,
    EmbeddingModel.VOYAGE_LARGE_2: 1536,
    EmbeddingModel.VOYAGE_CODE_2: 1536,
    EmbeddingModel.BGE_LARGE_EN: 1024,
    EmbeddingModel.BGE_M3: 1024,
    EmbeddingModel.INSTRUCTOR_XL: 768,
    EmbeddingModel.OLLAMA_NOMIC_EMBED: 768,
}


def expected_dimensions(model: EmbeddingModel) -> int | None:
    """Return expected output dimensions for *model*, or None if unknown."""
    return KNOWN_DIMENSIONS.get(model)


# ---------------------------------------------------------------------------
# Provider protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class EmbeddingProvider(Protocol):
    """Provider-neutral embedding interface.

    Implementations must be:
    - **Tenant-safe**: never mix tenant data across requests.
    - **Idempotent**: calling embed() twice with the same inputs is safe.
    - **Fail-closed**: raise on any ambiguous or partial failure rather than
      returning a zero-vector or silently truncated result.

    PR 21 will supply concrete implementations (OpenAI, Voyage, local bge,
    Instructor, Ollama).  Test providers only need to satisfy this Protocol.
    """

    @property
    def model(self) -> EmbeddingModel:
        """The model this provider wraps."""
        ...

    @property
    def dimensions(self) -> int:
        """Output vector length this provider produces."""
        ...

    def embed(self, request: "EmbeddingRequest") -> "EmbeddingResponse":
        """Embed a single chunk.  Raises on any failure."""
        ...

    def embed_batch(
        self, requests: list["EmbeddingRequest"]
    ) -> list["EmbeddingResponse"]:
        """Embed a batch of chunks.

        Must return responses in the same order as *requests*.
        Raises if any single request in the batch fails — partial success
        is not permitted at this interface level.
        """
        ...

    def is_available(self) -> bool:
        """Return True if the provider can currently serve requests.

        Used by the pipeline to gate embedding work before attempting calls.
        Must never raise.
        """
        ...
