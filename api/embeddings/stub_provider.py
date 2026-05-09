"""
api/embeddings/stub_provider.py — Deterministic local embedding provider stub.

For dev/test use ONLY.  Produces deterministic, reproducible embeddings by
hashing the chunk text and distributing the hash bytes into the output vector
space.  No network, no OpenAI, no external dependencies.

The output is deterministic: the same text always produces the same vector.
The output is tenant-blind: the stub does not receive or process tenant_id.
Tenant isolation is enforced by the pipeline and persistence layer.

DO NOT use in production.  DO NOT use for semantic similarity — the vectors are
not semantically meaningful.  This provider exists solely to satisfy the
EmbeddingProvider protocol in dev/test environments.
"""

from __future__ import annotations

import hashlib
import struct
from typing import TYPE_CHECKING

from api.embeddings.providers import (
    KNOWN_DIMENSIONS,
    EmbeddingModel,
)

if TYPE_CHECKING:
    from api.embeddings.contracts import EmbeddingRequest, EmbeddingResponse


# Supported deterministic stub model
_STUB_MODEL = EmbeddingModel.INSTRUCTOR_XL
_STUB_DIMENSIONS = KNOWN_DIMENSIONS[_STUB_MODEL]  # 768


def _deterministic_vector(text: str, dimensions: int) -> tuple[float, ...]:
    """Produce a deterministic, normalised float vector from text.

    Algorithm:
    1. SHA-256 hash the UTF-8 text.
    2. Repeatedly extend with indexed hashes to fill the required dimensions.
    3. Interpret 4-byte chunks as little-endian unsigned int32, normalise to [0, 1].

    Properties:
    - Deterministic: same text → same vector always.
    - No network calls.
    - Stable across Python interpreter restarts.
    - Not semantically meaningful.
    """
    raw = hashlib.sha256(text.encode("utf-8")).digest()
    # Extend to cover all dimensions (32 bytes = 8 floats per hash block)
    while len(raw) < dimensions * 4:
        raw += hashlib.sha256(raw).digest()

    floats: list[float] = []
    for i in range(dimensions):
        offset = i * 4
        (uint_val,) = struct.unpack_from("<I", raw, offset)
        floats.append(uint_val / 0xFFFFFFFF)  # normalise to [0, 1]

    return tuple(floats)


class DeterministicStubProvider:
    """Deterministic local embedding provider for dev/test.

    Satisfies the EmbeddingProvider Protocol.
    Produces stable, reproducible vectors with no external dependencies.
    Not for production use.
    """

    def __init__(
        self,
        model: EmbeddingModel = _STUB_MODEL,
    ) -> None:
        if model not in KNOWN_DIMENSIONS:
            raise ValueError(
                f"DeterministicStubProvider: model {model!r} not in KNOWN_DIMENSIONS"
            )
        self._model = model
        self._dimensions = KNOWN_DIMENSIONS[model]

    @property
    def model(self) -> EmbeddingModel:
        return self._model

    @property
    def dimensions(self) -> int:
        return self._dimensions

    def embed(self, request: "EmbeddingRequest") -> "EmbeddingResponse":
        """Embed a single request deterministically."""
        from api.embeddings.contracts import EmbeddingMetadata, EmbeddingResponse

        vector = _deterministic_vector(request.text, self._dimensions)
        meta = EmbeddingMetadata(
            model=self._model,
            dimensions=self._dimensions,
            corpus_id=request.corpus_id,
            chunk_id=request.chunk_id,
            content_hash=request.content_hash,
        )
        return EmbeddingResponse(
            chunk_id=request.chunk_id,
            tenant_id=request.tenant_id,
            vector=vector,
            metadata=meta,
        )

    def embed_batch(
        self, requests: list["EmbeddingRequest"]
    ) -> list["EmbeddingResponse"]:
        """Embed a batch of requests.

        Returns responses in the same order as *requests*.
        """
        return [self.embed(req) for req in requests]

    def is_available(self) -> bool:
        """Always available — no external dependencies."""
        return True
