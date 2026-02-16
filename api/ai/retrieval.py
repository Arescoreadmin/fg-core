from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class RetrievedChunk:
    source_id: str
    chunk_id: str
    score: float
    text: str
    trusted: bool = False


class RetrievalProvider(Protocol):
    """Tenant-bound retrieval contract; implementations must enforce tenant filtering.

    Security contract:
    - provider MUST scope retrieval by tenant_id.
    - chunk text should be sanitized by provider or returned as trusted=False.
    """

    def retrieve(self, tenant_id: str, query: str) -> list[RetrievedChunk]: ...


class NullRetrievalProvider:
    def retrieve(self, tenant_id: str, query: str) -> list[RetrievedChunk]:
        _ = tenant_id
        _ = query
        return []
