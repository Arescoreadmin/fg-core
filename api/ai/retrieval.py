from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class RetrievedChunk:
    source_id: str
    doc_id: str
    chunk_id: str
    chunk_hash: str
    score: float
    created_at: str
    text: str


class RetrievalProvider(Protocol):
    def retrieve(self, tenant_id: str, query: str) -> list[RetrievedChunk]:
        """Retrieve tenant-filtered chunks for a query. `tenant_id` is mandatory."""


class NullRetrievalProvider:
    def retrieve(self, tenant_id: str, query: str) -> list[RetrievedChunk]:
        _ = tenant_id
        _ = query
        return []
