from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from api.rag.chunking import CorpusChunk
from api.rag.retrieval import RetrievalError, RetrievalQuery, search_chunks

RAG_RETRIEVAL_EMPTY = "RAG_RETRIEVAL_EMPTY"
RAG_RETRIEVAL_SELECTED = "RAG_RETRIEVAL_SELECTED"
RAG_RETRIEVAL_FAILED = "RAG_RETRIEVAL_FAILED"

DEFAULT_RAG_CONTEXT_LIMIT = 4
MAX_RAG_CONTEXT_LIMIT = 8
MAX_RAG_CONTEXT_CHARS = 4000
MAX_RAG_CHUNK_CHARS = 1200
MIN_RAG_RELEVANCE_SCORE = 0.0

_SENSITIVITY_ORDER = {
    "none": 0,
    "low": 1,
    "moderate": 2,
    "high": 3,
}


@dataclass(frozen=True)
class RagContextChunk:
    source_id: str
    chunk_id: str
    chunk_index: int
    text: str
    phi_sensitivity_level: str | None
    phi_types: tuple[str, ...]


@dataclass(frozen=True)
class RagContextResult:
    chunks: tuple[RagContextChunk, ...]
    context_text: str
    chunk_count: int
    source_ids: tuple[str, ...]
    retrieval_reason_code: str
    query_phi_sensitivity: str | None
    max_sensitivity_level: str | None
    contains_phi: bool

    @property
    def rag_used(self) -> bool:
        return self.chunk_count > 0


class RagContextError(Exception):
    def __init__(self, error_code: str, message: str) -> None:
        super().__init__(message)
        self.error_code = error_code
        self.message = message


def retrieve_rag_context(
    *,
    tenant_id: str,
    query_text: str,
    chunks: Iterable[CorpusChunk],
    limit: int = DEFAULT_RAG_CONTEXT_LIMIT,
    phi_detected: bool,
    allowed_sensitivity_levels: set[str] | frozenset[str] | None = None,
    query_phi_sensitivity: str | None = None,
) -> RagContextResult:
    tenant = _require_tenant(tenant_id)
    bounded_limit = _bound_limit(limit)
    corpus = list(chunks)

    try:
        results = search_chunks(
            corpus,
            RetrievalQuery(query_text=query_text, limit=bounded_limit),
            trusted_tenant_id=tenant,
        )
    except RetrievalError as exc:
        raise RagContextError(exc.error_code, exc.message) from exc

    allowed_levels = (
        frozenset(str(item).strip().lower() for item in allowed_sensitivity_levels)
        if allowed_sensitivity_levels is not None
        else None
    )
    selected: list[RagContextChunk] = []
    for result in results:
        if result.tenant_id != tenant:
            raise RagContextError(
                RAG_RETRIEVAL_FAILED,
                "retrieval returned a chunk outside the trusted tenant boundary",
            )
        if result.score <= MIN_RAG_RELEVANCE_SCORE:
            continue
        sensitivity = _metadata_sensitivity(result.safe_metadata)
        if allowed_levels is not None and (sensitivity or "none") not in allowed_levels:
            continue
        selected.append(
            RagContextChunk(
                source_id=result.source_id,
                chunk_id=result.chunk_id,
                chunk_index=result.chunk_index,
                text=_bound_chunk_text(result.text),
                phi_sensitivity_level=sensitivity,
                phi_types=_metadata_phi_types(result.safe_metadata),
            )
        )

    context_text = _build_context_text(selected)
    source_ids = tuple(dict.fromkeys(chunk.source_id for chunk in selected))
    max_sensitivity = _max_sensitivity(
        chunk.phi_sensitivity_level for chunk in selected
    )
    contains_phi = bool(phi_detected) or any(
        (chunk.phi_sensitivity_level or "none") != "none" or chunk.phi_types
        for chunk in selected
    )
    return RagContextResult(
        chunks=tuple(selected),
        context_text=context_text,
        chunk_count=len(selected),
        source_ids=source_ids,
        retrieval_reason_code=RAG_RETRIEVAL_SELECTED
        if selected
        else RAG_RETRIEVAL_EMPTY,
        query_phi_sensitivity=query_phi_sensitivity,
        max_sensitivity_level=max_sensitivity,
        contains_phi=contains_phi,
    )


def build_rag_augmented_prompt(
    *,
    query_text: str,
    rag_context: RagContextResult,
) -> str:
    if not rag_context.rag_used:
        return query_text
    return (
        f"Retrieved context:\n{rag_context.context_text}\n\nUser query:\n{query_text}"
    )


def _require_tenant(tenant_id: str) -> str:
    if not isinstance(tenant_id, str) or not tenant_id.strip():
        raise RagContextError(
            RAG_RETRIEVAL_FAILED, "tenant_id is required and must not be blank"
        )
    return tenant_id.strip()


def _bound_limit(limit: int) -> int:
    if not isinstance(limit, int) or isinstance(limit, bool):
        raise RagContextError(RAG_RETRIEVAL_FAILED, "limit must be an integer")
    return max(1, min(limit, MAX_RAG_CONTEXT_LIMIT))


def _bound_chunk_text(text: str) -> str:
    normalized = " ".join(str(text).split())
    return normalized[:MAX_RAG_CHUNK_CHARS]


def _build_context_text(chunks: list[RagContextChunk]) -> str:
    parts: list[str] = []
    total = 0
    for index, chunk in enumerate(chunks, start=1):
        part = f"[{index}]\n{chunk.text}"
        remaining = MAX_RAG_CONTEXT_CHARS - total
        if remaining <= 0:
            break
        if len(part) > remaining:
            part = part[:remaining]
        parts.append(part)
        total += len(part)
    return "\n\n".join(parts)


def _metadata_sensitivity(metadata: dict[str, object]) -> str | None:
    value = metadata.get("phi_sensitivity_level")
    if not isinstance(value, str):
        return None
    cleaned = value.strip().lower()
    return cleaned or None


def _metadata_phi_types(metadata: dict[str, object]) -> tuple[str, ...]:
    raw = metadata.get("phi_types")
    if not isinstance(raw, list):
        return ()
    return tuple(sorted(str(item).strip() for item in raw if str(item).strip()))


def _max_sensitivity(values: Iterable[str | None]) -> str | None:
    max_value: str | None = None
    max_rank = -1
    for value in values:
        if value is None:
            continue
        rank = _SENSITIVITY_ORDER.get(value, -1)
        if rank > max_rank:
            max_value = value
            max_rank = rank
    return max_value
