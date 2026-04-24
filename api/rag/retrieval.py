"""
RAG Retrieval Tenant Isolation — Task 16.3

Minimal in-memory retrieval surface with strict tenant binding.
No embeddings, no vector DB, no LLM calls, no external services.
Scope: search, fetch-by-ID, and answer-context preparation only.
Reranking, citation assembly, provenance, and no-answer behavior are later tasks.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from api.rag.chunking import CorpusChunk

log = logging.getLogger("frostgate.rag.retrieval")

# ---------------------------------------------------------------------------
# Error codes (stable, never change meaning once published)
# ---------------------------------------------------------------------------

RETRIEVAL_ERR_MISSING_TENANT = "RAG_RETRIEVAL_E001"
RETRIEVAL_ERR_INVALID_LIMIT = "RAG_RETRIEVAL_E002"
RETRIEVAL_ERR_CHUNK_NOT_FOUND = "RAG_RETRIEVAL_E003"
RETRIEVAL_ERR_MIXED_TENANT = "RAG_RETRIEVAL_E004"

# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------

_DEFAULT_LIMIT = 10
_MAX_LIMIT = 100
_MIN_LIMIT = 1

# ---------------------------------------------------------------------------
# Input / output models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RetrievalQuery:
    """Query submitted to the retriever.

    `trusted_tenant_id` MUST come from the caller's trusted execution context.
    It MUST NOT be sourced from query text, client payload, or chunk metadata.
    """

    query_text: str
    limit: int = _DEFAULT_LIMIT


@dataclass(frozen=True)
class RetrievalResult:
    """A single chunk returned by the retriever.

    All identity fields are preserved from the source CorpusChunk.
    """

    tenant_id: str
    source_id: str
    document_id: str
    parent_content_hash: str
    chunk_id: str
    chunk_index: int
    text: str
    safe_metadata: dict[str, Any]
    score: float  # deterministic lexical score; higher = better match


@dataclass(frozen=True)
class AnswerContextItem:
    """A single item prepared for downstream answer assembly.

    All tenant/source/document/chunk identity fields are preserved.
    No raw text is stripped; no tenant identity is removed.
    """

    tenant_id: str
    source_id: str
    document_id: str
    parent_content_hash: str
    chunk_id: str
    chunk_index: int
    text: str
    safe_metadata: dict[str, Any]
    score: float


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class RetrievalError(Exception):
    """Raised for unrecoverable retrieval failures.

    error_code is always a stable RAG_RETRIEVAL_Exxx constant.
    message MUST NOT contain raw foreign chunk text or tenant-sensitive data.
    """

    def __init__(self, error_code: str, message: str) -> None:
        super().__init__(message)
        self.error_code = error_code
        self.message = message


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _require_trusted_tenant(trusted_tenant_id: str) -> str:
    """Validate and return stripped trusted tenant. Raises on missing/blank."""
    if not trusted_tenant_id or not trusted_tenant_id.strip():
        raise RetrievalError(
            RETRIEVAL_ERR_MISSING_TENANT,
            "trusted_tenant_id is required and must not be blank",
        )
    return trusted_tenant_id.strip()


def _filter_by_tenant(chunks: list[CorpusChunk], tenant_id: str) -> list[CorpusChunk]:
    """Return only chunks belonging to tenant_id. O(n), deterministic."""
    return [c for c in chunks if c.tenant_id == tenant_id]


def _lexical_score(chunk_text: str, query_text: str) -> float:
    """Deterministic lexical relevance score: fraction of query terms present.

    Score is in [0.0, 1.0]. Ties broken by chunk_index then chunk_id in callers.
    No randomness. No external calls.
    """
    if not query_text.strip():
        return 0.0
    query_terms = set(query_text.lower().split())
    chunk_terms = set(chunk_text.lower().split())
    matches = len(query_terms & chunk_terms)
    return matches / len(query_terms) if query_terms else 0.0


def _chunks_to_results(
    chunks: list[CorpusChunk], query_text: str
) -> list[RetrievalResult]:
    """Score and sort chunks deterministically.

    Sort order: score DESC → chunk_index ASC → chunk_id ASC.
    """
    scored = [
        RetrievalResult(
            tenant_id=c.tenant_id,
            source_id=c.source_id,
            document_id=c.document_id,
            parent_content_hash=c.parent_content_hash,
            chunk_id=c.chunk_id,
            chunk_index=c.chunk_index,
            text=c.text,
            safe_metadata=dict(c.safe_metadata),
            score=_lexical_score(c.text, query_text),
        )
        for c in chunks
    ]
    return sorted(scored, key=lambda r: (-r.score, r.chunk_index, r.chunk_id))


def _validate_limit(limit: int) -> None:
    if limit < _MIN_LIMIT or limit > _MAX_LIMIT:
        raise RetrievalError(
            RETRIEVAL_ERR_INVALID_LIMIT,
            f"limit must be between {_MIN_LIMIT} and {_MAX_LIMIT}",
        )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def search_chunks(
    chunks: list[CorpusChunk],
    query: RetrievalQuery,
    trusted_tenant_id: str,
) -> list[RetrievalResult]:
    """Search corpus chunks for query terms within the trusted tenant boundary.

    Args:
        chunks: All available CorpusChunk objects (may span multiple tenants).
        query: RetrievalQuery containing query_text and result limit.
        trusted_tenant_id: Tenant identity from the trusted execution context.
            MUST NOT be sourced from query text or client payload.

    Returns:
        Up to query.limit RetrievalResult objects, all belonging to
        trusted_tenant_id, ordered deterministically by
        (score DESC, chunk_index ASC, chunk_id ASC).

    Raises:
        RetrievalError: On missing tenant, invalid limit, or other violations.

    Security invariants:
        - All cross-tenant chunks in the candidate set are excluded before
          scoring.  A matching query term in a foreign chunk never surfaces.
        - trusted_tenant_id is the only source of tenant authority.
        - Missing/blank trusted_tenant_id fails closed.
    """
    tenant_id = _require_trusted_tenant(trusted_tenant_id)
    _validate_limit(query.limit)

    tenant_chunks = _filter_by_tenant(chunks, tenant_id)
    results = _chunks_to_results(tenant_chunks, query.query_text)

    bounded = results[: query.limit]

    log.debug(
        "rag.retrieval.search",
        extra={
            "tenant_id": tenant_id,
            "candidate_count": len(tenant_chunks),
            "result_count": len(bounded),
        },
    )
    return bounded


def fetch_chunk(
    chunks: list[CorpusChunk],
    chunk_id: str,
    trusted_tenant_id: str,
) -> RetrievalResult:
    """Fetch a single chunk by ID, enforcing tenant boundary.

    Args:
        chunks: All available CorpusChunk objects.
        chunk_id: The chunk_id to look up.
        trusted_tenant_id: Tenant identity from trusted execution context.

    Returns:
        RetrievalResult for the matching chunk.

    Raises:
        RetrievalError(RETRIEVAL_ERR_CHUNK_NOT_FOUND): if the chunk does not
            exist OR belongs to a different tenant.  Both cases return the same
            error code to prevent cross-tenant existence side-channel leakage.
        RetrievalError(RETRIEVAL_ERR_MISSING_TENANT): if trusted_tenant_id
            is missing or blank.

    Security invariants:
        - Foreign chunk ID returns RETRIEVAL_ERR_CHUNK_NOT_FOUND, identical to
          a truly absent ID.  The caller cannot distinguish the two cases.
        - Error message does not include chunk text or foreign metadata.
    """
    tenant_id = _require_trusted_tenant(trusted_tenant_id)

    for chunk in chunks:
        if chunk.chunk_id == chunk_id and chunk.tenant_id == tenant_id:
            return RetrievalResult(
                tenant_id=chunk.tenant_id,
                source_id=chunk.source_id,
                document_id=chunk.document_id,
                parent_content_hash=chunk.parent_content_hash,
                chunk_id=chunk.chunk_id,
                chunk_index=chunk.chunk_index,
                text=chunk.text,
                safe_metadata=dict(chunk.safe_metadata),
                score=1.0,
            )

    # Both "not found" and "found but wrong tenant" return the same error code.
    # This prevents a cross-tenant existence side channel.
    log.warning(
        "rag.retrieval.fetch: chunk not found or tenant mismatch",
        extra={
            "tenant_id": tenant_id,
            "error_code": RETRIEVAL_ERR_CHUNK_NOT_FOUND,
        },
    )
    raise RetrievalError(
        RETRIEVAL_ERR_CHUNK_NOT_FOUND,
        "chunk not found",
    )


def prepare_answer_context(
    results: list[RetrievalResult],
    trusted_tenant_id: str,
) -> list[AnswerContextItem]:
    """Prepare retrieval results for downstream answer assembly.

    Filters results to trusted_tenant_id, preserves all identity fields,
    and returns a list ready for prompt/answer construction.

    Args:
        results: List of RetrievalResult from search_chunks or similar.
        trusted_tenant_id: Tenant identity from trusted execution context.

    Returns:
        List of AnswerContextItem, all belonging to trusted_tenant_id,
        in the same order as the input (caller is responsible for ordering).

    Raises:
        RetrievalError(RETRIEVAL_ERR_MISSING_TENANT): if trusted_tenant_id
            is missing or blank.
        RetrievalError(RETRIEVAL_ERR_MIXED_TENANT): if any result in the input
            belongs to a different tenant (defensive: should not happen if
            search_chunks is used correctly, but enforced here as a hard gate).

    Security invariants:
        - Any foreign tenant item in the input triggers RETRIEVAL_ERR_MIXED_TENANT.
        - No tenant/source/document/chunk identity is stripped.
        - Result order is preserved (deterministic if caller passed sorted input).
    """
    tenant_id = _require_trusted_tenant(trusted_tenant_id)

    for result in results:
        if result.tenant_id != tenant_id:
            log.warning(
                "rag.retrieval.prepare_answer_context: mixed-tenant input rejected",
                extra={
                    "trusted_tenant_id": tenant_id,
                    "error_code": RETRIEVAL_ERR_MIXED_TENANT,
                },
            )
            raise RetrievalError(
                RETRIEVAL_ERR_MIXED_TENANT,
                "answer context input contains results from a different tenant",
            )

    return [
        AnswerContextItem(
            tenant_id=r.tenant_id,
            source_id=r.source_id,
            document_id=r.document_id,
            parent_content_hash=r.parent_content_hash,
            chunk_id=r.chunk_id,
            chunk_index=r.chunk_index,
            text=r.text,
            safe_metadata=dict(r.safe_metadata),
            score=r.score,
        )
        for r in results
    ]
