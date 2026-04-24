"""
RAG Answer Grounding and Citation Contract — Task 16.4

Transforms tenant-isolated retrieval evidence into grounded answer payloads
with explicit citations, or explicit no-answer payloads when evidence is
insufficient.

No LLM calls. No embeddings. No vector DB. No external services.
Scope: answer contract, citation construction, no-answer behavior only.
Reranking, provenance UI, latency/cost guardrails, and prompt-injection
defenses are later tasks.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from api.rag.retrieval import AnswerContextItem

log = logging.getLogger("frostgate.rag.answering")

# ---------------------------------------------------------------------------
# Error codes (stable, never change meaning once published)
# ---------------------------------------------------------------------------

ANSWER_ERR_MISSING_TENANT = "RAG_ANSWER_E001"
ANSWER_ERR_MIXED_TENANT = "RAG_ANSWER_E002"
ANSWER_ERR_CITATION_REQUIRED = "RAG_ANSWER_E003"
ANSWER_ERR_INVALID_CITATION_INPUT = "RAG_ANSWER_E004"

# No-answer reason codes (not errors — explicit safe states)
NO_ANSWER_EMPTY_CONTEXT = "RAG_NO_ANSWER_EMPTY_CONTEXT"
NO_ANSWER_INSUFFICIENT_CONTEXT = "RAG_NO_ANSWER_INSUFFICIENT_CONTEXT"
NO_ANSWER_TENANT_MISMATCH = "RAG_NO_ANSWER_TENANT_MISMATCH"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_CANONICAL_ENCODING = "utf-8"
_EXCERPT_MAX_CHARS = 300  # bounded excerpt length for extractive answers

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class AnswerStatus(str, Enum):
    GROUNDED = "grounded"
    NO_ANSWER = "no_answer"


@dataclass(frozen=True)
class CitationReference:
    """Stable, auditable citation pointing to a specific retrieved chunk.

    citation_id is deterministic: SHA-256 of canonical identity fields.
    No unsafe metadata or raw secrets are included.
    """

    citation_id: str  # deterministic SHA-256
    tenant_id: str
    source_id: str
    document_id: str
    chunk_id: str
    chunk_index: int
    parent_content_hash: str
    excerpt: str  # bounded excerpt from chunk text; never exceeds _EXCERPT_MAX_CHARS


@dataclass(frozen=True)
class GroundedAnswer:
    """An answer grounded in retrieved evidence with explicit citations.

    Invariant: citations is always non-empty.
    Invariant: grounded is always True.
    Invariant: all citations belong to tenant_id.
    """

    status: AnswerStatus
    grounded: bool
    tenant_id: str
    answer_text: str
    citations: list[CitationReference]
    evidence_count: int
    safe_metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class NoAnswer:
    """Explicit, structured no-answer payload.

    Returned when context is empty, low-score, or otherwise insufficient.
    Never contains foreign chunk text or tenant metadata.
    Invariant: grounded is always False.
    Invariant: citations is always empty.
    """

    status: AnswerStatus
    grounded: bool
    reason_code: str
    user_safe_message: str
    citations: list[CitationReference]  # always []


# Union type for answer assembly result
AnswerAssemblyResult = GroundedAnswer | NoAnswer


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class AnsweringError(Exception):
    """Raised for unrecoverable answer assembly failures.

    error_code is always a stable RAG_ANSWER_Exxx constant.
    message MUST NOT contain raw foreign chunk text or tenant-sensitive data.
    """

    def __init__(self, error_code: str, message: str) -> None:
        super().__init__(message)
        self.error_code = error_code
        self.message = message


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode(_CANONICAL_ENCODING)).hexdigest()


def _deterministic_citation_id(
    tenant_id: str,
    source_id: str,
    document_id: str,
    chunk_id: str,
    chunk_index: int,
    parent_content_hash: str,
) -> str:
    canonical = json.dumps(
        {
            "chunk_id": chunk_id,
            "chunk_index": chunk_index,
            "document_id": document_id,
            "parent_content_hash": parent_content_hash,
            "source_id": source_id,
            "tenant_id": tenant_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return _sha256_hex(canonical)


def _make_citation(item: AnswerContextItem) -> CitationReference:
    citation_id = _deterministic_citation_id(
        tenant_id=item.tenant_id,
        source_id=item.source_id,
        document_id=item.document_id,
        chunk_id=item.chunk_id,
        chunk_index=item.chunk_index,
        parent_content_hash=item.parent_content_hash,
    )
    excerpt = item.text[:_EXCERPT_MAX_CHARS]
    return CitationReference(
        citation_id=citation_id,
        tenant_id=item.tenant_id,
        source_id=item.source_id,
        document_id=item.document_id,
        chunk_id=item.chunk_id,
        chunk_index=item.chunk_index,
        parent_content_hash=item.parent_content_hash,
        excerpt=excerpt,
    )


def _require_trusted_tenant(trusted_tenant_id: str) -> str:
    if not trusted_tenant_id or not trusted_tenant_id.strip():
        raise AnsweringError(
            ANSWER_ERR_MISSING_TENANT,
            "trusted_tenant_id is required and must not be blank",
        )
    return trusted_tenant_id.strip()


def _check_mixed_tenant(context: list[AnswerContextItem], tenant_id: str) -> None:
    for item in context:
        if item.tenant_id != tenant_id:
            log.warning(
                "rag.answering: mixed-tenant context rejected",
                extra={
                    "trusted_tenant_id": tenant_id,
                    "error_code": ANSWER_ERR_MIXED_TENANT,
                },
            )
            raise AnsweringError(
                ANSWER_ERR_MIXED_TENANT,
                "answer context contains results from a different tenant",
            )


def _extractive_answer(context: list[AnswerContextItem]) -> str:
    """Produce a bounded deterministic extractive answer from top evidence.

    Uses the first context item's text (assumed ordered by score DESC from
    the retrieval layer). Bounded to _EXCERPT_MAX_CHARS characters.
    No LLM calls. No summarization. No fabrication.
    """
    return context[0].text[:_EXCERPT_MAX_CHARS]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def assemble_answer_from_context(
    context: list[AnswerContextItem],
    trusted_tenant_id: str,
    answer_text: str | None = None,
) -> AnswerAssemblyResult:
    """Assemble a grounded answer or explicit no-answer from retrieval context.

    Args:
        context: List of AnswerContextItem from prepare_answer_context().
            Must all belong to trusted_tenant_id.
        trusted_tenant_id: Tenant identity from trusted execution context.
            MUST NOT come from context items, query text, or client payload.
        answer_text: Optional caller-supplied answer text. If provided and
            sufficient context exists, it is used verbatim. If omitted,
            an extractive answer is derived from the top context item.

    Returns:
        GroundedAnswer if valid evidence exists (score > 0 on at least one
        item), or NoAnswer if context is empty or all scores are zero.

    Raises:
        AnsweringError: On missing/blank trusted tenant or mixed-tenant input.

    Security invariants:
        - trusted_tenant_id is the only source of tenant authority.
        - Mixed-tenant context raises ANSWER_ERR_MIXED_TENANT.
        - Empty context returns NoAnswer(NO_ANSWER_EMPTY_CONTEXT).
        - All-zero-score context returns NoAnswer(NO_ANSWER_INSUFFICIENT_CONTEXT).
        - Every grounded answer has at least one citation.
        - Citation IDs are deterministic SHA-256 of identity fields.
        - Error messages contain no raw foreign chunk text.
    """
    tenant_id = _require_trusted_tenant(trusted_tenant_id)

    # Guard: mixed-tenant input is an invariant violation
    _check_mixed_tenant(context, tenant_id)

    # Guard: empty context → explicit no-answer
    if not context:
        log.info(
            "rag.answering: no-answer (empty context)",
            extra={"tenant_id": tenant_id, "reason": NO_ANSWER_EMPTY_CONTEXT},
        )
        return NoAnswer(
            status=AnswerStatus.NO_ANSWER,
            grounded=False,
            reason_code=NO_ANSWER_EMPTY_CONTEXT,
            user_safe_message="No relevant documents were found for your query.",
            citations=[],
        )

    # Guard: low context — all scores are zero → no useful evidence
    if all(item.score == 0.0 for item in context):
        log.info(
            "rag.answering: no-answer (insufficient context)",
            extra={"tenant_id": tenant_id, "reason": NO_ANSWER_INSUFFICIENT_CONTEXT},
        )
        return NoAnswer(
            status=AnswerStatus.NO_ANSWER,
            grounded=False,
            reason_code=NO_ANSWER_INSUFFICIENT_CONTEXT,
            user_safe_message=(
                "The retrieved documents did not contain sufficient relevant "
                "information to produce a grounded answer."
            ),
            citations=[],
        )

    # Build citations from context items in input order (caller is responsible
    # for ordering via the retrieval layer).
    citations = [_make_citation(item) for item in context]

    # Defensive: grounded answer MUST have citations
    if not citations:
        raise AnsweringError(
            ANSWER_ERR_CITATION_REQUIRED,
            "grounded answer requires at least one citation",
        )

    effective_answer = (
        answer_text if answer_text is not None else _extractive_answer(context)
    )

    log.info(
        "rag.answering: grounded answer assembled",
        extra={
            "tenant_id": tenant_id,
            "evidence_count": len(context),
            "citation_count": len(citations),
        },
    )

    return GroundedAnswer(
        status=AnswerStatus.GROUNDED,
        grounded=True,
        tenant_id=tenant_id,
        answer_text=effective_answer,
        citations=citations,
        evidence_count=len(context),
    )


def build_no_answer(
    reason_code: str,
    user_safe_message: str,
    trusted_tenant_id: str | None = None,
) -> NoAnswer:
    """Build an explicit no-answer payload with a stable reason code.

    May be called without trusted_tenant_id for cases where tenant context
    is missing entirely (e.g., upstream validation failure).

    Returns:
        NoAnswer with grounded=False, empty citations, and stable reason_code.
    """
    return NoAnswer(
        status=AnswerStatus.NO_ANSWER,
        grounded=False,
        reason_code=reason_code,
        user_safe_message=user_safe_message,
        citations=[],
    )
