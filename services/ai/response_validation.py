from __future__ import annotations

import re
from dataclasses import dataclass

from services.ai.rag_context import RagContextResult

NO_ANSWER_TEXT = "NO_ANSWER"

RESPONSE_GROUNDED = "RESPONSE_GROUNDED"
RESPONSE_NO_RAG_CONTEXT = "RESPONSE_NO_RAG_CONTEXT"
RESPONSE_UNGROUNDED = "RESPONSE_UNGROUNDED"
RESPONSE_EMPTY = "RESPONSE_EMPTY"
RESPONSE_VALIDATION_FAILED = "RESPONSE_VALIDATION_FAILED"

RESPONSE_VALIDATOR_VERSION = "rag_lexical_grounding_v1"

_TOKEN_RE = re.compile(r"[a-z0-9]+")
_STOPWORDS = frozenset(
    {
        "about",
        "after",
        "also",
        "and",
        "are",
        "because",
        "been",
        "before",
        "being",
        "can",
        "could",
        "does",
        "from",
        "has",
        "have",
        "into",
        "its",
        "more",
        "must",
        "not",
        "only",
        "that",
        "the",
        "their",
        "there",
        "this",
        "was",
        "were",
        "with",
        "would",
    }
)


@dataclass(frozen=True)
class ResponseValidationResult:
    grounded: bool
    final_text: str
    reason_code: str
    citation_source_ids: tuple[str, ...]
    validator_version: str
    evidence_count: int


class ResponseValidationError(Exception):
    def __init__(self, error_code: str, message: str) -> None:
        super().__init__(message)
        self.error_code = error_code
        self.message = message


def validate_provider_response_grounding(
    *,
    response_text: str,
    rag_context: RagContextResult,
    tenant_id: str,
) -> ResponseValidationResult:
    """Validate provider output against retrieved tenant-scoped RAG context.

    The validator is intentionally extractive and fail-closed: all significant
    response tokens must be present in retrieved context before the provider
    text can be returned. Unsupported output is replaced with NO_ANSWER.
    """
    _require_tenant(tenant_id)
    if not rag_context.rag_used:
        return _no_answer(RESPONSE_NO_RAG_CONTEXT)
    if not isinstance(response_text, str) or not response_text.strip():
        return _no_answer(RESPONSE_EMPTY)

    response_tokens = _significant_tokens(response_text)
    if not response_tokens:
        return _no_answer(RESPONSE_UNGROUNDED)

    context_tokens: set[str] = set()
    evidence_source_ids: list[str] = []
    for chunk in rag_context.chunks:
        chunk_tokens = _significant_tokens(chunk.text)
        context_tokens.update(chunk_tokens)
        if (
            response_tokens & chunk_tokens
            and chunk.source_id not in evidence_source_ids
        ):
            evidence_source_ids.append(chunk.source_id)

    if response_tokens <= context_tokens and evidence_source_ids:
        citations = tuple(evidence_source_ids)
        return ResponseValidationResult(
            grounded=True,
            final_text=response_text,
            reason_code=RESPONSE_GROUNDED,
            citation_source_ids=citations,
            validator_version=RESPONSE_VALIDATOR_VERSION,
            evidence_count=len(citations),
        )

    return _no_answer(RESPONSE_UNGROUNDED)


def _no_answer(reason_code: str) -> ResponseValidationResult:
    return ResponseValidationResult(
        grounded=False,
        final_text=NO_ANSWER_TEXT,
        reason_code=reason_code,
        citation_source_ids=(),
        validator_version=RESPONSE_VALIDATOR_VERSION,
        evidence_count=0,
    )


def _require_tenant(tenant_id: str) -> str:
    if not isinstance(tenant_id, str) or not tenant_id.strip():
        raise ResponseValidationError(
            RESPONSE_VALIDATION_FAILED,
            "tenant_id is required and must not be blank",
        )
    return tenant_id.strip()


def _significant_tokens(text: str) -> set[str]:
    tokens = {
        token
        for token in _TOKEN_RE.findall(text.lower())
        if len(token) >= 3 and token not in _STOPWORDS
    }
    return tokens
