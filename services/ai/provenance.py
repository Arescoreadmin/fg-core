from __future__ import annotations

import re
from dataclasses import dataclass

from services.ai.rag_context import RagContextResult
from services.ai.response_validation import (
    NO_ANSWER_TEXT,
    RESPONSE_VALIDATOR_VERSION,
    ResponseValidationResult,
)

PROVENANCE_VALID = "PROVENANCE_VALID"
PROVENANCE_SOURCE_NOT_RETRIEVED = "PROVENANCE_SOURCE_NOT_RETRIEVED"
PROVENANCE_SOURCE_NOT_IN_PROMPT = "PROVENANCE_SOURCE_NOT_IN_PROMPT"
PROVENANCE_NO_CONTEXT_AVAILABLE = "PROVENANCE_NO_CONTEXT_AVAILABLE"

_EXPLICIT_CITATION_RE = re.compile(
    r"(?:chunk_id|source_id)\s*[:=]\s*([A-Za-z0-9_.:-]+)|\[(ck-[A-Za-z0-9_.:-]+)\]"
)


@dataclass(frozen=True)
class ProvenanceValidationResult:
    valid: bool
    reason_code: str
    citation_source_ids: tuple[str, ...]
    invalid_source_ids: tuple[str, ...]


def validate_answer_provenance(
    *,
    response_text: str,
    rag_context: RagContextResult,
    response_validation: ResponseValidationResult,
) -> tuple[ResponseValidationResult, ProvenanceValidationResult]:
    """Validate that response citations refer only to prompt-included context.

    This validator is ID-only and audit-safe. It never inspects or returns raw
    chunk text. Invalid provenance is stripped by replacing the response with
    NO_ANSWER and empty citation metadata.
    """
    explicit_claims = _extract_explicit_citation_ids(response_text)
    validation_ids = tuple(
        dict.fromkeys(
            source_id
            for source_id in response_validation.citation_source_ids
            if source_id
        )
    )
    claimed_ids = tuple(dict.fromkeys((*validation_ids, *explicit_claims)))

    if not rag_context.rag_used:
        if claimed_ids or response_validation.grounded:
            return _reject(PROVENANCE_NO_CONTEXT_AVAILABLE, claimed_ids)
        result = ProvenanceValidationResult(
            valid=True,
            reason_code=PROVENANCE_NO_CONTEXT_AVAILABLE,
            citation_source_ids=(),
            invalid_source_ids=(),
        )
        return response_validation, result

    retrieved_ids = set(rag_context.retrieved_source_chunk_ids or ())
    valid_source_ids = set(rag_context.source_ids)
    included_chunk_ids = set(rag_context.source_chunk_ids)
    included_source_ids = {
        chunk.source_id
        for chunk in rag_context.chunks
        if chunk.chunk_id in included_chunk_ids
    }
    prompt_ids = included_chunk_ids | included_source_ids

    not_retrieved = tuple(
        source_id
        for source_id in claimed_ids
        if source_id not in retrieved_ids and source_id not in valid_source_ids
    )
    if not_retrieved:
        return _reject(PROVENANCE_SOURCE_NOT_RETRIEVED, not_retrieved)

    not_in_prompt = tuple(
        source_id for source_id in claimed_ids if source_id not in prompt_ids
    )
    if not_in_prompt:
        return _reject(PROVENANCE_SOURCE_NOT_IN_PROMPT, not_in_prompt)

    result = ProvenanceValidationResult(
        valid=True,
        reason_code=PROVENANCE_VALID,
        citation_source_ids=claimed_ids,
        invalid_source_ids=(),
    )
    updated_validation = ResponseValidationResult(
        grounded=response_validation.grounded,
        final_text=response_validation.final_text,
        reason_code=response_validation.reason_code,
        citation_source_ids=claimed_ids,
        validator_version=response_validation.validator_version,
        evidence_count=len(claimed_ids),
        provenance_reason_code=PROVENANCE_VALID,
        provenance_valid=True,
    )
    return updated_validation, result


def _reject(
    reason_code: str,
    invalid_source_ids: tuple[str, ...],
) -> tuple[ResponseValidationResult, ProvenanceValidationResult]:
    validation = ResponseValidationResult(
        grounded=False,
        final_text=NO_ANSWER_TEXT,
        reason_code=reason_code,
        citation_source_ids=(),
        validator_version=RESPONSE_VALIDATOR_VERSION,
        evidence_count=0,
        provenance_reason_code=reason_code,
        provenance_valid=False,
    )
    provenance = ProvenanceValidationResult(
        valid=False,
        reason_code=reason_code,
        citation_source_ids=(),
        invalid_source_ids=invalid_source_ids,
    )
    return validation, provenance


def _extract_explicit_citation_ids(response_text: str) -> tuple[str, ...]:
    if not isinstance(response_text, str) or not response_text:
        return ()
    ids: list[str] = []
    for match in _EXPLICIT_CITATION_RE.finditer(response_text):
        candidate = match.group(1) or match.group(2)
        if candidate and candidate not in ids:
            ids.append(candidate)
    return tuple(ids)
