"""Deterministic prompt minimization for provider-bound AI prompts."""

from __future__ import annotations

import re
from dataclasses import dataclass

from services.phi_classifier.classifier import classify_phi
from services.phi_classifier.models import PhiClassificationResult, PhiSpan

MINIMIZATION_VERSION = "prompt_minimization_v1"

REASON_UNCHANGED_EMPTY = "PROMPT_MINIMIZATION_EMPTY"
REASON_UNCHANGED_NO_PHI = "PROMPT_MINIMIZATION_NO_PHI"
REASON_UNCHANGED_NO_SUPPORTED_SPANS = "PROMPT_MINIMIZATION_NO_SUPPORTED_SPANS"
REASON_MINIMIZED = "PROMPT_MINIMIZATION_APPLIED"
REASON_NON_STRING = "PROMPT_MINIMIZATION_NON_STRING"

_PLACEHOLDERS: dict[str, str] = {
    "ssn": "[SSN]",
    "mrn": "[MRN]",
    "dob": "[DATE]",
    "date": "[DATE]",
    "email": "[EMAIL]",
    "phone": "[PHONE]",
    "name": "[PATIENT_NAME]",
}

_RE_MRN_VALUE = re.compile(r"\d+")
_RE_NAME_VALUE = re.compile(
    r"\b(?i:patient|name)[:\s]+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2})\b",
)


@dataclass(frozen=True)
class PromptReplacement:
    """Safe replacement metadata. Contains offsets and type names, never raw values."""

    placeholder_type: str
    start: int
    end: int
    phi_type: str
    replacement_token: str


@dataclass(frozen=True)
class PromptMinimizationResult:
    minimized_text: str
    changed: bool
    replacements: tuple[PromptReplacement, ...]
    replacement_count: int
    placeholder_types: list[str]
    minimization_version: str
    reason_code: str


def minimize_prompt(
    text: str, classification: PhiClassificationResult | None = None
) -> PromptMinimizationResult:
    """Replace supported PHI spans with stable placeholders.

    The function is deterministic, side-effect free, and never includes raw PHI in
    replacement metadata. Non-string input fails closed with an empty blocked prompt.
    """
    if not isinstance(text, str):
        return PromptMinimizationResult(
            minimized_text="",
            changed=True,
            replacements=(),
            replacement_count=0,
            placeholder_types=[],
            minimization_version=MINIMIZATION_VERSION,
            reason_code=REASON_NON_STRING,
        )
    if text == "":
        return PromptMinimizationResult(
            minimized_text="",
            changed=False,
            replacements=(),
            replacement_count=0,
            placeholder_types=[],
            minimization_version=MINIMIZATION_VERSION,
            reason_code=REASON_UNCHANGED_EMPTY,
        )

    phi_result = classification if classification is not None else classify_phi(text)
    if not phi_result.contains_phi:
        return _unchanged(text, REASON_UNCHANGED_NO_PHI)

    replacements = _build_replacements(text, phi_result.redaction_candidates)
    if not replacements:
        return _unchanged(text, REASON_UNCHANGED_NO_SUPPORTED_SPANS)

    minimized_parts: list[str] = []
    cursor = 0
    for replacement in replacements:
        minimized_parts.append(text[cursor : replacement.start])
        minimized_parts.append(replacement.replacement_token)
        cursor = replacement.end
    minimized_parts.append(text[cursor:])
    minimized_text = "".join(minimized_parts)

    return PromptMinimizationResult(
        minimized_text=minimized_text,
        changed=minimized_text != text,
        replacements=tuple(replacements),
        replacement_count=len(replacements),
        placeholder_types=sorted({item.placeholder_type for item in replacements}),
        minimization_version=MINIMIZATION_VERSION,
        reason_code=REASON_MINIMIZED
        if minimized_text != text
        else REASON_UNCHANGED_NO_SUPPORTED_SPANS,
    )


def _unchanged(text: str, reason_code: str) -> PromptMinimizationResult:
    return PromptMinimizationResult(
        minimized_text=text,
        changed=False,
        replacements=(),
        replacement_count=0,
        placeholder_types=[],
        minimization_version=MINIMIZATION_VERSION,
        reason_code=reason_code,
    )


def _build_replacements(
    text: str, spans: tuple[PhiSpan, ...]
) -> tuple[PromptReplacement, ...]:
    candidates: list[PromptReplacement] = []
    text_len = len(text)
    for span in spans:
        if span.start < 0 or span.end > text_len or span.start >= span.end:
            continue
        placeholder = _PLACEHOLDERS.get(span.phi_type)
        if placeholder is None:
            continue
        start, end = _replacement_bounds(text, span)
        if start < 0 or end > text_len or start >= end:
            continue
        candidates.append(
            PromptReplacement(
                placeholder_type=placeholder.strip("[]"),
                start=start,
                end=end,
                phi_type=span.phi_type,
                replacement_token=placeholder,
            )
        )

    ordered = sorted(candidates, key=lambda item: (item.start, item.end, item.phi_type))
    selected: list[PromptReplacement] = []
    last_end = -1
    for candidate in ordered:
        if candidate.start < last_end:
            continue
        selected.append(candidate)
        last_end = candidate.end
    return tuple(selected)


def _replacement_bounds(text: str, span: PhiSpan) -> tuple[int, int]:
    if span.phi_type == "mrn":
        return _last_match_bounds(text, span, _RE_MRN_VALUE)
    if span.phi_type == "name":
        return _last_match_bounds(text, span, _RE_NAME_VALUE)
    return span.start, span.end


def _last_match_bounds(
    text: str, span: PhiSpan, pattern: re.Pattern[str]
) -> tuple[int, int]:
    segment = text[span.start : span.end]
    last_match: re.Match[str] | None = None
    for match in pattern.finditer(segment):
        last_match = match
    if last_match is None:
        return span.start, span.end
    group_index = 1 if last_match.lastindex else 0
    return span.start + last_match.start(group_index), span.start + last_match.end(
        group_index
    )
