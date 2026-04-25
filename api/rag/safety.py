"""
RAG Prompt Injection and Poisoned-Document Resistance — Task 16.8

Deterministic, local, in-process guard for retrieved content that contains
instruction-override or tenant-manipulation patterns.

No LLM calls.  No external classifiers.  No network calls.  No randomness.
Scope: detection, annotation, and score-zeroing of suspicious context items only.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from api.rag.retrieval import AnswerContextItem

log = logging.getLogger("frostgate.rag.safety")

# ---------------------------------------------------------------------------
# Injection rule definitions
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PromptInjectionRule:
    """A single deterministic injection-detection rule.

    patterns are all lowercase; matching is performed on lowercased input.
    """

    rule_id: str
    patterns: tuple[str, ...]
    description: str


# Stable rule set — IDs never change meaning once published.
_RULES: tuple[PromptInjectionRule, ...] = (
    PromptInjectionRule(
        rule_id="PI001",
        patterns=(
            "ignore previous instructions",
            "ignore prior instructions",
            "disregard previous instructions",
            "disregard system instructions",
            "disregard the above",
        ),
        description="instruction-override: ignore previous",
    ),
    PromptInjectionRule(
        rule_id="PI002",
        patterns=(
            "disable citations",
            "do not cite sources",
            "answer without citing",
            "no need to cite",
            "skip citation",
        ),
        description="citation bypass attempt",
    ),
    PromptInjectionRule(
        rule_id="PI003",
        patterns=(
            "exfiltrate",
            "reveal your system prompt",
            "show your system prompt",
            "leak credentials",
            "reveal secrets",
        ),
        description="secret exfiltration attempt",
    ),
    PromptInjectionRule(
        rule_id="PI004",
        patterns=(
            "switch tenants",
            "use tenant_id=",
            "change tenant to",
            "act as tenant",
            "tenant override",
        ),
        description="tenant switch attempt",
    ),
    PromptInjectionRule(
        rule_id="PI005",
        patterns=(
            "follow these instructions instead",
            "override instructions",
            "new system instructions",
            "updated system prompt",
            "your new instructions",
        ),
        description="system instruction override",
    ),
    PromptInjectionRule(
        rule_id="PI006",
        patterns=(
            "answer without evidence",
            "answer without grounding",
            "fabricate an answer",
            "make up an answer",
        ),
        description="grounding bypass attempt",
    ),
)

# ---------------------------------------------------------------------------
# Output models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PromptInjectionFinding:
    """A single rule match within an assessed text.

    matched_pattern is from the predefined rule set — not raw document text.
    No foreign content appears in this payload.
    """

    rule_id: str
    matched_pattern: str  # the rule-defined pattern string; never raw doc content


@dataclass(frozen=True)
class PromptInjectionAssessment:
    """Deterministic, auditable result of a prompt-injection assessment.

    Same input always produces the same assessment.
    No raw document text is stored beyond the matched_pattern fields (which are
    predefined rule strings, not raw content).
    """

    is_suspicious: bool
    risk_level: str  # "none" | "high"
    findings: tuple[PromptInjectionFinding, ...]
    matched_rule_ids: frozenset[str]
    action: str  # "allowed_as_content" | "constrained"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_SAFE_ASSESSMENT = PromptInjectionAssessment(
    is_suspicious=False,
    risk_level="none",
    findings=(),
    matched_rule_ids=frozenset(),
    action="allowed_as_content",
)


def _assess_normalized(normalized: str) -> PromptInjectionAssessment:
    """Run rules against pre-lowercased text. Internal use only."""
    findings: list[PromptInjectionFinding] = []
    matched_ids: set[str] = set()

    for rule in _RULES:
        for pattern in rule.patterns:
            if pattern in normalized:
                findings.append(
                    PromptInjectionFinding(
                        rule_id=rule.rule_id, matched_pattern=pattern
                    )
                )
                matched_ids.add(rule.rule_id)
                break  # one finding per rule per text is sufficient

    if not findings:
        return _SAFE_ASSESSMENT

    return PromptInjectionAssessment(
        is_suspicious=True,
        risk_level="high",
        findings=tuple(findings),
        matched_rule_ids=frozenset(matched_ids),
        action="constrained",
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def assess_prompt_injection(text: str) -> PromptInjectionAssessment:
    """Assess a single text string for prompt injection patterns.

    Deterministic: same input always produces the same result.
    Non-string inputs are treated as non-suspicious (safe default).

    Returns:
        PromptInjectionAssessment with is_suspicious=False for clean text,
        or is_suspicious=True with matched rule IDs and action="constrained"
        for text containing known hostile patterns.

    Security invariants:
        - No external calls, no randomness, no timestamps.
        - matched_pattern fields contain only predefined rule strings — never
          raw document content.
        - Non-string inputs return safe assessment without raising.
    """
    if not isinstance(text, str):
        return _SAFE_ASSESSMENT
    if not text:
        return _SAFE_ASSESSMENT
    return _assess_normalized(text.lower())


def assess_context_items(
    context_items: list[AnswerContextItem],
) -> PromptInjectionAssessment:
    """Assess all context items and return an aggregate assessment.

    Findings from all items are merged into a single assessment.
    Same inputs always produce identical results.

    Returns:
        Aggregate PromptInjectionAssessment across all items.
    """
    all_findings: list[PromptInjectionFinding] = []
    all_rule_ids: set[str] = set()

    for item in context_items:
        a = assess_prompt_injection(item.text)
        if a.is_suspicious:
            all_findings.extend(a.findings)
            all_rule_ids.update(a.matched_rule_ids)

    if not all_findings:
        return _SAFE_ASSESSMENT

    return PromptInjectionAssessment(
        is_suspicious=True,
        risk_level="high",
        findings=tuple(all_findings),
        matched_rule_ids=frozenset(all_rule_ids),
        action="constrained",
    )


def constrain_answer_context(
    context_items: list[AnswerContextItem],
    trusted_tenant_id: str,
) -> list[AnswerContextItem]:
    """Return context items with injection-risk annotations applied.

    Suspicious items are returned with:
      - score set to 0.0 (prevents them from supporting grounded evidence)
      - safe_metadata["prompt_injection_risk"] = True
      - safe_metadata["injection_rule_ids"] = sorted list of matched rule IDs

    Clean items are returned unchanged.

    Args:
        context_items: Context items to assess and annotate.
        trusted_tenant_id: Passed for audit context only.  This function does
            NOT alter tenant_id on any item.  Tenant authority is unchanged.

    Returns:
        New list of AnswerContextItem — caller input is never mutated.

    Security invariants:
        - tenant_id of each item is never altered.
        - trusted_tenant_id cannot be overridden by document content.
        - Suspicious item score is zeroed; existing policy evaluation then
          determines whether remaining evidence is sufficient.
        - Log output does not include raw item text or tenant identifiers.
        - Deterministic: same inputs always produce same output.
    """
    result: list[AnswerContextItem] = []

    for item in context_items:
        assessment = assess_prompt_injection(item.text)

        if assessment.is_suspicious:
            log.warning(
                "rag.safety: prompt injection pattern detected — item score zeroed",
                extra={
                    "rule_ids": sorted(assessment.matched_rule_ids),
                    "action": assessment.action,
                    # NOT logging item.text, item.tenant_id, or item.source_id
                },
            )
            new_metadata = dict(item.safe_metadata)
            new_metadata["prompt_injection_risk"] = True
            new_metadata["injection_rule_ids"] = sorted(assessment.matched_rule_ids)
            result.append(
                AnswerContextItem(
                    tenant_id=item.tenant_id,
                    source_id=item.source_id,
                    document_id=item.document_id,
                    parent_content_hash=item.parent_content_hash,
                    chunk_id=item.chunk_id,
                    chunk_index=item.chunk_index,
                    text=item.text,
                    safe_metadata=new_metadata,
                    score=0.0,
                )
            )
        else:
            result.append(item)

    return result
