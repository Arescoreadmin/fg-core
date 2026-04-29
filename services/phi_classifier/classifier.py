"""
PHI Classifier — deterministic, rule-based detection boundary.

Design contract:
- classify_phi() is the single entry point. Never raises.
- Fail-safe: non-string or classifier error → contains_phi=True (fail-closed bias).
- Medical keywords alone do NOT constitute PHI; they only upgrade severity
  when combined with an identifier (ssn, mrn, email, phone, dob, name).
- Routing must depend on PhiClassifier (ABC), not RuleBasedPhiClassifier,
  so the implementation can be swapped without rewriting routing code.
- Audit emission via emit_phi_classification_audit / emit_phi_enforcement_block_audit.
  Payloads include phi_types (type names only, no raw values) and metadata.
  Payloads NEVER include raw input text, extracted PHI values, or full request body.

Future evolution:
  Replace RuleBasedPhiClassifier with an ML or LLM-backed implementation by
  calling set_classifier(). The routing and audit surfaces are unchanged.
"""

from __future__ import annotations

import logging
import re
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from services.phi_classifier.models import (
    PhiClassificationResult,
    PhiSpan,
    SensitivityLevel,
)

if TYPE_CHECKING:
    from fastapi import Request

log = logging.getLogger("frostgate.phi_classifier")

# ---------------------------------------------------------------------------
# Stable reasoning codes — never change meaning once published
# ---------------------------------------------------------------------------

REASON_CLEAN = "PHI_RULE_NO_SIGNALS"
REASON_SSN = "PHI_RULE_SSN"
REASON_MRN = "PHI_RULE_MRN"
REASON_PHONE = "PHI_RULE_PHONE"
REASON_EMAIL = "PHI_RULE_EMAIL"
REASON_DOB = "PHI_RULE_DOB"
REASON_NAME = "PHI_RULE_NAME_HEURISTIC"
REASON_MEDICAL = "PHI_RULE_MEDICAL_KEYWORD"
REASON_MULTI = "PHI_RULE_MULTI_IDENTIFIER"
REASON_HIGH_RISK = "PHI_RULE_HIGH_RISK_IDENTIFIER"
REASON_ERROR = "PHI_RULE_CLASSIFY_ERROR"

# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

# SSN: 123-45-6789 or 123 45 6789
_RE_SSN = re.compile(r"\b\d{3}[- ]\d{2}[- ]\d{4}\b")

# NANP phone numbers (area code cannot start with 0 or 1)
_RE_PHONE = re.compile(r"\b(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")

# Email
_RE_EMAIL = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")

# DOB: requires an explicit keyword to reduce false positives on bare dates
_RE_DOB_KEYWORD = re.compile(
    r"\b(?:date\s+of\s+birth|dob|born\s+on|birthday)\b", re.IGNORECASE
)

# Date formats: MM/DD/YYYY or YYYY-MM-DD (only matched when DOB keyword present)
_RE_DATE = re.compile(
    r"\b(?:0?[1-9]|1[0-2])[/\-](?:0?[1-9]|[12]\d|3[01])[/\-](?:19|20)\d{2}\b"
    r"|\b(?:19|20)\d{2}[/\-](?:0?[1-9]|1[0-2])[/\-](?:0?[1-9]|[12]\d|3[01])\b"
)

# MRN / medical record number / patient ID with numeric value
_RE_MRN = re.compile(
    r"\b(?:mrn|medical\s+record(?:\s+number)?|patient\s+id)[:\s#]*\d+\b",
    re.IGNORECASE,
)

# Name heuristic: "patient: John Smith" or "name: Jane Doe" (requires label)
_RE_NAME = re.compile(r"\b(?:patient|name)[:\s]+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2})\b")

# Medical context keywords — used only as a severity UPGRADE, not PHI by themselves
_MEDICAL_KEYWORDS: frozenset[str] = frozenset(
    {
        "diagnosis",
        "diagnose",
        "diagnosed",
        "prescription",
        "prescribed",
        "medication",
        "dosage",
        "treatment plan",
        "prognosis",
        "clinical notes",
        "medical record",
        "health record",
        "electronic health",
        "ehr",
        "emr",
        "icd-",
        "cpt code",
        "hipaa",
        "healthcare provider",
        "discharge summary",
    }
)

_MAX_CLASSIFY_CHARS = 100_000


# ---------------------------------------------------------------------------
# Interface — routing depends on this, not the concrete implementation
# ---------------------------------------------------------------------------


class PhiClassifier(ABC):
    """Interface for PHI classifiers.

    Routing logic MUST depend on this interface, not RuleBasedPhiClassifier,
    so the backing implementation can be swapped without rewriting routing code.
    """

    @abstractmethod
    def classify(self, text: str) -> PhiClassificationResult:
        """Classify text for PHI. Must be deterministic and never raise."""
        ...


# ---------------------------------------------------------------------------
# Default implementation
# ---------------------------------------------------------------------------


class RuleBasedPhiClassifier(PhiClassifier):
    """Deterministic regex + keyword PHI classifier.

    Fail-safe: non-string input → contains_phi=True (never crash).
    Medical keywords alone → NONE (no PHI without an identifier).
    """

    def classify(self, text: str) -> PhiClassificationResult:
        if not isinstance(text, str):
            return PhiClassificationResult(
                contains_phi=True,
                phi_types=frozenset(),
                confidence=0.5,
                sensitivity_level=SensitivityLevel.LOW,
                redaction_candidates=(),
                reasoning_code=REASON_ERROR,
            )

        if not text.strip():
            return PhiClassificationResult(
                contains_phi=False,
                phi_types=frozenset(),
                confidence=1.0,
                sensitivity_level=SensitivityLevel.NONE,
                redaction_candidates=(),
                reasoning_code=REASON_CLEAN,
            )

        sample = text[:_MAX_CLASSIFY_CHARS]
        phi_types: set[str] = set()
        spans: list[PhiSpan] = []

        for m in _RE_SSN.finditer(sample):
            phi_types.add("ssn")
            spans.append(PhiSpan(start=m.start(), end=m.end(), phi_type="ssn"))

        for m in _RE_MRN.finditer(sample):
            phi_types.add("mrn")
            spans.append(PhiSpan(start=m.start(), end=m.end(), phi_type="mrn"))

        for m in _RE_EMAIL.finditer(sample):
            phi_types.add("email")
            spans.append(PhiSpan(start=m.start(), end=m.end(), phi_type="email"))

        for m in _RE_PHONE.finditer(sample):
            phi_types.add("phone")
            spans.append(PhiSpan(start=m.start(), end=m.end(), phi_type="phone"))

        if _RE_DOB_KEYWORD.search(sample):
            phi_types.add("dob")
            for m in _RE_DATE.finditer(sample):
                spans.append(PhiSpan(start=m.start(), end=m.end(), phi_type="dob"))

        for m in _RE_NAME.finditer(sample):
            phi_types.add("name")
            spans.append(PhiSpan(start=m.start(), end=m.end(), phi_type="name"))

        lower = sample.lower()
        if any(kw in lower for kw in _MEDICAL_KEYWORDS):
            phi_types.add("medical_keyword")

        level, confidence, reasoning_code = _score(phi_types)

        return PhiClassificationResult(
            contains_phi=level != SensitivityLevel.NONE,
            phi_types=frozenset(phi_types),
            confidence=confidence,
            sensitivity_level=level,
            redaction_candidates=tuple(spans),
            reasoning_code=reasoning_code,
        )


def _single_reason(phi_type: str) -> str:
    return {
        "ssn": REASON_SSN,
        "mrn": REASON_MRN,
        "email": REASON_EMAIL,
        "phone": REASON_PHONE,
        "dob": REASON_DOB,
        "name": REASON_NAME,
    }.get(phi_type, REASON_MULTI)


def _score(phi_types: set[str]) -> tuple[SensitivityLevel, float, str]:
    """Deterministic sensitivity scoring from detected phi_types.

    Medical keywords alone → NONE (not PHI without an identifier).
    """
    high_risk = phi_types & {"ssn", "mrn"}
    non_medical = phi_types - {"medical_keyword"}
    has_medical = "medical_keyword" in phi_types

    if high_risk:
        return SensitivityLevel.HIGH, 0.95, REASON_HIGH_RISK

    if len(non_medical) >= 2 and has_medical:
        return SensitivityLevel.HIGH, 0.85, REASON_MULTI

    if len(non_medical) >= 2:
        return SensitivityLevel.MODERATE, 0.75, REASON_MULTI

    if len(non_medical) == 1 and has_medical:
        return SensitivityLevel.MODERATE, 0.70, _single_reason(next(iter(non_medical)))

    if non_medical:
        return SensitivityLevel.LOW, 0.60, _single_reason(next(iter(non_medical)))

    # Medical keywords alone are context signals only, not PHI by themselves
    return SensitivityLevel.NONE, 1.0, REASON_CLEAN


# ---------------------------------------------------------------------------
# Module-level accessor (swappable for testing / future ML upgrade)
# ---------------------------------------------------------------------------

_default_classifier: PhiClassifier = RuleBasedPhiClassifier()


def classify_phi(text: str) -> PhiClassificationResult:
    """Classify text for PHI. Deterministic, no side effects, never raises."""
    try:
        return _default_classifier.classify(text)
    except Exception:
        log.exception(
            "phi_classifier: unexpected error — failing safe (contains_phi=True)"
        )
        return PhiClassificationResult(
            contains_phi=True,
            phi_types=frozenset(),
            confidence=0.0,
            sensitivity_level=SensitivityLevel.HIGH,
            redaction_candidates=(),
            reasoning_code=REASON_ERROR,
        )


def set_classifier(classifier: PhiClassifier) -> None:
    """Replace the module-level default classifier.

    Use for tests or to upgrade to an ML/LLM/remote classifier without
    rewriting routing code.
    """
    global _default_classifier
    _default_classifier = classifier


# ---------------------------------------------------------------------------
# Audit emission — follows the same pattern as services/provider_baa/policy.py
# ---------------------------------------------------------------------------


def emit_phi_classification_audit(
    result: PhiClassificationResult,
    *,
    tenant_id: str,
    enforcement_action: str,
    request: "Request | None" = None,
) -> None:
    """Emit a PHI classification audit event.

    Emits PHI_CLASSIFICATION_DETECTED when PHI is present (severity WARNING),
    PHI_CLASSIFICATION_PERFORMED when no PHI (severity INFO).

    Payload: contains_phi, sensitivity_level, phi_types (type names, no raw values),
    enforcement_action, reasoning_code.
    Payload NEVER includes: raw text, extracted PHI values, full request body.
    """
    from api.security_audit import AuditEvent, EventType, Severity, get_auditor  # noqa: PLC0415

    event_type = (
        EventType.PHI_CLASSIFICATION_DETECTED
        if result.contains_phi
        else EventType.PHI_CLASSIFICATION_PERFORMED
    )
    severity = Severity.WARNING if result.contains_phi else Severity.INFO

    request_id, request_path, request_method = _extract_request_context(request)

    get_auditor().log_event(
        AuditEvent(
            event_type=event_type,
            success=True,
            severity=severity,
            tenant_id=tenant_id,
            reason=result.reasoning_code,
            request_id=request_id,
            request_path=request_path,
            request_method=request_method,
            details={
                "contains_phi": result.contains_phi,
                "sensitivity_level": result.sensitivity_level.value,
                "phi_types": _safe_phi_types(result),
                "enforcement_action": enforcement_action,
                "reasoning_code": result.reasoning_code,
            },
        )
    )


def emit_phi_enforcement_block_audit(
    result: PhiClassificationResult,
    *,
    tenant_id: str,
    provider_id: str,
    request: "Request | None" = None,
) -> None:
    """Emit a PHI enforcement block event.

    Emitted when PHI is detected and the provider cannot satisfy BAA requirements.
    Payload NEVER includes raw text, extracted PHI values, or full request body.
    """
    from api.security_audit import AuditEvent, EventType, Severity, get_auditor  # noqa: PLC0415

    request_id, request_path, request_method = _extract_request_context(request)

    get_auditor().log_event(
        AuditEvent(
            event_type=EventType.PHI_CLASSIFICATION_ENFORCED_BLOCK,
            success=False,
            severity=Severity.WARNING,
            tenant_id=tenant_id,
            reason="AI_PHI_PROVIDER_NOT_BAA_CAPABLE",
            request_id=request_id,
            request_path=request_path,
            request_method=request_method,
            details={
                "contains_phi": True,
                "sensitivity_level": result.sensitivity_level.value,
                "phi_types": _safe_phi_types(result),
                "enforcement_action": "denied",
                "provider_id": provider_id,
                "reasoning_code": result.reasoning_code,
            },
        )
    )


def _safe_phi_types(result: PhiClassificationResult) -> list[str]:
    """Return phi_types with medical_keyword excluded (internal signal only)."""
    return sorted(result.phi_types - {"medical_keyword"})


def _extract_request_context(
    request: "Request | None",
) -> tuple[str | None, str | None, str | None]:
    if request is None:
        return None, None, None
    request_id = getattr(getattr(request, "state", None), "request_id", None)
    request_path = str(request.url.path) if request.url else None
    request_method = request.method
    return request_id, request_path, request_method
