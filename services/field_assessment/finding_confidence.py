"""
Finding confidence enforcement — DEF-003 closure.

L14-SCAN-INTEGRITY-001

This module implements the canonical finding confidence model defined in
``docs/assurance/FROSTGATE_FINDING_CONFIDENCE_POLICY.md``.

Key invariants (all fail-closed):
- Missing evidence → UNKNOWN (not NOT_ASSESSED, not CONFIRMED)
- INVALID or MISSING provenance → max SUSPECTED
- INTERVIEW_ASSERTION alone → max PROBABLE
- INFERENCE alone → max SUSPECTED
- collection_complete=False → max PROBABLE
- Direct observation + complete + VERIFIED_* → CONFIRMED allowed

Confidence and severity are independent dimensions (Rule 3.5).

NOT_STANDALONE: This module is part of the FrostGate Core field assessment
pipeline.  It requires the full fg-core stack.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from services.field_assessment.evidence_integrity import ProvenanceStatus

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class ConfidenceLevel(str, Enum):
    """Evidence confidence levels — mutually exclusive per finding."""

    CONFIRMED = "CONFIRMED"
    PROBABLE = "PROBABLE"
    SUSPECTED = "SUSPECTED"
    UNKNOWN = "UNKNOWN"
    NOT_ASSESSED = "NOT_ASSESSED"


class VerificationMethod(str, Enum):
    """Recognized verification methods for a finding."""

    DIRECT_TECHNICAL_OBSERVATION = "DIRECT_TECHNICAL_OBSERVATION"
    AUTHORITATIVE_CONFIGURATION_EXPORT = "AUTHORITATIVE_CONFIGURATION_EXPORT"
    INDEPENDENT_CORROBORATION = "INDEPENDENT_CORROBORATION"
    DOCUMENT_REVIEW = "DOCUMENT_REVIEW"
    INTERVIEW_ASSERTION = "INTERVIEW_ASSERTION"
    INFERENCE = "INFERENCE"
    NOT_VERIFIED = "NOT_VERIFIED"


# ---------------------------------------------------------------------------
# FindingConfidence dataclass
# ---------------------------------------------------------------------------


@dataclass
class FindingConfidence:
    """Evidence confidence for a single normalized finding.

    Attributes
    ----------
    level               : ConfidenceLevel — computed by classify_confidence()
    verification_method : primary verification method used
    justification       : optional human-readable note from assessor
    evidence_ids        : list of evidence envelope UUIDs supporting this finding
    """

    level: ConfidenceLevel
    verification_method: VerificationMethod
    justification: str | None = None
    evidence_ids: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Classification rules
# ---------------------------------------------------------------------------

# Verification methods that are authoritative (can support CONFIRMED)
_AUTHORITATIVE_METHODS = {
    VerificationMethod.DIRECT_TECHNICAL_OBSERVATION,
    VerificationMethod.AUTHORITATIVE_CONFIGURATION_EXPORT,
}

# Verification methods that cannot alone support CONFIRMED
_WEAK_ONLY_METHODS = {
    VerificationMethod.INTERVIEW_ASSERTION,
    VerificationMethod.INFERENCE,
    VerificationMethod.NOT_VERIFIED,
}

# Provenance statuses considered verified (digest or authenticated)
_VERIFIED_STATUSES = {
    ProvenanceStatus.VERIFIED_AUTHENTIC,
    ProvenanceStatus.VERIFIED_INTEGRITY_ONLY,
}


def classify_confidence(
    *,
    evidence_present: bool,
    collection_complete: bool,
    verification_method: VerificationMethod,
    provenance_status: ProvenanceStatus,
) -> ConfidenceLevel:
    """Compute ConfidenceLevel from evidence quality inputs.

    Rules (fail-closed — stricter rule wins):

    Rule C-1 (evidence absent)
        evidence_present=False → UNKNOWN.
        Cannot be NOT_ASSESSED (that requires out-of-scope, not missing data).
        Cannot be CONFIRMED.

    Rule C-2 (provenance invalid)
        provenance_status in {INVALID, MISSING} → max SUSPECTED.
        Even strong verification methods cannot save a tampered payload.

    Rule C-3 (weak method — INTERVIEW_ASSERTION)
        INTERVIEW_ASSERTION alone → max PROBABLE.
        Requires corroboration with a technical method for CONFIRMED.

    Rule C-4 (weak method — INFERENCE)
        INFERENCE alone → max SUSPECTED.
        Logical deduction is never direct observation.

    Rule C-5 (incomplete collection)
        collection_complete=False → max PROBABLE.
        Partial data cannot support CONFIRMED.

    Rule C-6 (confirmed path)
        evidence_present=True AND collection_complete=True
        AND verification_method in _AUTHORITATIVE_METHODS
        AND provenance_status in _VERIFIED_STATUSES → CONFIRMED allowed.

    Rule C-7 (default partial evidence)
        evidence_present=True with authoritative method but
        collection_complete=False or unverified provenance → PROBABLE.

    Rule C-8 (default weak evidence)
        evidence_present=True with non-authoritative, non-weak method
        (e.g. DOCUMENT_REVIEW) → PROBABLE (may be downgraded by other rules).

    Parameters
    ----------
    evidence_present        : True if any evidence payload was collected
    collection_complete     : True if the scan completed without error/partial
    verification_method     : primary method used to generate this finding
    provenance_status       : integrity status of the backing evidence envelope

    Returns
    -------
    ConfidenceLevel
    """
    # Rule C-1: no evidence → UNKNOWN
    if not evidence_present:
        return ConfidenceLevel.UNKNOWN

    # Rule C-2: tampered or missing provenance → cap at SUSPECTED
    if provenance_status in {ProvenanceStatus.INVALID, ProvenanceStatus.MISSING}:
        return ConfidenceLevel.SUSPECTED

    # Rule C-4: inference only → cap at SUSPECTED
    if verification_method == VerificationMethod.INFERENCE:
        return ConfidenceLevel.SUSPECTED

    # Rule C-3: interview assertion only → cap at PROBABLE
    if verification_method == VerificationMethod.INTERVIEW_ASSERTION:
        return ConfidenceLevel.PROBABLE

    # Rule C-5: incomplete collection → cap at PROBABLE
    if not collection_complete:
        return ConfidenceLevel.PROBABLE

    # Rule C-6: confirmed path
    if (
        verification_method in _AUTHORITATIVE_METHODS
        and provenance_status in _VERIFIED_STATUSES
    ):
        return ConfidenceLevel.CONFIRMED

    # Rule C-8: authoritative method but unverified provenance → PROBABLE
    if verification_method in _AUTHORITATIVE_METHODS:
        return ConfidenceLevel.PROBABLE

    # Rule C-8 (non-authoritative methods like DOCUMENT_REVIEW, INDEPENDENT_CORROBORATION)
    if verification_method == VerificationMethod.NOT_VERIFIED:
        return ConfidenceLevel.SUSPECTED

    # DOCUMENT_REVIEW, INDEPENDENT_CORROBORATION → PROBABLE
    return ConfidenceLevel.PROBABLE


def build_finding_confidence(
    *,
    evidence_present: bool,
    collection_complete: bool,
    verification_method: VerificationMethod,
    provenance_status: ProvenanceStatus,
    justification: str | None = None,
    evidence_ids: list[str] | None = None,
) -> FindingConfidence:
    """Convenience wrapper: classify and build a FindingConfidence object."""
    level = classify_confidence(
        evidence_present=evidence_present,
        collection_complete=collection_complete,
        verification_method=verification_method,
        provenance_status=provenance_status,
    )
    return FindingConfidence(
        level=level,
        verification_method=verification_method,
        justification=justification,
        evidence_ids=evidence_ids or [],
    )
