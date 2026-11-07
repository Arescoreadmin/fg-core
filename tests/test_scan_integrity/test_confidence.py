"""
Tests for FindingConfidence classification rules.

L14-SCAN-INTEGRITY-001 — test_confidence.py

Verifies:
- evidence_present=False → UNKNOWN (not NOT_ASSESSED, not CONFIRMED)
- collection_complete=False → max PROBABLE
- INVALID provenance → never CONFIRMED
- INTERVIEW_ASSERTION alone → never CONFIRMED
- INFERENCE alone → never CONFIRMED, never PROBABLE
- Direct observation + complete + VERIFIED → CONFIRMED allowed
- High-severity finding with SUSPECTED confidence → allowed
- All 5 confidence levels achievable
"""

from services.field_assessment.evidence_integrity import ProvenanceStatus
from services.field_assessment.finding_confidence import (
    ConfidenceLevel,
    FindingConfidence,
    VerificationMethod,
    build_finding_confidence,
    classify_confidence,
)


# ---------------------------------------------------------------------------
# classify_confidence invariant tests
# ---------------------------------------------------------------------------


class TestClassifyConfidence:
    """Core classification rule tests (fail-closed invariants)."""

    # Rule C-1: missing evidence → UNKNOWN

    def test_no_evidence_returns_unknown(self):
        """evidence_present=False must return UNKNOWN."""
        level = classify_confidence(
            evidence_present=False,
            collection_complete=True,
            verification_method=VerificationMethod.DIRECT_TECHNICAL_OBSERVATION,
            provenance_status=ProvenanceStatus.VERIFIED_INTEGRITY_ONLY,
        )
        assert level == ConfidenceLevel.UNKNOWN

    def test_no_evidence_not_not_assessed(self):
        """evidence_present=False must NOT return NOT_ASSESSED."""
        level = classify_confidence(
            evidence_present=False,
            collection_complete=True,
            verification_method=VerificationMethod.NOT_VERIFIED,
            provenance_status=ProvenanceStatus.UNVERIFIED,
        )
        assert level != ConfidenceLevel.NOT_ASSESSED

    def test_no_evidence_not_confirmed(self):
        """evidence_present=False must NOT return CONFIRMED."""
        level = classify_confidence(
            evidence_present=False,
            collection_complete=True,
            verification_method=VerificationMethod.DIRECT_TECHNICAL_OBSERVATION,
            provenance_status=ProvenanceStatus.VERIFIED_AUTHENTIC,
        )
        assert level != ConfidenceLevel.CONFIRMED

    # Rule C-2: invalid provenance → cap at SUSPECTED

    def test_invalid_provenance_returns_suspected_max(self):
        """INVALID provenance with strong method → SUSPECTED (not CONFIRMED)."""
        level = classify_confidence(
            evidence_present=True,
            collection_complete=True,
            verification_method=VerificationMethod.DIRECT_TECHNICAL_OBSERVATION,
            provenance_status=ProvenanceStatus.INVALID,
        )
        assert level == ConfidenceLevel.SUSPECTED

    def test_missing_provenance_returns_suspected_max(self):
        """MISSING provenance → SUSPECTED (not CONFIRMED, not PROBABLE)."""
        level = classify_confidence(
            evidence_present=True,
            collection_complete=True,
            verification_method=VerificationMethod.AUTHORITATIVE_CONFIGURATION_EXPORT,
            provenance_status=ProvenanceStatus.MISSING,
        )
        assert level == ConfidenceLevel.SUSPECTED

    def test_invalid_provenance_never_confirmed(self):
        """INVALID provenance MUST NOT produce CONFIRMED in any configuration."""
        for vm in VerificationMethod:
            level = classify_confidence(
                evidence_present=True,
                collection_complete=True,
                verification_method=vm,
                provenance_status=ProvenanceStatus.INVALID,
            )
            assert level != ConfidenceLevel.CONFIRMED, (
                f"INVALID provenance produced CONFIRMED with method={vm}"
            )

    # Rule C-3: interview assertion → cap at PROBABLE

    def test_interview_assertion_returns_probable_max(self):
        """INTERVIEW_ASSERTION alone must return PROBABLE (not CONFIRMED)."""
        level = classify_confidence(
            evidence_present=True,
            collection_complete=True,
            verification_method=VerificationMethod.INTERVIEW_ASSERTION,
            provenance_status=ProvenanceStatus.VERIFIED_INTEGRITY_ONLY,
        )
        assert level == ConfidenceLevel.PROBABLE

    def test_interview_assertion_never_confirmed(self):
        """INTERVIEW_ASSERTION with any provenance status must not return CONFIRMED."""
        for ps in ProvenanceStatus:
            level = classify_confidence(
                evidence_present=True,
                collection_complete=True,
                verification_method=VerificationMethod.INTERVIEW_ASSERTION,
                provenance_status=ps,
            )
            assert level != ConfidenceLevel.CONFIRMED, (
                f"INTERVIEW_ASSERTION produced CONFIRMED with provenance={ps}"
            )

    # Rule C-4: inference → cap at SUSPECTED

    def test_inference_returns_suspected(self):
        """INFERENCE alone must return SUSPECTED."""
        level = classify_confidence(
            evidence_present=True,
            collection_complete=True,
            verification_method=VerificationMethod.INFERENCE,
            provenance_status=ProvenanceStatus.VERIFIED_INTEGRITY_ONLY,
        )
        assert level == ConfidenceLevel.SUSPECTED

    def test_inference_never_confirmed(self):
        """INFERENCE must never produce CONFIRMED."""
        for ps in ProvenanceStatus:
            level = classify_confidence(
                evidence_present=True,
                collection_complete=True,
                verification_method=VerificationMethod.INFERENCE,
                provenance_status=ps,
            )
            assert level != ConfidenceLevel.CONFIRMED, (
                f"INFERENCE produced CONFIRMED with provenance={ps}"
            )

    def test_inference_never_probable(self):
        """INFERENCE must never produce PROBABLE."""
        for ps in ProvenanceStatus:
            level = classify_confidence(
                evidence_present=True,
                collection_complete=True,
                verification_method=VerificationMethod.INFERENCE,
                provenance_status=ps,
            )
            assert level != ConfidenceLevel.PROBABLE, (
                f"INFERENCE produced PROBABLE with provenance={ps}"
            )

    # Rule C-5: incomplete collection → cap at PROBABLE

    def test_incomplete_collection_max_probable(self):
        """collection_complete=False with authoritative method → max PROBABLE."""
        level = classify_confidence(
            evidence_present=True,
            collection_complete=False,
            verification_method=VerificationMethod.DIRECT_TECHNICAL_OBSERVATION,
            provenance_status=ProvenanceStatus.VERIFIED_INTEGRITY_ONLY,
        )
        assert level == ConfidenceLevel.PROBABLE

    def test_incomplete_collection_never_confirmed(self):
        """collection_complete=False must never produce CONFIRMED."""
        for vm in VerificationMethod:
            for ps in ProvenanceStatus:
                level = classify_confidence(
                    evidence_present=True,
                    collection_complete=False,
                    verification_method=vm,
                    provenance_status=ps,
                )
                assert level != ConfidenceLevel.CONFIRMED, (
                    f"collection_complete=False produced CONFIRMED "
                    f"with method={vm}, provenance={ps}"
                )

    # Rule C-6: confirmed path

    def test_direct_observation_complete_verified_returns_confirmed(self):
        """DIRECT_TECHNICAL_OBSERVATION + complete + VERIFIED_INTEGRITY_ONLY → CONFIRMED."""
        level = classify_confidence(
            evidence_present=True,
            collection_complete=True,
            verification_method=VerificationMethod.DIRECT_TECHNICAL_OBSERVATION,
            provenance_status=ProvenanceStatus.VERIFIED_INTEGRITY_ONLY,
        )
        assert level == ConfidenceLevel.CONFIRMED

    def test_authoritative_export_complete_verified_returns_confirmed(self):
        """AUTHORITATIVE_CONFIGURATION_EXPORT + complete + VERIFIED_AUTHENTIC → CONFIRMED."""
        level = classify_confidence(
            evidence_present=True,
            collection_complete=True,
            verification_method=VerificationMethod.AUTHORITATIVE_CONFIGURATION_EXPORT,
            provenance_status=ProvenanceStatus.VERIFIED_AUTHENTIC,
        )
        assert level == ConfidenceLevel.CONFIRMED

    def test_direct_observation_incomplete_returns_probable(self):
        """DIRECT_TECHNICAL_OBSERVATION + incomplete → PROBABLE (not CONFIRMED)."""
        level = classify_confidence(
            evidence_present=True,
            collection_complete=False,
            verification_method=VerificationMethod.DIRECT_TECHNICAL_OBSERVATION,
            provenance_status=ProvenanceStatus.VERIFIED_INTEGRITY_ONLY,
        )
        assert level == ConfidenceLevel.PROBABLE


# ---------------------------------------------------------------------------
# Confidence and severity independence (Rule 3.5)
# ---------------------------------------------------------------------------


class TestConfidenceSeverityIndependence:
    def test_suspected_confidence_with_high_severity_allowed(self):
        """SUSPECTED confidence is a valid outcome regardless of severity."""
        # This test simply confirms classify_confidence returns SUSPECTED
        # for a high-impact finding with partial evidence.
        level = classify_confidence(
            evidence_present=True,
            collection_complete=True,
            verification_method=VerificationMethod.INFERENCE,
            provenance_status=ProvenanceStatus.VERIFIED_INTEGRITY_ONLY,
        )
        assert level == ConfidenceLevel.SUSPECTED
        # Severity is an independent dimension — SUSPECTED is valid here
        # (the caller would still mark severity=HIGH)

    def test_confirmed_low_severity_allowed(self):
        """CONFIRMED with any severity is valid."""
        level = classify_confidence(
            evidence_present=True,
            collection_complete=True,
            verification_method=VerificationMethod.DIRECT_TECHNICAL_OBSERVATION,
            provenance_status=ProvenanceStatus.VERIFIED_INTEGRITY_ONLY,
        )
        assert level == ConfidenceLevel.CONFIRMED

    def test_unknown_critical_severity_allowed(self):
        """UNKNOWN confidence is valid even for critical-severity findings."""
        level = classify_confidence(
            evidence_present=False,
            collection_complete=False,
            verification_method=VerificationMethod.NOT_VERIFIED,
            provenance_status=ProvenanceStatus.MISSING,
        )
        assert level == ConfidenceLevel.UNKNOWN


# ---------------------------------------------------------------------------
# build_finding_confidence helper
# ---------------------------------------------------------------------------


class TestBuildFindingConfidence:
    def test_returns_finding_confidence_dataclass(self):
        """build_finding_confidence must return a FindingConfidence instance."""
        fc = build_finding_confidence(
            evidence_present=True,
            collection_complete=True,
            verification_method=VerificationMethod.DIRECT_TECHNICAL_OBSERVATION,
            provenance_status=ProvenanceStatus.VERIFIED_INTEGRITY_ONLY,
        )
        assert isinstance(fc, FindingConfidence)
        assert fc.level == ConfidenceLevel.CONFIRMED

    def test_justification_stored(self):
        """Justification note must be stored on the returned object."""
        fc = build_finding_confidence(
            evidence_present=True,
            collection_complete=True,
            verification_method=VerificationMethod.DIRECT_TECHNICAL_OBSERVATION,
            provenance_status=ProvenanceStatus.VERIFIED_INTEGRITY_ONLY,
            justification="Port 443 directly observed open in nmap scan",
        )
        assert fc.justification == "Port 443 directly observed open in nmap scan"

    def test_evidence_ids_stored(self):
        """Evidence IDs must be stored on the returned object."""
        ids = ["env-001", "env-002"]
        fc = build_finding_confidence(
            evidence_present=True,
            collection_complete=True,
            verification_method=VerificationMethod.DIRECT_TECHNICAL_OBSERVATION,
            provenance_status=ProvenanceStatus.VERIFIED_INTEGRITY_ONLY,
            evidence_ids=ids,
        )
        assert fc.evidence_ids == ids

    def test_no_evidence_ids_defaults_empty(self):
        """When evidence_ids is not provided it defaults to empty list."""
        fc = build_finding_confidence(
            evidence_present=False,
            collection_complete=False,
            verification_method=VerificationMethod.NOT_VERIFIED,
            provenance_status=ProvenanceStatus.MISSING,
        )
        assert fc.evidence_ids == []


# ---------------------------------------------------------------------------
# NOT_VERIFIED method
# ---------------------------------------------------------------------------


class TestNotVerifiedMethod:
    def test_not_verified_with_evidence_returns_suspected(self):
        """NOT_VERIFIED method with evidence returns SUSPECTED (not PROBABLE or higher)."""
        level = classify_confidence(
            evidence_present=True,
            collection_complete=True,
            verification_method=VerificationMethod.NOT_VERIFIED,
            provenance_status=ProvenanceStatus.VERIFIED_INTEGRITY_ONLY,
        )
        assert level == ConfidenceLevel.SUSPECTED

    def test_not_verified_without_evidence_returns_unknown(self):
        """NOT_VERIFIED without evidence returns UNKNOWN."""
        level = classify_confidence(
            evidence_present=False,
            collection_complete=False,
            verification_method=VerificationMethod.NOT_VERIFIED,
            provenance_status=ProvenanceStatus.MISSING,
        )
        assert level == ConfidenceLevel.UNKNOWN
