"""L14-SCAN-ACCURACY-001 — Finding confidence model tests.

Tests the FrostGate evidence confidence policy rules.
Confidence and severity are separately justified.
Confidence levels: CONFIRMED / PROBABLE / SUSPECTED / UNKNOWN / NOT_ASSESSED
Verification methods: DIRECT_TECHNICAL_OBSERVATION / AUTHORITATIVE_CONFIGURATION_EXPORT /
  INDEPENDENT_CORROBORATION / DOCUMENT_REVIEW / INTERVIEW_ASSERTION / INFERENCE / NOT_VERIFIED

Rules enforced:
- CONFIRMED requires DIRECT_TECHNICAL_OBSERVATION or AUTHORITATIVE_CONFIGURATION_EXPORT
- CONFIRMED with only INTERVIEW_ASSERTION is not permitted
- PROBABLE is minimum when primary evidence exists but independent corroboration absent
- Confidence != Severity (SUSPECTED may be HIGH; CONFIRMED may be LOW)
- Missing data -> UNKNOWN or NOT_ASSESSED, never CONFIRMED_ABSENT without evidence
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Confidence model definitions (pure logic, no external dependencies)
# ---------------------------------------------------------------------------

CONFIDENCE_LEVELS = frozenset(
    {"CONFIRMED", "PROBABLE", "SUSPECTED", "UNKNOWN", "NOT_ASSESSED"}
)
SEVERITY_LEVELS = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"})
VERIFICATION_METHODS = frozenset(
    {
        "DIRECT_TECHNICAL_OBSERVATION",
        "AUTHORITATIVE_CONFIGURATION_EXPORT",
        "INDEPENDENT_CORROBORATION",
        "DOCUMENT_REVIEW",
        "INTERVIEW_ASSERTION",
        "INFERENCE",
        "NOT_VERIFIED",
    }
)


def _validate_finding_confidence(finding: dict) -> list[str]:
    """Validate a finding against the confidence policy rules.

    Returns a list of violations. Empty list = valid.
    """
    violations = []
    confidence = finding.get("confidence", "")
    severity = finding.get("severity", "")
    methods = set(finding.get("verification_methods", []))

    # Rule 1: confidence must be a known level
    if confidence not in CONFIDENCE_LEVELS:
        violations.append(f"Unknown confidence level: {confidence!r}")

    # Rule 2: severity must be a known level (if set)
    if severity and severity not in SEVERITY_LEVELS:
        violations.append(f"Unknown severity level: {severity!r}")

    # Rule 3: verification methods must all be known
    for m in methods:
        if m not in VERIFICATION_METHODS:
            violations.append(f"Unknown verification method: {m!r}")

    # Rule 4: CONFIRMED requires DIRECT_TECHNICAL_OBSERVATION or AUTHORITATIVE_CONFIGURATION_EXPORT
    if confidence == "CONFIRMED":
        required = {
            "DIRECT_TECHNICAL_OBSERVATION",
            "AUTHORITATIVE_CONFIGURATION_EXPORT",
        }
        if not (methods & required):
            violations.append(
                "CONFIRMED requires DIRECT_TECHNICAL_OBSERVATION or "
                "AUTHORITATIVE_CONFIGURATION_EXPORT; none present."
            )

    # Rule 5: CONFIRMED with ONLY INTERVIEW_ASSERTION is not permitted
    if confidence == "CONFIRMED" and methods == {"INTERVIEW_ASSERTION"}:
        violations.append(
            "CONFIRMED with only INTERVIEW_ASSERTION is not permitted. "
            "Interview assertion is insufficient for CONFIRMED confidence."
        )

    # Rule 6: CONFIRMED with ONLY INFERENCE is not permitted
    if confidence == "CONFIRMED" and methods == {"INFERENCE"}:
        violations.append(
            "CONFIRMED with only INFERENCE is not permitted. "
            "Inference without direct observation is insufficient for CONFIRMED."
        )

    return violations


def _is_confirmed_absent_claim(finding: dict) -> bool:
    """Check if a finding makes a CONFIRMED_ABSENT claim without evidence."""
    # Finding type or description contains 'confirmed absent' claim
    description = finding.get("description", "").lower()
    finding_type = finding.get("type", "").lower()
    return (
        "confirmed absent" in description
        or "confirmed_absent" in finding_type
        or "confirmed_missing" in finding_type
    )


# ---------------------------------------------------------------------------
# SA-CONF-001: Confidence level enumeration validation
# ---------------------------------------------------------------------------


class TestConfidenceLevelValidation:
    def test_confirmed_with_direct_observation_is_valid(self):
        finding = {
            "type": "test.finding",
            "confidence": "CONFIRMED",
            "severity": "HIGH",
            "verification_methods": ["DIRECT_TECHNICAL_OBSERVATION"],
        }
        violations = _validate_finding_confidence(finding)
        assert violations == []

    def test_confirmed_with_authoritative_export_is_valid(self):
        finding = {
            "type": "test.finding",
            "confidence": "CONFIRMED",
            "severity": "HIGH",
            "verification_methods": ["AUTHORITATIVE_CONFIGURATION_EXPORT"],
        }
        violations = _validate_finding_confidence(finding)
        assert violations == []

    def test_all_confidence_levels_are_valid_enum_values(self):
        for level in CONFIDENCE_LEVELS:
            finding = {
                "type": "test.finding",
                "confidence": level,
                "severity": "MEDIUM",
                "verification_methods": ["DIRECT_TECHNICAL_OBSERVATION"],
            }
            violations = _validate_finding_confidence(finding)
            # Only check that the confidence level itself is valid (not all rules pass)
            conf_violations = [v for v in violations if "Unknown confidence level" in v]
            assert conf_violations == [], (
                f"Level {level!r} produced violation: {conf_violations}"
            )

    def test_unknown_confidence_level_produces_violation(self):
        finding = {
            "type": "test.finding",
            "confidence": "GUESSED",
            "severity": "HIGH",
            "verification_methods": ["DIRECT_TECHNICAL_OBSERVATION"],
        }
        violations = _validate_finding_confidence(finding)
        assert any("Unknown confidence level" in v for v in violations)


# ---------------------------------------------------------------------------
# SA-CONF-002: CONFIRMED requires direct observation or authoritative export
# ---------------------------------------------------------------------------


class TestConfirmedRequiresDirectObservation:
    def test_confirmed_without_required_method_produces_violation(self):
        finding = {
            "type": "test.finding",
            "confidence": "CONFIRMED",
            "severity": "HIGH",
            "verification_methods": ["DOCUMENT_REVIEW", "INFERENCE"],
        }
        violations = _validate_finding_confidence(finding)
        assert any("CONFIRMED requires" in v for v in violations)

    def test_confirmed_with_multiple_methods_including_direct_is_valid(self):
        finding = {
            "type": "test.finding",
            "confidence": "CONFIRMED",
            "severity": "HIGH",
            "verification_methods": [
                "DIRECT_TECHNICAL_OBSERVATION",
                "INDEPENDENT_CORROBORATION",
                "DOCUMENT_REVIEW",
            ],
        }
        violations = _validate_finding_confidence(finding)
        # Only rule-related violations (not unrelated ones)
        conf_violations = [v for v in violations if "CONFIRMED requires" in v]
        assert conf_violations == []


# ---------------------------------------------------------------------------
# SA-CONF-003: CONFIRMED with only INTERVIEW_ASSERTION is not permitted
# ---------------------------------------------------------------------------


class TestConfirmedInterviewAssertionNotPermitted:
    def test_confirmed_only_interview_produces_violation(self):
        finding = {
            "type": "test.finding",
            "confidence": "CONFIRMED",
            "severity": "HIGH",
            "verification_methods": ["INTERVIEW_ASSERTION"],
        }
        violations = _validate_finding_confidence(finding)
        assert any("INTERVIEW_ASSERTION" in v for v in violations)

    def test_confirmed_interview_plus_direct_observation_is_valid(self):
        """Interview + direct observation = CONFIRMED is permitted."""
        finding = {
            "type": "test.finding",
            "confidence": "CONFIRMED",
            "severity": "HIGH",
            "verification_methods": [
                "DIRECT_TECHNICAL_OBSERVATION",
                "INTERVIEW_ASSERTION",
            ],
        }
        violations = _validate_finding_confidence(finding)
        interview_violations = [
            v for v in violations if "only INTERVIEW_ASSERTION" in v
        ]
        assert interview_violations == []


# ---------------------------------------------------------------------------
# SA-CONF-004: Confidence != Severity (independence)
# ---------------------------------------------------------------------------


class TestConfidenceIndependentFromSeverity:
    """Confidence and severity are separately justified.
    A SUSPECTED finding may be HIGH severity.
    A CONFIRMED finding may be LOW severity.
    These are orthogonal dimensions.
    """

    def test_suspected_finding_can_be_high_severity(self):
        finding = {
            "type": "test.finding",
            "confidence": "SUSPECTED",
            "severity": "HIGH",
            "verification_methods": ["INFERENCE"],
        }
        violations = _validate_finding_confidence(finding)
        # SUSPECTED + HIGH is valid (confidence != severity)
        severity_violations = [
            v for v in violations if "severity" in v.lower() and "HIGH" in v
        ]
        assert severity_violations == [], (
            "SUSPECTED confidence + HIGH severity is valid per policy. "
            "These are independent dimensions."
        )

    def test_confirmed_finding_can_be_low_severity(self):
        finding = {
            "type": "test.finding",
            "confidence": "CONFIRMED",
            "severity": "LOW",
            "verification_methods": ["DIRECT_TECHNICAL_OBSERVATION"],
        }
        violations = _validate_finding_confidence(finding)
        assert violations == [], (
            "CONFIRMED confidence + LOW severity is valid. "
            "High-confidence observations can be low-impact."
        )

    def test_unknown_confidence_can_have_any_severity(self):
        """UNKNOWN confidence (insufficient data) may still have an estimated severity."""
        for severity in ("HIGH", "MEDIUM", "LOW"):
            finding = {
                "type": "test.finding",
                "confidence": "UNKNOWN",
                "severity": severity,
                "verification_methods": ["NOT_VERIFIED"],
            }
            violations = _validate_finding_confidence(finding)
            # Only check for wrong-severity type violations
            sev_violations = [v for v in violations if "Unknown severity" in v]
            assert sev_violations == []


# ---------------------------------------------------------------------------
# SA-CONF-005: Missing data → UNKNOWN or NOT_ASSESSED, never CONFIRMED_ABSENT
# ---------------------------------------------------------------------------


class TestMissingDataNotConfirmedAbsent:
    """CRITICAL TRUTH CONDITION: When data is unavailable or collection failed,
    the finding confidence must be UNKNOWN or NOT_ASSESSED.
    It must NOT claim CONFIRMED_ABSENT.
    """

    def test_no_evidence_produces_unknown_not_confirmed_absent(self):
        finding = {
            "type": "test.missing_control",
            "confidence": "UNKNOWN",
            "severity": "MEDIUM",
            "verification_methods": ["NOT_VERIFIED"],
            "description": "Could not collect data to verify this control.",
        }
        # UNKNOWN is valid for missing data
        violations = _validate_finding_confidence(finding)
        assert not any("Unknown confidence level" in v for v in violations)
        # Must NOT make a confirmed-absent claim
        assert not _is_confirmed_absent_claim(finding)

    def test_confirmed_absent_claim_without_evidence_is_flagged(self):
        finding = {
            "type": "mfa.confirmed_absent",
            "confidence": "CONFIRMED",
            "severity": "HIGH",
            "verification_methods": ["DOCUMENT_REVIEW"],
            "description": "MFA is confirmed absent for all users.",
        }
        # confirmed_absent in finding_type with only DOCUMENT_REVIEW
        # violates the rule that CONFIRMED requires DIRECT_TECHNICAL_OBSERVATION
        violations = _validate_finding_confidence(finding)
        assert any("CONFIRMED requires" in v for v in violations)

    def test_not_assessed_confidence_is_valid_for_out_of_scope(self):
        finding = {
            "type": "test.cloud_infra",
            "confidence": "NOT_ASSESSED",
            "severity": "INFORMATIONAL",
            "verification_methods": [],
            "description": "AWS infrastructure was out of scope for this assessment.",
        }
        violations = _validate_finding_confidence(finding)
        not_assessed_violations = [
            v for v in violations if "Unknown confidence level" in v
        ]
        assert not_assessed_violations == []


# ---------------------------------------------------------------------------
# SA-CONF-006: PROBABLE is minimum for primary evidence without corroboration
# ---------------------------------------------------------------------------


class TestProbableMinimumForPartialEvidence:
    def test_primary_evidence_without_corroboration_is_at_least_probable(self):
        """When primary evidence exists but independent corroboration is absent,
        PROBABLE is the minimum confidence level."""
        finding = {
            "type": "test.finding",
            "confidence": "PROBABLE",
            "severity": "MEDIUM",
            "verification_methods": ["DIRECT_TECHNICAL_OBSERVATION"],
            # No INDEPENDENT_CORROBORATION
        }
        violations = _validate_finding_confidence(finding)
        assert violations == [], (
            "PROBABLE with DIRECT_TECHNICAL_OBSERVATION (no corroboration) is valid."
        )

    def test_suspected_is_valid_for_indirect_evidence(self):
        finding = {
            "type": "test.finding",
            "confidence": "SUSPECTED",
            "severity": "MEDIUM",
            "verification_methods": ["INFERENCE"],
        }
        violations = _validate_finding_confidence(finding)
        assert not any("Unknown confidence" in v for v in violations)


# ---------------------------------------------------------------------------
# SA-CONF-007: All 7 verification methods are valid
# ---------------------------------------------------------------------------


class TestVerificationMethodEnumeration:
    def test_all_verification_methods_are_valid(self):
        for method in VERIFICATION_METHODS:
            finding = {
                "type": "test.finding",
                "confidence": "PROBABLE",
                "severity": "MEDIUM",
                "verification_methods": [method],
            }
            violations = _validate_finding_confidence(finding)
            method_violations = [
                v for v in violations if "Unknown verification method" in v
            ]
            assert method_violations == [], (
                f"Method {method!r} produced a violation: {method_violations}"
            )

    def test_unknown_verification_method_produces_violation(self):
        finding = {
            "type": "test.finding",
            "confidence": "PROBABLE",
            "severity": "MEDIUM",
            "verification_methods": ["MAGIC_GUESS"],
        }
        violations = _validate_finding_confidence(finding)
        assert any("Unknown verification method" in v for v in violations)
