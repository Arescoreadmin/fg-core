"""Tests for the claim-level epistemic determination authority (FGA-026).

Covers:
  - All six EpistemicState values across the required matrix
  - Fail-closed invariants (malformed/missing freshness, empty evidence)
  - Order invariance (sort by evidence_id before processing)
  - Contradiction detection logic
  - Staleness thresholds
  - assess_report_epistemic_states() convenience wrapper
  - confidence.py _FAIL_CLOSED_AGE_DAYS sentinel behavior
"""

from __future__ import annotations

import pytest

from services.field_assessment.confidence import (
    _FAIL_CLOSED_AGE_DAYS,
    degrade_confidence,
    evidence_age_days,
)
from services.governance.report.epistemic import (
    EpistemicState,
    assess_report_epistemic_states,
    determine_epistemic_state,
)
from services.governance.report.models import (
    ConfidenceScore,
    EvidenceRef,
    GovernanceFinding,
    GovernanceReport,
    ValidationState,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ref(
    eid: str,
    state: ValidationState = ValidationState.VALIDATED,
    freshness_days: int | None = 10,
    source: str = "scanner_a",
) -> EvidenceRef:
    return EvidenceRef(
        evidence_id=eid,
        source=source,
        validation_state=state,
        classification="scan_result",
        provenance="test",
        freshness_days=freshness_days,
    )


def _make_report(findings: tuple[GovernanceFinding, ...]) -> GovernanceReport:
    return GovernanceReport(
        report_id="rpt-001",
        assessment_id="asmt-001",
        tenant_id="tenant-001",
        version=1,
        generated_at="2026-09-09T00:00:00+00:00",
        findings=findings,
        remediations=(),
        evidence_appendix=(),
        framework_summary={},
        confidence=ConfidenceScore(
            overall=0.5,
            evidence_completeness=0.5,
            evidence_freshness=0.5,
            control_coverage=0.5,
            reviewer_validated=False,
            degradation_reasons=(),
        ),
        manifest_hash="abc123",
        schema_version="1.0",
    )


def _make_finding(finding_id: str, evidence_ids: tuple[str, ...]) -> GovernanceFinding:
    return GovernanceFinding(
        finding_id=finding_id,
        control_id="security_posture",
        domain="security_posture",
        severity="high",
        confidence=0.8,
        evidence_ids=evidence_ids,
        framework_mappings=(),
        remediation_id="rem-001",
        gap_classification="high_gap",
        description="Test finding",
    )


# ---------------------------------------------------------------------------
# 1. NOT_PROVEN — empty evidence body
# ---------------------------------------------------------------------------


def test_not_proven_empty_evidence():
    det = determine_epistemic_state(evidence_refs=[], has_adverse_finding=False)
    assert det.state == EpistemicState.NOT_PROVEN
    assert "no_evidence" in det.reason_codes
    assert det.evidence_ids == ()
    assert "evidence_required" in det.missing_requirements
    assert det.methodology_version == "1.0"


def test_not_proven_only_missing_refs():
    refs = [_ref("e1", ValidationState.MISSING, freshness_days=None)]
    det = determine_epistemic_state(refs)
    # MISSING refs = all invalid, zero fresh_validated → STALE path?
    # No: MISSING has no freshness claim; _is_stale checks non-MISSING only.
    # all fresh_validated = [] → STALE (not NOT_PROVEN, since refs exist).
    # But invalid_ids has e1, stale_ids is empty (MISSING excluded).
    assert det.state == EpistemicState.STALE
    assert det.invalid_evidence_ids == ("e1",)
    assert det.stale_evidence_ids == ()


def test_not_proven_empty_is_never_verified_effective():
    det = determine_epistemic_state(evidence_refs=[], has_adverse_finding=False)
    assert det.state != EpistemicState.VERIFIED_EFFECTIVE


def test_not_proven_empty_is_never_verified_deficient():
    det = determine_epistemic_state(evidence_refs=[], has_adverse_finding=True)
    assert det.state == EpistemicState.NOT_PROVEN


# ---------------------------------------------------------------------------
# 2. CONTRADICTORY — same source: VALIDATED + PENDING or MISSING
# ---------------------------------------------------------------------------


def test_contradictory_validated_plus_pending():
    refs = [
        _ref("e1", ValidationState.VALIDATED, freshness_days=5, source="src_x"),
        _ref("e2", ValidationState.PENDING, freshness_days=5, source="src_x"),
    ]
    det = determine_epistemic_state(refs)
    assert det.state == EpistemicState.CONTRADICTORY
    assert "source_conflict:src_x" in det.reason_codes
    assert "e1" in det.contradictory_evidence_ids
    assert "e2" in det.contradictory_evidence_ids


def test_contradictory_validated_plus_missing():
    refs = [
        _ref("e1", ValidationState.VALIDATED, freshness_days=5, source="audit_log"),
        _ref("e2", ValidationState.MISSING, freshness_days=None, source="audit_log"),
    ]
    det = determine_epistemic_state(refs)
    assert det.state == EpistemicState.CONTRADICTORY
    assert "source_conflict:audit_log" in det.reason_codes
    assert set(det.contradictory_evidence_ids) == {"e1", "e2"}


def test_contradictory_multiple_conflicting_sources():
    refs = [
        _ref("e1", ValidationState.VALIDATED, freshness_days=5, source="src_a"),
        _ref("e2", ValidationState.MISSING, freshness_days=None, source="src_a"),
        _ref("e3", ValidationState.VALIDATED, freshness_days=5, source="src_b"),
        _ref("e4", ValidationState.PENDING, freshness_days=5, source="src_b"),
    ]
    det = determine_epistemic_state(refs)
    assert det.state == EpistemicState.CONTRADICTORY
    assert "source_conflict:src_a" in det.reason_codes
    assert "source_conflict:src_b" in det.reason_codes


def test_contradictory_checked_before_stale():
    # All refs are stale AND from a contradictory source — CONTRADICTORY wins
    refs = [
        _ref("e1", ValidationState.VALIDATED, freshness_days=200, source="src_y"),
        _ref("e2", ValidationState.PENDING, freshness_days=200, source="src_y"),
    ]
    det = determine_epistemic_state(refs, stale_threshold_days=90)
    assert det.state == EpistemicState.CONTRADICTORY


def test_different_sources_no_contradiction():
    refs = [
        _ref("e1", ValidationState.VALIDATED, freshness_days=5, source="src_a"),
        _ref("e2", ValidationState.PENDING, freshness_days=5, source="src_b"),
    ]
    det = determine_epistemic_state(refs)
    assert det.state != EpistemicState.CONTRADICTORY


# ---------------------------------------------------------------------------
# 3. STALE — evidence exists but none is fresh-validated
# ---------------------------------------------------------------------------


def test_stale_all_validated_but_aged():
    refs = [
        _ref("e1", ValidationState.VALIDATED, freshness_days=100),
        _ref("e2", ValidationState.VALIDATED, freshness_days=95),
    ]
    det = determine_epistemic_state(refs, stale_threshold_days=90)
    assert det.state == EpistemicState.STALE
    assert "all_evidence_stale" in det.reason_codes
    assert set(det.stale_evidence_ids) == {"e1", "e2"}


def test_stale_unknown_freshness_treated_as_stale():
    # freshness_days=None → fail-closed → treated as stale
    refs = [
        _ref("e1", ValidationState.VALIDATED, freshness_days=None),
    ]
    det = determine_epistemic_state(refs)
    assert det.state == EpistemicState.STALE
    assert "freshness_unknown" in det.reason_codes
    assert "e1" in det.stale_evidence_ids


def test_stale_pending_with_unknown_freshness():
    refs = [
        _ref("e1", ValidationState.PENDING, freshness_days=None),
        _ref("e2", ValidationState.PENDING, freshness_days=200),
    ]
    det = determine_epistemic_state(refs, stale_threshold_days=90)
    assert det.state == EpistemicState.STALE


def test_stale_never_verified_effective():
    refs = [_ref("e1", ValidationState.VALIDATED, freshness_days=None)]
    det = determine_epistemic_state(refs, has_adverse_finding=False)
    assert det.state != EpistemicState.VERIFIED_EFFECTIVE


# ---------------------------------------------------------------------------
# 4. PARTIALLY_SUPPORTED — some fresh-validated, some not
# ---------------------------------------------------------------------------


def test_partially_supported_some_pending():
    refs = [
        _ref("e1", ValidationState.VALIDATED, freshness_days=10),
        _ref("e2", ValidationState.PENDING, freshness_days=10, source="src_b"),
    ]
    det = determine_epistemic_state(refs)
    assert det.state == EpistemicState.PARTIALLY_SUPPORTED
    assert "partial_validation" in det.reason_codes
    assert "e2" in det.missing_requirements


def test_partially_supported_some_missing():
    refs = [
        _ref("e1", ValidationState.VALIDATED, freshness_days=10),
        _ref("e2", ValidationState.MISSING, freshness_days=None, source="src_b"),
    ]
    det = determine_epistemic_state(refs)
    assert det.state == EpistemicState.PARTIALLY_SUPPORTED
    assert f"missing_refs:{1}" in det.reason_codes
    assert "e2" in det.invalid_evidence_ids


def test_partially_supported_some_stale_validated():
    refs = [
        _ref("e1", ValidationState.VALIDATED, freshness_days=10),
        _ref("e2", ValidationState.VALIDATED, freshness_days=200),
    ]
    det = determine_epistemic_state(refs, stale_threshold_days=90)
    assert det.state == EpistemicState.PARTIALLY_SUPPORTED
    assert f"stale_refs:{1}" in det.reason_codes
    assert "e2" in det.stale_evidence_ids


def test_partially_supported_missing_requirements_excludes_validated():
    refs = [
        _ref("e1", ValidationState.VALIDATED, freshness_days=10),
        _ref("e2", ValidationState.PENDING, freshness_days=10, source="src_b"),
        _ref("e3", ValidationState.MISSING, freshness_days=None, source="src_c"),
    ]
    det = determine_epistemic_state(refs)
    assert det.state == EpistemicState.PARTIALLY_SUPPORTED
    assert "e1" not in det.missing_requirements
    assert "e2" in det.missing_requirements
    assert "e3" in det.missing_requirements


# ---------------------------------------------------------------------------
# 5. VERIFIED_DEFICIENT — all fresh-validated + adverse finding active
# ---------------------------------------------------------------------------


def test_verified_deficient_all_fresh_with_adverse_finding():
    refs = [
        _ref("e1", ValidationState.VALIDATED, freshness_days=5),
        _ref("e2", ValidationState.VALIDATED, freshness_days=10),
    ]
    det = determine_epistemic_state(refs, has_adverse_finding=True)
    assert det.state == EpistemicState.VERIFIED_DEFICIENT
    assert "adverse_finding_active" in det.reason_codes
    assert det.stale_evidence_ids == ()
    assert det.contradictory_evidence_ids == ()
    assert det.missing_requirements == ()


def test_verified_deficient_single_fresh_validated():
    refs = [_ref("e1", ValidationState.VALIDATED, freshness_days=1)]
    det = determine_epistemic_state(refs, has_adverse_finding=True)
    assert det.state == EpistemicState.VERIFIED_DEFICIENT


# ---------------------------------------------------------------------------
# 6. VERIFIED_EFFECTIVE — all fresh-validated + no adverse finding
# ---------------------------------------------------------------------------


def test_verified_effective_all_fresh_no_adverse():
    refs = [
        _ref("e1", ValidationState.VALIDATED, freshness_days=5),
        _ref("e2", ValidationState.VALIDATED, freshness_days=10),
    ]
    det = determine_epistemic_state(refs, has_adverse_finding=False)
    assert det.state == EpistemicState.VERIFIED_EFFECTIVE
    assert "all_validated_fresh" in det.reason_codes
    assert det.stale_evidence_ids == ()
    assert det.contradictory_evidence_ids == ()
    assert det.missing_requirements == ()


def test_verified_effective_exactly_at_threshold():
    refs = [_ref("e1", ValidationState.VALIDATED, freshness_days=90)]
    det = determine_epistemic_state(
        refs, stale_threshold_days=90, has_adverse_finding=False
    )
    assert det.state == EpistemicState.VERIFIED_EFFECTIVE


def test_verified_effective_one_past_threshold_is_stale():
    refs = [_ref("e1", ValidationState.VALIDATED, freshness_days=91)]
    det = determine_epistemic_state(
        refs, stale_threshold_days=90, has_adverse_finding=False
    )
    assert det.state == EpistemicState.STALE


# ---------------------------------------------------------------------------
# 7. Fail-closed malformed timestamp invariants (confidence.py)
# ---------------------------------------------------------------------------


def test_fail_closed_age_days_constant_exceeds_max_threshold():
    # _FAIL_CLOSED_AGE_DAYS must be > 90 so max decay is always applied
    assert _FAIL_CLOSED_AGE_DAYS > 90


def test_malformed_date_returns_fail_closed_sentinel():
    assert evidence_age_days("not-a-date") == _FAIL_CLOSED_AGE_DAYS
    assert evidence_age_days("") == _FAIL_CLOSED_AGE_DAYS
    assert evidence_age_days(None) == _FAIL_CLOSED_AGE_DAYS  # type: ignore[arg-type]


def test_malformed_date_cannot_improve_confidence():
    base = 80
    # Malformed date → age = _FAIL_CLOSED_AGE_DAYS (91) → max decay (-30)
    effective = degrade_confidence(base, "bad-timestamp")
    fresh_effective = degrade_confidence(base, "2026-09-08T00:00:00+00:00")
    # Malformed must not produce a higher score than a fresh timestamp
    assert effective <= fresh_effective


def test_malformed_date_applies_max_decay():
    base = 80
    effective = degrade_confidence(base, "bad-timestamp")
    # _DECAY_BEYOND_90 = 30; floor = 30 → 80-30 = 50
    assert effective == 50


def test_malformed_date_deterministic_across_replay():
    result_a = evidence_age_days("garbage")
    result_b = evidence_age_days("garbage")
    assert result_a == result_b == _FAIL_CLOSED_AGE_DAYS


# ---------------------------------------------------------------------------
# 8. Fail-closed malformed freshness_days in epistemic determination
# ---------------------------------------------------------------------------


def test_malformed_freshness_cannot_produce_verified_effective():
    refs = [_ref("e1", ValidationState.VALIDATED, freshness_days=None)]
    det = determine_epistemic_state(refs, has_adverse_finding=False)
    assert det.state != EpistemicState.VERIFIED_EFFECTIVE


def test_malformed_freshness_cannot_be_treated_as_current():
    refs = [_ref("e1", ValidationState.VALIDATED, freshness_days=None)]
    det = determine_epistemic_state(refs)
    assert det.state == EpistemicState.STALE
    assert "e1" in det.stale_evidence_ids


# ---------------------------------------------------------------------------
# 9. Order invariance
# ---------------------------------------------------------------------------


def test_order_invariance_different_input_order_same_result():
    refs_asc = [
        _ref("e1", ValidationState.VALIDATED, freshness_days=5, source="src_a"),
        _ref("e2", ValidationState.PENDING, freshness_days=5, source="src_b"),
    ]
    refs_desc = list(reversed(refs_asc))
    det_a = determine_epistemic_state(refs_asc)
    det_b = determine_epistemic_state(refs_desc)
    assert det_a == det_b


def test_order_invariance_evidence_ids_sorted():
    refs = [
        _ref("zzz", ValidationState.VALIDATED, freshness_days=5),
        _ref("aaa", ValidationState.VALIDATED, freshness_days=5),
    ]
    det = determine_epistemic_state(refs, has_adverse_finding=False)
    assert det.evidence_ids == ("aaa", "zzz")


# ---------------------------------------------------------------------------
# 10. assess_report_epistemic_states — batch wrapper
# ---------------------------------------------------------------------------


def test_assess_report_empty_findings():
    report = _make_report(findings=())
    result = assess_report_epistemic_states(report=report, evidence_refs=[])
    assert result == {}


def test_assess_report_finding_with_no_evidence_is_not_proven():
    finding = _make_finding("f1", evidence_ids=())
    report = _make_report(findings=(finding,))
    result = assess_report_epistemic_states(report=report, evidence_refs=[])
    assert result["f1"].state == EpistemicState.NOT_PROVEN


def test_assess_report_all_findings_have_entries():
    f1 = _make_finding("f1", ("e1",))
    f2 = _make_finding("f2", ("e2",))
    report = _make_report(findings=(f1, f2))
    refs = [
        _ref("e1", ValidationState.VALIDATED, freshness_days=5),
        _ref("e2", ValidationState.VALIDATED, freshness_days=5),
    ]
    result = assess_report_epistemic_states(report=report, evidence_refs=refs)
    assert set(result.keys()) == {"f1", "f2"}
    assert result["f1"].state == EpistemicState.VERIFIED_DEFICIENT
    assert result["f2"].state == EpistemicState.VERIFIED_DEFICIENT


def test_assess_report_has_adverse_finding_always_true():
    # All findings in a report are adverse (domain score < 60) by engine contract.
    # assess_report_epistemic_states must pass has_adverse_finding=True.
    finding = _make_finding("f1", ("e1",))
    report = _make_report(findings=(finding,))
    refs = [_ref("e1", ValidationState.VALIDATED, freshness_days=5)]
    result = assess_report_epistemic_states(report=report, evidence_refs=refs)
    # With fresh-validated evidence and an adverse finding → VERIFIED_DEFICIENT
    assert result["f1"].state == EpistemicState.VERIFIED_DEFICIENT


def test_assess_report_evidence_ids_not_in_report_refs_ignored():
    finding = _make_finding("f1", ("e1",))
    report = _make_report(findings=(finding,))
    # e2 exists in refs but is not in finding.evidence_ids
    refs = [
        _ref("e1", ValidationState.VALIDATED, freshness_days=5),
        _ref("e2", ValidationState.VALIDATED, freshness_days=5),
    ]
    result = assess_report_epistemic_states(report=report, evidence_refs=refs)
    assert result["f1"].evidence_ids == ("e1",)


# ---------------------------------------------------------------------------
# 11. EpistemicDetermination is frozen (immutable)
# ---------------------------------------------------------------------------


def test_epistemic_determination_is_frozen():
    import dataclasses

    det = determine_epistemic_state(evidence_refs=[])
    with pytest.raises(dataclasses.FrozenInstanceError):
        det.state = EpistemicState.VERIFIED_EFFECTIVE  # type: ignore[misc]


# ---------------------------------------------------------------------------
# 12. methodology_version propagates through all states
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "refs,has_adverse",
    [
        ([], False),
        ([_ref("e1", ValidationState.MISSING, freshness_days=None)], False),
        ([_ref("e1", ValidationState.VALIDATED, freshness_days=200)], False),
        (
            [
                _ref("e1", ValidationState.VALIDATED, freshness_days=5),
                _ref("e2", ValidationState.PENDING, freshness_days=5, source="src_b"),
            ],
            False,
        ),
        ([_ref("e1", ValidationState.VALIDATED, freshness_days=5)], True),
        ([_ref("e1", ValidationState.VALIDATED, freshness_days=5)], False),
    ],
)
def test_methodology_version_always_present(refs, has_adverse):
    det = determine_epistemic_state(refs, has_adverse_finding=has_adverse)
    assert det.methodology_version == "1.0"
