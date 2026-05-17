"""Tests for the Enterprise Gap Analysis & Remediation Prioritization Engine.

No database. No I/O. Pure Python deterministic contracts.

Test categories:
- Enum value stability
- Model immutability (frozen dataclasses)
- Metadata dict immutability (MappingProxyType)
- Missing control detection
- Weak / failed control detection
- Stale evidence detection and gap conversion
- Threshold gap detection
- Incomplete assessment gap
- Dependency cycle detection
- Dependency chain building
- Readiness blocker detection
- Maturity blocker detection
- Gap prioritization (deterministic ordering)
- Governance override application
- Readiness impact estimation
- Remediation recommendation building
- Compensating control handling
- Policy exception handling
- Tenant isolation (engine validation)
- Framework isolation (engine validation)
- Full engine integration (GapAnalysisEngine.analyze)
- Integrity hashing (compute / replay / verify)
- GapReplayContract version pins
- Deterministic tie-breaking
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from services.readiness.gap_analysis import (
    _ANALYSIS_VERSION,
    CompensatingControl,
    EvidenceFreshnessRecord,
    ExceptionType,
    GapAnalysisEngine,
    GapAnalysisFrameworkMismatchError,
    GapAnalysisInput,
    GapAnalysisTenantIsolationError,
    GapClassification,
    GapDependency,
    GapDependencyType,
    GapSeverity,
    GovernanceOverride,
    OverrideType,
    PolicyException,
    ReadinessGap,
    ReadinessImpactEstimate,
    RemediationIntegrityRecord,
    build_dependency_chains,
    build_maturity_blockers,
    build_readiness_blockers,
    build_remediation_recommendations,
    compute_gap_analysis_hash,
    detect_cycles_in_dependencies,
    detect_incomplete_assessment_gap,
    detect_missing_controls,
    detect_stale_evidence,
    detect_threshold_gaps,
    detect_weak_controls,
    estimate_readiness_impact,
    prioritize_gaps,
    replay_gap_analysis_hash,
    stale_evidence_to_gaps,
    verify_gap_analysis_hash,
)
from services.readiness.models import (
    Assessment,
    AssessmentOutcome,
    AssessmentResult,
    AssessmentStatus,
    Control,
    Domain,
    EvidenceReference,
    EvidenceType,
    Framework,
    FrameworkStatus,
)
from services.readiness.scoring.models import (
    CompletionState,
    ControlScore,
    DomainScore,
    RemediationPriority,
    RiskLevel,
    ScoreOutput,
    ThresholdFailure,
)

# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

_TENANT = "tenant-abc"
_OTHER_TENANT = "tenant-xyz"
_FW_ID = "fw-nist-001"
_FW_VER = "1.0"
_DOMAIN_ID = "domain-001"
_CTRL_A = "ctrl-a"
_CTRL_B = "ctrl-b"
_CTRL_C = "ctrl-c"
_CTRL_D = "ctrl-d"
_NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
_PAST_30 = _NOW - timedelta(days=30)
_PAST_100 = _NOW - timedelta(days=100)


# ---------------------------------------------------------------------------
# Shared fixture builders
# ---------------------------------------------------------------------------


def _make_framework(
    framework_id: str = _FW_ID,
    framework_version: str = _FW_VER,
    tenant_id: str | None = None,
) -> Framework:
    return Framework(
        framework_id=framework_id,
        framework_name="NIST AI RMF",
        framework_slug="nist-ai-rmf",
        framework_version=framework_version,
        framework_status=FrameworkStatus.ACTIVE,
        created_by="system",
        created_at=_NOW,
        updated_at=_NOW,
        tenant_id=tenant_id,
    )


def _make_domain(domain_id: str = _DOMAIN_ID) -> Domain:
    return Domain(
        domain_id=domain_id,
        framework_id=_FW_ID,
        domain_name="Governance",
        domain_slug="governance",
        domain_description="Governance domain",
        domain_order=1,
        created_by="system",
        created_at=_NOW,
    )


def _make_control(
    control_id: str = _CTRL_A,
    control_identifier: str = "GV-1",
    domain_id: str = _DOMAIN_ID,
) -> Control:
    return Control(
        control_id=control_id,
        framework_id=_FW_ID,
        domain_id=domain_id,
        control_identifier=control_identifier,
        control_name=f"Control {control_identifier}",
        control_description="Test control",
        created_by="system",
        created_at=_NOW,
    )


def _make_assessment(tenant_id: str = _TENANT) -> Assessment:
    return Assessment(
        assessment_id="assess-001",
        tenant_id=tenant_id,
        framework_id=_FW_ID,
        framework_version_tag=_FW_VER,
        assessment_status=AssessmentStatus.ACTIVE,
        snapshot_version=1,
        created_by="test-actor",
        created_at=_NOW,
        updated_at=_NOW,
    )


def _make_result(
    control_id: str = _CTRL_A,
    outcome: AssessmentOutcome = AssessmentOutcome.COMPLIANT,
    tenant_id: str = _TENANT,
) -> AssessmentResult:
    return AssessmentResult(
        result_id=f"res-{control_id}",
        assessment_id="assess-001",
        control_id=control_id,
        maturity_tier_id=None,
        outcome=outcome,
        actor="test-actor",
        timestamp=_NOW,
        tenant_id=tenant_id,
    )


def _make_evidence_ref(
    evidence_id: str = "ev-001",
    submitted_at: datetime = _PAST_30,
    control_ids: list[str] | None = None,
    tenant_id: str = _TENANT,
) -> EvidenceReference:
    return EvidenceReference(
        evidence_id=evidence_id,
        assessment_id="assess-001",
        evidence_type=EvidenceType.DOCUMENT,
        evidence_title="Test Evidence",
        submitted_by="test-actor",
        submitted_at=submitted_at,
        tenant_id=tenant_id,
        control_ids=control_ids or [_CTRL_A],
    )


def _make_control_score(
    control_id: str = _CTRL_A,
    control_identifier: str = "GV-1",
    domain_id: str = _DOMAIN_ID,
    outcome: AssessmentOutcome = AssessmentOutcome.COMPLIANT,
    raw_score: float = 100.0,
    weight: float = 1.0,
    is_evaluated: bool = True,
    is_applicable: bool = True,
    evidence_count: int = 1,
) -> ControlScore:
    return ControlScore(
        control_id=control_id,
        control_identifier=control_identifier,
        domain_id=domain_id,
        outcome=outcome,
        raw_score=raw_score,
        weight=weight,
        is_evaluated=is_evaluated,
        is_applicable=is_applicable,
        evidence_count=evidence_count,
    )


def _make_domain_score(
    domain_id: str = _DOMAIN_ID,
    raw_score: float = 100.0,
    threshold_failed: bool = False,
) -> DomainScore:
    return DomainScore(
        domain_id=domain_id,
        domain_name="Governance",
        raw_score=raw_score,
        normalized_score=raw_score / 100.0,
        weight=1.0,
        completion_percentage=100.0,
        missing_control_count=0,
        incomplete_control_count=0,
        failed_control_count=0,
        risk_classification=RiskLevel.MINIMAL,
        threshold_failed=threshold_failed,
    )


def _make_score_output(
    overall_score: float = 100.0,
    control_scores: dict[str, ControlScore] | None = None,
    domain_scores: dict[str, DomainScore] | None = None,
    missing_controls: tuple[str, ...] = (),
    incomplete_controls: tuple[str, ...] = (),
    failed_controls: tuple[str, ...] = (),
    not_applicable_controls: tuple[str, ...] = (),
    threshold_failures: tuple[ThresholdFailure, ...] = (),
    completion_percentage: float = 100.0,
    maturity_tier_id: str | None = "tier-001",
    tenant_id: str = _TENANT,
) -> ScoreOutput:
    cs = control_scores or {_CTRL_A: _make_control_score()}
    ds = domain_scores or {_DOMAIN_ID: _make_domain_score()}
    return ScoreOutput(
        assessment_id="assess-001",
        tenant_id=tenant_id,
        framework_id=_FW_ID,
        framework_version_tag=_FW_VER,
        overall_score=overall_score,
        normalized_score=overall_score / 100.0,
        domain_scores=ds,
        control_scores=cs,
        maturity_tier="Tier 1",
        maturity_tier_id=maturity_tier_id,
        risk_classification=RiskLevel.MINIMAL,
        remediation_priority=RemediationPriority.NOT_REQUIRED,
        remediation_factors=(),
        missing_controls=missing_controls,
        incomplete_controls=incomplete_controls,
        failed_controls=failed_controls,
        not_applicable_controls=not_applicable_controls,
        threshold_failures=threshold_failures,
        scoring_warnings=(),
        completion_state=CompletionState.COMPLETE,
        completion_percentage=completion_percentage,
        is_complete=completion_percentage >= 100.0,
        computed_at=_NOW,
        score_version="1.0.0",
    )


def _make_gap_analysis_input(
    controls: tuple[Control, ...] | None = None,
    results: tuple[AssessmentResult, ...] | None = None,
    evidence_refs: tuple[EvidenceReference, ...] | None = None,
    score_output: ScoreOutput | None = None,
    critical_control_ids: frozenset[str] = frozenset(),
    required_control_ids: frozenset[str] = frozenset(),
    default_freshness_window_days: int = 90,
    gap_dependencies: tuple[GapDependency, ...] = (),
    policy_exceptions: tuple[PolicyException, ...] = (),
    compensating_controls: tuple[CompensatingControl, ...] = (),
    governance_overrides: tuple[GovernanceOverride, ...] = (),
    tenant_id: str = _TENANT,
) -> GapAnalysisInput:
    ctrls = controls or (_make_control(),)
    evid = evidence_refs or (_make_evidence_ref(),)
    res = results or (_make_result(),)
    so = score_output or _make_score_output()
    return GapAnalysisInput(
        assessment=_make_assessment(tenant_id=tenant_id),
        framework=_make_framework(),
        controls=ctrls,
        domains=(_make_domain(),),
        maturity_tiers=(),
        results=res,
        evidence_refs=evid,
        score_output=so,
        critical_control_ids=critical_control_ids,
        required_control_ids=required_control_ids,
        default_freshness_window_days=default_freshness_window_days,
        gap_dependencies=gap_dependencies,
        policy_exceptions=policy_exceptions,
        compensating_controls=compensating_controls,
        governance_overrides=governance_overrides,
    )


def _run_engine(inp: GapAnalysisInput, result_id: str = "result-001") -> Any:
    return GapAnalysisEngine().analyze(inp, result_id=result_id, analyzed_at=_NOW)


# ---------------------------------------------------------------------------
# Enum value stability
# ---------------------------------------------------------------------------


def test_gap_severity_values_stable() -> None:
    assert GapSeverity.INFORMATIONAL.value == "informational"
    assert GapSeverity.LOW.value == "low"
    assert GapSeverity.MODERATE.value == "moderate"
    assert GapSeverity.HIGH.value == "high"
    assert GapSeverity.CRITICAL.value == "critical"
    assert GapSeverity.BLOCKING.value == "blocking"


def test_gap_classification_values_stable() -> None:
    assert GapClassification.MISSING_CONTROL.value == "missing_control"
    assert GapClassification.FAILED_CONTROL.value == "failed_control"
    assert GapClassification.WEAK_CONTROL.value == "weak_control"
    assert GapClassification.STALE_EVIDENCE.value == "stale_evidence"
    assert GapClassification.PARTIALLY_IMPLEMENTED.value == "partially_implemented"
    assert GapClassification.INCOMPLETE_ASSESSMENT.value == "incomplete_assessment"
    assert (
        GapClassification.MISSING_REQUIRED_EVIDENCE.value == "missing_required_evidence"
    )
    assert GapClassification.FAILED_MATURITY_GATE.value == "failed_maturity_gate"
    assert (
        GapClassification.FAILED_READINESS_THRESHOLD.value
        == "failed_readiness_threshold"
    )
    assert (
        GapClassification.FAILED_PREREQUISITE_CONTROL.value
        == "failed_prerequisite_control"
    )


def test_gap_dependency_type_values_stable() -> None:
    assert GapDependencyType.PREREQUISITE.value == "prerequisite"
    assert GapDependencyType.INHERITED.value == "inherited"
    assert GapDependencyType.FRAMEWORK_REQUIRED.value == "framework_required"


def test_exception_type_values_stable() -> None:
    assert ExceptionType.APPROVED_EXCEPTION.value == "approved_exception"
    assert ExceptionType.TEMPORARY_WAIVER.value == "temporary_waiver"
    assert ExceptionType.COMPENSATING_CONTROL.value == "compensating_control"
    assert ExceptionType.JURISDICTIONAL.value == "jurisdictional"
    assert ExceptionType.CONTRACTUAL.value == "contractual"
    assert ExceptionType.REGULATORY.value == "regulatory"


def test_override_type_values_stable() -> None:
    assert OverrideType.SEVERITY.value == "severity"
    assert OverrideType.REMEDIATION_PRIORITY.value == "remediation_priority"
    assert OverrideType.BLOCKER_CLASSIFICATION.value == "blocker_classification"
    assert OverrideType.MATURITY_IMPACT.value == "maturity_impact"
    assert OverrideType.READINESS_IMPACT.value == "readiness_impact"


# ---------------------------------------------------------------------------
# Model immutability
# ---------------------------------------------------------------------------


def _make_readiness_gap(
    gap_id: str = "gap-001",
    severity: GapSeverity = GapSeverity.HIGH,
    classification: GapClassification = GapClassification.MISSING_CONTROL,
) -> ReadinessGap:
    return ReadinessGap(
        gap_id=gap_id,
        gap_classification=classification,
        gap_severity=severity,
        framework_id=_FW_ID,
        framework_version=_FW_VER,
        gap_rationale="Test gap",
        detected_at=_NOW,
        is_blocker=True,
        is_maturity_blocker=False,
        affected_control_ids=(_CTRL_A,),
        affected_framework_ids=(_FW_ID,),
        evidence_ids=(),
        tenant_id=_TENANT,
    )


def test_readiness_gap_is_frozen() -> None:
    gap = _make_readiness_gap()
    with pytest.raises(Exception):
        gap.gap_severity = GapSeverity.LOW  # type: ignore[misc]


def test_evidence_freshness_record_is_frozen() -> None:
    rec = EvidenceFreshnessRecord(
        freshness_id="f-001",
        evidence_id="ev-001",
        control_id=_CTRL_A,
        framework_id=_FW_ID,
        framework_version=_FW_VER,
        submitted_at=_PAST_30,
        freshness_window_days=90,
        is_stale=False,
        staleness_days=None,
        evaluated_at=_NOW,
    )
    with pytest.raises(Exception):
        rec.is_stale = True  # type: ignore[misc]


def test_gap_analysis_result_is_frozen(tmp_path: Any) -> None:
    result = _run_engine(_make_gap_analysis_input())
    with pytest.raises(Exception):
        result.analysis_version = "tampered"  # type: ignore[misc]


def test_remediation_integrity_record_is_frozen() -> None:
    result = _run_engine(_make_gap_analysis_input())
    record = compute_gap_analysis_hash(result, computed_at=_NOW)
    with pytest.raises(Exception):
        record.hash_value = "tampered"  # type: ignore[misc]


def test_readiness_blocker_is_frozen() -> None:
    gap = _make_readiness_gap()
    blockers = build_readiness_blockers((gap,), tenant_id=_TENANT)
    assert len(blockers) == 1
    with pytest.raises(Exception):
        blockers[0].blocker_rationale = "tampered"  # type: ignore[misc]


def test_gap_replay_contract_is_frozen() -> None:
    result = _run_engine(_make_gap_analysis_input())
    with pytest.raises(Exception):
        result.replay_contract.framework_version = "tampered"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Metadata dict immutability (MappingProxyType)
# ---------------------------------------------------------------------------


def test_readiness_gap_metadata_is_read_only() -> None:
    gap = ReadinessGap(
        gap_id="g-001",
        gap_classification=GapClassification.MISSING_CONTROL,
        gap_severity=GapSeverity.HIGH,
        framework_id=_FW_ID,
        framework_version=_FW_VER,
        gap_rationale="test",
        detected_at=_NOW,
        is_blocker=False,
        is_maturity_blocker=False,
        affected_control_ids=(),
        affected_framework_ids=(),
        evidence_ids=(),
        gap_metadata={"key": "val"},
    )
    with pytest.raises(TypeError):
        gap.gap_metadata["key"] = "mutated"  # type: ignore[index]


def test_compensating_control_metadata_is_read_only() -> None:
    cc = CompensatingControl(
        compensating_id="cc-001",
        gap_id="g-001",
        mitigation_rationale="test",
        framework_applicability=(_FW_ID,),
        approved_by="governance",
        approved_at=_NOW,
        compensating_metadata={"k": "v"},
    )
    with pytest.raises(TypeError):
        cc.compensating_metadata["k"] = "mutated"  # type: ignore[index]


def test_governance_override_metadata_is_read_only() -> None:
    ov = GovernanceOverride(
        override_id="ov-001",
        gap_id="g-001",
        override_type=OverrideType.SEVERITY,
        original_value="high",
        overridden_value="moderate",
        override_authority="governance-board",
        override_rationale="test",
        approved_at=_NOW,
        override_metadata={"meta": "val"},
    )
    with pytest.raises(TypeError):
        ov.override_metadata["meta"] = "mutated"  # type: ignore[index]


def test_policy_exception_metadata_is_read_only() -> None:
    exc = PolicyException(
        exception_id="exc-001",
        exception_type=ExceptionType.APPROVED_EXCEPTION,
        exception_authority="CISO",
        approval_rationale="approved",
        affected_control_ids=(_CTRL_A,),
        affected_framework_ids=(_FW_ID,),
        approved_at=_NOW,
        exception_metadata={"k": "v"},
    )
    with pytest.raises(TypeError):
        exc.exception_metadata["k"] = "mutated"  # type: ignore[index]


def test_readiness_impact_estimate_domain_impact_is_read_only() -> None:
    est = ReadinessImpactEstimate(
        estimate_id="est-001",
        gap_id="g-001",
        maturity_impact=0.0,
        framework_impact=0.1,
        remediation_impact=0.1,
        governance_coverage_impact=0.0,
        domain_impact={"dom-001": 0.1},
        estimation_rationale="test",
    )
    with pytest.raises(TypeError):
        est.domain_impact["dom-001"] = 0.9  # type: ignore[index]


# ---------------------------------------------------------------------------
# Missing control detection
# ---------------------------------------------------------------------------


def test_detect_missing_controls_all_missing() -> None:
    controls = (
        _make_control(_CTRL_A, "GV-1"),
        _make_control(_CTRL_B, "GV-2"),
    )
    gaps = detect_missing_controls(
        controls,
        frozenset(),
        critical_control_ids=frozenset(),
        required_control_ids=frozenset(),
        framework_id=_FW_ID,
        framework_version=_FW_VER,
        tenant_id=_TENANT,
        detected_at=_NOW,
    )
    assert len(gaps) == 2
    assert all(g.gap_classification == GapClassification.MISSING_CONTROL for g in gaps)


def test_detect_missing_controls_evaluated_excluded() -> None:
    controls = (
        _make_control(_CTRL_A, "GV-1"),
        _make_control(_CTRL_B, "GV-2"),
    )
    gaps = detect_missing_controls(
        controls,
        frozenset({_CTRL_A}),
        critical_control_ids=frozenset(),
        required_control_ids=frozenset(),
        framework_id=_FW_ID,
        framework_version=_FW_VER,
        tenant_id=_TENANT,
        detected_at=_NOW,
    )
    assert len(gaps) == 1
    assert gaps[0].control_id == _CTRL_B


def test_detect_missing_critical_control_is_critical_and_blocker() -> None:
    controls = (_make_control(_CTRL_A, "GV-1"),)
    gaps = detect_missing_controls(
        controls,
        frozenset(),
        critical_control_ids=frozenset({_CTRL_A}),
        required_control_ids=frozenset(),
        framework_id=_FW_ID,
        framework_version=_FW_VER,
        tenant_id=_TENANT,
        detected_at=_NOW,
    )
    assert gaps[0].gap_severity == GapSeverity.CRITICAL
    assert gaps[0].is_blocker is True
    assert gaps[0].is_maturity_blocker is True


def test_detect_missing_required_control_is_high() -> None:
    controls = (_make_control(_CTRL_A, "GV-1"),)
    gaps = detect_missing_controls(
        controls,
        frozenset(),
        critical_control_ids=frozenset(),
        required_control_ids=frozenset({_CTRL_A}),
        framework_id=_FW_ID,
        framework_version=_FW_VER,
        tenant_id=_TENANT,
        detected_at=_NOW,
    )
    assert gaps[0].gap_severity == GapSeverity.HIGH
    assert gaps[0].is_blocker is True


def test_detect_missing_non_required_control_is_moderate() -> None:
    controls = (_make_control(_CTRL_A, "GV-1"),)
    gaps = detect_missing_controls(
        controls,
        frozenset(),
        critical_control_ids=frozenset(),
        required_control_ids=frozenset(),
        framework_id=_FW_ID,
        framework_version=_FW_VER,
        tenant_id=_TENANT,
        detected_at=_NOW,
    )
    assert gaps[0].gap_severity == GapSeverity.MODERATE
    assert gaps[0].is_blocker is False


def test_detect_missing_controls_gap_ids_deterministic() -> None:
    controls = (_make_control(_CTRL_A, "GV-1"),)
    gaps1 = detect_missing_controls(
        controls,
        frozenset(),
        critical_control_ids=frozenset(),
        required_control_ids=frozenset(),
        framework_id=_FW_ID,
        framework_version=_FW_VER,
        tenant_id=_TENANT,
        detected_at=_NOW,
    )
    gaps2 = detect_missing_controls(
        controls,
        frozenset(),
        critical_control_ids=frozenset(),
        required_control_ids=frozenset(),
        framework_id=_FW_ID,
        framework_version=_FW_VER,
        tenant_id=_TENANT,
        detected_at=_NOW,
    )
    assert gaps1[0].gap_id == gaps2[0].gap_id


# ---------------------------------------------------------------------------
# Weak / failed control detection
# ---------------------------------------------------------------------------


def test_detect_failed_control_is_high() -> None:
    cs = _make_control_score(outcome=AssessmentOutcome.NON_COMPLIANT, raw_score=0.0)
    gaps = detect_weak_controls(
        (cs,),
        weak_threshold=50.0,
        required_control_ids=frozenset(),
        critical_control_ids=frozenset(),
        framework_id=_FW_ID,
        framework_version=_FW_VER,
        tenant_id=_TENANT,
        detected_at=_NOW,
    )
    assert len(gaps) == 1
    assert gaps[0].gap_classification == GapClassification.FAILED_CONTROL
    assert gaps[0].gap_severity == GapSeverity.HIGH


def test_detect_critical_failed_control_is_critical() -> None:
    cs = _make_control_score(outcome=AssessmentOutcome.NON_COMPLIANT, raw_score=0.0)
    gaps = detect_weak_controls(
        (cs,),
        weak_threshold=50.0,
        required_control_ids=frozenset(),
        critical_control_ids=frozenset({_CTRL_A}),
        framework_id=_FW_ID,
        framework_version=_FW_VER,
        tenant_id=_TENANT,
        detected_at=_NOW,
    )
    assert gaps[0].gap_severity == GapSeverity.CRITICAL
    assert gaps[0].is_blocker is True


def test_detect_partial_control_is_partially_implemented() -> None:
    cs = _make_control_score(
        outcome=AssessmentOutcome.PARTIALLY_COMPLIANT, raw_score=50.0
    )
    gaps = detect_weak_controls(
        (cs,),
        weak_threshold=50.0,
        required_control_ids=frozenset(),
        critical_control_ids=frozenset(),
        framework_id=_FW_ID,
        framework_version=_FW_VER,
        tenant_id=_TENANT,
        detected_at=_NOW,
    )
    assert gaps[0].gap_classification == GapClassification.PARTIALLY_IMPLEMENTED
    assert gaps[0].gap_severity == GapSeverity.MODERATE


def test_detect_weak_score_below_threshold() -> None:
    cs = _make_control_score(outcome=AssessmentOutcome.COMPLIANT, raw_score=30.0)
    gaps = detect_weak_controls(
        (cs,),
        weak_threshold=50.0,
        required_control_ids=frozenset(),
        critical_control_ids=frozenset(),
        framework_id=_FW_ID,
        framework_version=_FW_VER,
        tenant_id=_TENANT,
        detected_at=_NOW,
    )
    assert gaps[0].gap_classification == GapClassification.WEAK_CONTROL
    assert gaps[0].gap_severity == GapSeverity.LOW


def test_not_applicable_control_excluded_from_weak_detection() -> None:
    cs = _make_control_score(
        outcome=AssessmentOutcome.NOT_APPLICABLE, raw_score=0.0, is_applicable=False
    )
    gaps = detect_weak_controls(
        (cs,),
        weak_threshold=50.0,
        required_control_ids=frozenset(),
        critical_control_ids=frozenset(),
        framework_id=_FW_ID,
        framework_version=_FW_VER,
        tenant_id=_TENANT,
        detected_at=_NOW,
    )
    assert len(gaps) == 0


# ---------------------------------------------------------------------------
# Stale evidence detection
# ---------------------------------------------------------------------------


def test_detect_stale_evidence_returns_record_for_all_refs() -> None:
    refs = (
        _make_evidence_ref("ev-1", _PAST_30),
        _make_evidence_ref("ev-2", _PAST_100),
    )
    records = detect_stale_evidence(
        refs,
        default_freshness_window_days=90,
        framework_id=_FW_ID,
        framework_version=_FW_VER,
        as_of=_NOW,
        tenant_id=_TENANT,
    )
    assert len(records) == 2


def test_detect_stale_evidence_fresh_is_not_stale() -> None:
    refs = (_make_evidence_ref("ev-1", _PAST_30),)
    records = detect_stale_evidence(
        refs,
        default_freshness_window_days=90,
        framework_id=_FW_ID,
        framework_version=_FW_VER,
        as_of=_NOW,
        tenant_id=_TENANT,
    )
    assert records[0].is_stale is False
    assert records[0].staleness_days is None


def test_detect_stale_evidence_past_window_is_stale() -> None:
    refs = (_make_evidence_ref("ev-1", _PAST_100),)
    records = detect_stale_evidence(
        refs,
        default_freshness_window_days=90,
        framework_id=_FW_ID,
        framework_version=_FW_VER,
        as_of=_NOW,
        tenant_id=_TENANT,
    )
    assert records[0].is_stale is True
    assert records[0].staleness_days == 10


def test_stale_evidence_to_gaps_only_stale_records_produce_gaps() -> None:
    refs = (
        _make_evidence_ref("ev-1", _PAST_30),
        _make_evidence_ref("ev-2", _PAST_100),
    )
    records = detect_stale_evidence(
        refs,
        default_freshness_window_days=90,
        framework_id=_FW_ID,
        framework_version=_FW_VER,
        as_of=_NOW,
        tenant_id=_TENANT,
    )
    gaps = stale_evidence_to_gaps(
        records, required_control_ids=frozenset(), detected_at=_NOW
    )
    assert len(gaps) == 1
    assert gaps[0].gap_classification == GapClassification.STALE_EVIDENCE


def test_stale_evidence_for_required_control_is_high() -> None:
    ref = _make_evidence_ref("ev-1", _PAST_100, control_ids=[_CTRL_A])
    records = detect_stale_evidence(
        (ref,),
        default_freshness_window_days=90,
        framework_id=_FW_ID,
        framework_version=_FW_VER,
        as_of=_NOW,
        tenant_id=_TENANT,
    )
    gaps = stale_evidence_to_gaps(
        records, required_control_ids=frozenset({_CTRL_A}), detected_at=_NOW
    )
    assert gaps[0].gap_severity == GapSeverity.HIGH


def test_per_evidence_freshness_window_override() -> None:
    ref = EvidenceReference(
        evidence_id="ev-1",
        assessment_id="assess-001",
        evidence_type=EvidenceType.DOCUMENT,
        evidence_title="Overridden window",
        submitted_by="actor",
        submitted_at=_PAST_30,
        tenant_id=_TENANT,
        evidence_source_metadata={"freshness_window_days": 10},
    )
    records = detect_stale_evidence(
        (ref,),
        default_freshness_window_days=90,
        framework_id=_FW_ID,
        framework_version=_FW_VER,
        as_of=_NOW,
        tenant_id=_TENANT,
    )
    assert records[0].freshness_window_days == 10
    assert records[0].is_stale is True


# ---------------------------------------------------------------------------
# Threshold gap detection
# ---------------------------------------------------------------------------


def test_detect_threshold_gaps_required_control_failure() -> None:
    failure = ThresholdFailure(
        threshold_type="required_control",
        threshold_name=_CTRL_A,
        required_value=100.0,
        actual_value=0.0,
        message=f"Required control {_CTRL_A} is non-compliant.",
    )
    gaps = detect_threshold_gaps(
        (failure,),
        (),
        framework_id=_FW_ID,
        framework_version=_FW_VER,
        tenant_id=_TENANT,
        detected_at=_NOW,
    )
    assert len(gaps) == 1
    assert gaps[0].gap_classification == GapClassification.FAILED_PREREQUISITE_CONTROL
    assert gaps[0].gap_severity == GapSeverity.CRITICAL
    assert gaps[0].is_blocker is True


def test_detect_threshold_gaps_maturity_gate() -> None:
    failure = ThresholdFailure(
        threshold_type="maturity_gate",
        threshold_name="tier-2",
        required_value=80.0,
        actual_value=65.0,
        message="Maturity gate not met.",
    )
    gaps = detect_threshold_gaps(
        (failure,),
        (),
        framework_id=_FW_ID,
        framework_version=_FW_VER,
        tenant_id=_TENANT,
        detected_at=_NOW,
    )
    assert gaps[0].gap_classification == GapClassification.FAILED_MATURITY_GATE
    assert gaps[0].is_maturity_blocker is True


def test_detect_threshold_gaps_overall_pass() -> None:
    failure = ThresholdFailure(
        threshold_type="overall_pass",
        threshold_name="overall",
        required_value=70.0,
        actual_value=60.0,
        message="Overall pass threshold not met.",
    )
    gaps = detect_threshold_gaps(
        (failure,),
        (),
        framework_id=_FW_ID,
        framework_version=_FW_VER,
        tenant_id=_TENANT,
        detected_at=_NOW,
    )
    assert gaps[0].gap_classification == GapClassification.FAILED_READINESS_THRESHOLD
    assert gaps[0].is_blocker is True


# ---------------------------------------------------------------------------
# Incomplete assessment gap
# ---------------------------------------------------------------------------


def test_detect_incomplete_assessment_gap_returns_gap_when_partial() -> None:
    gap = detect_incomplete_assessment_gap(
        75.0,
        framework_id=_FW_ID,
        framework_version=_FW_VER,
        tenant_id=_TENANT,
        assessment_id="assess-001",
        detected_at=_NOW,
    )
    assert gap is not None
    assert gap.gap_classification == GapClassification.INCOMPLETE_ASSESSMENT


def test_detect_incomplete_assessment_gap_returns_none_when_complete() -> None:
    gap = detect_incomplete_assessment_gap(
        100.0,
        framework_id=_FW_ID,
        framework_version=_FW_VER,
        tenant_id=_TENANT,
        assessment_id="assess-001",
        detected_at=_NOW,
    )
    assert gap is None


# ---------------------------------------------------------------------------
# Dependency cycle detection
# ---------------------------------------------------------------------------


def test_detect_cycles_empty_dependencies() -> None:
    assert detect_cycles_in_dependencies(()) == ()


def test_detect_cycles_no_cycle_linear_chain() -> None:
    deps = (
        GapDependency(
            dependency_id="d1",
            dependent_gap_id="gap-b",
            prerequisite_gap_id="gap-a",
            dependency_type=GapDependencyType.PREREQUISITE,
            dependency_rationale="B depends on A",
        ),
        GapDependency(
            dependency_id="d2",
            dependent_gap_id="gap-c",
            prerequisite_gap_id="gap-b",
            dependency_type=GapDependencyType.PREREQUISITE,
            dependency_rationale="C depends on B",
        ),
    )
    assert detect_cycles_in_dependencies(deps) == ()


def test_detect_cycles_simple_two_node_cycle() -> None:
    deps = (
        GapDependency(
            dependency_id="d1",
            dependent_gap_id="gap-b",
            prerequisite_gap_id="gap-a",
            dependency_type=GapDependencyType.PREREQUISITE,
            dependency_rationale="B depends on A",
        ),
        GapDependency(
            dependency_id="d2",
            dependent_gap_id="gap-a",
            prerequisite_gap_id="gap-b",
            dependency_type=GapDependencyType.PREREQUISITE,
            dependency_rationale="A depends on B (cycle)",
        ),
    )
    cycles = detect_cycles_in_dependencies(deps)
    assert len(cycles) > 0


def test_detect_cycles_three_node_cycle() -> None:
    deps = (
        GapDependency("d1", "gap-b", "gap-a", GapDependencyType.PREREQUISITE, "B→A"),
        GapDependency("d2", "gap-c", "gap-b", GapDependencyType.PREREQUISITE, "C→B"),
        GapDependency(
            "d3", "gap-a", "gap-c", GapDependencyType.PREREQUISITE, "A→C (cycle)"
        ),
    )
    cycles = detect_cycles_in_dependencies(deps)
    assert len(cycles) > 0


# ---------------------------------------------------------------------------
# Dependency chain building
# ---------------------------------------------------------------------------


def test_build_dependency_chains_linear_chain_ordered() -> None:
    gap_ids = frozenset({"gap-a", "gap-b", "gap-c"})
    deps = (
        GapDependency("d1", "gap-b", "gap-a", GapDependencyType.PREREQUISITE, "B→A"),
        GapDependency("d2", "gap-c", "gap-b", GapDependencyType.PREREQUISITE, "C→B"),
    )
    chains = build_dependency_chains(gap_ids, deps)
    assert len(chains) == 1
    chain = chains[0]
    assert chain.has_cycle is False
    ordered = chain.ordered_gap_ids
    # gap-a must come before gap-b; gap-b before gap-c
    assert ordered.index("gap-a") < ordered.index("gap-b")
    assert ordered.index("gap-b") < ordered.index("gap-c")


def test_build_dependency_chains_cycle_detected() -> None:
    gap_ids = frozenset({"gap-a", "gap-b"})
    deps = (
        GapDependency("d1", "gap-b", "gap-a", GapDependencyType.PREREQUISITE, "B→A"),
        GapDependency(
            "d2", "gap-a", "gap-b", GapDependencyType.PREREQUISITE, "A→B cycle"
        ),
    )
    chains = build_dependency_chains(gap_ids, deps)
    assert len(chains) == 1
    assert chains[0].has_cycle is True
    assert len(chains[0].cycle_gap_ids) > 0


def test_build_dependency_chains_empty_dependencies() -> None:
    gap_ids = frozenset({"gap-a", "gap-b"})
    chains = build_dependency_chains(gap_ids, ())
    assert chains == ()


# ---------------------------------------------------------------------------
# Blocker detection
# ---------------------------------------------------------------------------


def test_build_readiness_blockers_only_blocker_gaps() -> None:
    blocker_gap = _make_readiness_gap(
        "g-block", GapSeverity.CRITICAL, GapClassification.MISSING_CONTROL
    )
    non_blocker = ReadinessGap(
        gap_id="g-noblok",
        gap_classification=GapClassification.WEAK_CONTROL,
        gap_severity=GapSeverity.LOW,
        framework_id=_FW_ID,
        framework_version=_FW_VER,
        gap_rationale="weak",
        detected_at=_NOW,
        is_blocker=False,
        is_maturity_blocker=False,
        affected_control_ids=(),
        affected_framework_ids=(),
        evidence_ids=(),
    )
    blockers = build_readiness_blockers((blocker_gap, non_blocker), tenant_id=_TENANT)
    assert len(blockers) == 1
    assert blockers[0].gap_id == "g-block"


def test_build_maturity_blockers_returns_empty_when_no_tier() -> None:
    gap = _make_readiness_gap()
    blockers = build_maturity_blockers((gap,), None, tenant_id=_TENANT)
    assert blockers == ()


def test_build_maturity_blockers_only_maturity_blocker_gaps() -> None:
    mat_gap = ReadinessGap(
        gap_id="g-mat",
        gap_classification=GapClassification.FAILED_MATURITY_GATE,
        gap_severity=GapSeverity.HIGH,
        framework_id=_FW_ID,
        framework_version=_FW_VER,
        gap_rationale="maturity gate",
        detected_at=_NOW,
        is_blocker=False,
        is_maturity_blocker=True,
        affected_control_ids=(),
        affected_framework_ids=(),
        evidence_ids=(),
    )
    blockers = build_maturity_blockers((mat_gap,), "tier-001", tenant_id=_TENANT)
    assert len(blockers) == 1
    assert blockers[0].maturity_tier_id == "tier-001"


# ---------------------------------------------------------------------------
# Gap prioritization (deterministic ordering)
# ---------------------------------------------------------------------------


def test_prioritize_gaps_higher_severity_comes_first() -> None:
    low_gap = _make_readiness_gap(
        "g-low", GapSeverity.LOW, GapClassification.WEAK_CONTROL
    )
    high_gap = _make_readiness_gap(
        "g-high", GapSeverity.HIGH, GapClassification.FAILED_CONTROL
    )
    result = prioritize_gaps((low_gap, high_gap))
    assert result[0].gap_id == "g-high"
    assert result[1].gap_id == "g-low"


def test_prioritize_gaps_same_severity_classification_rank_breaks_tie() -> None:
    missing = _make_readiness_gap(
        "g-mis", GapSeverity.HIGH, GapClassification.MISSING_CONTROL
    )
    failed = _make_readiness_gap(
        "g-fail", GapSeverity.HIGH, GapClassification.FAILED_CONTROL
    )
    result = prioritize_gaps((failed, missing))
    # MISSING_CONTROL rank=9 > FAILED_CONTROL rank=8
    assert result[0].gap_id == "g-mis"


def test_prioritize_gaps_same_severity_same_classification_gap_id_breaks_tie() -> None:
    gap_b = _make_readiness_gap(
        "gap-b", GapSeverity.MODERATE, GapClassification.WEAK_CONTROL
    )
    gap_a = _make_readiness_gap(
        "gap-a", GapSeverity.MODERATE, GapClassification.WEAK_CONTROL
    )
    result = prioritize_gaps((gap_b, gap_a))
    assert result[0].gap_id == "gap-a"
    assert result[1].gap_id == "gap-b"


def test_prioritize_gaps_ordering_is_stable_regardless_of_input_order() -> None:
    gaps = tuple(
        _make_readiness_gap(
            f"g-{i:03d}", GapSeverity.MODERATE, GapClassification.WEAK_CONTROL
        )
        for i in range(10)
    )
    forward = prioritize_gaps(gaps)
    backward = prioritize_gaps(tuple(reversed(gaps)))
    assert [g.gap_id for g in forward] == [g.gap_id for g in backward]


# ---------------------------------------------------------------------------
# Governance override application
# ---------------------------------------------------------------------------


def test_severity_override_changes_effective_ordering() -> None:
    """A LOW gap with SEVERITY override to CRITICAL should sort above a HIGH gap."""
    low_gap = _make_readiness_gap(
        "g-low", GapSeverity.LOW, GapClassification.WEAK_CONTROL
    )
    high_gap = _make_readiness_gap(
        "g-high", GapSeverity.HIGH, GapClassification.FAILED_CONTROL
    )
    override = GovernanceOverride(
        override_id="ov-001",
        gap_id="g-low",
        override_type=OverrideType.SEVERITY,
        original_value="low",
        overridden_value="critical",
        override_authority="governance-board",
        override_rationale="Escalated per audit finding",
        approved_at=_NOW,
    )
    result = prioritize_gaps((high_gap, low_gap), overrides=(override,))
    # After override, g-low (effective CRITICAL) should come first
    assert result[0].gap_id == "g-low"


def test_severity_override_does_not_mutate_original_gap() -> None:
    gap = _make_readiness_gap("g-low", GapSeverity.LOW)
    override = GovernanceOverride(
        override_id="ov-001",
        gap_id="g-low",
        override_type=OverrideType.SEVERITY,
        original_value="low",
        overridden_value="critical",
        override_authority="board",
        override_rationale="test",
        approved_at=_NOW,
    )
    prioritize_gaps((gap,), overrides=(override,))
    # Original gap must not be mutated
    assert gap.gap_severity == GapSeverity.LOW


# ---------------------------------------------------------------------------
# Readiness impact estimation
# ---------------------------------------------------------------------------


def test_estimate_readiness_impact_missing_control_has_nonzero_impact() -> None:
    gap = _make_readiness_gap(
        "g-001", GapSeverity.HIGH, GapClassification.MISSING_CONTROL
    )
    cs = _make_control_score(
        control_id=_CTRL_A,
        outcome=AssessmentOutcome.NOT_EVALUATED,
        raw_score=0.0,
        is_evaluated=False,
    )
    ds = _make_domain_score()
    est = estimate_readiness_impact(gap, (cs,), (ds,), total_control_count=1)
    assert est.gap_id == "g-001"
    assert 0.0 <= est.framework_impact <= 1.0
    assert 0.0 <= est.remediation_impact <= 1.0


def test_estimate_readiness_impact_maturity_blocker_has_full_maturity_impact() -> None:
    gap = ReadinessGap(
        gap_id="g-mat",
        gap_classification=GapClassification.FAILED_MATURITY_GATE,
        gap_severity=GapSeverity.HIGH,
        framework_id=_FW_ID,
        framework_version=_FW_VER,
        gap_rationale="maturity",
        detected_at=_NOW,
        is_blocker=False,
        is_maturity_blocker=True,
        affected_control_ids=(),
        affected_framework_ids=(_FW_ID,),
        evidence_ids=(),
    )
    est = estimate_readiness_impact(gap, (), (), total_control_count=1)
    assert est.maturity_impact == 1.0


def test_estimate_readiness_impact_id_is_deterministic() -> None:
    gap = _make_readiness_gap("g-001")
    est1 = estimate_readiness_impact(gap, (), (), total_control_count=1)
    est2 = estimate_readiness_impact(gap, (), (), total_control_count=1)
    assert est1.estimate_id == est2.estimate_id
    assert est1.framework_impact == est2.framework_impact


# ---------------------------------------------------------------------------
# Remediation recommendation building
# ---------------------------------------------------------------------------


def test_build_remediation_recommendations_one_per_gap() -> None:
    gaps = (
        _make_readiness_gap(
            "g-001", GapSeverity.HIGH, GapClassification.MISSING_CONTROL
        ),
        _make_readiness_gap("g-002", GapSeverity.LOW, GapClassification.WEAK_CONTROL),
    )
    recs = build_remediation_recommendations(gaps, (), (), (), (), (), ())
    assert len(recs) == 2


def test_build_remediation_recommendations_classification_mapped() -> None:
    gap = _make_readiness_gap(
        "g-001", GapSeverity.HIGH, GapClassification.MISSING_CONTROL
    )
    recs = build_remediation_recommendations((gap,), (), (), (), (), (), ())
    assert recs[0].remediation_classification == "address_missing_control"


def test_build_remediation_recommendations_compensating_control_reduces_impact() -> (
    None
):
    gap = _make_readiness_gap(
        "g-001", GapSeverity.HIGH, GapClassification.FAILED_CONTROL
    )
    cs = _make_control_score(
        control_id=_CTRL_A, outcome=AssessmentOutcome.NON_COMPLIANT, raw_score=0.0
    )
    ds = _make_domain_score()
    est = estimate_readiness_impact(gap, (cs,), (ds,), total_control_count=1)
    cc = CompensatingControl(
        compensating_id="cc-001",
        gap_id="g-001",
        mitigation_rationale="Mitigated by alt control",
        framework_applicability=(_FW_ID,),
        approved_by="CISO",
        approved_at=_NOW,
    )
    recs_with = build_remediation_recommendations((gap,), (), (est,), (), (), (cc,), ())
    recs_without = build_remediation_recommendations((gap,), (), (est,), (), (), (), ())
    # Compensating control halves the effective impact
    assert (
        recs_with[0].estimated_readiness_impact
        <= recs_without[0].estimated_readiness_impact
    )


def test_build_remediation_recommendations_sorted_by_impact_desc() -> None:
    gap_high = _make_readiness_gap(
        "g-001", GapSeverity.HIGH, GapClassification.MISSING_CONTROL
    )
    gap_low = _make_readiness_gap(
        "g-002", GapSeverity.LOW, GapClassification.WEAK_CONTROL
    )
    cs_h = _make_control_score(
        control_id=_CTRL_A,
        outcome=AssessmentOutcome.NOT_EVALUATED,
        raw_score=0.0,
        is_evaluated=False,
    )
    cs_l = _make_control_score(
        control_id=_CTRL_B,
        control_identifier="GV-2",
        outcome=AssessmentOutcome.COMPLIANT,
        raw_score=30.0,
    )
    ds = _make_domain_score()
    est_h = estimate_readiness_impact(gap_high, (cs_h,), (ds,), total_control_count=2)
    est_l = estimate_readiness_impact(gap_low, (cs_l,), (ds,), total_control_count=2)
    recs = build_remediation_recommendations(
        (gap_high, gap_low), (), (est_h, est_l), (), (), (), ()
    )
    # Higher impact recommendation must come first
    assert recs[0].estimated_readiness_impact >= recs[1].estimated_readiness_impact


# ---------------------------------------------------------------------------
# Compensating control handling
# ---------------------------------------------------------------------------


def test_compensating_control_does_not_suppress_gap() -> None:
    cc = CompensatingControl(
        compensating_id="cc-001",
        gap_id="g-001",
        mitigation_rationale="Alt control",
        framework_applicability=(_FW_ID,),
        approved_by="CISO",
        approved_at=_NOW,
    )
    inp = _make_gap_analysis_input(
        controls=(_make_control(_CTRL_A, "GV-1"),),
        results=(_make_result(_CTRL_A, AssessmentOutcome.NON_COMPLIANT),),
        score_output=_make_score_output(
            overall_score=0.0,
            control_scores={
                _CTRL_A: _make_control_score(
                    outcome=AssessmentOutcome.NON_COMPLIANT, raw_score=0.0
                )
            },
            failed_controls=(_CTRL_A,),
        ),
        compensating_controls=(cc,),
    )
    result = _run_engine(inp)
    # Gap still visible — compensating control does not suppress
    gap_ids = [g.gap_id for g in result.gaps]
    assert any(_CTRL_A in gid for gid in gap_ids)
    # Compensating control is recorded
    assert len(result.compensating_controls) == 1


# ---------------------------------------------------------------------------
# Policy exception handling
# ---------------------------------------------------------------------------


def test_policy_exception_does_not_suppress_gap() -> None:
    exc = PolicyException(
        exception_id="exc-001",
        exception_type=ExceptionType.TEMPORARY_WAIVER,
        exception_authority="CISO",
        approval_rationale="Waiver approved",
        affected_control_ids=(_CTRL_A,),
        affected_framework_ids=(_FW_ID,),
        approved_at=_NOW,
        tenant_id=_TENANT,
    )
    inp = _make_gap_analysis_input(
        controls=(_make_control(_CTRL_A, "GV-1"),),
        results=(_make_result(_CTRL_A, AssessmentOutcome.NON_COMPLIANT),),
        score_output=_make_score_output(
            overall_score=0.0,
            control_scores={
                _CTRL_A: _make_control_score(
                    outcome=AssessmentOutcome.NON_COMPLIANT, raw_score=0.0
                )
            },
            failed_controls=(_CTRL_A,),
        ),
        policy_exceptions=(exc,),
    )
    result = _run_engine(inp)
    # Gap remains present
    assert any(_CTRL_A in g.gap_id for g in result.gaps)
    assert len(result.policy_exceptions) == 1


# ---------------------------------------------------------------------------
# Tenant isolation (engine validation)
# ---------------------------------------------------------------------------


def test_engine_rejects_mismatched_result_tenant() -> None:
    wrong_result = _make_result(
        _CTRL_A, AssessmentOutcome.COMPLIANT, tenant_id=_OTHER_TENANT
    )
    inp = _make_gap_analysis_input(results=(wrong_result,))
    with pytest.raises(GapAnalysisTenantIsolationError):
        _run_engine(inp)


def test_engine_rejects_mismatched_evidence_tenant() -> None:
    wrong_ref = _make_evidence_ref("ev-1", _PAST_30, tenant_id=_OTHER_TENANT)
    inp = _make_gap_analysis_input(evidence_refs=(wrong_ref,))
    with pytest.raises(GapAnalysisTenantIsolationError):
        _run_engine(inp)


def test_engine_rejects_mismatched_score_output_tenant() -> None:
    so = _make_score_output(tenant_id=_OTHER_TENANT)
    inp = _make_gap_analysis_input(score_output=so)
    with pytest.raises(GapAnalysisTenantIsolationError):
        _run_engine(inp)


# ---------------------------------------------------------------------------
# Framework isolation (engine validation)
# ---------------------------------------------------------------------------


def test_engine_rejects_score_output_with_wrong_framework() -> None:
    so = ScoreOutput(
        assessment_id="assess-001",
        tenant_id=_TENANT,
        framework_id="different-framework",
        framework_version_tag=_FW_VER,
        overall_score=100.0,
        normalized_score=1.0,
        domain_scores={},
        control_scores={},
        maturity_tier=None,
        maturity_tier_id=None,
        risk_classification=RiskLevel.MINIMAL,
        remediation_priority=RemediationPriority.NOT_REQUIRED,
        remediation_factors=(),
        missing_controls=(),
        incomplete_controls=(),
        failed_controls=(),
        not_applicable_controls=(),
        threshold_failures=(),
        scoring_warnings=(),
        completion_state=CompletionState.COMPLETE,
        completion_percentage=100.0,
        is_complete=True,
        computed_at=_NOW,
        score_version="1.0.0",
    )
    inp = _make_gap_analysis_input(score_output=so)
    with pytest.raises(GapAnalysisFrameworkMismatchError):
        _run_engine(inp)


# ---------------------------------------------------------------------------
# Full engine integration
# ---------------------------------------------------------------------------


def test_engine_produces_gap_analysis_result() -> None:
    result = _run_engine(_make_gap_analysis_input())
    assert result.result_id == "result-001"
    assert result.framework_id == _FW_ID
    assert result.analysis_version == _ANALYSIS_VERSION


def test_engine_no_gaps_when_fully_compliant() -> None:
    inp = _make_gap_analysis_input(
        controls=(_make_control(_CTRL_A, "GV-1"),),
        results=(_make_result(_CTRL_A, AssessmentOutcome.COMPLIANT),),
        evidence_refs=(_make_evidence_ref("ev-1", _PAST_30),),
        score_output=_make_score_output(
            overall_score=100.0,
            control_scores={_CTRL_A: _make_control_score()},
            completion_percentage=100.0,
        ),
    )
    result = _run_engine(inp)
    assert (
        len(
            [
                g
                for g in result.gaps
                if g.gap_classification == GapClassification.MISSING_CONTROL
            ]
        )
        == 0
    )
    assert (
        len(
            [
                g
                for g in result.gaps
                if g.gap_classification == GapClassification.FAILED_CONTROL
            ]
        )
        == 0
    )


def test_engine_detects_missing_control_end_to_end() -> None:
    # Control A has a result, Control B does not
    ctrl_a = _make_control(_CTRL_A, "GV-1")
    ctrl_b = _make_control(_CTRL_B, "GV-2")
    result_a = _make_result(_CTRL_A, AssessmentOutcome.COMPLIANT)
    so = _make_score_output(
        control_scores={
            _CTRL_A: _make_control_score(_CTRL_A, "GV-1", is_evaluated=True),
            _CTRL_B: _make_control_score(
                _CTRL_B,
                "GV-2",
                outcome=AssessmentOutcome.NOT_EVALUATED,
                raw_score=0.0,
                is_evaluated=False,
            ),
        },
        missing_controls=(_CTRL_B,),
        completion_percentage=50.0,
    )
    inp = _make_gap_analysis_input(
        controls=(ctrl_a, ctrl_b),
        results=(result_a,),
        score_output=so,
    )
    result = _run_engine(inp)
    missing = [
        g
        for g in result.gaps
        if g.gap_classification == GapClassification.MISSING_CONTROL
    ]
    assert len(missing) == 1
    assert missing[0].control_id == _CTRL_B


def test_engine_result_has_replay_contract_with_version_pins() -> None:
    inp = GapAnalysisInput(
        assessment=_make_assessment(),
        framework=_make_framework(),
        controls=(_make_control(),),
        domains=(_make_domain(),),
        maturity_tiers=(),
        results=(_make_result(),),
        evidence_refs=(_make_evidence_ref(),),
        score_output=_make_score_output(),
        scoring_contract_version="1.2.3",
        maturity_model_version="2.0.0",
        mapping_version="3.1.0",
        evidence_snapshot_version="snap-abc",
    )
    result = _run_engine(inp)
    rc = result.replay_contract
    assert rc.scoring_contract_version == "1.2.3"
    assert rc.maturity_model_version == "2.0.0"
    assert rc.mapping_version == "3.1.0"
    assert rc.evidence_snapshot_version == "snap-abc"
    assert rc.analysis_version == _ANALYSIS_VERSION


def test_engine_gaps_are_deterministically_ordered() -> None:
    ctrl_b = _make_control(_CTRL_B, "GV-2")
    ctrl_a = _make_control(_CTRL_A, "GV-1")
    so = _make_score_output(
        control_scores={
            _CTRL_B: _make_control_score(
                _CTRL_B,
                "GV-2",
                outcome=AssessmentOutcome.NOT_EVALUATED,
                raw_score=0.0,
                is_evaluated=False,
            ),
            _CTRL_A: _make_control_score(
                _CTRL_A,
                "GV-1",
                outcome=AssessmentOutcome.NOT_EVALUATED,
                raw_score=0.0,
                is_evaluated=False,
            ),
        },
        missing_controls=(_CTRL_A, _CTRL_B),
        completion_percentage=0.0,
    )
    inp1 = _make_gap_analysis_input(
        controls=(ctrl_b, ctrl_a), results=(), score_output=so
    )
    inp2 = _make_gap_analysis_input(
        controls=(ctrl_a, ctrl_b), results=(), score_output=so
    )
    r1 = _run_engine(inp1)
    r2 = _run_engine(inp2)
    assert [g.gap_id for g in r1.gaps] == [g.gap_id for g in r2.gaps]


def test_engine_immutable_result_cannot_be_mutated() -> None:
    result = _run_engine(_make_gap_analysis_input())
    with pytest.raises(Exception):
        result.gaps = ()  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Integrity hashing
# ---------------------------------------------------------------------------


def test_compute_gap_analysis_hash_returns_integrity_record() -> None:
    result = _run_engine(_make_gap_analysis_input())
    record = compute_gap_analysis_hash(result, computed_at=_NOW)
    assert isinstance(record, RemediationIntegrityRecord)
    assert record.algorithm == "sha256"
    assert len(record.hash_value) == 64
    assert record.is_replay_safe is True


def test_compute_gap_analysis_hash_is_deterministic() -> None:
    result = _run_engine(_make_gap_analysis_input())
    h1 = compute_gap_analysis_hash(result, computed_at=_NOW)
    h2 = compute_gap_analysis_hash(result, computed_at=_NOW)
    assert h1.hash_value == h2.hash_value


def test_hash_changes_when_gap_added() -> None:
    """A result with one gap hashes differently from a result with two gaps."""
    inp_one = _make_gap_analysis_input(
        controls=(_make_control(_CTRL_A, "GV-1"),),
        results=(),
        score_output=_make_score_output(
            control_scores={
                _CTRL_A: _make_control_score(
                    _CTRL_A,
                    "GV-1",
                    outcome=AssessmentOutcome.NOT_EVALUATED,
                    raw_score=0.0,
                    is_evaluated=False,
                )
            },
            missing_controls=(_CTRL_A,),
            completion_percentage=0.0,
        ),
    )
    inp_two = _make_gap_analysis_input(
        controls=(
            _make_control(_CTRL_A, "GV-1"),
            _make_control(_CTRL_B, "GV-2"),
        ),
        results=(),
        score_output=_make_score_output(
            control_scores={
                _CTRL_A: _make_control_score(
                    _CTRL_A,
                    "GV-1",
                    outcome=AssessmentOutcome.NOT_EVALUATED,
                    raw_score=0.0,
                    is_evaluated=False,
                ),
                _CTRL_B: _make_control_score(
                    _CTRL_B,
                    "GV-2",
                    outcome=AssessmentOutcome.NOT_EVALUATED,
                    raw_score=0.0,
                    is_evaluated=False,
                ),
            },
            missing_controls=(_CTRL_A, _CTRL_B),
            completion_percentage=0.0,
        ),
    )
    r1 = _run_engine(inp_one, "result-001")
    r2 = _run_engine(inp_two, "result-002")
    h1 = compute_gap_analysis_hash(r1, computed_at=_NOW)
    h2 = compute_gap_analysis_hash(r2, computed_at=_NOW)
    assert h1.hash_value != h2.hash_value


def test_hash_stable_across_different_analyzed_at() -> None:
    """analyzed_at is excluded from hash — different timestamps produce same hash."""
    result = _run_engine(_make_gap_analysis_input())
    h1 = compute_gap_analysis_hash(result, computed_at=_NOW)
    h2 = compute_gap_analysis_hash(result, computed_at=_NOW + timedelta(hours=1))
    assert h1.hash_value == h2.hash_value


def test_replay_gap_analysis_hash_matches_original() -> None:
    result = _run_engine(_make_gap_analysis_input())
    record = compute_gap_analysis_hash(result, computed_at=_NOW)
    replayed = replay_gap_analysis_hash(record.inputs_canonical)
    assert replayed == record.hash_value


def test_verify_gap_analysis_hash_returns_true_for_valid() -> None:
    result = _run_engine(_make_gap_analysis_input())
    record = compute_gap_analysis_hash(result, computed_at=_NOW)
    assert verify_gap_analysis_hash(result, record) is True


def test_verify_gap_analysis_hash_returns_false_for_different_result() -> None:
    result1 = _run_engine(_make_gap_analysis_input(), "result-001")
    inp2 = _make_gap_analysis_input(
        controls=(_make_control(_CTRL_A, "GV-1"),),
        results=(),
        score_output=_make_score_output(
            control_scores={
                _CTRL_A: _make_control_score(
                    _CTRL_A,
                    "GV-1",
                    outcome=AssessmentOutcome.NOT_EVALUATED,
                    raw_score=0.0,
                    is_evaluated=False,
                )
            },
            missing_controls=(_CTRL_A,),
            completion_percentage=0.0,
        ),
    )
    result2 = _run_engine(inp2, "result-002")
    record1 = compute_gap_analysis_hash(result1, computed_at=_NOW)
    assert verify_gap_analysis_hash(result2, record1) is False


# ---------------------------------------------------------------------------
# Analysis version constant
# ---------------------------------------------------------------------------


def test_analysis_version_is_semver() -> None:
    parts = _ANALYSIS_VERSION.split(".")
    assert len(parts) == 3
    assert all(p.isdigit() for p in parts)
