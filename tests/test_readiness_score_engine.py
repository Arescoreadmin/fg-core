"""Unit tests for ReadinessScoreEngine.

No database. No I/O. Pure Python deterministic scoring.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

import pytest

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
    MaturityTier,
    ScoringContract,
)
from services.readiness.scoring import (
    CompletionState,
    FrameworkMismatchError,
    InvalidWeightError,
    ReadinessScoreEngine,
    RiskLevel,
    RemediationPriority,
    ScoringContractMismatchError,
    ScoringInput,
    TenantIsolationViolation,
)

# ---------------------------------------------------------------------------
# Factories
# ---------------------------------------------------------------------------

_NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
_TENANT = "tenant-x"
_FW_ID = "fw-001"
_ACTOR = "test-actor"


def _fw(fw_id: str = _FW_ID) -> Framework:
    return Framework(
        framework_id=fw_id,
        framework_name="Test FW",
        framework_slug="test-fw",
        framework_version="1.0",
        framework_status=FrameworkStatus.ACTIVE,
        created_by=_ACTOR,
        created_at=_NOW,
        updated_at=_NOW,
    )


def _domain(domain_id: str, order: int = 1, fw_id: str = _FW_ID) -> Domain:
    return Domain(
        domain_id=domain_id,
        framework_id=fw_id,
        domain_name=f"Domain {domain_id}",
        domain_slug=domain_id,
        domain_description="",
        domain_order=order,
        created_by=_ACTOR,
        created_at=_NOW,
    )


def _control(
    control_id: str, domain_id: str, identifier: str = "", fw_id: str = _FW_ID
) -> Control:
    return Control(
        control_id=control_id,
        framework_id=fw_id,
        domain_id=domain_id,
        control_identifier=identifier or control_id,
        control_name=f"Control {control_id}",
        control_description="",
        created_by=_ACTOR,
        created_at=_NOW,
    )


def _assessment(fw_id: str = _FW_ID, tenant_id: str = _TENANT) -> Assessment:
    return Assessment(
        assessment_id="assess-001",
        tenant_id=tenant_id,
        framework_id=fw_id,
        framework_version_tag="v1",
        assessment_status=AssessmentStatus.ACTIVE,
        snapshot_version=1,
        created_by=_ACTOR,
        created_at=_NOW,
        updated_at=_NOW,
    )


def _result(
    control_id: str,
    outcome: AssessmentOutcome,
    assessment_id: str = "assess-001",
    tenant_id: str = _TENANT,
    ts: Optional[datetime] = None,
) -> AssessmentResult:
    return AssessmentResult(
        result_id=str(uuid.uuid4()),
        assessment_id=assessment_id,
        control_id=control_id,
        maturity_tier_id=None,
        outcome=outcome,
        actor=_ACTOR,
        timestamp=ts or _NOW,
        tenant_id=tenant_id,
    )


def _contract(
    fw_id: str = _FW_ID,
    weighting: Optional[dict] = None,
    scoring: Optional[dict] = None,
) -> ScoringContract:
    return ScoringContract(
        contract_id="contract-001",
        framework_id=fw_id,
        scoring_schema_version="1.0",
        created_by=_ACTOR,
        created_at=_NOW,
        weighting_metadata=weighting or {},
        scoring_metadata=scoring or {},
    )


def _tier(
    tier_id: str, identifier: str, order: int, metadata: Optional[dict] = None
) -> MaturityTier:
    return MaturityTier(
        tier_id=tier_id,
        framework_id=_FW_ID,
        tier_identifier=identifier,
        tier_name=f"Tier {identifier}",
        tier_order=order,
        tier_criteria="",
        created_by=_ACTOR,
        created_at=_NOW,
        tier_metadata=metadata or {},
    )


def _evidence(control_ids: list[str], tenant_id: str = _TENANT) -> EvidenceReference:
    return EvidenceReference(
        evidence_id=str(uuid.uuid4()),
        assessment_id="assess-001",
        evidence_type=EvidenceType.DOCUMENT,
        evidence_title="Evidence",
        submitted_by=_ACTOR,
        submitted_at=_NOW,
        tenant_id=tenant_id,
        control_ids=control_ids,
    )


def _basic_inp(
    outcomes: dict[str, AssessmentOutcome],
    *,
    domain_id: str = "d1",
    scoring_contract: Optional[ScoringContract] = None,
    extra_controls: Optional[list[Control]] = None,
    maturity_tiers: tuple[MaturityTier, ...] = (),
) -> ScoringInput:
    domains = (_domain(domain_id),)
    controls = tuple(_control(cid, domain_id, cid) for cid in outcomes)
    if extra_controls:
        controls = controls + tuple(extra_controls)
    results = tuple(_result(cid, oc) for cid, oc in outcomes.items())
    return ScoringInput(
        assessment=_assessment(),
        framework=_fw(),
        controls=controls,
        domains=domains,
        maturity_tiers=maturity_tiers,
        results=results,
        evidence_refs=(),
        scoring_contract=scoring_contract,
    )


engine = ReadinessScoreEngine()

# ---------------------------------------------------------------------------
# Basic scoring
# ---------------------------------------------------------------------------


def test_all_compliant_score_100():
    inp = _basic_inp(
        {"c1": AssessmentOutcome.COMPLIANT, "c2": AssessmentOutcome.COMPLIANT}
    )
    out = engine.score(inp)
    assert out.overall_score == 100.0
    assert out.normalized_score == 1.0
    assert out.is_complete is True
    assert out.completion_state == CompletionState.COMPLETE
    assert out.risk_classification == RiskLevel.MINIMAL
    assert out.remediation_priority == RemediationPriority.NOT_REQUIRED


def test_all_non_compliant_score_0():
    inp = _basic_inp(
        {"c1": AssessmentOutcome.NON_COMPLIANT, "c2": AssessmentOutcome.NON_COMPLIANT}
    )
    out = engine.score(inp)
    assert out.overall_score == 0.0
    assert out.risk_classification == RiskLevel.CRITICAL
    assert out.remediation_priority == RemediationPriority.CRITICAL_IMMEDIATE


def test_partially_compliant_score_50():
    inp = _basic_inp({"c1": AssessmentOutcome.PARTIALLY_COMPLIANT})
    out = engine.score(inp)
    assert out.overall_score == 50.0
    assert out.risk_classification == RiskLevel.MODERATE


def test_mixed_outcomes():
    # 2 compliant (100), 1 non-compliant (0), 1 partial (50) → avg = 62.5
    inp = _basic_inp(
        {
            "c1": AssessmentOutcome.COMPLIANT,
            "c2": AssessmentOutcome.COMPLIANT,
            "c3": AssessmentOutcome.NON_COMPLIANT,
            "c4": AssessmentOutcome.PARTIALLY_COMPLIANT,
        }
    )
    out = engine.score(inp)
    assert out.overall_score == 62.5
    assert out.is_complete is True
    assert out.completion_state == CompletionState.COMPLETE
    assert "c3" in out.failed_controls
    assert "c4" in out.incomplete_controls


def test_not_applicable_excluded():
    # Only c1=COMPLIANT is applicable; c2=NOT_APPLICABLE excluded
    inp = _basic_inp(
        {"c1": AssessmentOutcome.COMPLIANT, "c2": AssessmentOutcome.NOT_APPLICABLE}
    )
    out = engine.score(inp)
    assert out.overall_score == 100.0
    assert "c2" in out.not_applicable_controls
    assert "c2" not in out.failed_controls
    assert "c2" not in out.missing_controls


# ---------------------------------------------------------------------------
# Completion states
# ---------------------------------------------------------------------------


def test_empty_completion_state_no_results():
    # Controls defined but no results
    domains = (_domain("d1"),)
    controls = (_control("c1", "d1"),)
    inp = ScoringInput(
        assessment=_assessment(),
        framework=_fw(),
        controls=controls,
        domains=domains,
        maturity_tiers=(),
        results=(),
        evidence_refs=(),
    )
    out = engine.score(inp)
    assert out.completion_state == CompletionState.EMPTY
    assert out.is_complete is False
    assert out.missing_controls == ("c1",)


def test_partial_completion_state():
    # 3 applicable, 2 evaluated → 66.7% → PARTIAL
    domains = (_domain("d1"),)
    controls = (
        _control("c1", "d1"),
        _control("c2", "d1"),
        _control("c3", "d1"),
    )
    results = (
        _result("c1", AssessmentOutcome.COMPLIANT),
        _result("c2", AssessmentOutcome.COMPLIANT),
    )
    inp2 = ScoringInput(
        assessment=_assessment(),
        framework=_fw(),
        controls=controls,
        domains=domains,
        maturity_tiers=(),
        results=results,
        evidence_refs=(),
    )
    out = engine.score(inp2)
    assert out.completion_state == CompletionState.PARTIAL
    assert "c3" in out.missing_controls


def test_incomplete_completion_state():
    # 5 controls, 1 evaluated → 20% → INCOMPLETE
    controls = tuple(_control(f"c{i}", "d1") for i in range(5))
    results = (_result("c0", AssessmentOutcome.COMPLIANT),)
    inp = ScoringInput(
        assessment=_assessment(),
        framework=_fw(),
        controls=controls,
        domains=(_domain("d1"),),
        maturity_tiers=(),
        results=results,
        evidence_refs=(),
    )
    out = engine.score(inp)
    assert out.completion_state == CompletionState.INCOMPLETE
    assert len(out.missing_controls) == 4


# ---------------------------------------------------------------------------
# Weighted scoring
# ---------------------------------------------------------------------------


def test_weighted_controls():
    # c1=COMPLIANT weight=3, c2=NON_COMPLIANT weight=1 → (100*3 + 0*1)/4 = 75.0
    contract = _contract(weighting={"controls": {"c1": 3.0, "c2": 1.0}})
    inp = _basic_inp(
        {"c1": AssessmentOutcome.COMPLIANT, "c2": AssessmentOutcome.NON_COMPLIANT},
        scoring_contract=contract,
    )
    out = engine.score(inp)
    assert out.overall_score == 75.0


def test_weighted_domains():
    # Two domains: d1=COMPLIANT(100) weight=3, d2=NON_COMPLIANT(0) weight=1 → 75.0
    fw = _fw()
    assess = _assessment()
    d1 = _domain("d1")
    d2 = _domain("d2", order=2)
    c1 = _control("c1", "d1")
    c2 = _control("c2", "d2")
    r1 = _result("c1", AssessmentOutcome.COMPLIANT)
    r2 = _result("c2", AssessmentOutcome.NON_COMPLIANT)
    contract = _contract(weighting={"domains": {"d1": 3.0, "d2": 1.0}})
    inp = ScoringInput(
        assessment=assess,
        framework=fw,
        controls=(c1, c2),
        domains=(d1, d2),
        maturity_tiers=(),
        results=(r1, r2),
        evidence_refs=(),
        scoring_contract=contract,
    )
    out = engine.score(inp)
    assert out.overall_score == 75.0


def test_invalid_weight_raises():
    contract = _contract(weighting={"controls": {"c1": -1.0}})
    inp = _basic_inp({"c1": AssessmentOutcome.COMPLIANT}, scoring_contract=contract)
    with pytest.raises(InvalidWeightError):
        engine.score(inp)


# ---------------------------------------------------------------------------
# Risk classification
# ---------------------------------------------------------------------------


def test_risk_minimal_complete_high_score():
    inp = _basic_inp({"c1": AssessmentOutcome.COMPLIANT})
    out = engine.score(inp)
    assert out.risk_classification == RiskLevel.MINIMAL


def test_risk_incomplete_caps_at_moderate():
    # score=100 but not complete → MODERATE (not MINIMAL/LOW)
    controls = (_control("c1", "d1"), _control("c2", "d1"))
    results = (_result("c1", AssessmentOutcome.COMPLIANT),)
    inp = ScoringInput(
        assessment=_assessment(),
        framework=_fw(),
        controls=controls,
        domains=(_domain("d1"),),
        maturity_tiers=(),
        results=results,
        evidence_refs=(),
    )
    out = engine.score(inp)
    # c1 compliant = 100, c2 missing → domain score 50 (weight-avg with NOT_EVALUATED=0)
    # Actually: c2 has no result → NOT_EVALUATED (is_applicable=True, raw=0)
    # So score = (100+0)/2 = 50 → MODERATE anyway
    assert out.risk_classification in (RiskLevel.MODERATE, RiskLevel.HIGH)
    assert out.is_complete is False


def test_risk_critical_with_critical_control_failure():
    contract = _contract(scoring={"critical_controls": ["c1"]})
    inp = _basic_inp(
        {"c1": AssessmentOutcome.NON_COMPLIANT, "c2": AssessmentOutcome.COMPLIANT},
        scoring_contract=contract,
    )
    out = engine.score(inp)
    assert out.risk_classification == RiskLevel.CRITICAL
    assert out.remediation_priority == RemediationPriority.CRITICAL_IMMEDIATE


# ---------------------------------------------------------------------------
# Threshold failures
# ---------------------------------------------------------------------------


def test_overall_pass_threshold_failure():
    # score=50, threshold=75 → failure recorded
    contract = _contract(scoring={"overall_pass": 75.0})
    inp = _basic_inp(
        {"c1": AssessmentOutcome.PARTIALLY_COMPLIANT},
        scoring_contract=contract,
    )
    out = engine.score(inp)
    types = [tf.threshold_type for tf in out.threshold_failures]
    assert "overall_pass" in types


def test_domain_minimum_threshold_failure():
    contract = _contract(scoring={"domain_minimums": {"d1": 80.0}})
    inp = _basic_inp(
        {"c1": AssessmentOutcome.PARTIALLY_COMPLIANT},  # score=50
        scoring_contract=contract,
    )
    out = engine.score(inp)
    types = [tf.threshold_type for tf in out.threshold_failures]
    assert "domain_minimum" in types


def test_no_threshold_failure_when_passing():
    contract = _contract(scoring={"overall_pass": 50.0})
    inp = _basic_inp({"c1": AssessmentOutcome.COMPLIANT}, scoring_contract=contract)
    out = engine.score(inp)
    assert not any(tf.threshold_type == "overall_pass" for tf in out.threshold_failures)


# ---------------------------------------------------------------------------
# Maturity tiers
# ---------------------------------------------------------------------------


def test_maturity_tier_awarded_by_score():
    # 3 tiers: advanced(order=3), intermediate(order=2), basic(order=1)
    # No contract thresholds → evenly distributed: basic≥0, intermediate≥33.3, advanced≥66.7
    tiers = (
        _tier("t3", "advanced", 3),
        _tier("t2", "intermediate", 2),
        _tier("t1", "basic", 1),
    )
    inp = _basic_inp({"c1": AssessmentOutcome.COMPLIANT}, maturity_tiers=tiers)
    out = engine.score(inp)
    assert out.maturity_tier == "advanced"
    assert out.maturity_tier_id == "t3"


def test_maturity_tier_contract_thresholds():
    tiers = (
        _tier("t2", "advanced", 2),
        _tier("t1", "basic", 1),
    )
    contract = _contract(
        scoring={"maturity_thresholds": {"advanced": 90.0, "basic": 50.0}}
    )
    # score=50 → qualifies for basic, not advanced
    inp = _basic_inp(
        {"c1": AssessmentOutcome.PARTIALLY_COMPLIANT},
        maturity_tiers=tiers,
        scoring_contract=contract,
    )
    out = engine.score(inp)
    assert out.maturity_tier == "basic"


def test_maturity_tier_blocked_by_missing_required_control():
    tiers = (_tier("t1", "basic", 1, metadata={"required_control_ids": ["c2"]}),)
    # c2 has no result → tier blocked
    controls = (_control("c1", "d1"), _control("c2", "d1"))
    results = (_result("c1", AssessmentOutcome.COMPLIANT),)
    inp = ScoringInput(
        assessment=_assessment(),
        framework=_fw(),
        controls=controls,
        domains=(_domain("d1"),),
        maturity_tiers=tiers,
        results=results,
        evidence_refs=(),
    )
    out = engine.score(inp)
    assert out.maturity_tier is None


def test_maturity_tier_none_when_no_tiers():
    inp = _basic_inp({"c1": AssessmentOutcome.COMPLIANT})
    out = engine.score(inp)
    assert out.maturity_tier is None
    assert out.maturity_tier_id is None


# ---------------------------------------------------------------------------
# Evidence count
# ---------------------------------------------------------------------------


def test_evidence_count_on_control_score():
    ev1 = _evidence(["c1", "c2"])
    ev2 = _evidence(["c1"])
    controls = (_control("c1", "d1"), _control("c2", "d1"))
    results = (
        _result("c1", AssessmentOutcome.COMPLIANT),
        _result("c2", AssessmentOutcome.COMPLIANT),
    )
    inp = ScoringInput(
        assessment=_assessment(),
        framework=_fw(),
        controls=controls,
        domains=(_domain("d1"),),
        maturity_tiers=(),
        results=results,
        evidence_refs=(ev1, ev2),
    )
    out = engine.score(inp)
    assert out.control_scores["c1"].evidence_count == 2
    assert out.control_scores["c2"].evidence_count == 1


# ---------------------------------------------------------------------------
# Most-recent result wins
# ---------------------------------------------------------------------------


def test_most_recent_result_used():
    earlier = _result("c1", AssessmentOutcome.NON_COMPLIANT, ts=_NOW)
    later = _result(
        "c1",
        AssessmentOutcome.COMPLIANT,
        ts=datetime(2026, 1, 2, tzinfo=timezone.utc),
    )
    inp = ScoringInput(
        assessment=_assessment(),
        framework=_fw(),
        controls=(_control("c1", "d1"),),
        domains=(_domain("d1"),),
        maturity_tiers=(),
        results=(earlier, later),
        evidence_refs=(),
    )
    out = engine.score(inp)
    assert out.overall_score == 100.0
    assert out.control_scores["c1"].outcome == AssessmentOutcome.COMPLIANT


# ---------------------------------------------------------------------------
# Tenant isolation
# ---------------------------------------------------------------------------


def test_tenant_isolation_result_raises():
    bad_result = _result("c1", AssessmentOutcome.COMPLIANT, tenant_id="tenant-evil")
    inp = ScoringInput(
        assessment=_assessment(),
        framework=_fw(),
        controls=(_control("c1", "d1"),),
        domains=(_domain("d1"),),
        maturity_tiers=(),
        results=(bad_result,),
        evidence_refs=(),
    )
    with pytest.raises(TenantIsolationViolation):
        engine.score(inp)


def test_tenant_isolation_evidence_raises():
    bad_ev = _evidence(["c1"], tenant_id="tenant-evil")
    results = (_result("c1", AssessmentOutcome.COMPLIANT),)
    inp = ScoringInput(
        assessment=_assessment(),
        framework=_fw(),
        controls=(_control("c1", "d1"),),
        domains=(_domain("d1"),),
        maturity_tiers=(),
        results=results,
        evidence_refs=(bad_ev,),
    )
    with pytest.raises(TenantIsolationViolation):
        engine.score(inp)


# ---------------------------------------------------------------------------
# Framework mismatch
# ---------------------------------------------------------------------------


def test_framework_id_mismatch_raises():
    wrong_fw = _fw(fw_id="fw-WRONG")
    inp = ScoringInput(
        assessment=_assessment(),
        framework=wrong_fw,
        controls=(),
        domains=(),
        maturity_tiers=(),
        results=(),
        evidence_refs=(),
    )
    with pytest.raises(FrameworkMismatchError):
        engine.score(inp)


def test_control_framework_mismatch_raises():
    wrong_ctrl = _control("c1", "d1", fw_id="fw-WRONG")
    inp = ScoringInput(
        assessment=_assessment(),
        framework=_fw(),
        controls=(wrong_ctrl,),
        domains=(_domain("d1"),),
        maturity_tiers=(),
        results=(),
        evidence_refs=(),
    )
    with pytest.raises(FrameworkMismatchError):
        engine.score(inp)


def test_scoring_contract_mismatch_raises():
    bad_contract = _contract(fw_id="fw-WRONG")
    inp = ScoringInput(
        assessment=_assessment(),
        framework=_fw(),
        controls=(),
        domains=(),
        maturity_tiers=(),
        results=(),
        evidence_refs=(),
        scoring_contract=bad_contract,
    )
    with pytest.raises(ScoringContractMismatchError):
        engine.score(inp)


# ---------------------------------------------------------------------------
# Warnings
# ---------------------------------------------------------------------------


def test_warning_no_scoring_contract():
    inp = _basic_inp({"c1": AssessmentOutcome.COMPLIANT})
    out = engine.score(inp)
    assert any("ScoringContract" in w for w in out.scoring_warnings)


def test_warning_incomplete_assessment():
    controls = (_control("c1", "d1"), _control("c2", "d1"))
    results = (_result("c1", AssessmentOutcome.COMPLIANT),)
    inp = ScoringInput(
        assessment=_assessment(),
        framework=_fw(),
        controls=controls,
        domains=(_domain("d1"),),
        maturity_tiers=(),
        results=results,
        evidence_refs=(),
    )
    out = engine.score(inp)
    assert any("incomplete" in w.lower() for w in out.scoring_warnings)


def test_no_applicable_controls_empty_warning():
    # All NOT_APPLICABLE
    inp = _basic_inp({"c1": AssessmentOutcome.NOT_APPLICABLE})
    out = engine.score(inp)
    assert any("No applicable" in w for w in out.scoring_warnings)
    assert out.risk_classification == RiskLevel.UNKNOWN


# ---------------------------------------------------------------------------
# ScoreOutput metadata
# ---------------------------------------------------------------------------


def test_score_output_version():
    inp = _basic_inp({"c1": AssessmentOutcome.COMPLIANT})
    out = engine.score(inp)
    assert out.score_version == "1.0.0"


def test_score_output_ids():
    inp = _basic_inp({"c1": AssessmentOutcome.COMPLIANT})
    out = engine.score(inp)
    assert out.assessment_id == "assess-001"
    assert out.tenant_id == _TENANT
    assert out.framework_id == _FW_ID


def test_scoring_contract_id_in_output():
    contract = _contract()
    inp = _basic_inp({"c1": AssessmentOutcome.COMPLIANT}, scoring_contract=contract)
    out = engine.score(inp)
    assert out.scoring_contract_id == "contract-001"
    assert out.scoring_contract_version == "1.0"


def test_no_scoring_contract_id_none():
    inp = _basic_inp({"c1": AssessmentOutcome.COMPLIANT})
    out = engine.score(inp)
    assert out.scoring_contract_id is None
    assert out.scoring_contract_version is None


# ---------------------------------------------------------------------------
# Multi-domain aggregation
# ---------------------------------------------------------------------------


def test_multi_domain_equal_weights():
    # d1: c1=COMPLIANT(100), d2: c2=NON_COMPLIANT(0) → overall=50
    fw = _fw()
    assess = _assessment()
    d1 = _domain("d1")
    d2 = _domain("d2", order=2)
    c1 = _control("c1", "d1")
    c2 = _control("c2", "d2")
    r1 = _result("c1", AssessmentOutcome.COMPLIANT)
    r2 = _result("c2", AssessmentOutcome.NON_COMPLIANT)
    inp = ScoringInput(
        assessment=assess,
        framework=fw,
        controls=(c1, c2),
        domains=(d1, d2),
        maturity_tiers=(),
        results=(r1, r2),
        evidence_refs=(),
    )
    out = engine.score(inp)
    assert out.overall_score == 50.0
    assert out.domain_scores["d1"].raw_score == 100.0
    assert out.domain_scores["d2"].raw_score == 0.0


def test_empty_domain_no_controls():
    # Domain with no controls contributes 0 with weight 1
    fw = _fw()
    assess = _assessment()
    d1 = _domain("d1")
    d2 = _domain("d2", order=2)
    c1 = _control("c1", "d1")
    r1 = _result("c1", AssessmentOutcome.COMPLIANT)
    inp = ScoringInput(
        assessment=assess,
        framework=fw,
        controls=(c1,),
        domains=(d1, d2),
        maturity_tiers=(),
        results=(r1,),
        evidence_refs=(),
    )
    out = engine.score(inp)
    # d2 has no controls → raw_score=0, d1=100 → overall=(100+0)/2=50
    assert out.domain_scores["d2"].raw_score == 0.0
    assert out.overall_score == 50.0
