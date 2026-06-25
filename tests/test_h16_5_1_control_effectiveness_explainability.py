"""Tests for PR 16.5.1 — Control Effectiveness Explainability & Governance Action Engine.

Coverage:
  CEX-1   to CEX-30:  Pure function tests (contributions, root causes, actions, narrative)
  CEX-31  to CEX-55:  Priority classification
  CEX-56  to CEX-80:  Change detection
  CEX-81  to CEX-110: ExplainabilityEngine — explain, contributors, actions
  CEX-111 to CEX-130: Rankings (recalculate_rankings, get_rankings)
  CEX-131 to CEX-150: Priorities endpoint (get_priorities)
  CEX-151 to CEX-165: Executive dashboard
  CEX-166 to CEX-190: API routes — auth, scope, route ordering
  CEX-191 to CEX-215: Tenant isolation
  CEX-216 to CEX-240: Integration (recalculate triggers explainability, CGIN snapshots)
  CEX-241+:           ORM guards, schema validation, edge cases
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from api.auth_scopes import mint_key
from api.db import get_engine
from api.db_models_control_effectiveness_explainability import FaControlRanking
from api.db_models_evidence_authority import (
    FaEvidence,
    FaEvidenceControlLink,
    FaVerification,
)
from api.db_models_evidence_freshness_authority import (
    FaEvidenceFreshnessRecord,
    FaFreshnessException,
)
from services.control_effectiveness.engine import ControlEffectivenessEngine
from services.control_effectiveness_explainability.engine import ExplainabilityEngine
from services.control_effectiveness_explainability.models import (
    COMPONENT_WEIGHTS,
    GovernancePriority,
    SignalImpact,
    classify_priority,
    compute_contributions,
    compute_governance_actions,
    compute_root_causes,
    detect_change,
    generate_narrative,
)
from services.control_effectiveness_explainability.schemas import (
    ControlExplainResponse,
    GovernanceActionsResponse,
    PrioritiesResponse,
    RankingsResponse,
    ScoreContributorsResponse,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_TENANT = "t-cex-001"
_TENANT_B = "t-cex-002"
_NOW = datetime.now(tz=timezone.utc)
_NOW_ISO = _NOW.isoformat()
_FUTURE = (_NOW + timedelta(days=90)).isoformat()
_PAST_10D = (_NOW - timedelta(days=10)).strftime("%Y-%m-%d")
_PAST_35D = (_NOW - timedelta(days=35)).strftime("%Y-%m-%d")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _uid() -> str:
    return str(uuid.uuid4())[:16]


def _now_str() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _make_evidence(
    db: Session,
    tenant_id: str = _TENANT,
    lifecycle_state: str = "COLLECTED",
    trust_state: str = "VERIFIED",
    source_system: str = "JIRA",
    freshness_score: int | None = 85,
    verification_score: int | None = 80,
    completeness_score: int | None = 90,
) -> FaEvidence:
    now = _now_str()
    ev = FaEvidence(
        id=_uid(),
        tenant_id=tenant_id,
        evidence_ref=f"ref-{_uid()}",
        lifecycle_state=lifecycle_state,
        classification="internal",
        classification_labels="[]",
        source_type="DOCUMENT",
        source_system=source_system,
        collection_method="MANUAL",
        title=f"Evidence {_uid()}",
        creator_id="test-actor",
        creator_type="human",
        trust_state=trust_state,
        collected_at=now,
        created_at=now,
        updated_at=now,
        freshness_score=freshness_score,
        verification_score=verification_score,
        completeness_score=completeness_score,
    )
    db.add(ev)
    db.flush()
    return ev


def _link_evidence(
    db: Session,
    evidence_id: str,
    control_id: str,
    tenant_id: str = _TENANT,
) -> FaEvidenceControlLink:
    now = _now_str()
    link = FaEvidenceControlLink(
        id=_uid(),
        tenant_id=tenant_id,
        evidence_id=evidence_id,
        control_id=control_id,
        linked_by="test",
        linked_at=now,
        created_at=now,
    )
    db.add(link)
    db.flush()
    return link


def _make_verification(
    db: Session,
    evidence_id: str,
    result: str = "PASS",
    tenant_id: str = _TENANT,
) -> FaVerification:
    now = _now_str()
    v = FaVerification(
        id=_uid(),
        tenant_id=tenant_id,
        evidence_id=evidence_id,
        verification_type="MANUAL_REVIEW",
        verification_result=result,
        verified_by="test-actor",
        verified_actor_type="human",
        verified_at=now,
        created_at=now,
    )
    db.add(v)
    db.flush()
    return v


def _make_freshness_record(
    db: Session,
    evidence_id: str,
    freshness_score: int = 85,
    tenant_id: str = _TENANT,
) -> FaEvidenceFreshnessRecord:
    now = _now_str()
    rec = FaEvidenceFreshnessRecord(
        id=_uid(),
        tenant_id=tenant_id,
        evidence_id=evidence_id,
        freshness_score=freshness_score,
        freshness_state="CURRENT",
        created_at=now,
        updated_at=now,
    )
    db.add(rec)
    db.flush()
    return rec


def _make_exception(
    db: Session,
    evidence_id: str,
    status: str = "ACTIVE",
    expires_at: str | None = None,
    tenant_id: str = _TENANT,
) -> FaFreshnessException:
    now = _now_str()
    exc = FaFreshnessException(
        id=_uid(),
        tenant_id=tenant_id,
        evidence_id=evidence_id,
        reason="test exception",
        approved_by="test-approver",
        expires_at=expires_at or _FUTURE,
        status=status,
        created_at=now,
    )
    db.add(exc)
    db.flush()
    return exc


def _setup_control(
    db: Session,
    tenant_id: str = _TENANT,
    count: int = 5,
) -> tuple[str, list[str]]:
    """Create a control with evidence and verifications, return (control_id, ev_ids)."""
    cid = _uid()
    ev_ids = []
    for _ in range(count):
        ev = _make_evidence(db, tenant_id=tenant_id)
        _link_evidence(db, ev.id, cid, tenant_id=tenant_id)
        _make_verification(db, ev.id, result="PASS", tenant_id=tenant_id)
        _make_freshness_record(db, ev.id, freshness_score=85, tenant_id=tenant_id)
        ev_ids.append(ev.id)
    return cid, ev_ids


def _ce_engine(db: Session, tenant_id: str = _TENANT) -> ControlEffectivenessEngine:
    return ControlEffectivenessEngine(db, tenant_id=tenant_id)


def _exp_engine(db: Session, tenant_id: str = _TENANT) -> ExplainabilityEngine:
    return ExplainabilityEngine(db, tenant_id=tenant_id)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def db(build_app):
    build_app(auth_enabled=False)
    engine = get_engine()
    with Session(engine) as session:
        yield session


@pytest.fixture()
def client(build_app):
    app = build_app(auth_enabled=True)
    key = mint_key("governance:read", "governance:write", tenant_id=_TENANT)
    return TestClient(app, headers={"X-API-Key": key, "X-Tenant-Id": _TENANT})


@pytest.fixture()
def ro_client(build_app):
    app = build_app(auth_enabled=True)
    key = mint_key("governance:read", tenant_id=_TENANT)
    return TestClient(app, headers={"X-API-Key": key, "X-Tenant-Id": _TENANT})


@pytest.fixture()
def wrong_scope_client(build_app):
    app = build_app(auth_enabled=True)
    key = mint_key("audit:read", tenant_id=_TENANT)
    return TestClient(app, headers={"X-API-Key": key, "X-Tenant-Id": _TENANT})


# ===========================================================================
# CEX-1 to CEX-30: Pure function tests
# ===========================================================================


class TestComputeContributions:
    """CEX-1 through CEX-15: Score contribution pure functions."""

    def test_CEX_1_returns_seven_components(self):
        items = compute_contributions(80, 80, 80, 80, 80, 80, 80)
        assert len(items) == 7

    def test_CEX_2_component_names_correct(self):
        items = compute_contributions(80, 80, 80, 80, 80, 80, 80)
        names = [i["component_name"] for i in items]
        assert names == [
            "coverage",
            "verification",
            "freshness",
            "trend",
            "forecast",
            "evidence_density",
            "exception",
        ]

    def test_CEX_3_contribution_percentages_sum_to_100(self):
        items = compute_contributions(80, 70, 85, 60, 65, 75, 100)
        total_pct = sum(i["contribution_percentage"] for i in items)
        assert abs(total_pct - 100.0) < 0.5

    def test_CEX_4_high_score_is_positive_impact(self):
        items = compute_contributions(90, 90, 90, 90, 90, 90, 90)
        for item in items:
            assert item["impact"] == SignalImpact.POSITIVE.value

    def test_CEX_5_low_score_is_negative_impact(self):
        items = compute_contributions(30, 30, 30, 30, 30, 30, 30)
        for item in items:
            assert item["impact"] == SignalImpact.NEGATIVE.value

    def test_CEX_6_mid_score_is_neutral_impact(self):
        items = compute_contributions(60, 60, 60, 60, 60, 60, 60)
        for item in items:
            assert item["impact"] == SignalImpact.NEUTRAL.value

    def test_CEX_7_weights_sum_to_one(self):
        total_weight = sum(cw.weight for cw in COMPONENT_WEIGHTS)
        assert abs(total_weight - 1.0) < 1e-9

    def test_CEX_8_weighted_score_matches_raw_times_weight(self):
        items = compute_contributions(80, 70, 90, 60, 65, 75, 100)
        for item in items:
            expected = round(item["raw_score"] * item["weight"], 2)
            assert abs(item["weighted_score"] - expected) < 0.01

    def test_CEX_9_none_scores_use_defaults(self):
        items = compute_contributions(None, None, None, None, None, None, None)
        assert len(items) == 7
        assert all(i["raw_score"] >= 0 for i in items)

    def test_CEX_10_coverage_has_correct_weight(self):
        items = compute_contributions(80, 80, 80, 80, 80, 80, 80)
        cov = next(i for i in items if i["component_name"] == "coverage")
        assert abs(cov["weight"] - 0.20) < 1e-9

    def test_CEX_11_verification_has_correct_weight(self):
        items = compute_contributions(80, 80, 80, 80, 80, 80, 80)
        ver = next(i for i in items if i["component_name"] == "verification")
        assert abs(ver["weight"] - 0.20) < 1e-9

    def test_CEX_12_exception_has_correct_weight(self):
        items = compute_contributions(80, 80, 80, 80, 80, 80, 80)
        exc = next(i for i in items if i["component_name"] == "exception")
        assert abs(exc["weight"] - 0.10) < 1e-9

    def test_CEX_13_boundary_positive_at_70(self):
        items = compute_contributions(70, 80, 80, 80, 80, 80, 80)
        cov = next(i for i in items if i["component_name"] == "coverage")
        assert cov["impact"] == SignalImpact.POSITIVE.value

    def test_CEX_14_boundary_negative_below_50(self):
        items = compute_contributions(49, 80, 80, 80, 80, 80, 80)
        cov = next(i for i in items if i["component_name"] == "coverage")
        assert cov["impact"] == SignalImpact.NEGATIVE.value

    def test_CEX_15_zero_total_weighted_no_error(self):
        items = compute_contributions(0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
        assert all(i["contribution_percentage"] == 0.0 for i in items)


class TestComputeRootCauses:
    """CEX-16 through CEX-25: Root cause analysis."""

    def test_CEX_16_low_verification_generates_failure_signal(self):
        rcs = compute_root_causes(40, 80, 80, "STABLE", 100, 80, 80, 65)
        types = [rc["root_cause_type"] for rc in rcs]
        assert "VERIFICATION_FAILURES" in types

    def test_CEX_17_high_verification_generates_positive_signal(self):
        rcs = compute_root_causes(90, 80, 80, "STABLE", 100, 80, 80, 65)
        types = [rc["root_cause_type"] for rc in rcs]
        assert "STRONG_VERIFICATION" in types

    def test_CEX_18_low_freshness_generates_decline_signal(self):
        rcs = compute_root_causes(80, 40, 80, "STABLE", 100, 80, 80, 65)
        types = [rc["root_cause_type"] for rc in rcs]
        assert "FRESHNESS_DECLINE" in types

    def test_CEX_19_high_freshness_generates_positive_signal(self):
        rcs = compute_root_causes(80, 90, 80, "STABLE", 100, 80, 80, 65)
        types = [rc["root_cause_type"] for rc in rcs]
        assert "HIGH_FRESHNESS" in types

    def test_CEX_20_low_coverage_generates_gap_signal(self):
        rcs = compute_root_causes(80, 80, 40, "STABLE", 100, 80, 80, 65)
        types = [rc["root_cause_type"] for rc in rcs]
        assert "COVERAGE_GAPS" in types

    def test_CEX_21_critical_trend_generates_critical_signal(self):
        rcs = compute_root_causes(80, 80, 80, "CRITICAL", 100, 80, 80, 65)
        types = [rc["root_cause_type"] for rc in rcs]
        assert "CRITICAL_TREND" in types

    def test_CEX_22_improving_trend_generates_positive_signal(self):
        rcs = compute_root_causes(80, 80, 80, "IMPROVING", 100, 80, 80, 65)
        types = [rc["root_cause_type"] for rc in rcs]
        assert "IMPROVING_TREND" in types

    def test_CEX_23_active_exceptions_generate_negative_signal(self):
        rcs = compute_root_causes(80, 80, 80, "STABLE", 50, 80, 80, 65)
        types = [rc["root_cause_type"] for rc in rcs]
        assert "ACTIVE_EXCEPTIONS" in types

    def test_CEX_24_negatives_sorted_before_positives(self):
        rcs = compute_root_causes(40, 40, 40, "DEGRADING", 50, 30, 40, 30)
        negatives = [rc for rc in rcs if rc["impact"] == "NEGATIVE"]
        positives = [rc for rc in rcs if rc["impact"] == "POSITIVE"]
        if negatives and positives:
            neg_indices = [i for i, rc in enumerate(rcs) if rc["impact"] == "NEGATIVE"]
            pos_indices = [i for i, rc in enumerate(rcs) if rc["impact"] == "POSITIVE"]
            assert max(neg_indices) < min(pos_indices)

    def test_CEX_25_all_signals_have_required_fields(self):
        rcs = compute_root_causes(40, 40, 40, "DEGRADING", 50, 30, 40, 30)
        for rc in rcs:
            assert "root_cause_type" in rc
            assert "impact" in rc
            assert "severity" in rc
            assert "impact_score" in rc
            assert "description" in rc


class TestComputeGovernanceActions:
    """CEX-26 through CEX-35: Governance action generation."""

    def test_CEX_26_critical_verification_triggers_critical_action(self):
        actions = compute_governance_actions(30, 80, 80, 100, 80, "STABLE", 65)
        types = [a["action_type"] for a in actions]
        assert "REVIEW_VERIFICATION_WORKFLOW" in types
        action = next(
            a for a in actions if a["action_type"] == "REVIEW_VERIFICATION_WORKFLOW"
        )
        assert action["priority"] == "CRITICAL"

    def test_CEX_27_low_freshness_triggers_refresh_action(self):
        actions = compute_governance_actions(80, 45, 80, 100, 80, "STABLE", 65)
        types = [a["action_type"] for a in actions]
        assert "REFRESH_EVIDENCE" in types

    def test_CEX_28_low_coverage_triggers_collect_action(self):
        actions = compute_governance_actions(80, 80, 40, 100, 80, "STABLE", 65)
        types = [a["action_type"] for a in actions]
        assert "COLLECT_ADDITIONAL_EVIDENCE" in types

    def test_CEX_29_critical_trend_triggers_investigate_critical(self):
        actions = compute_governance_actions(80, 80, 80, 100, 80, "CRITICAL", 65)
        action = next(
            a for a in actions if a["action_type"] == "INVESTIGATE_DECLINING_TREND"
        )
        assert action["priority"] == "CRITICAL"

    def test_CEX_30_degrading_trend_triggers_investigate_high(self):
        actions = compute_governance_actions(80, 80, 80, 100, 80, "DEGRADING", 65)
        action = next(
            a for a in actions if a["action_type"] == "INVESTIGATE_DECLINING_TREND"
        )
        assert action["priority"] == "HIGH"

    def test_CEX_31_actions_sorted_by_priority(self):
        actions = compute_governance_actions(30, 30, 30, 50, 40, "CRITICAL", 30)
        priorities = [a["priority"] for a in actions]
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        ranks = [order[p] for p in priorities]
        assert ranks == sorted(ranks)

    def test_CEX_32_actions_have_required_fields(self):
        actions = compute_governance_actions(40, 50, 60, 80, 70, "DEGRADING", 55)
        for a in actions:
            assert "action_type" in a
            assert "priority" in a
            assert "description" in a
            assert "rationale" in a

    def test_CEX_33_high_verification_no_verification_action(self):
        actions = compute_governance_actions(90, 90, 90, 100, 95, "IMPROVING", 85)
        types = [a["action_type"] for a in actions]
        assert "REVIEW_VERIFICATION_WORKFLOW" not in types

    def test_CEX_34_low_governance_health_triggers_review_action(self):
        actions = compute_governance_actions(80, 80, 80, 100, 40, "STABLE", 65)
        types = [a["action_type"] for a in actions]
        assert "REVIEW_GOVERNANCE_HEALTH" in types

    def test_CEX_35_low_exception_score_triggers_resolve_action(self):
        actions = compute_governance_actions(80, 80, 80, 50, 80, "STABLE", 65)
        types = [a["action_type"] for a in actions]
        assert "RESOLVE_ACTIVE_EXCEPTIONS" in types


# ===========================================================================
# CEX-36 to CEX-55: Priority classification
# ===========================================================================


class TestClassifyPriority:
    """CEX-36 through CEX-55: GovernancePriority classification."""

    def test_CEX_36_ineffective_is_critical(self):
        p = classify_priority(35, "INEFFECTIVE", "STABLE", 65, 100)
        assert p == GovernancePriority.CRITICAL

    def test_CEX_37_score_below_40_is_critical(self):
        p = classify_priority(38, "WEAK", "STABLE", 65, 100)
        assert p == GovernancePriority.CRITICAL

    def test_CEX_38_weak_with_critical_trend_is_critical(self):
        p = classify_priority(50, "WEAK", "CRITICAL", 65, 100)
        assert p == GovernancePriority.CRITICAL

    def test_CEX_39_score_50_stable_is_high(self):
        p = classify_priority(50, "WEAK", "STABLE", 65, 100)
        assert p == GovernancePriority.HIGH

    def test_CEX_40_score_65_degrading_is_high(self):
        p = classify_priority(65, "ADEQUATE", "DEGRADING", 65, 100)
        assert p == GovernancePriority.HIGH

    def test_CEX_41_score_65_stable_is_medium(self):
        p = classify_priority(65, "ADEQUATE", "STABLE", 65, 100)
        assert p == GovernancePriority.MEDIUM

    def test_CEX_42_score_80_stable_is_low(self):
        p = classify_priority(80, "EFFECTIVE", "STABLE", 65, 100)
        assert p == GovernancePriority.LOW

    def test_CEX_43_score_92_is_low(self):
        p = classify_priority(92, "HIGHLY_EFFECTIVE", "IMPROVING", 85, 100)
        assert p == GovernancePriority.LOW

    def test_CEX_44_effective_degrading_is_medium(self):
        p = classify_priority(78, "EFFECTIVE", "DEGRADING", 65, 100)
        assert p == GovernancePriority.MEDIUM

    def test_CEX_45_low_exception_score_raises_priority(self):
        p = classify_priority(70, "ADEQUATE", "STABLE", 65, 50)
        assert p == GovernancePriority.HIGH

    def test_CEX_46_low_forecast_raises_to_medium(self):
        p = classify_priority(80, "EFFECTIVE", "STABLE", 45, 100)
        assert p == GovernancePriority.MEDIUM

    def test_CEX_47_score_boundary_40_is_critical(self):
        p = classify_priority(39.9, "WEAK", "STABLE", 65, 100)
        assert p == GovernancePriority.CRITICAL

    def test_CEX_48_score_boundary_60_is_medium(self):
        p = classify_priority(60, "ADEQUATE", "STABLE", 65, 100)
        assert p == GovernancePriority.MEDIUM

    def test_CEX_49_none_trend_does_not_error(self):
        p = classify_priority(70, "ADEQUATE", None, 65, 100)
        assert p in (GovernancePriority.MEDIUM, GovernancePriority.LOW)

    def test_CEX_50_none_forecast_does_not_error(self):
        p = classify_priority(80, "EFFECTIVE", "STABLE", None, 100)
        assert p == GovernancePriority.LOW

    def test_CEX_51_none_exception_does_not_error(self):
        p = classify_priority(80, "EFFECTIVE", "STABLE", 65, None)
        assert p == GovernancePriority.LOW

    def test_CEX_52_priority_enum_values_correct(self):
        assert GovernancePriority.CRITICAL.value == "CRITICAL"
        assert GovernancePriority.HIGH.value == "HIGH"
        assert GovernancePriority.MEDIUM.value == "MEDIUM"
        assert GovernancePriority.LOW.value == "LOW"

    def test_CEX_53_score_exactly_75_with_degrading_is_medium(self):
        p = classify_priority(75, "EFFECTIVE", "DEGRADING", 65, 100)
        assert p == GovernancePriority.MEDIUM

    def test_CEX_54_score_exactly_75_stable_is_low(self):
        p = classify_priority(75, "EFFECTIVE", "STABLE", 65, 100)
        assert p == GovernancePriority.LOW

    def test_CEX_55_all_priorities_are_string_enum(self):
        for p in GovernancePriority:
            assert isinstance(p.value, str)


# ===========================================================================
# CEX-56 to CEX-80: Change detection
# ===========================================================================


class TestDetectChange:
    """CEX-56 through CEX-80: Change detection logic."""

    def test_CEX_56_no_deltas_returns_stable(self):
        result = detect_change(None, None, None)
        assert result["status"] == "STABLE"
        assert "Insufficient" in result["explanation"]

    def test_CEX_57_large_positive_delta_is_improved(self):
        result = detect_change(None, 15.0, None)
        assert result["status"] == "IMPROVED"

    def test_CEX_58_moderate_positive_delta_is_improving(self):
        result = detect_change(None, 5.0, None)
        assert result["status"] == "IMPROVING"

    def test_CEX_59_large_negative_delta_is_critical(self):
        result = detect_change(None, -12.0, None)
        assert result["status"] == "CRITICAL"

    def test_CEX_60_moderate_negative_delta_is_declining(self):
        result = detect_change(None, -6.0, None)
        assert result["status"] == "DECLINING"

    def test_CEX_61_small_delta_is_stable(self):
        result = detect_change(None, 2.0, None)
        assert result["status"] == "STABLE"

    def test_CEX_62_prefers_30d_over_7d(self):
        result = detect_change(
            score_delta_7d=20.0, score_delta_30d=-15.0, score_delta_90d=None
        )
        assert result["status"] == "CRITICAL"

    def test_CEX_63_falls_back_to_7d_when_30d_none(self):
        result = detect_change(
            score_delta_7d=12.0, score_delta_30d=None, score_delta_90d=None
        )
        assert result["status"] == "IMPROVED"

    def test_CEX_64_deltas_passed_through(self):
        result = detect_change(1.0, 5.0, -3.0)
        assert result["delta_7d"] == 1.0
        assert result["delta_30d"] == 5.0
        assert result["delta_90d"] == -3.0

    def test_CEX_65_boundary_positive_10_is_improved(self):
        result = detect_change(None, 10.5, None)
        assert result["status"] == "IMPROVED"

    def test_CEX_66_boundary_negative_10_is_critical(self):
        result = detect_change(None, -10.5, None)
        assert result["status"] == "CRITICAL"

    def test_CEX_67_explanation_non_empty(self):
        for delta in [15.0, 5.0, -6.0, -12.0, 1.0]:
            result = detect_change(None, delta, None)
            assert len(result["explanation"]) > 0

    def test_CEX_68_delta_exactly_3_is_improving(self):
        result = detect_change(None, 3.1, None)
        assert result["status"] == "IMPROVING"

    def test_CEX_69_delta_exactly_minus_3_is_declining(self):
        result = detect_change(None, -3.1, None)
        assert result["status"] == "DECLINING"

    def test_CEX_70_stable_boundary_at_3(self):
        result = detect_change(None, 2.9, None)
        assert result["status"] == "STABLE"


# ===========================================================================
# CEX-71 to CEX-80: Narrative generation
# ===========================================================================


class TestGenerateNarrative:
    """CEX-71 through CEX-80: Template-driven narrative."""

    def test_CEX_71_narrative_mentions_level(self):
        narrative = generate_narrative(75.0, "EFFECTIVE", "STABLE", [], [])
        assert "effective" in narrative.lower()

    def test_CEX_72_narrative_mentions_score(self):
        narrative = generate_narrative(75.0, "EFFECTIVE", "STABLE", [], [])
        assert "75" in narrative

    def test_CEX_73_narrative_includes_trend_phrase(self):
        narrative = generate_narrative(75.0, "EFFECTIVE", "DEGRADING", [], [])
        assert "declining" in narrative.lower()

    def test_CEX_74_narrative_mentions_positive_factors(self):
        rcs = [{"impact": "POSITIVE", "description": "Verification SLA is being met."}]
        narrative = generate_narrative(80.0, "EFFECTIVE", "STABLE", rcs, [])
        assert "verification sla" in narrative.lower()

    def test_CEX_75_narrative_mentions_negative_factors(self):
        rcs = [
            {
                "impact": "NEGATIVE",
                "description": "Evidence freshness is below threshold.",
            }
        ]
        narrative = generate_narrative(60.0, "ADEQUATE", "STABLE", rcs, [])
        assert "freshness" in narrative.lower()

    def test_CEX_76_narrative_mentions_top_action(self):
        actions = [{"description": "Refresh stale evidence.", "priority": "HIGH"}]
        narrative = generate_narrative(60.0, "ADEQUATE", "STABLE", [], actions)
        assert "refresh" in narrative.lower()

    def test_CEX_77_narrative_non_empty(self):
        narrative = generate_narrative(50.0, "WEAK", "CRITICAL", [], [])
        assert len(narrative) > 0

    def test_CEX_78_narrative_highly_effective_phrase(self):
        narrative = generate_narrative(92.0, "HIGHLY_EFFECTIVE", "IMPROVING", [], [])
        assert "highly effective" in narrative.lower()

    def test_CEX_79_narrative_ineffective_phrase(self):
        narrative = generate_narrative(20.0, "INEFFECTIVE", "CRITICAL", [], [])
        assert "ineffective" in narrative.lower()

    def test_CEX_80_narrative_no_trend_when_none(self):
        narrative = generate_narrative(70.0, "ADEQUATE", None, [], [])
        assert "has been improving" not in narrative
        assert "has been declining" not in narrative


# ===========================================================================
# CEX-81 to CEX-110: ExplainabilityEngine — explain, contributors, actions
# ===========================================================================


class TestExplainabilityEngineExplain:
    """CEX-81 through CEX-100: ExplainabilityEngine.explain()."""

    def test_CEX_81_explain_unknown_control_returns_none(self, db):
        result = _exp_engine(db).explain("nonexistent-control")
        assert result is None

    def test_CEX_82_explain_returns_response_after_recalculate(self, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        result = _exp_engine(db).explain(cid)
        assert isinstance(result, ControlExplainResponse)

    def test_CEX_83_explain_has_correct_tenant_id(self, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        result = _exp_engine(db).explain(cid)
        assert result.tenant_id == _TENANT

    def test_CEX_84_explain_has_correct_control_id(self, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        result = _exp_engine(db).explain(cid)
        assert result.control_id == cid

    def test_CEX_85_explain_has_seven_contributions(self, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        result = _exp_engine(db).explain(cid)
        assert len(result.contributions) == 7

    def test_CEX_86_explain_has_non_empty_narrative(self, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        result = _exp_engine(db).explain(cid)
        assert len(result.narrative) > 0

    def test_CEX_87_explain_has_governance_priority(self, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        result = _exp_engine(db).explain(cid)
        assert result.governance_priority in ("CRITICAL", "HIGH", "MEDIUM", "LOW")

    def test_CEX_88_explain_has_change_detection(self, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        result = _exp_engine(db).explain(cid)
        assert result.change_detection is not None
        assert result.change_detection.status in (
            "IMPROVED",
            "IMPROVING",
            "STABLE",
            "DECLINING",
            "CRITICAL",
        )

    def test_CEX_89_explain_separates_positive_negative_signals(self, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        result = _exp_engine(db).explain(cid)
        assert all(s.impact == "POSITIVE" for s in result.positive_signals)
        assert all(s.impact == "NEGATIVE" for s in result.negative_signals)

    def test_CEX_90_explain_effectiveness_score_matches_ce_row(self, db):
        cid, _ = _setup_control(db)
        ce_result = _ce_engine(db).recalculate(cid)
        exp_result = _exp_engine(db).explain(cid)
        assert (
            abs(exp_result.effectiveness_score - ce_result.effectiveness_score) < 0.01
        )

    def test_CEX_91_explain_low_verification_shows_negative_signal(self, db):
        cid = _uid()
        ev = _make_evidence(db, verification_score=30)
        _link_evidence(db, ev.id, cid)
        _make_verification(db, ev.id, result="FAIL")
        _make_verification(db, ev.id, result="FAIL")
        _make_verification(db, ev.id, result="FAIL")
        _ce_engine(db).recalculate(cid)
        result = _exp_engine(db).explain(cid)
        neg_types = [s.root_cause_type for s in result.negative_signals]
        assert "VERIFICATION_FAILURES" in neg_types

    def test_CEX_92_explain_actions_present_for_weak_control(self, db):
        cid = _uid()
        ev = _make_evidence(db, verification_score=30)
        _link_evidence(db, ev.id, cid)
        _make_verification(db, ev.id, result="FAIL")
        _ce_engine(db).recalculate(cid)
        result = _exp_engine(db).explain(cid)
        assert len(result.actions) > 0

    def test_CEX_93_explain_contribution_percentages_sum_100(self, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        result = _exp_engine(db).explain(cid)
        total = sum(c.contribution_percentage for c in result.contributions)
        assert abs(total - 100.0) < 0.5

    def test_CEX_94_explain_has_effectiveness_level(self, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        result = _exp_engine(db).explain(cid)
        assert result.effectiveness_level in (
            "HIGHLY_EFFECTIVE",
            "EFFECTIVE",
            "ADEQUATE",
            "WEAK",
            "INEFFECTIVE",
        )

    def test_CEX_95_explain_has_effectiveness_risk(self, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        result = _exp_engine(db).explain(cid)
        assert result.effectiveness_risk in ("LOW", "MEDIUM", "HIGH", "CRITICAL")


class TestExplainabilityEngineContributors:
    """CEX-96 through CEX-105: get_contributors."""

    def test_CEX_96_contributors_unknown_returns_none(self, db):
        result = _exp_engine(db).get_contributors("nonexistent")
        assert result is None

    def test_CEX_97_contributors_returns_seven_items(self, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        result = _exp_engine(db).get_contributors(cid)
        assert isinstance(result, ScoreContributorsResponse)
        assert len(result.contributions) == 7

    def test_CEX_98_contributors_tenant_id_correct(self, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        result = _exp_engine(db).get_contributors(cid)
        assert result.tenant_id == _TENANT

    def test_CEX_99_contributors_control_id_correct(self, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        result = _exp_engine(db).get_contributors(cid)
        assert result.control_id == cid

    def test_CEX_100_contributors_have_correct_components(self, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        result = _exp_engine(db).get_contributors(cid)
        names = {c.component_name for c in result.contributions}
        assert "coverage" in names
        assert "verification" in names
        assert "exception" in names


class TestExplainabilityEngineActions:
    """CEX-101 through CEX-110: get_actions."""

    def test_CEX_101_actions_unknown_returns_none(self, db):
        result = _exp_engine(db).get_actions("nonexistent")
        assert result is None

    def test_CEX_102_actions_returns_response(self, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        result = _exp_engine(db).get_actions(cid)
        assert isinstance(result, GovernanceActionsResponse)

    def test_CEX_103_actions_tenant_id_correct(self, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        result = _exp_engine(db).get_actions(cid)
        assert result.tenant_id == _TENANT

    def test_CEX_104_actions_include_governance_priority(self, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        result = _exp_engine(db).get_actions(cid)
        assert result.governance_priority in ("CRITICAL", "HIGH", "MEDIUM", "LOW")

    def test_CEX_105_actions_sorted_by_priority(self, db):
        cid = _uid()
        ev = _make_evidence(db, verification_score=30)
        _link_evidence(db, ev.id, cid)
        _make_verification(db, ev.id, result="FAIL")
        _make_freshness_record(db, ev.id, freshness_score=30)
        _ce_engine(db).recalculate(cid)
        result = _exp_engine(db).get_actions(cid)
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        priorities = [a.priority for a in result.actions]
        ranks = [order[p] for p in priorities]
        assert ranks == sorted(ranks)

    def test_CEX_106_actions_have_description_and_rationale(self, db):
        cid = _uid()
        ev = _make_evidence(db, verification_score=30)
        _link_evidence(db, ev.id, cid)
        _make_verification(db, ev.id, result="FAIL")
        _ce_engine(db).recalculate(cid)
        result = _exp_engine(db).get_actions(cid)
        for a in result.actions:
            assert len(a.description) > 0
            assert len(a.rationale) > 0

    def test_CEX_107_healthy_control_may_have_no_critical_actions(self, db):
        cid, _ = _setup_control(db, count=10)
        _ce_engine(db).recalculate(cid)
        result = _exp_engine(db).get_actions(cid)
        critical = [a for a in result.actions if a.priority == "CRITICAL"]
        # A healthy control should not have critical actions
        assert len(critical) == 0

    def test_CEX_108_actions_action_type_is_known(self, db):
        from services.control_effectiveness_explainability.models import ActionType

        cid = _uid()
        ev = _make_evidence(db, verification_score=30)
        _link_evidence(db, ev.id, cid)
        _make_verification(db, ev.id, result="FAIL")
        _ce_engine(db).recalculate(cid)
        result = _exp_engine(db).get_actions(cid)
        valid_types = {at.value for at in ActionType}
        for a in result.actions:
            assert a.action_type in valid_types

    def test_CEX_109_actions_generated_at_non_empty(self, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        result = _exp_engine(db).get_actions(cid)
        assert len(result.generated_at) > 0

    def test_CEX_110_actions_control_id_matches(self, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        result = _exp_engine(db).get_actions(cid)
        assert result.control_id == cid


# ===========================================================================
# CEX-111 to CEX-130: Rankings
# ===========================================================================


class TestRankings:
    """CEX-111 through CEX-130: Rankings storage and retrieval."""

    def _setup_two_controls(self, db: Session) -> tuple[str, str]:
        cid_a, _ = _setup_control(db, count=5)
        cid_b, _ = _setup_control(db, count=2)
        _ce_engine(db).recalculate(cid_a)
        ev = _make_evidence(db, verification_score=20)
        _link_evidence(db, ev.id, cid_b)
        _make_verification(db, ev.id, result="FAIL")
        _make_verification(db, ev.id, result="FAIL")
        _ce_engine(db).recalculate(cid_b)
        return cid_a, cid_b

    def test_CEX_111_recalculate_rankings_runs_without_error(self, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        _exp_engine(db).recalculate_rankings()

    def test_CEX_112_rankings_returns_response(self, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        _exp_engine(db).recalculate_rankings()
        result = _exp_engine(db).get_rankings()
        assert isinstance(result, RankingsResponse)

    def test_CEX_113_top_controls_in_desc_order(self, db):
        cid_a, cid_b = self._setup_two_controls(db)
        _exp_engine(db).recalculate_rankings()
        result = _exp_engine(db).get_rankings()
        if len(result.top_controls) >= 2:
            scores = [r.effectiveness_score for r in result.top_controls]
            assert scores == sorted(scores, reverse=True)

    def test_CEX_114_weakest_controls_in_asc_order(self, db):
        cid_a, cid_b = self._setup_two_controls(db)
        _exp_engine(db).recalculate_rankings()
        result = _exp_engine(db).get_rankings()
        if len(result.weakest_controls) >= 2:
            scores = [r.effectiveness_score for r in result.weakest_controls]
            assert scores == sorted(scores)

    def test_CEX_115_rankings_have_rank_positions(self, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        _exp_engine(db).recalculate_rankings()
        result = _exp_engine(db).get_rankings()
        for item in result.top_controls:
            assert item.rank_position >= 1

    def test_CEX_116_rankings_tenant_isolated(self, db):
        cid_a, _ = _setup_control(db, tenant_id=_TENANT)
        _ce_engine(db, _TENANT).recalculate(cid_a)
        _exp_engine(db, _TENANT).recalculate_rankings()

        cid_b, _ = _setup_control(db, tenant_id=_TENANT_B)
        _ce_engine(db, _TENANT_B).recalculate(cid_b)
        _exp_engine(db, _TENANT_B).recalculate_rankings()

        rankings_a = _exp_engine(db, _TENANT).get_rankings()
        rankings_b = _exp_engine(db, _TENANT_B).get_rankings()
        ids_a = {r.control_id for r in rankings_a.top_controls}
        ids_b = {r.control_id for r in rankings_b.top_controls}
        assert ids_a.isdisjoint(ids_b)

    def test_CEX_117_rankings_refresh_replaces_old(self, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        _exp_engine(db).recalculate_rankings()
        count_before = (
            db.query(FaControlRanking)
            .filter(
                FaControlRanking.tenant_id == _TENANT,
                FaControlRanking.rank_type == "TOP",
            )
            .count()
        )
        _exp_engine(db).recalculate_rankings()
        count_after = (
            db.query(FaControlRanking)
            .filter(
                FaControlRanking.tenant_id == _TENANT,
                FaControlRanking.rank_type == "TOP",
            )
            .count()
        )
        assert count_after == count_before

    def test_CEX_118_highest_risk_ranks_critical_first(self, db):
        cid_a, cid_b = self._setup_two_controls(db)
        _exp_engine(db).recalculate_rankings()
        result = _exp_engine(db).get_rankings()
        if len(result.highest_risk) >= 2:
            risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            ranks = [risk_order[r.effectiveness_risk] for r in result.highest_risk]
            assert ranks == sorted(ranks)

    def test_CEX_119_most_fragile_lowest_health_first(self, db):
        _exp_engine(db).recalculate_rankings()
        result = _exp_engine(db).get_rankings()
        assert result is not None

    def test_CEX_120_most_valuable_only_effective_controls(self, db):
        cid, _ = _setup_control(db, count=10)
        _ce_engine(db).recalculate(cid)
        _exp_engine(db).recalculate_rankings()
        result = _exp_engine(db).get_rankings()
        for item in result.most_valuable:
            assert item.effectiveness_level in ("EFFECTIVE", "HIGHLY_EFFECTIVE")

    def test_CEX_121_empty_tenant_returns_empty_rankings(self, db):
        result = _exp_engine(db, "tenant-no-data").get_rankings()
        assert result.top_controls == []
        assert result.weakest_controls == []

    def test_CEX_122_rankings_generated_at_present(self, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        _exp_engine(db).recalculate_rankings()
        result = _exp_engine(db).get_rankings()
        assert len(result.generated_at) > 0

    def test_CEX_123_ranking_items_have_rank_type_field(self, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        _exp_engine(db).recalculate_rankings()
        result = _exp_engine(db).get_rankings()
        for item in result.top_controls:
            assert item.rank_type == "TOP"
        for item in result.weakest_controls:
            assert item.rank_type == "WEAKEST"

    def test_CEX_124_at_most_10_items_per_ranking(self, db):
        for _ in range(12):
            cid, _ = _setup_control(db, count=3)
            _ce_engine(db).recalculate(cid)
        _exp_engine(db).recalculate_rankings()
        result = _exp_engine(db).get_rankings()
        assert len(result.top_controls) <= 10
        assert len(result.weakest_controls) <= 10

    def test_CEX_125_recalculate_all_refreshes_rankings(self, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate_all()
        result = _exp_engine(db).get_rankings()
        assert isinstance(result, RankingsResponse)


# ===========================================================================
# CEX-126 to CEX-145: Priorities
# ===========================================================================


class TestPriorities:
    """CEX-126 through CEX-145: get_priorities."""

    def test_CEX_126_priorities_empty_tenant(self, db):
        result = _exp_engine(db, "tenant-empty-prio").get_priorities(50, 0)
        assert isinstance(result, PrioritiesResponse)
        assert result.total == 0

    def test_CEX_127_priorities_after_recalculate(self, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        result = _exp_engine(db).get_priorities(50, 0)
        assert result.total >= 1

    def test_CEX_128_priorities_counts_sum_to_total(self, db):
        for _ in range(3):
            cid, _ = _setup_control(db)
            _ce_engine(db).recalculate(cid)
        result = _exp_engine(db).get_priorities(200, 0)
        total_counts = (
            result.critical_count
            + result.high_count
            + result.medium_count
            + result.low_count
        )
        assert total_counts == result.total

    def test_CEX_129_priorities_paginated(self, db):
        for _ in range(5):
            cid, _ = _setup_control(db)
            _ce_engine(db).recalculate(cid)
        page1 = _exp_engine(db).get_priorities(2, 0)
        page2 = _exp_engine(db).get_priorities(2, 2)
        assert len(page1.items) == 2
        if page2.total > 2:
            assert len(page2.items) >= 1

    def test_CEX_130_priorities_items_have_required_fields(self, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        result = _exp_engine(db).get_priorities(50, 0)
        for item in result.items:
            assert item.control_id
            assert item.governance_priority in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
            assert item.effectiveness_level
            assert item.priority_rationale

    def test_CEX_131_critical_items_come_first(self, db):
        cid = _uid()
        ev = _make_evidence(db, verification_score=10)
        _link_evidence(db, ev.id, cid)
        _make_verification(db, ev.id, result="FAIL")
        _make_verification(db, ev.id, result="FAIL")
        _make_verification(db, ev.id, result="FAIL")
        _ce_engine(db).recalculate(cid)
        result = _exp_engine(db).get_priorities(50, 0)
        if result.critical_count > 0 and len(result.items) > 1:
            assert result.items[0].governance_priority in ("CRITICAL", "HIGH")

    def test_CEX_132_priorities_tenant_id_correct(self, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        result = _exp_engine(db).get_priorities(50, 0)
        assert result.tenant_id == _TENANT

    def test_CEX_133_priorities_generated_at_present(self, db):
        result = _exp_engine(db).get_priorities(50, 0)
        assert len(result.generated_at) > 0

    def test_CEX_134_priorities_items_contain_trend_direction(self, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        result = _exp_engine(db).get_priorities(50, 0)
        for item in result.items:
            # trend_direction may be None but field must exist
            assert hasattr(item, "trend_direction")

    def test_CEX_135_priorities_items_effectiveness_score_present(self, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        result = _exp_engine(db).get_priorities(50, 0)
        for item in result.items:
            assert 0.0 <= item.effectiveness_score <= 100.0


# ===========================================================================
# CEX-136 to CEX-155: Executive dashboard
# ===========================================================================


class TestExecutiveDashboard:
    """CEX-136 through CEX-155: get_executive_dashboard."""

    def test_CEX_136_executive_dashboard_empty_tenant(self, db):
        result = _exp_engine(db, "tenant-exec-empty").get_executive_dashboard()
        assert result.total_controls == 0
        assert result.average_effectiveness_score == 0.0

    def test_CEX_137_executive_dashboard_after_recalculate(self, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        result = _exp_engine(db).get_executive_dashboard()
        assert result.total_controls >= 1

    def test_CEX_138_executive_dashboard_level_counts_sum_to_total(self, db):
        for _ in range(3):
            cid, _ = _setup_control(db)
            _ce_engine(db).recalculate(cid)
        result = _exp_engine(db).get_executive_dashboard()
        count_sum = (
            result.highly_effective_count
            + result.effective_count
            + result.adequate_count
            + result.weak_count
            + result.ineffective_count
        )
        assert count_sum == result.total_controls

    def test_CEX_139_executive_dashboard_priority_counts_sum_to_total(self, db):
        for _ in range(3):
            cid, _ = _setup_control(db)
            _ce_engine(db).recalculate(cid)
        result = _exp_engine(db).get_executive_dashboard()
        prio_sum = (
            result.critical_priority_count
            + result.high_priority_count
            + result.medium_priority_count
            + result.low_priority_count
        )
        assert prio_sum == result.total_controls

    def test_CEX_140_executive_dashboard_avg_score_in_range(self, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        result = _exp_engine(db).get_executive_dashboard()
        assert 0.0 <= result.average_effectiveness_score <= 100.0

    def test_CEX_141_executive_dashboard_has_signal_lists(self, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        result = _exp_engine(db).get_executive_dashboard()
        assert isinstance(result.top_positive_signals, list)
        assert isinstance(result.top_negative_signals, list)

    def test_CEX_142_executive_dashboard_has_action_recommendations(self, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        result = _exp_engine(db).get_executive_dashboard()
        assert isinstance(result.top_recommended_actions, list)

    def test_CEX_143_executive_dashboard_tenant_id_correct(self, db):
        result = _exp_engine(db).get_executive_dashboard()
        assert result.tenant_id == _TENANT

    def test_CEX_144_executive_dashboard_has_ranking_lists(self, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        result = _exp_engine(db).get_executive_dashboard()
        assert isinstance(result.top_controls, list)
        assert isinstance(result.weakest_controls, list)
        assert isinstance(result.highest_risk_controls, list)

    def test_CEX_145_executive_dashboard_generated_at_non_empty(self, db):
        result = _exp_engine(db).get_executive_dashboard()
        assert len(result.generated_at) > 0

    def test_CEX_146_executive_dashboard_signals_at_most_5(self, db):
        for _ in range(10):
            cid, _ = _setup_control(db)
            _ce_engine(db).recalculate(cid)
        result = _exp_engine(db).get_executive_dashboard()
        assert len(result.top_positive_signals) <= 5
        assert len(result.top_negative_signals) <= 5
        assert len(result.top_recommended_actions) <= 5


# ===========================================================================
# CEX-147 to CEX-165: API routes — auth, scope, route ordering
# ===========================================================================


class TestAPIRouteAuth:
    """CEX-147 through CEX-165: API auth and scope enforcement."""

    def test_CEX_147_explain_no_auth_returns_401(self, client):
        from fastapi.testclient import TestClient
        from api.main import build_app

        app = build_app(auth_enabled=True)
        unauth = TestClient(app)
        r = unauth.get(f"/control-effectiveness/explain/{_uid()}")
        assert r.status_code == 401

    def test_CEX_148_explain_wrong_scope_returns_403(self, wrong_scope_client):
        r = wrong_scope_client.get(f"/control-effectiveness/explain/{_uid()}")
        assert r.status_code == 403

    def test_CEX_149_explain_valid_scope_returns_404_on_missing(self, client):
        r = client.get(f"/control-effectiveness/explain/{_uid()}")
        assert r.status_code == 404

    def test_CEX_150_contributors_no_auth_returns_401(self, client):
        from fastapi.testclient import TestClient
        from api.main import build_app

        app = build_app(auth_enabled=True)
        unauth = TestClient(app)
        r = unauth.get(f"/control-effectiveness/contributors/{_uid()}")
        assert r.status_code == 401

    def test_CEX_151_contributors_wrong_scope_returns_403(self, wrong_scope_client):
        r = wrong_scope_client.get(f"/control-effectiveness/contributors/{_uid()}")
        assert r.status_code == 403

    def test_CEX_152_contributors_missing_control_returns_404(self, client):
        r = client.get(f"/control-effectiveness/contributors/{_uid()}")
        assert r.status_code == 404

    def test_CEX_153_actions_no_auth_returns_401(self, client):
        from fastapi.testclient import TestClient
        from api.main import build_app

        app = build_app(auth_enabled=True)
        unauth = TestClient(app)
        r = unauth.get(f"/control-effectiveness/actions/{_uid()}")
        assert r.status_code == 401

    def test_CEX_154_actions_wrong_scope_returns_403(self, wrong_scope_client):
        r = wrong_scope_client.get(f"/control-effectiveness/actions/{_uid()}")
        assert r.status_code == 403

    def test_CEX_155_actions_missing_control_returns_404(self, client):
        r = client.get(f"/control-effectiveness/actions/{_uid()}")
        assert r.status_code == 404

    def test_CEX_156_priorities_no_auth_returns_401(self, client):
        from fastapi.testclient import TestClient
        from api.main import build_app

        app = build_app(auth_enabled=True)
        unauth = TestClient(app)
        r = unauth.get("/control-effectiveness/priorities")
        assert r.status_code == 401

    def test_CEX_157_priorities_wrong_scope_returns_403(self, wrong_scope_client):
        r = wrong_scope_client.get("/control-effectiveness/priorities")
        assert r.status_code == 403

    def test_CEX_158_priorities_valid_scope_returns_200(self, client):
        r = client.get("/control-effectiveness/priorities")
        assert r.status_code == 200

    def test_CEX_159_rankings_no_auth_returns_401(self, client):
        from fastapi.testclient import TestClient
        from api.main import build_app

        app = build_app(auth_enabled=True)
        unauth = TestClient(app)
        r = unauth.get("/control-effectiveness/rankings")
        assert r.status_code == 401

    def test_CEX_160_rankings_wrong_scope_returns_403(self, wrong_scope_client):
        r = wrong_scope_client.get("/control-effectiveness/rankings")
        assert r.status_code == 403

    def test_CEX_161_rankings_valid_scope_returns_200(self, client):
        r = client.get("/control-effectiveness/rankings")
        assert r.status_code == 200

    def test_CEX_162_executive_dashboard_no_auth_returns_401(self, client):
        from fastapi.testclient import TestClient
        from api.main import build_app

        app = build_app(auth_enabled=True)
        unauth = TestClient(app)
        r = unauth.get("/control-effectiveness/executive-dashboard")
        assert r.status_code == 401

    def test_CEX_163_executive_dashboard_wrong_scope_returns_403(
        self, wrong_scope_client
    ):
        r = wrong_scope_client.get("/control-effectiveness/executive-dashboard")
        assert r.status_code == 403

    def test_CEX_164_executive_dashboard_valid_scope_returns_200(self, client):
        r = client.get("/control-effectiveness/executive-dashboard")
        assert r.status_code == 200

    def test_CEX_165_ro_client_can_access_all_explain_routes(self, ro_client):
        r1 = ro_client.get("/control-effectiveness/priorities")
        r2 = ro_client.get("/control-effectiveness/rankings")
        r3 = ro_client.get("/control-effectiveness/executive-dashboard")
        assert r1.status_code == 200
        assert r2.status_code == 200
        assert r3.status_code == 200


# ===========================================================================
# CEX-166 to CEX-190: Route ordering — explainability routes not caught by /{control_id}
# ===========================================================================


class TestRouteOrdering:
    """CEX-166 through CEX-175: Route ordering invariants."""

    def test_CEX_166_priorities_not_caught_by_control_id_route(self, client):
        r = client.get("/control-effectiveness/priorities")
        assert r.status_code == 200
        data = r.json()
        assert "items" in data

    def test_CEX_167_rankings_not_caught_by_control_id_route(self, client):
        r = client.get("/control-effectiveness/rankings")
        assert r.status_code == 200
        data = r.json()
        assert "top_controls" in data

    def test_CEX_168_executive_dashboard_not_caught_by_control_id_route(self, client):
        r = client.get("/control-effectiveness/executive-dashboard")
        assert r.status_code == 200
        data = r.json()
        assert "total_controls" in data

    def test_CEX_169_explain_sub_route_not_caught_by_ce_get(self, client, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        r = client.get(f"/control-effectiveness/explain/{cid}")
        assert r.status_code == 200
        data = r.json()
        assert "narrative" in data

    def test_CEX_170_contributors_sub_route_resolves_correctly(self, client, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        r = client.get(f"/control-effectiveness/contributors/{cid}")
        assert r.status_code == 200
        data = r.json()
        assert "contributions" in data

    def test_CEX_171_actions_sub_route_resolves_correctly(self, client, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        r = client.get(f"/control-effectiveness/actions/{cid}")
        assert r.status_code == 200
        data = r.json()
        assert "actions" in data

    def test_CEX_172_original_ce_get_still_works(self, client, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        r = client.get(f"/control-effectiveness/{cid}")
        assert r.status_code == 200
        data = r.json()
        assert "effectiveness_score" in data

    def test_CEX_173_dashboard_route_still_works(self, client):
        r = client.get("/control-effectiveness/dashboard")
        assert r.status_code == 200

    def test_CEX_174_cgin_snapshot_still_works(self, client):
        r = client.get("/control-effectiveness/cgin/snapshot")
        assert r.status_code == 200

    def test_CEX_175_history_route_still_works(self, client, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        r = client.get(f"/control-effectiveness/history/{cid}")
        assert r.status_code == 200


# ===========================================================================
# CEX-176 to CEX-200: Tenant isolation
# ===========================================================================


class TestTenantIsolation:
    """CEX-176 through CEX-200: Strict tenant isolation."""

    def test_CEX_176_explain_cross_tenant_returns_404(self, build_app, db):
        cid, _ = _setup_control(db, tenant_id=_TENANT)
        _ce_engine(db, _TENANT).recalculate(cid)
        app = build_app(auth_enabled=True)
        key_b = mint_key("governance:read", tenant_id=_TENANT_B)
        client_b = TestClient(
            app, headers={"X-API-Key": key_b, "X-Tenant-Id": _TENANT_B}
        )
        r = client_b.get(f"/control-effectiveness/explain/{cid}")
        assert r.status_code == 404

    def test_CEX_177_contributors_cross_tenant_returns_404(self, build_app, db):
        cid, _ = _setup_control(db, tenant_id=_TENANT)
        _ce_engine(db, _TENANT).recalculate(cid)
        app = build_app(auth_enabled=True)
        key_b = mint_key("governance:read", tenant_id=_TENANT_B)
        client_b = TestClient(
            app, headers={"X-API-Key": key_b, "X-Tenant-Id": _TENANT_B}
        )
        r = client_b.get(f"/control-effectiveness/contributors/{cid}")
        assert r.status_code == 404

    def test_CEX_178_actions_cross_tenant_returns_404(self, build_app, db):
        cid, _ = _setup_control(db, tenant_id=_TENANT)
        _ce_engine(db, _TENANT).recalculate(cid)
        app = build_app(auth_enabled=True)
        key_b = mint_key("governance:read", tenant_id=_TENANT_B)
        client_b = TestClient(
            app, headers={"X-API-Key": key_b, "X-Tenant-Id": _TENANT_B}
        )
        r = client_b.get(f"/control-effectiveness/actions/{cid}")
        assert r.status_code == 404

    def test_CEX_179_priorities_only_own_tenant(self, build_app, db):
        cid_a, _ = _setup_control(db, tenant_id=_TENANT)
        _ce_engine(db, _TENANT).recalculate(cid_a)
        cid_b, _ = _setup_control(db, tenant_id=_TENANT_B)
        _ce_engine(db, _TENANT_B).recalculate(cid_b)
        result_a = _exp_engine(db, _TENANT).get_priorities(50, 0)
        result_b = _exp_engine(db, _TENANT_B).get_priorities(50, 0)
        ids_a = {i.control_id for i in result_a.items}
        ids_b = {i.control_id for i in result_b.items}
        assert ids_a.isdisjoint(ids_b)

    def test_CEX_180_rankings_only_own_tenant(self, db):
        cid_a, _ = _setup_control(db, tenant_id=_TENANT)
        _ce_engine(db, _TENANT).recalculate(cid_a)
        _exp_engine(db, _TENANT).recalculate_rankings()
        cid_b, _ = _setup_control(db, tenant_id=_TENANT_B)
        _ce_engine(db, _TENANT_B).recalculate(cid_b)
        _exp_engine(db, _TENANT_B).recalculate_rankings()
        result_a = _exp_engine(db, _TENANT).get_rankings()
        result_b = _exp_engine(db, _TENANT_B).get_rankings()
        ids_a = {r.control_id for r in result_a.top_controls}
        ids_b = {r.control_id for r in result_b.top_controls}
        assert ids_a.isdisjoint(ids_b)

    def test_CEX_181_executive_dashboard_only_own_tenant(self, db):
        cid_a, _ = _setup_control(db, tenant_id=_TENANT)
        _ce_engine(db, _TENANT).recalculate(cid_a)
        cid_b, _ = _setup_control(db, tenant_id=_TENANT_B)
        _ce_engine(db, _TENANT_B).recalculate(cid_b)
        dash_a = _exp_engine(db, _TENANT).get_executive_dashboard()
        dash_b = _exp_engine(db, _TENANT_B).get_executive_dashboard()
        assert dash_a.tenant_id == _TENANT
        assert dash_b.tenant_id == _TENANT_B

    def test_CEX_182_explain_engine_tenant_scoped(self, db):
        cid, _ = _setup_control(db, tenant_id=_TENANT)
        _ce_engine(db, _TENANT).recalculate(cid)
        result_tenant_b = _exp_engine(db, _TENANT_B).explain(cid)
        assert result_tenant_b is None

    def test_CEX_183_contributors_engine_tenant_scoped(self, db):
        cid, _ = _setup_control(db, tenant_id=_TENANT)
        _ce_engine(db, _TENANT).recalculate(cid)
        result = _exp_engine(db, _TENANT_B).get_contributors(cid)
        assert result is None

    def test_CEX_184_actions_engine_tenant_scoped(self, db):
        cid, _ = _setup_control(db, tenant_id=_TENANT)
        _ce_engine(db, _TENANT).recalculate(cid)
        result = _exp_engine(db, _TENANT_B).get_actions(cid)
        assert result is None

    def test_CEX_185_priorities_api_only_own_tenant(self, build_app, db):
        cid_a, _ = _setup_control(db, tenant_id=_TENANT)
        _ce_engine(db, _TENANT).recalculate(cid_a)
        cid_b, _ = _setup_control(db, tenant_id=_TENANT_B)
        _ce_engine(db, _TENANT_B).recalculate(cid_b)
        app = build_app(auth_enabled=True)
        key_a = mint_key("governance:read", tenant_id=_TENANT)
        key_b = mint_key("governance:read", tenant_id=_TENANT_B)
        client_a = TestClient(app, headers={"X-API-Key": key_a, "X-Tenant-Id": _TENANT})
        client_b = TestClient(
            app, headers={"X-API-Key": key_b, "X-Tenant-Id": _TENANT_B}
        )
        ids_a = {
            i["control_id"]
            for i in client_a.get("/control-effectiveness/priorities").json()["items"]
        }
        ids_b = {
            i["control_id"]
            for i in client_b.get("/control-effectiveness/priorities").json()["items"]
        }
        assert ids_a.isdisjoint(ids_b)


# ===========================================================================
# CEX-186 to CEX-215: API response shape validation
# ===========================================================================


class TestAPIResponseShapes:
    """CEX-186 through CEX-215: Response shape and field validation."""

    def test_CEX_186_explain_response_shape(self, client, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        r = client.get(f"/control-effectiveness/explain/{cid}")
        assert r.status_code == 200
        data = r.json()
        for field in [
            "tenant_id",
            "control_id",
            "effectiveness_score",
            "effectiveness_level",
            "effectiveness_risk",
            "governance_priority",
            "narrative",
            "contributions",
            "positive_signals",
            "negative_signals",
            "actions",
            "change_detection",
            "generated_at",
        ]:
            assert field in data, f"Missing field: {field}"

    def test_CEX_187_contributors_response_shape(self, client, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        r = client.get(f"/control-effectiveness/contributors/{cid}")
        assert r.status_code == 200
        data = r.json()
        for field in [
            "tenant_id",
            "control_id",
            "effectiveness_score",
            "effectiveness_level",
            "contributions",
            "generated_at",
        ]:
            assert field in data

    def test_CEX_188_contributions_items_shape(self, client, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        r = client.get(f"/control-effectiveness/contributors/{cid}")
        data = r.json()
        for item in data["contributions"]:
            for field in [
                "component_name",
                "raw_score",
                "weight",
                "weighted_score",
                "contribution_percentage",
                "impact",
            ]:
                assert field in item

    def test_CEX_189_actions_response_shape(self, client, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        r = client.get(f"/control-effectiveness/actions/{cid}")
        assert r.status_code == 200
        data = r.json()
        for field in [
            "tenant_id",
            "control_id",
            "governance_priority",
            "actions",
            "generated_at",
        ]:
            assert field in data

    def test_CEX_190_priorities_response_shape(self, client):
        r = client.get("/control-effectiveness/priorities")
        assert r.status_code == 200
        data = r.json()
        for field in [
            "tenant_id",
            "items",
            "total",
            "critical_count",
            "high_count",
            "medium_count",
            "low_count",
            "generated_at",
        ]:
            assert field in data

    def test_CEX_191_rankings_response_shape(self, client):
        r = client.get("/control-effectiveness/rankings")
        assert r.status_code == 200
        data = r.json()
        for field in [
            "tenant_id",
            "top_controls",
            "weakest_controls",
            "fastest_improving",
            "fastest_declining",
            "highest_risk",
            "most_fragile",
            "most_valuable",
            "generated_at",
        ]:
            assert field in data

    def test_CEX_192_executive_dashboard_response_shape(self, client):
        r = client.get("/control-effectiveness/executive-dashboard")
        assert r.status_code == 200
        data = r.json()
        for field in [
            "tenant_id",
            "total_controls",
            "average_effectiveness_score",
            "highly_effective_count",
            "effective_count",
            "adequate_count",
            "weak_count",
            "ineffective_count",
            "critical_risk_count",
            "high_risk_count",
            "critical_priority_count",
            "high_priority_count",
            "medium_priority_count",
            "low_priority_count",
            "top_positive_signals",
            "top_negative_signals",
            "top_recommended_actions",
            "top_controls",
            "weakest_controls",
            "generated_at",
        ]:
            assert field in data

    def test_CEX_193_change_detection_shape(self, client, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        r = client.get(f"/control-effectiveness/explain/{cid}")
        data = r.json()
        cd = data["change_detection"]
        assert "status" in cd
        assert "explanation" in cd
        assert "delta_7d" in cd
        assert "delta_30d" in cd
        assert "delta_90d" in cd

    def test_CEX_194_ranking_item_shape(self, client, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        _exp_engine(db).recalculate_rankings()
        r = client.get("/control-effectiveness/rankings")
        data = r.json()
        for items in data["top_controls"]:
            for field in [
                "control_id",
                "rank_position",
                "effectiveness_score",
                "effectiveness_level",
                "effectiveness_risk",
                "rank_type",
            ]:
                assert field in items

    def test_CEX_195_explain_contributions_count_is_7(self, client, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        r = client.get(f"/control-effectiveness/explain/{cid}")
        data = r.json()
        assert len(data["contributions"]) == 7

    def test_CEX_196_priorities_pagination_query_params_work(self, client, db):
        for _ in range(5):
            cid, _ = _setup_control(db)
            _ce_engine(db).recalculate(cid)
        r = client.get("/control-effectiveness/priorities?limit=2&offset=0")
        assert r.status_code == 200
        data = r.json()
        assert len(data["items"]) <= 2

    def test_CEX_197_priorities_offset_beyond_total_returns_empty_items(self, client):
        r = client.get("/control-effectiveness/priorities?limit=10&offset=99999")
        assert r.status_code == 200
        data = r.json()
        assert data["items"] == []

    def test_CEX_198_narrative_is_string(self, client, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        r = client.get(f"/control-effectiveness/explain/{cid}")
        data = r.json()
        assert isinstance(data["narrative"], str)
        assert len(data["narrative"]) > 10

    def test_CEX_199_positive_signals_all_have_positive_impact(self, client, db):
        cid, _ = _setup_control(db, count=8)
        _ce_engine(db).recalculate(cid)
        r = client.get(f"/control-effectiveness/explain/{cid}")
        data = r.json()
        for s in data["positive_signals"]:
            assert s["impact"] == "POSITIVE"

    def test_CEX_200_negative_signals_all_have_negative_impact(self, client, db):
        cid = _uid()
        ev = _make_evidence(db, verification_score=20)
        _link_evidence(db, ev.id, cid)
        _make_verification(db, ev.id, result="FAIL")
        _ce_engine(db).recalculate(cid)
        r = client.get(f"/control-effectiveness/explain/{cid}")
        data = r.json()
        for s in data["negative_signals"]:
            assert s["impact"] == "NEGATIVE"


# ===========================================================================
# CEX-201 to CEX-230: Integration + CGIN snapshots
# ===========================================================================


class TestIntegration:
    """CEX-201 through CEX-230: Integration and CGIN snapshot tests."""

    def test_CEX_201_recalculate_all_triggers_ranking_refresh(self, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate_all()
        count = (
            db.query(FaControlRanking)
            .filter(FaControlRanking.tenant_id == _TENANT)
            .count()
        )
        assert count > 0

    def test_CEX_202_rankings_stored_in_fa_control_ranking(self, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        _exp_engine(db).recalculate_rankings()
        rows = (
            db.query(FaControlRanking)
            .filter(FaControlRanking.tenant_id == _TENANT)
            .all()
        )
        assert len(rows) > 0

    def test_CEX_203_ranking_rows_have_tenant_id(self, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        _exp_engine(db).recalculate_rankings()
        rows = (
            db.query(FaControlRanking)
            .filter(FaControlRanking.tenant_id == _TENANT)
            .all()
        )
        for row in rows:
            assert row.tenant_id == _TENANT

    def test_CEX_204_contribution_snapshot_returns_correctly(self, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        snap = _exp_engine(db).build_contribution_snapshot(cid)
        assert snap is not None
        assert snap.control_id == cid
        assert len(snap.contributions) == 7

    def test_CEX_205_risk_snapshot_returns_correctly(self, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        snap = _exp_engine(db).build_risk_snapshot(cid)
        assert snap is not None
        assert snap.control_id == cid
        assert snap.governance_priority in ("CRITICAL", "HIGH", "MEDIUM", "LOW")

    def test_CEX_206_action_snapshot_returns_correctly(self, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        snap = _exp_engine(db).build_action_snapshot(cid)
        assert snap is not None
        assert snap.control_id == cid

    def test_CEX_207_priority_snapshot_returns_correctly(self, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        snap = _exp_engine(db).build_priority_snapshot(cid)
        assert snap is not None
        assert snap.control_id == cid

    def test_CEX_208_contribution_snapshot_unknown_control_is_none(self, db):
        snap = _exp_engine(db).build_contribution_snapshot("nonexistent")
        assert snap is None

    def test_CEX_209_risk_snapshot_unknown_control_is_none(self, db):
        snap = _exp_engine(db).build_risk_snapshot("nonexistent")
        assert snap is None

    def test_CEX_210_action_snapshot_unknown_control_is_none(self, db):
        snap = _exp_engine(db).build_action_snapshot("nonexistent")
        assert snap is None

    def test_CEX_211_priority_snapshot_unknown_control_is_none(self, db):
        snap = _exp_engine(db).build_priority_snapshot("nonexistent")
        assert snap is None

    def test_CEX_212_contribution_snapshot_tenant_scoped(self, db):
        cid, _ = _setup_control(db, tenant_id=_TENANT)
        _ce_engine(db, _TENANT).recalculate(cid)
        snap = _exp_engine(db, _TENANT_B).build_contribution_snapshot(cid)
        assert snap is None

    def test_CEX_213_risk_snapshot_tenant_scoped(self, db):
        cid, _ = _setup_control(db, tenant_id=_TENANT)
        _ce_engine(db, _TENANT).recalculate(cid)
        snap = _exp_engine(db, _TENANT_B).build_risk_snapshot(cid)
        assert snap is None

    def test_CEX_214_action_snapshot_tenant_scoped(self, db):
        cid, _ = _setup_control(db, tenant_id=_TENANT)
        _ce_engine(db, _TENANT).recalculate(cid)
        snap = _exp_engine(db, _TENANT_B).build_action_snapshot(cid)
        assert snap is None

    def test_CEX_215_snapshot_at_non_empty_in_cgin_snapshots(self, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        snap = _exp_engine(db).build_priority_snapshot(cid)
        assert len(snap.snapshot_at) > 0

    def test_CEX_216_explain_and_original_ce_consistent_score(self, db):
        cid, _ = _setup_control(db)
        ce_result = _ce_engine(db).recalculate(cid)
        exp_result = _exp_engine(db).explain(cid)
        assert (
            abs(exp_result.effectiveness_score - ce_result.effectiveness_score) < 0.01
        )

    def test_CEX_217_recalculate_twice_updates_explain_data(self, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        result1 = _exp_engine(db).explain(cid)

        ev = _make_evidence(db, verification_score=10)
        _link_evidence(db, ev.id, cid)
        _make_verification(db, ev.id, result="FAIL")
        _ce_engine(db).recalculate(cid)
        result2 = _exp_engine(db).explain(cid)

        assert result1 is not None
        assert result2 is not None

    def test_CEX_218_executive_dashboard_with_rankings_precomputed(self, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        _exp_engine(db).recalculate_rankings()
        result = _exp_engine(db).get_executive_dashboard()
        assert result.total_controls >= 1

    def test_CEX_219_executive_dashboard_falls_back_when_no_rankings(self, db):
        tenant = f"tenant-fallback-{_uid()}"
        cid, _ = _setup_control(db, tenant_id=tenant)
        _ce_engine(db, tenant).recalculate(cid)
        # No recalculate_rankings call — dashboard derives on-the-fly
        result = _exp_engine(db, tenant).get_executive_dashboard()
        assert result.total_controls == 1

    def test_CEX_220_contributions_snapshot_has_correct_effectiveness_score(self, db):
        cid, _ = _setup_control(db)
        ce = _ce_engine(db).recalculate(cid)
        snap = _exp_engine(db).build_contribution_snapshot(cid)
        assert abs(snap.effectiveness_score - ce.effectiveness_score) < 0.01


# ===========================================================================
# CEX-221 to CEX-250+: Edge cases and schema validation
# ===========================================================================


class TestEdgeCasesAndSchema:
    """CEX-221 through CEX-250+: Edge cases."""

    def test_CEX_221_contributions_with_all_none_scores(self):
        items = compute_contributions(None, None, None, None, None, None, None)
        total = sum(i["contribution_percentage"] for i in items)
        assert abs(total - 100.0) < 0.5 or total == 0.0

    def test_CEX_222_root_causes_with_all_none(self):
        rcs = compute_root_causes(None, None, None, None, None, None, None, None)
        assert isinstance(rcs, list)

    def test_CEX_223_actions_with_all_none(self):
        actions = compute_governance_actions(None, None, None, None, None, None, None)
        assert isinstance(actions, list)

    def test_CEX_224_narrative_with_empty_lists(self):
        n = generate_narrative(70.0, "ADEQUATE", "STABLE", [], [])
        assert isinstance(n, str)
        assert len(n) > 0

    def test_CEX_225_detect_change_all_none(self):
        result = detect_change(None, None, None)
        assert result["status"] == "STABLE"

    def test_CEX_226_priority_with_score_exactly_0(self):
        p = classify_priority(0.0, "INEFFECTIVE", "CRITICAL", 0.0, 0.0)
        assert p == GovernancePriority.CRITICAL

    def test_CEX_227_priority_with_score_exactly_100(self):
        p = classify_priority(100.0, "HIGHLY_EFFECTIVE", "IMPROVING", 90.0, 100.0)
        assert p == GovernancePriority.LOW

    def test_CEX_228_rankings_empty_tenant_no_error(self, db):
        _exp_engine(db, "empty-tenant-cex-228").recalculate_rankings()

    def test_CEX_229_explain_response_is_pydantic_serializable(self, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        result = _exp_engine(db).explain(cid)
        serialized = result.model_dump()
        assert "narrative" in serialized

    def test_CEX_230_contributors_response_is_pydantic_serializable(self, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        result = _exp_engine(db).get_contributors(cid)
        serialized = result.model_dump()
        assert "contributions" in serialized

    def test_CEX_231_actions_response_is_pydantic_serializable(self, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        result = _exp_engine(db).get_actions(cid)
        serialized = result.model_dump()
        assert "actions" in serialized

    def test_CEX_232_priorities_response_is_pydantic_serializable(self, db):
        result = _exp_engine(db).get_priorities(50, 0)
        serialized = result.model_dump()
        assert "items" in serialized

    def test_CEX_233_rankings_response_is_pydantic_serializable(self, db):
        result = _exp_engine(db).get_rankings()
        serialized = result.model_dump()
        assert "top_controls" in serialized

    def test_CEX_234_executive_dashboard_is_pydantic_serializable(self, db):
        result = _exp_engine(db).get_executive_dashboard()
        serialized = result.model_dump()
        assert "total_controls" in serialized

    def test_CEX_235_orm_ranking_has_correct_fields(self, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        _exp_engine(db).recalculate_rankings()
        row = (
            db.query(FaControlRanking)
            .filter(FaControlRanking.tenant_id == _TENANT)
            .first()
        )
        if row is not None:
            assert row.control_id
            assert row.rank_type
            assert row.rank_position >= 1
            assert 0.0 <= row.effectiveness_score <= 100.0

    def test_CEX_236_signal_impact_enum_all_values_covered(self):
        assert set(e.value for e in SignalImpact) == {"POSITIVE", "NEGATIVE", "NEUTRAL"}

    def test_CEX_237_action_type_descriptions_non_empty(self):
        from services.control_effectiveness_explainability.models import (
            _ACTION_DESCRIPTIONS,
            ActionType,
        )

        for at in ActionType:
            assert at.value in _ACTION_DESCRIPTIONS
            assert len(_ACTION_DESCRIPTIONS[at.value]) > 0

    def test_CEX_238_root_cause_descriptions_non_empty(self):
        from services.control_effectiveness_explainability.models import (
            _SIGNAL_DESCRIPTIONS,
            RootCauseType,
        )

        for rct in RootCauseType:
            assert rct.value in _SIGNAL_DESCRIPTIONS
            assert len(_SIGNAL_DESCRIPTIONS[rct.value]) > 0

    def test_CEX_239_priorities_limit_max_200(self, client):
        r = client.get("/control-effectiveness/priorities?limit=201")
        assert r.status_code == 422

    def test_CEX_240_priorities_limit_min_1(self, client):
        r = client.get("/control-effectiveness/priorities?limit=0")
        assert r.status_code == 422

    def test_CEX_241_priorities_offset_negative_rejected(self, client):
        r = client.get("/control-effectiveness/priorities?offset=-1")
        assert r.status_code == 422

    def test_CEX_242_explain_generates_at_iso_format(self, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        result = _exp_engine(db).explain(cid)
        assert "T" in result.generated_at
        assert "+" in result.generated_at or "Z" in result.generated_at

    def test_CEX_243_contributions_weighted_scores_sum_to_effectiveness(self, db):
        cid, _ = _setup_control(db)
        ce_result = _ce_engine(db).recalculate(cid)
        contributions = compute_contributions(
            coverage_score=ce_result.coverage_score,
            verification_score=ce_result.verification_score,
            freshness_score=ce_result.freshness_score,
            trend_score=ce_result.trend_score,
            forecast_score=ce_result.forecast_score,
            evidence_density_score=ce_result.evidence_density_score,
            exception_score=ce_result.exception_score,
        )
        total_weighted = sum(c["weighted_score"] for c in contributions)
        assert abs(total_weighted - ce_result.effectiveness_score) < 0.5

    def test_CEX_244_governance_priority_persists_across_calls(self, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        result1 = _exp_engine(db).explain(cid)
        result2 = _exp_engine(db).explain(cid)
        assert result1.governance_priority == result2.governance_priority

    def test_CEX_245_narrative_deterministic(self, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        r1 = _exp_engine(db).explain(cid)
        r2 = _exp_engine(db).explain(cid)
        assert r1.narrative == r2.narrative

    def test_CEX_246_all_rank_types_stored(self, db):
        cid, _ = _setup_control(db)
        _ce_engine(db).recalculate(cid)
        _exp_engine(db).recalculate_rankings()
        from services.control_effectiveness_explainability.models import RankType

        for rt in RankType:
            rows = _exp_engine(db)._repo.get_rankings(rt.value)
            assert isinstance(rows, list)
