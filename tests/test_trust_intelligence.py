"""Trust Intelligence Layer tests — PR 1.8.

Coverage matrix:
  Constants                     version string, posture/risk/weight/drift/forecast constants
  calculate_trust_posture        all-None defaults, keys, score weights, drift, posture levels,
                                 boundary scores, clamping, tenant/engagement propagation
  calculate_trust_trend          empty/single/two-item lists, direction/velocity labels,
                                 window validation, data_points, trend_available
  generate_trust_priorities      all-None default, broken chain, confidence deficit, drift,
                                 risk, posture, hotspots, sort/dedup/re-number, required keys
  calculate_trust_risk           all-None defaults, category breakdown, replay/confidence/
                                 graph/drift/governance/autonomy risk, overall level, factors
  generate_trust_insights        all-None default, drift insights, confidence insights,
                                 risk-category insights, hotspot insights, posture insights,
                                 sort order, required keys
  detect_trust_hotspots          all-None empty, evidence/authority/replay/graph/corroboration/
                                 governance hotspots, sort order, required keys
  generate_executive_actions     all-None default, critical/degraded/watch posture, rapidly_
                                 degrading trend, critical/high risk, autonomy risk, sort order
  generate_governance_recommendations  all-None default, human/agent/autonomous_system/agi/any
                                 entity types, risk gates, trend monitoring, hotspot remediation
  forecast_trust_posture         no-trend stable, invalid window, dampening windows, clamping,
                                 score_delta computation, confidence tiers, required keys
  generate_trust_intelligence_graph  empty nodes/edges, node types, edge types, node IDs,
                                 tenant/engagement propagation, node/edge counts
  Determinism                    every exported function called twice returns identical results
  CrossTenantIsolation           tenant_id propagated and isolated across all functions
  CrossEngagementIsolation       engagement_id propagated and isolated
  Performance                    throughput guards for all 10 functions
  FutureAgentCompatibility       agent/autonomous_system/agent_fleet entity types
  AGIGovernanceCompatibility     agi entity type governance requirements
  SecurityInvariants             no function ever raises; score always clamped 0–100
  EnterpriseScenarios            banking, healthcare, critical infrastructure, govcon, AI gov
  EdgeCases                      None items in lists, unknown drift direction, empty violations,
                                 window=0, empty-string tenant, all-100 scores, broken chain
                                 with high confidence, all modifiers combined
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from services.field_assessment.trust_intelligence import (
    TRUST_INTELLIGENCE_VERSION,
    GRAPH_NODE_POSTURE,
    GRAPH_NODE_TREND,
    GRAPH_NODE_RISK,
    GRAPH_NODE_PRIORITY,
    GRAPH_NODE_RECOMMENDATION,
    GRAPH_NODE_FORECAST,
    GRAPH_NODE_INSIGHT,
    GRAPH_NODE_HOTSPOT,
    _POSTURE_EXCELLENT,
    _POSTURE_HEALTHY,
    _POSTURE_STABLE,
    _POSTURE_WATCH,
    _POSTURE_DEGRADED,
    _TREND_RAPID_THRESHOLD,
    _TREND_VELOCITY_RAPID,
    _TREND_VELOCITY_SIGNIFICANT,
    _TREND_VELOCITY_MODERATE,
    _TREND_VELOCITY_LOW,
    _RISK_CRITICAL_THRESHOLD,
    _RISK_HIGH_THRESHOLD,
    _RISK_MEDIUM_THRESHOLD,
    _RISK_LOW_THRESHOLD,
    _WEIGHT_CONFIDENCE,
    _WEIGHT_REPLAY,
    _WEIGHT_GRAPH,
    _WEIGHT_AUTHORITY,
    _WEIGHT_ENFORCEMENT,
    _DRIFT_RAPIDLY_IMPROVING,
    _DRIFT_IMPROVING,
    _DRIFT_STABLE,
    _DRIFT_DEGRADING,
    _DRIFT_RAPIDLY_DEGRADING,
    _FORECAST_WINDOWS,
    calculate_trust_posture,
    calculate_trust_trend,
    generate_trust_priorities,
    calculate_trust_risk,
    generate_trust_insights,
    detect_trust_hotspots,
    generate_executive_actions,
    generate_governance_recommendations,
    forecast_trust_posture,
    generate_trust_intelligence_graph,
)

# ---------------------------------------------------------------------------
# Shared constants used across many tests
# ---------------------------------------------------------------------------

TENANT_A = "tenant-alpha"
TENANT_B = "tenant-beta"
ENG_A = "eng-001"
ENG_B = "eng-002"

NOW = datetime.now(tz=timezone.utc)


def _ts(days_ago: float = 0.0) -> str:
    """Return an ISO-8601 UTC timestamp string *days_ago* days before now."""
    return (NOW - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def confidence_result_high() -> dict[str, Any]:
    return {"confidence_score": 85, "level": "strong"}


@pytest.fixture
def confidence_result_low() -> dict[str, Any]:
    return {"confidence_score": 20, "level": "critical"}


@pytest.fixture
def replay_result_full() -> dict[str, Any]:
    return {"chain_replay_score": 100}


@pytest.fixture
def replay_result_broken() -> dict[str, Any]:
    return {"chain_replay_score": 0}


@pytest.fixture
def graph_result_valid() -> dict[str, Any]:
    return {"graph_valid": True, "violations": 0}


@pytest.fixture
def graph_result_invalid() -> dict[str, Any]:
    return {"graph_valid": False}


@pytest.fixture
def drift_result_stable() -> dict[str, Any]:
    return {"direction": "stable", "velocity": "minimal"}


@pytest.fixture
def drift_result_rapidly_degrading() -> dict[str, Any]:
    return {"direction": "rapidly_degrading", "velocity": "rapid"}


@pytest.fixture
def drift_result_improving() -> dict[str, Any]:
    return {"direction": "improving", "velocity": "moderate"}


@pytest.fixture
def enforcement_result_ok() -> dict[str, Any]:
    return {"allowed": True, "enforcement_mode": "on", "trust_score": 90}


@pytest.fixture
def evidence_authority_valid() -> dict[str, Any]:
    return {"valid": True, "version_mismatch": False}


@pytest.fixture
def standard_posture_result() -> dict[str, Any]:
    """A healthy posture result (score=80)."""
    return {
        "trust_posture": "healthy",
        "score": 80,
        "confidence": 80,
        "tenant_id": TENANT_A,
        "engagement_id": ENG_A,
        "intelligence_version": TRUST_INTELLIGENCE_VERSION,
        "component_scores": {},
        "reasoning": "test",
        "generated_from": "calculate_trust_posture",
    }


@pytest.fixture
def standard_trend_result() -> dict[str, Any]:
    return {
        "direction": "stable",
        "velocity": "minimal",
        "score_change": 0,
        "confidence_change": 0,
        "window_days": 90,
        "data_points": 2,
        "trend_available": True,
        "start_score": 80,
        "end_score": 80,
        "tenant_id": TENANT_A,
        "engagement_id": ENG_A,
        "intelligence_version": TRUST_INTELLIGENCE_VERSION,
    }


@pytest.fixture
def standard_risk_result() -> dict[str, Any]:
    return {
        "risk_level": "none",
        "risk_score": 0,
        "contributing_factors": [],
        "category_scores": {
            "authority_risk": 0,
            "replay_risk": 0,
            "graph_risk": 0,
            "confidence_risk": 0,
            "drift_risk": 0,
            "governance_risk": 0,
            "future_autonomy_risk": 0,
        },
        "tenant_id": TENANT_A,
        "engagement_id": ENG_A,
        "intelligence_version": TRUST_INTELLIGENCE_VERSION,
    }


# ---------------------------------------------------------------------------
# 1. TestTrustIntelligenceConstants
# ---------------------------------------------------------------------------


class TestTrustIntelligenceConstants:
    def test_version_string(self):
        assert TRUST_INTELLIGENCE_VERSION == "trust-intelligence-v1"

    def test_no_exception_class_exported(self):
        import services.field_assessment.trust_intelligence as mod

        assert not hasattr(mod, "TrustIntelligenceError"), (
            "Module must NOT export a custom exception class"
        )

    def test_posture_constants_values(self):
        assert _POSTURE_EXCELLENT == 90
        assert _POSTURE_HEALTHY == 75
        assert _POSTURE_STABLE == 60
        assert _POSTURE_WATCH == 45
        assert _POSTURE_DEGRADED == 25

    def test_risk_thresholds(self):
        assert _RISK_CRITICAL_THRESHOLD == 75
        assert _RISK_HIGH_THRESHOLD == 55
        assert _RISK_MEDIUM_THRESHOLD == 35
        assert _RISK_LOW_THRESHOLD == 15

    def test_weights_sum_to_one(self):
        total = (
            _WEIGHT_CONFIDENCE
            + _WEIGHT_REPLAY
            + _WEIGHT_GRAPH
            + _WEIGHT_AUTHORITY
            + _WEIGHT_ENFORCEMENT
        )
        assert abs(total - 1.0) < 1e-9

    def test_forecast_windows_tuple(self):
        assert _FORECAST_WINDOWS == (30, 90, 180, 365)

    def test_graph_node_type_constants(self):
        assert GRAPH_NODE_POSTURE == "trust_posture"
        assert GRAPH_NODE_TREND == "trust_trend"
        assert GRAPH_NODE_RISK == "trust_risk"
        assert GRAPH_NODE_PRIORITY == "trust_priority"
        assert GRAPH_NODE_RECOMMENDATION == "trust_recommendation"
        assert GRAPH_NODE_FORECAST == "trust_forecast"
        assert GRAPH_NODE_INSIGHT == "trust_insight"
        assert GRAPH_NODE_HOTSPOT == "trust_hotspot"

    def test_trend_constants(self):
        assert _TREND_RAPID_THRESHOLD == 10
        assert _TREND_VELOCITY_RAPID == 20
        assert _TREND_VELOCITY_SIGNIFICANT == 12
        assert _TREND_VELOCITY_MODERATE == 6
        assert _TREND_VELOCITY_LOW == 2
        assert _DRIFT_RAPIDLY_IMPROVING == 8
        assert _DRIFT_IMPROVING == 3
        assert _DRIFT_STABLE == 0
        assert _DRIFT_DEGRADING == -5
        assert _DRIFT_RAPIDLY_DEGRADING == -12


# ---------------------------------------------------------------------------
# 2. TestCalculateTrustPosture
# ---------------------------------------------------------------------------


class TestCalculateTrustPosture:
    def test_all_none_returns_valid_dict(self):
        result = calculate_trust_posture()
        assert isinstance(result, dict)

    def test_required_output_keys_present(self):
        result = calculate_trust_posture()
        for key in (
            "trust_posture",
            "score",
            "confidence",
            "reasoning",
            "generated_from",
            "tenant_id",
            "engagement_id",
            "intelligence_version",
            "component_scores",
        ):
            assert key in result, f"Missing key: {key}"

    def test_all_none_posture_level_valid(self):
        result = calculate_trust_posture()
        valid = {"excellent", "healthy", "stable", "watch", "degraded", "critical"}
        assert result["trust_posture"] in valid

    def test_confidence_score_drives_final_score(self):
        low = calculate_trust_posture(confidence_result={"confidence_score": 0})
        high = calculate_trust_posture(confidence_result={"confidence_score": 100})
        assert high["score"] > low["score"]

    def test_replay_score_zero_reduces_posture(self):
        baseline = calculate_trust_posture(confidence_result={"confidence_score": 100})
        with_broken = calculate_trust_posture(
            confidence_result={"confidence_score": 100},
            replay_result={"chain_replay_score": 0},
        )
        assert with_broken["score"] < baseline["score"]

    def test_graph_invalid_reduces_score(self):
        baseline = calculate_trust_posture(confidence_result={"confidence_score": 80})
        with_bad_graph = calculate_trust_posture(
            confidence_result={"confidence_score": 80},
            graph_result={"graph_valid": False},
        )
        assert with_bad_graph["score"] < baseline["score"]

    def test_drift_modifier_applied(self):
        stable = calculate_trust_posture(
            confidence_result={"confidence_score": 50},
            drift_result={"direction": "stable"},
        )
        improving = calculate_trust_posture(
            confidence_result={"confidence_score": 50},
            drift_result={"direction": "rapidly_improving"},
        )
        assert improving["score"] > stable["score"]

    def test_posture_excellent_at_score_90(self):
        # All weights max + rapidly_improving (+8) easily produces 100
        result = calculate_trust_posture(
            confidence_result={"confidence_score": 100},
            replay_result={"chain_replay_score": 100},
            graph_result={"graph_valid": True, "violations": 0},
            evidence_authority={"valid": True},
            enforcement_result={"allowed": True, "trust_score": 100},
            drift_result={"direction": "stable"},
        )
        assert result["trust_posture"] == "excellent"
        assert result["score"] >= _POSTURE_EXCELLENT

    def test_posture_healthy_at_score_75_to_89(self):
        # confidence=75, rest default → weighted = 75*0.5 + 100*0.2 + 100*0.15 + 100*0.1 + 100*0.05 = 87.5 → healthy
        result = calculate_trust_posture(confidence_result={"confidence_score": 75})
        # The score should land in healthy range (75–89)
        assert 75 <= result["score"] <= 89
        assert result["trust_posture"] == "healthy"

    def test_posture_stable_boundary(self):
        # Produce a score that maps to stable (60–74)
        # confidence=60, no replay penalty → 60*0.5 + 100*0.7 = 30+70=100 → that's 100, too high
        # Use graph_invalid to pull it down: confidence=50 → 25 + 70 (replay 100, graph 0*0.15=0, ...) =
        # Let's use: confidence=50, graph_invalid → 50*0.5 + 100*0.2 + 0*0.15 + 100*0.1 + 100*0.05 = 25+20+0+10+5=60 → stable
        result = calculate_trust_posture(
            confidence_result={"confidence_score": 50},
            graph_result={"graph_valid": False},
        )
        assert result["trust_posture"] == "stable"
        assert result["score"] == 60

    def test_posture_watch_boundary(self):
        # confidence=30, graph_invalid, authority_invalid
        # 30*0.5 + 100*0.2 + 0*0.15 + 0*0.1 + 100*0.05 = 15+20+0+0+5 = 40 → watch? No 40 is degraded(25-44)
        # Let's target 45: confidence=50, graph_invalid, authority_invalid, enforcement=50
        # 50*0.5 + 100*0.2 + 0*0.15 + 0*0.1 + 50*0.05 = 25+20+0+0+2.5 = 47.5 → round=48 → watch (48)
        result = calculate_trust_posture(
            confidence_result={"confidence_score": 50},
            graph_result={"graph_valid": False},
            evidence_authority={"valid": False},
            enforcement_result={"allowed": True, "trust_score": 50},
        )
        assert _POSTURE_WATCH <= result["score"] < _POSTURE_STABLE
        assert result["trust_posture"] == "watch"

    def test_posture_degraded_boundary(self):
        # Score in [25, 44]
        # confidence=30, graph_invalid, authority_invalid, replay=0 → 15+0+0+0+5=20 → critical
        # Need 25–44: confidence=45, graph_invalid, authority_invalid, replay=50
        # 45*0.5 + 50*0.2 + 0*0.15 + 0*0.1 + 100*0.05 = 22.5+10+0+0+5=37.5 → 38 → degraded
        result = calculate_trust_posture(
            confidence_result={"confidence_score": 45},
            replay_result={"chain_replay_score": 50},
            graph_result={"graph_valid": False},
            evidence_authority={"valid": False},
        )
        assert _POSTURE_DEGRADED <= result["score"] < _POSTURE_WATCH
        assert result["trust_posture"] == "degraded"

    def test_posture_critical_at_near_zero(self):
        result = calculate_trust_posture(
            confidence_result={"confidence_score": 0},
            replay_result={"chain_replay_score": 0},
            graph_result={"graph_valid": False},
            evidence_authority={"valid": False},
            enforcement_result={"allowed": False},
        )
        assert result["trust_posture"] == "critical"
        assert result["score"] < _POSTURE_DEGRADED

    def test_tenant_id_in_output(self):
        result = calculate_trust_posture(tenant_id=TENANT_A)
        assert result["tenant_id"] == TENANT_A

    def test_engagement_id_in_output(self):
        result = calculate_trust_posture(engagement_id=ENG_A)
        assert result["engagement_id"] == ENG_A

    def test_component_scores_in_output(self):
        result = calculate_trust_posture(confidence_result={"confidence_score": 70})
        cs = result["component_scores"]
        assert "confidence_score" in cs
        assert "replay_score" in cs
        assert "graph_score" in cs
        assert "authority_score" in cs
        assert "enforcement_score" in cs

    def test_generated_from_field(self):
        result = calculate_trust_posture()
        assert result["generated_from"] == "calculate_trust_posture"

    def test_reasoning_populated(self):
        result = calculate_trust_posture(confidence_result={"confidence_score": 10})
        assert isinstance(result["reasoning"], str)
        assert len(result["reasoning"]) > 0

    def test_score_clamped_min(self):
        result = calculate_trust_posture(
            confidence_result={"confidence_score": 0},
            replay_result={"chain_replay_score": 0},
            graph_result={"graph_valid": False},
            evidence_authority={"valid": False},
            enforcement_result={"allowed": False},
            drift_result={"direction": "rapidly_degrading"},
        )
        assert result["score"] >= 0

    def test_score_clamped_max(self):
        result = calculate_trust_posture(
            confidence_result={"confidence_score": 100},
            replay_result={"chain_replay_score": 100},
            drift_result={"direction": "rapidly_improving"},
        )
        assert result["score"] <= 100

    def test_intelligence_version_in_output(self):
        result = calculate_trust_posture()
        assert result["intelligence_version"] == TRUST_INTELLIGENCE_VERSION

    def test_confidence_score_reflected_in_component_scores(self):
        result = calculate_trust_posture(confidence_result={"confidence_score": 42})
        assert result["component_scores"]["confidence_score"] == 42

    def test_replay_default_when_none(self):
        result = calculate_trust_posture()
        # When replay_result is None, replay_score defaults to 100
        assert result["component_scores"]["replay_score"] == 100


# ---------------------------------------------------------------------------
# 3. TestCalculateTrustTrend
# ---------------------------------------------------------------------------


class TestCalculateTrustTrend:
    def test_empty_list_returns_stable(self):
        result = calculate_trust_trend([])
        assert result["direction"] == "stable"

    def test_empty_list_minimal_velocity(self):
        result = calculate_trust_trend([])
        assert result["velocity"] == "minimal"

    def test_single_item_no_trend_available(self):
        snaps = [{"created_at": _ts(1), "score": 70}]
        result = calculate_trust_trend(snaps)
        assert result["trend_available"] is False

    def test_two_items_compute_direction(self):
        snaps = [
            {"created_at": _ts(10), "score": 50},
            {"created_at": _ts(1), "score": 70},
        ]
        result = calculate_trust_trend(snaps, window_days=30)
        assert result["direction"] in {"improving", "rapidly_improving"}
        assert result["trend_available"] is True

    def test_rapidly_improving_at_delta_10_inclusive(self):
        snaps = [
            {"created_at": _ts(30), "score": 60},
            {"created_at": _ts(1), "score": 70},
        ]
        result = calculate_trust_trend(snaps, window_days=90)
        assert result["score_change"] == 10
        assert result["direction"] == "rapidly_improving"

    def test_stable_at_delta_zero(self):
        snaps = [
            {"created_at": _ts(10), "score": 65},
            {"created_at": _ts(1), "score": 65},
        ]
        result = calculate_trust_trend(snaps, window_days=30)
        assert result["direction"] == "stable"
        assert result["score_change"] == 0

    def test_degrading_at_negative_delta(self):
        snaps = [
            {"created_at": _ts(10), "score": 75},
            {"created_at": _ts(1), "score": 70},
        ]
        result = calculate_trust_trend(snaps, window_days=30)
        assert result["direction"] == "degrading"

    def test_rapidly_degrading_at_delta_minus_10_inclusive(self):
        snaps = [
            {"created_at": _ts(10), "score": 80},
            {"created_at": _ts(1), "score": 70},
        ]
        result = calculate_trust_trend(snaps, window_days=30)
        assert result["score_change"] == -10
        assert result["direction"] == "rapidly_degrading"

    def test_velocity_rapid_at_20(self):
        snaps = [
            {"created_at": _ts(30), "score": 40},
            {"created_at": _ts(1), "score": 60},
        ]
        result = calculate_trust_trend(snaps, window_days=90)
        assert result["score_change"] == 20
        assert result["velocity"] == "rapid"

    def test_velocity_significant_at_12(self):
        snaps = [
            {"created_at": _ts(30), "score": 60},
            {"created_at": _ts(1), "score": 72},
        ]
        result = calculate_trust_trend(snaps, window_days=90)
        assert result["score_change"] == 12
        assert result["velocity"] == "significant"

    def test_velocity_moderate_at_6(self):
        snaps = [
            {"created_at": _ts(30), "score": 60},
            {"created_at": _ts(1), "score": 66},
        ]
        result = calculate_trust_trend(snaps, window_days=90)
        assert result["score_change"] == 6
        assert result["velocity"] == "moderate"

    def test_velocity_low_at_2(self):
        snaps = [
            {"created_at": _ts(30), "score": 60},
            {"created_at": _ts(1), "score": 62},
        ]
        result = calculate_trust_trend(snaps, window_days=90)
        assert result["score_change"] == 2
        assert result["velocity"] == "low"

    def test_velocity_minimal_at_1(self):
        snaps = [
            {"created_at": _ts(30), "score": 60},
            {"created_at": _ts(1), "score": 61},
        ]
        result = calculate_trust_trend(snaps, window_days=90)
        assert result["score_change"] == 1
        assert result["velocity"] == "minimal"

    def test_invalid_window_defaults_to_90(self):
        snaps = [
            {"created_at": _ts(10), "score": 50},
            {"created_at": _ts(1), "score": 60},
        ]
        result = calculate_trust_trend(snaps, window_days=999)
        assert result["window_days"] == 90

    def test_window_days_in_output(self):
        result = calculate_trust_trend([], window_days=30)
        assert result["window_days"] == 30

    def test_data_points_count_correct(self):
        snaps = [
            {"created_at": _ts(5), "score": 50},
            {"created_at": _ts(3), "score": 60},
            {"created_at": _ts(1), "score": 70},
        ]
        result = calculate_trust_trend(snaps, window_days=30)
        assert result["data_points"] == 3

    def test_trend_available_true_when_2_items(self):
        snaps = [
            {"created_at": _ts(5), "score": 50},
            {"created_at": _ts(1), "score": 60},
        ]
        result = calculate_trust_trend(snaps, window_days=30)
        assert result["trend_available"] is True

    def test_confidence_change_computed(self):
        snaps = [
            {"created_at": _ts(10), "score": 60, "confidence": 70},
            {"created_at": _ts(1), "score": 70, "confidence": 80},
        ]
        result = calculate_trust_trend(snaps, window_days=30)
        assert result["confidence_change"] == 10

    def test_tenant_id_and_engagement_id_in_output(self):
        result = calculate_trust_trend([], tenant_id=TENANT_A, engagement_id=ENG_A)
        assert result["tenant_id"] == TENANT_A
        assert result["engagement_id"] == ENG_A


# ---------------------------------------------------------------------------
# 4. TestGenerateTrustPriorities
# ---------------------------------------------------------------------------


class TestGenerateTrustPriorities:
    def test_empty_inputs_returns_maintain_trust_posture(self):
        result = generate_trust_priorities()
        assert len(result) == 1
        assert result[0]["issue"] == "maintain_trust_posture"

    def test_broken_chain_produces_trust_chain_broken_with_delta_30(self):
        result = generate_trust_priorities(replay_result={"chain_replay_score": 0})
        issues = {p["issue"] for p in result}
        assert "trust_chain_broken" in issues
        broken = next(p for p in result if p["issue"] == "trust_chain_broken")
        assert broken["trust_delta"] == 30

    def test_critical_confidence_produces_delta_40(self):
        result = generate_trust_priorities(confidence_result={"confidence_score": 10})
        delta_40 = next(
            (
                p
                for p in result
                if p["trust_delta"] == 40
                and p["issue"] == "critical_confidence_deficit"
            ),
            None,
        )
        assert delta_40 is not None

    def test_rapidly_degrading_produces_delta_35(self):
        result = generate_trust_priorities(
            drift_result={"direction": "rapidly_degrading"}
        )
        item = next((p for p in result if p["issue"] == "rapid_trust_decline"), None)
        assert item is not None
        assert item["trust_delta"] == 35

    def test_critical_risk_produces_delta_30(self):
        result = generate_trust_priorities(risk_result={"risk_level": "critical"})
        item = next((p for p in result if p["issue"] == "critical_risk_exposure"), None)
        assert item is not None
        assert item["trust_delta"] == 30

    def test_posture_score_below_25_produces_delta_50(self):
        result = generate_trust_priorities(
            posture_result={"score": 10, "trust_posture": "critical"}
        )
        item = next((p for p in result if p["issue"] == "critical_posture"), None)
        assert item is not None
        assert item["trust_delta"] == 50

    def test_priorities_sorted_by_trust_delta_descending(self):
        result = generate_trust_priorities(
            confidence_result={"confidence_score": 10},
            drift_result={"direction": "rapidly_degrading"},
            risk_result={"risk_level": "critical"},
        )
        deltas = [p["trust_delta"] for p in result]
        assert deltas == sorted(deltas, reverse=True)

    def test_priorities_renumbered_1_to_n(self):
        result = generate_trust_priorities(
            confidence_result={"confidence_score": 10},
            drift_result={"direction": "rapidly_degrading"},
        )
        for idx, item in enumerate(result, start=1):
            assert item["priority"] == idx

    def test_dedup_by_issue(self):
        # Provide same drift_result twice would just add one entry
        result = generate_trust_priorities(
            drift_result={"direction": "rapidly_degrading"},
        )
        issues = [p["issue"] for p in result]
        assert len(issues) == len(set(issues))

    def test_hotspot_critical_produces_hotspot_area(self):
        result = generate_trust_priorities(
            hotspots=[{"area": "evidence", "severity": "critical"}]
        )
        item = next((p for p in result if p["issue"].startswith("hotspot_")), None)
        assert item is not None
        assert item["issue"] == "hotspot_evidence"

    def test_low_confidence_produces_high_impact_item(self):
        result = generate_trust_priorities(confidence_result={"confidence_score": 40})
        item = next((p for p in result if p["issue"] == "low_confidence_score"), None)
        assert item is not None
        assert item["impact"] == "high"

    def test_each_item_has_required_keys(self):
        result = generate_trust_priorities(confidence_result={"confidence_score": 10})
        required = {"priority", "issue", "impact", "trust_delta", "reason", "evidence"}
        for item in result:
            assert required.issubset(set(item.keys()))

    def test_chain_replay_below_75_produces_trust_chain_degraded(self):
        result = generate_trust_priorities(replay_result={"chain_replay_score": 50})
        item = next((p for p in result if p["issue"] == "trust_chain_degraded"), None)
        assert item is not None

    def test_chain_replay_below_100_above_75_produces_legacy_unsigned(self):
        result = generate_trust_priorities(replay_result={"chain_replay_score": 80})
        item = next(
            (p for p in result if p["issue"] == "trust_chain_legacy_unsigned"), None
        )
        assert item is not None
        assert item["trust_delta"] == 10

    def test_degrading_drift_produces_trust_decline(self):
        result = generate_trust_priorities(drift_result={"direction": "degrading"})
        item = next((p for p in result if p["issue"] == "trust_decline"), None)
        assert item is not None

    def test_high_risk_produces_high_risk_exposure(self):
        result = generate_trust_priorities(risk_result={"risk_level": "high"})
        item = next((p for p in result if p["issue"] == "high_risk_exposure"), None)
        assert item is not None
        assert item["trust_delta"] == 18

    def test_hotspot_high_severity_produces_delta_12(self):
        result = generate_trust_priorities(
            hotspots=[{"area": "replay", "severity": "high"}]
        )
        item = next((p for p in result if p["issue"] == "hotspot_replay"), None)
        assert item is not None
        assert item["trust_delta"] == 12

    def test_tenant_id_passed_through_in_first_item(self):
        # generate_trust_priorities doesn't add tenant_id per spec — it's a list of dicts
        # The function does not add tenant_id to each item, but we verify it doesn't crash
        result = generate_trust_priorities(tenant_id=TENANT_A)
        assert isinstance(result, list)

    def test_maintain_trust_posture_has_trust_delta_zero(self):
        result = generate_trust_priorities()
        assert result[0]["trust_delta"] == 0

    def test_multiple_sources_all_represented_before_dedup(self):
        result = generate_trust_priorities(
            confidence_result={"confidence_score": 10},
            drift_result={"direction": "rapidly_degrading"},
            risk_result={"risk_level": "critical"},
            posture_result={"score": 10},
        )
        # Should have at least 4 unique items
        assert len(result) >= 4


# ---------------------------------------------------------------------------
# 5. TestCalculateTrustRisk
# ---------------------------------------------------------------------------


class TestCalculateTrustRisk:
    def test_all_none_returns_risk_level_none(self):
        result = calculate_trust_risk()
        assert result["risk_level"] == "none"

    def test_replay_score_zero_produces_90_replay_risk(self):
        result = calculate_trust_risk(replay_result={"chain_replay_score": 0})
        assert result["category_scores"]["replay_risk"] == 90

    def test_replay_below_75_produces_45(self):
        result = calculate_trust_risk(replay_result={"chain_replay_score": 60})
        assert result["category_scores"]["replay_risk"] == 45

    def test_replay_below_100_above_75_produces_20(self):
        result = calculate_trust_risk(replay_result={"chain_replay_score": 80})
        assert result["category_scores"]["replay_risk"] == 20

    def test_confidence_below_25_produces_85_confidence_risk(self):
        result = calculate_trust_risk(confidence_result={"confidence_score": 10})
        assert result["category_scores"]["confidence_risk"] == 85

    def test_confidence_below_50_above_25_produces_60(self):
        result = calculate_trust_risk(confidence_result={"confidence_score": 40})
        assert result["category_scores"]["confidence_risk"] == 60

    def test_graph_invalid_produces_80_graph_risk(self):
        result = calculate_trust_risk(graph_result={"graph_valid": False})
        assert result["category_scores"]["graph_risk"] == 80

    def test_violations_proportional_to_graph_risk(self):
        r1 = calculate_trust_risk(graph_result={"graph_valid": True, "violations": 2})
        r2 = calculate_trust_risk(graph_result={"graph_valid": True, "violations": 4})
        assert (
            r2["category_scores"]["graph_risk"] >= r1["category_scores"]["graph_risk"]
        )

    def test_drift_rapidly_degrading_produces_high_drift_risk(self):
        result = calculate_trust_risk(
            drift_result={"direction": "rapidly_degrading", "velocity": "minimal"}
        )
        assert result["category_scores"]["drift_risk"] >= 75

    def test_enforcement_mode_off_produces_50_governance_risk(self):
        result = calculate_trust_risk(
            enforcement_result={"enforcement_mode": "off", "allowed": True}
        )
        assert result["category_scores"]["governance_risk"] == 50

    def test_future_autonomy_risk_elevated_when_confidence_below_50(self):
        result = calculate_trust_risk(confidence_result={"confidence_score": 40})
        assert result["category_scores"]["future_autonomy_risk"] == 60

    def test_category_scores_dict_has_all_7_keys(self):
        result = calculate_trust_risk()
        expected = {
            "authority_risk",
            "replay_risk",
            "graph_risk",
            "confidence_risk",
            "drift_risk",
            "governance_risk",
            "future_autonomy_risk",
        }
        assert expected == set(result["category_scores"].keys())

    def test_risk_level_from_overall_score(self):
        # All zeros → risk_level none
        result = calculate_trust_risk()
        assert result["risk_level"] == "none"

    def test_contributing_factors_sorted_alphabetically(self):
        result = calculate_trust_risk(
            confidence_result={"confidence_score": 10},
            replay_result={"chain_replay_score": 0},
        )
        factors = result["contributing_factors"]
        assert factors == sorted(factors)

    def test_tenant_id_in_output(self):
        result = calculate_trust_risk(tenant_id=TENANT_A)
        assert result["tenant_id"] == TENANT_A

    def test_engagement_id_in_output(self):
        result = calculate_trust_risk(engagement_id=ENG_B)
        assert result["engagement_id"] == ENG_B

    def test_high_replay_risk_produces_critical_or_high_overall(self):
        result = calculate_trust_risk(replay_result={"chain_replay_score": 0})
        assert result["risk_level"] in ("critical", "high")

    def test_authority_invalid_produces_80_authority_risk(self):
        result = calculate_trust_risk(evidence_authority={"valid": False})
        assert result["category_scores"]["authority_risk"] == 80

    def test_authority_version_mismatch_produces_40(self):
        result = calculate_trust_risk(
            evidence_authority={"valid": True, "version_mismatch": True}
        )
        assert result["category_scores"]["authority_risk"] == 40

    def test_contributing_factors_only_above_medium_threshold(self):
        result = calculate_trust_risk()
        # No risk → no factors
        for factor in result["contributing_factors"]:
            assert result["category_scores"][factor] >= _RISK_MEDIUM_THRESHOLD

    def test_intelligence_version_in_output(self):
        result = calculate_trust_risk()
        assert result["intelligence_version"] == TRUST_INTELLIGENCE_VERSION


# ---------------------------------------------------------------------------
# 6. TestGenerateTrustInsights
# ---------------------------------------------------------------------------


class TestGenerateTrustInsights:
    def test_all_none_returns_info_insight(self):
        result = generate_trust_insights()
        assert len(result) == 1
        assert result[0]["severity"] == "info"

    def test_drift_rapidly_degrading_produces_critical_insight(self):
        result = generate_trust_insights(
            drift_result={"direction": "rapidly_degrading"}
        )
        severities = [i["severity"] for i in result]
        assert "critical" in severities

    def test_drift_degrading_produces_high_insight(self):
        result = generate_trust_insights(drift_result={"direction": "degrading"})
        categories = [(i["category"], i["severity"]) for i in result]
        assert ("drift", "high") in categories

    def test_drift_improving_produces_info_insight(self):
        result = generate_trust_insights(drift_result={"direction": "improving"})
        cats = {(i["category"], i["severity"]) for i in result}
        assert ("drift", "info") in cats

    def test_confidence_below_25_produces_critical_corroboration_insight(self):
        result = generate_trust_insights(confidence_result={"confidence_score": 20})
        hits = [
            i
            for i in result
            if i["category"] == "corroboration" and i["severity"] == "critical"
        ]
        assert len(hits) >= 1

    def test_confidence_below_50_produces_high_corroboration_insight(self):
        result = generate_trust_insights(confidence_result={"confidence_score": 40})
        hits = [
            i
            for i in result
            if i["category"] == "corroboration" and i["severity"] == "high"
        ]
        assert len(hits) >= 1

    def test_replay_risk_high_produces_replay_insight(self):
        risk = {
            "category_scores": {
                "replay_risk": 60,
                "governance_risk": 0,
                "future_autonomy_risk": 0,
            }
        }
        result = generate_trust_insights(risk_result=risk)
        cats = [i["category"] for i in result]
        assert "replay" in cats

    def test_governance_risk_high_produces_governance_insight(self):
        risk = {
            "category_scores": {
                "replay_risk": 0,
                "governance_risk": 60,
                "future_autonomy_risk": 0,
            }
        }
        result = generate_trust_insights(risk_result=risk)
        hits = [i for i in result if i["category"] == "governance"]
        assert len(hits) >= 1

    def test_future_autonomy_risk_high_produces_governance_insight(self):
        risk = {
            "category_scores": {
                "replay_risk": 0,
                "governance_risk": 0,
                "future_autonomy_risk": 60,
            }
        }
        result = generate_trust_insights(risk_result=risk)
        hits = [i for i in result if i["category"] == "governance"]
        assert len(hits) >= 1

    def test_hotspot_critical_produces_corroboration_insight(self):
        result = generate_trust_insights(
            hotspots=[{"area": "evidence", "severity": "critical"}]
        )
        hits = [
            i
            for i in result
            if i["category"] == "corroboration" and i["severity"] == "critical"
        ]
        assert len(hits) >= 1

    def test_posture_critical_produces_general_insight(self):
        result = generate_trust_insights(
            posture_result={"trust_posture": "critical", "score": 10}
        )
        hits = [
            i
            for i in result
            if i["category"] == "general" and i["severity"] == "critical"
        ]
        assert len(hits) >= 1

    def test_results_sorted_critical_first(self):
        result = generate_trust_insights(
            drift_result={"direction": "degrading"},
            confidence_result={"confidence_score": 10},
        )
        _order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        ranks = [_order.get(i["severity"], 99) for i in result]
        assert ranks == sorted(ranks)

    def test_each_insight_has_required_keys(self):
        result = generate_trust_insights(confidence_result={"confidence_score": 10})
        required = {"category", "severity", "insight", "evidence", "recommended_action"}
        for item in result:
            assert required.issubset(set(item.keys()))

    def test_no_duplicates_on_simple_input(self):
        result = generate_trust_insights(drift_result={"direction": "degrading"})
        insights_text = [i["insight"] for i in result]
        assert len(insights_text) == len(set(insights_text))

    def test_posture_degraded_produces_high_general_insight(self):
        result = generate_trust_insights(
            posture_result={"trust_posture": "degraded", "score": 30}
        )
        hits = [
            i for i in result if i["category"] == "general" and i["severity"] == "high"
        ]
        assert len(hits) >= 1

    def test_intelligence_version_not_required_in_items(self):
        # Insights are plain dicts; no version key required per spec
        result = generate_trust_insights()
        assert isinstance(result, list)

    def test_rapidly_improving_drift_produces_info_insight(self):
        result = generate_trust_insights(
            drift_result={"direction": "rapidly_improving"}
        )
        hits = [
            i for i in result if i["category"] == "drift" and i["severity"] == "info"
        ]
        assert len(hits) >= 1

    def test_default_insight_text(self):
        result = generate_trust_insights()
        assert result[0]["insight"] == "trust_posture_is_within_acceptable_parameters"


# ---------------------------------------------------------------------------
# 7. TestDetectTrustHotspots
# ---------------------------------------------------------------------------


class TestDetectTrustHotspots:
    def _risk(self, **kwargs) -> dict[str, Any]:
        base = {
            "authority_risk": 0,
            "replay_risk": 0,
            "graph_risk": 0,
            "confidence_risk": 0,
            "drift_risk": 0,
            "governance_risk": 0,
            "future_autonomy_risk": 0,
        }
        base.update(kwargs)
        return {"category_scores": base}

    def test_all_none_returns_empty_list(self):
        result = detect_trust_hotspots()
        assert result == []

    def test_confidence_risk_high_produces_evidence_hotspot(self):
        result = detect_trust_hotspots(risk_result=self._risk(confidence_risk=60))
        areas = [h["area"] for h in result]
        assert "evidence" in areas

    def test_authority_risk_high_produces_authority_hotspot(self):
        result = detect_trust_hotspots(risk_result=self._risk(authority_risk=60))
        areas = [h["area"] for h in result]
        assert "authority" in areas

    def test_replay_risk_high_produces_replay_hotspot(self):
        result = detect_trust_hotspots(risk_result=self._risk(replay_risk=60))
        areas = [h["area"] for h in result]
        assert "replay" in areas

    def test_graph_risk_high_produces_graph_hotspot(self):
        result = detect_trust_hotspots(risk_result=self._risk(graph_risk=60))
        areas = [h["area"] for h in result]
        assert "graph" in areas

    def test_low_avg_corroboration_below_30_produces_critical_hotspot(self):
        snaps = [{"corroboration_score": 10}, {"corroboration_score": 20}]
        result = detect_trust_hotspots(confidence_snapshots=snaps)
        hits = [
            h
            for h in result
            if h["area"] == "corroboration" and h["severity"] == "critical"
        ]
        assert len(hits) == 1

    def test_avg_corroboration_below_50_produces_high_hotspot(self):
        snaps = [{"corroboration_score": 35}, {"corroboration_score": 45}]
        result = detect_trust_hotspots(confidence_snapshots=snaps)
        hits = [
            h
            for h in result
            if h["area"] == "corroboration" and h["severity"] == "high"
        ]
        assert len(hits) == 1

    def test_governance_risk_high_produces_governance_hotspot(self):
        result = detect_trust_hotspots(risk_result=self._risk(governance_risk=60))
        areas = [h["area"] for h in result]
        assert "governance" in areas

    def test_each_hotspot_has_required_keys(self):
        snaps = [{"corroboration_score": 10}]
        result = detect_trust_hotspots(confidence_snapshots=snaps)
        for h in result:
            assert "area" in h
            assert "severity" in h
            assert "reason" in h
            assert "risk_score" in h

    def test_sorted_by_risk_score_desc(self):
        result = detect_trust_hotspots(
            risk_result=self._risk(confidence_risk=90, replay_risk=60, graph_risk=70)
        )
        scores = [h["risk_score"] for h in result]
        assert scores == sorted(scores, reverse=True)

    def test_no_graph_result_no_graph_hotspot_from_none(self):
        result = detect_trust_hotspots()
        areas = [h["area"] for h in result]
        assert "graph" not in areas

    def test_no_snapshots_no_corroboration_hotspot(self):
        result = detect_trust_hotspots(risk_result=self._risk(confidence_risk=0))
        areas = [h["area"] for h in result]
        assert "corroboration" not in areas

    def test_confidence_risk_critical_severity(self):
        result = detect_trust_hotspots(risk_result=self._risk(confidence_risk=90))
        hit = next(h for h in result if h["area"] == "evidence")
        assert hit["severity"] == "critical"

    def test_confidence_risk_at_threshold_high_severity(self):
        result = detect_trust_hotspots(
            risk_result=self._risk(confidence_risk=_RISK_HIGH_THRESHOLD)
        )
        hit = next((h for h in result if h["area"] == "evidence"), None)
        assert hit is not None
        assert hit["severity"] == "high"

    def test_autonomy_risk_high_produces_governance_hotspot(self):
        result = detect_trust_hotspots(risk_result=self._risk(future_autonomy_risk=60))
        areas = [h["area"] for h in result]
        assert "governance" in areas

    def test_multiple_hotspots_all_present(self):
        result = detect_trust_hotspots(
            risk_result=self._risk(
                confidence_risk=80,
                authority_risk=80,
                replay_risk=80,
            )
        )
        areas = {h["area"] for h in result}
        assert {"evidence", "authority", "replay"}.issubset(areas)


# ---------------------------------------------------------------------------
# 8. TestGenerateExecutiveActions
# ---------------------------------------------------------------------------


class TestGenerateExecutiveActions:
    def test_all_none_returns_maintain_action(self):
        result = generate_executive_actions()
        assert len(result) == 1
        assert result[0]["action"] == "maintain_current_trust_practices"

    def test_critical_posture_produces_immediate_action(self):
        result = generate_executive_actions(
            posture_result={"trust_posture": "critical", "score": 10}
        )
        priorities = [a["priority"] for a in result]
        assert "immediate" in priorities

    def test_rapidly_degrading_produces_immediate_action(self):
        result = generate_executive_actions(
            trend_result={"direction": "rapidly_degrading"}
        )
        priorities = [a["priority"] for a in result]
        assert "immediate" in priorities

    def test_critical_risk_produces_immediate_action(self):
        result = generate_executive_actions(
            risk_result={
                "risk_level": "critical",
                "category_scores": {"future_autonomy_risk": 0},
            }
        )
        priorities = [a["priority"] for a in result]
        assert "immediate" in priorities

    def test_degraded_posture_produces_short_term_action(self):
        result = generate_executive_actions(
            posture_result={"trust_posture": "degraded", "score": 30}
        )
        priorities = [a["priority"] for a in result]
        assert "short_term" in priorities

    def test_high_risk_produces_short_term_action(self):
        result = generate_executive_actions(
            risk_result={
                "risk_level": "high",
                "category_scores": {"future_autonomy_risk": 0},
            }
        )
        priorities = [a["priority"] for a in result]
        assert "short_term" in priorities

    def test_posture_below_75_produces_medium_term_action(self):
        result = generate_executive_actions(
            posture_result={"trust_posture": "stable", "score": 60}
        )
        priorities = [a["priority"] for a in result]
        assert "medium_term" in priorities

    def test_future_autonomy_risk_high_produces_governance_action(self):
        result = generate_executive_actions(
            risk_result={
                "risk_level": "none",
                "category_scores": {"future_autonomy_risk": 60},
            }
        )
        priorities = [a["priority"] for a in result]
        assert "medium_term" in priorities
        audiences = [a["audience"] for a in result]
        assert "governance" in audiences

    def test_actions_sorted_immediate_first(self):
        _order = {"immediate": 0, "short_term": 1, "medium_term": 2, "long_term": 3}
        result = generate_executive_actions(
            posture_result={"trust_posture": "critical", "score": 10},
            risk_result={
                "risk_level": "critical",
                "category_scores": {"future_autonomy_risk": 60},
            },
        )
        ranks = [_order.get(a["priority"], 99) for a in result]
        assert ranks == sorted(ranks)

    def test_each_action_has_required_keys(self):
        result = generate_executive_actions(
            posture_result={"trust_posture": "critical", "score": 10}
        )
        required = {"action", "priority", "expected_outcome", "reason", "audience"}
        for a in result:
            assert required.issubset(set(a.keys()))

    def test_audience_values_valid(self):
        valid_audiences = {"executive", "operations", "governance", "management"}
        result = generate_executive_actions(
            posture_result={"trust_posture": "critical", "score": 5},
            trend_result={"direction": "rapidly_degrading"},
            risk_result={
                "risk_level": "critical",
                "category_scores": {"future_autonomy_risk": 60},
            },
        )
        for a in result:
            assert a["audience"] in valid_audiences

    def test_watch_posture_produces_short_term_action(self):
        result = generate_executive_actions(
            posture_result={"trust_posture": "watch", "score": 50}
        )
        priorities = [a["priority"] for a in result]
        assert "short_term" in priorities

    def test_degrading_trend_produces_short_term_action(self):
        result = generate_executive_actions(trend_result={"direction": "degrading"})
        priorities = [a["priority"] for a in result]
        assert "short_term" in priorities

    def test_no_duplicates_on_single_trigger(self):
        result = generate_executive_actions(
            posture_result={"trust_posture": "critical", "score": 10}
        )
        actions_text = [a["action"] for a in result]
        assert len(actions_text) == len(set(actions_text))

    def test_default_action_priority_long_term(self):
        result = generate_executive_actions()
        assert result[0]["priority"] == "long_term"

    def test_default_action_audience_management(self):
        result = generate_executive_actions()
        assert result[0]["audience"] == "management"

    def test_critical_posture_executive_audience(self):
        result = generate_executive_actions(
            posture_result={"trust_posture": "critical", "score": 5}
        )
        executive_items = [a for a in result if a["audience"] == "executive"]
        assert len(executive_items) >= 1

    def test_multiple_triggers_produce_multiple_actions(self):
        result = generate_executive_actions(
            posture_result={"trust_posture": "critical", "score": 5},
            trend_result={"direction": "rapidly_degrading"},
            risk_result={
                "risk_level": "critical",
                "category_scores": {"future_autonomy_risk": 0},
            },
        )
        assert len(result) >= 3


# ---------------------------------------------------------------------------
# 9. TestGenerateGovernanceRecommendations
# ---------------------------------------------------------------------------


class TestGenerateGovernanceRecommendations:
    def test_all_none_returns_default_recommendation(self):
        # entity_type="any", no inputs → agent permits + autonomous suspend + agi cryptographic
        # Actually with entity_type="any" we get recommendations for human/agent/autonomous_system/agi
        # all with default posture_score=100 and autonomy_risk=0
        # human: posture<60? No (100>=60) → skip
        # agent: autonomy_risk>=55? No, posture<60? No → permit
        # autonomous_system: posture<75? No (100>=75) → skip
        # agi: always cryptographic, posture<90? No → skip
        # So we get agent+agi recommendations
        result = generate_governance_recommendations()
        assert isinstance(result, list)
        assert len(result) >= 1

    def test_entity_type_human_posture_below_60_produces_multi_person_approval(self):
        result = generate_governance_recommendations(
            posture_result={"trust_posture": "degraded", "score": 50},
            entity_type="human",
        )
        texts = [r["recommendation"] for r in result]
        assert any("multi-person approval" in t for t in texts)

    def test_entity_type_agent_autonomy_risk_high_produces_supervised_mode(self):
        result = generate_governance_recommendations(
            risk_result={
                "risk_level": "none",
                "category_scores": {"future_autonomy_risk": 60},
            },
            entity_type="agent",
        )
        texts = [r["recommendation"] for r in result]
        assert any("supervised mode" in t for t in texts)

    def test_entity_type_agent_good_posture_permits_with_monitoring(self):
        result = generate_governance_recommendations(
            posture_result={"trust_posture": "excellent", "score": 95},
            risk_result={
                "risk_level": "none",
                "category_scores": {"future_autonomy_risk": 0},
            },
            entity_type="agent",
        )
        texts = [r["recommendation"] for r in result]
        assert any("continuous trust monitoring" in t for t in texts)

    def test_entity_type_autonomous_system_posture_below_75_suspend(self):
        result = generate_governance_recommendations(
            posture_result={"trust_posture": "stable", "score": 65},
            entity_type="autonomous_system",
        )
        texts = [r["recommendation"] for r in result]
        assert any("Suspend autonomous system" in t for t in texts)

    def test_entity_type_agi_always_cryptographic_verification(self):
        result = generate_governance_recommendations(entity_type="agi")
        texts = [r["recommendation"] for r in result]
        assert any("cryptographic verification" in t for t in texts)

    def test_entity_type_agi_posture_below_90_human_approval(self):
        result = generate_governance_recommendations(
            posture_result={"trust_posture": "healthy", "score": 80},
            entity_type="agi",
        )
        texts = [r["recommendation"] for r in result]
        assert any("human approval" in t.lower() for t in texts)

    def test_entity_type_any_gets_agent_recommendation(self):
        result = generate_governance_recommendations(entity_type="any")
        applies = [r["applies_to"] for r in result]
        assert "agent" in applies

    def test_risk_high_produces_ai_trust_gates(self):
        result = generate_governance_recommendations(
            risk_result={
                "risk_level": "high",
                "category_scores": {"future_autonomy_risk": 0},
            },
            entity_type="agent",
        )
        texts = [r["recommendation"] for r in result]
        assert any("trust gates" in t for t in texts)

    def test_degrading_trend_produces_monitoring_alert(self):
        result = generate_governance_recommendations(
            trend_result={"direction": "degrading"},
            entity_type="agent",
        )
        layers = [r["governance_layer"] for r in result]
        assert "monitoring" in layers

    def test_hotspot_critical_produces_address_hotspot_recommendation(self):
        result = generate_governance_recommendations(
            hotspots=[{"area": "evidence", "severity": "critical"}],
            entity_type="agent",
        )
        texts = [r["recommendation"] for r in result]
        assert any("critical governance hotspot" in t for t in texts)

    def test_each_rec_has_required_keys(self):
        result = generate_governance_recommendations(
            posture_result={"trust_posture": "degraded", "score": 30},
            entity_type="human",
        )
        required = {
            "recommendation",
            "justification",
            "trust_impact",
            "applies_to",
            "governance_layer",
        }
        for r in result:
            assert required.issubset(set(r.keys()))

    def test_entity_type_agent_fleet_fallback_no_crash(self):
        # agent_fleet is not explicitly handled; should not crash
        result = generate_governance_recommendations(entity_type="agent_fleet")
        assert isinstance(result, list)

    def test_rapidly_degrading_trend_also_triggers_monitoring(self):
        result = generate_governance_recommendations(
            trend_result={"direction": "rapidly_degrading"},
            entity_type="human",
        )
        layers = [r["governance_layer"] for r in result]
        assert "monitoring" in layers

    def test_agi_governance_layer_cryptographic_control(self):
        result = generate_governance_recommendations(entity_type="agi")
        layers = [r["governance_layer"] for r in result]
        assert "cryptographic_control" in layers

    def test_agent_governance_layer_operational_mode(self):
        result = generate_governance_recommendations(
            posture_result={"trust_posture": "excellent", "score": 95},
            risk_result={
                "risk_level": "none",
                "category_scores": {"future_autonomy_risk": 0},
            },
            entity_type="agent",
        )
        layers = [r["governance_layer"] for r in result]
        assert "operational_mode" in layers

    def test_default_recommendation_governance_layer_steady_state(self):
        # entity_type that produces NO recommendations triggers default
        # Use a custom entity_type that isn't any/human/agent/autonomous_system/agi
        # and has no risk/trend/hotspot triggers
        result = generate_governance_recommendations(entity_type="service_account")
        assert result[0]["governance_layer"] == "steady_state"

    def test_applies_to_matches_entity_type(self):
        result = generate_governance_recommendations(
            risk_result={
                "risk_level": "high",
                "category_scores": {"future_autonomy_risk": 0},
            },
            entity_type="human",
        )
        trust_gate_items = [r for r in result if r["governance_layer"] == "trust_gate"]
        for item in trust_gate_items:
            assert item["applies_to"] == "human"

    def test_hotspot_high_severity_does_not_produce_hotspot_remediation(self):
        # Only critical hotspots trigger hotspot_remediation
        result = generate_governance_recommendations(
            hotspots=[{"area": "evidence", "severity": "high"}],
            entity_type="agent",
        )
        layers = [r["governance_layer"] for r in result]
        assert "hotspot_remediation" not in layers

    def test_no_posture_with_agi_still_returns_cryptographic(self):
        result = generate_governance_recommendations(entity_type="agi")
        texts = [r["recommendation"] for r in result]
        assert any("cryptographic" in t for t in texts)


# ---------------------------------------------------------------------------
# 10. TestForecastTrustPosture
# ---------------------------------------------------------------------------


class TestForecastTrustPosture:
    def _trend(self, score_change: int, window_days: int = 90) -> dict[str, Any]:
        return {
            "direction": "improving" if score_change > 0 else "degrading",
            "velocity": "moderate",
            "score_change": score_change,
            "confidence_change": 0,
            "window_days": window_days,
            "data_points": 2,
            "trend_available": True,
            "start_score": 50,
            "end_score": 50 + score_change,
        }

    def test_all_none_projects_stable(self):
        result = forecast_trust_posture()
        assert result["direction"] == "stable"
        assert result["score_delta"] == 0

    def test_no_trend_available_projects_stable(self):
        result = forecast_trust_posture(
            trend_result={"trend_available": False, "score_change": 0}
        )
        assert result["direction"] == "stable"

    def test_invalid_window_defaults_to_90(self):
        result = forecast_trust_posture(
            trend_result=self._trend(10),
            window_days=999,
        )
        assert result["days"] == 90

    def test_30_day_high_confidence(self):
        result = forecast_trust_posture(
            trend_result=self._trend(5),
            window_days=30,
        )
        assert result["forecast_confidence"] == "high"

    def test_90_day_medium_confidence(self):
        result = forecast_trust_posture(
            trend_result=self._trend(5),
            window_days=90,
        )
        assert result["forecast_confidence"] == "medium"

    def test_180_day_low_confidence_with_dampening(self):
        result = forecast_trust_posture(
            trend_result=self._trend(10),
            window_days=180,
        )
        assert result["forecast_confidence"] == "low"
        # Dampening 20% applied: raw_delta = (10/90)*180 * 0.8
        expected_delta = round((10 / 90) * 180 * 0.8)
        assert result["score_delta"] == expected_delta

    def test_365_day_low_confidence_with_35_percent_dampening(self):
        result = forecast_trust_posture(
            trend_result=self._trend(10),
            window_days=365,
        )
        assert result["forecast_confidence"] == "low"
        expected_delta = round((10 / 90) * 365 * 0.65)
        assert result["score_delta"] == expected_delta

    def test_positive_score_change_projects_improvement(self):
        result = forecast_trust_posture(
            trend_result=self._trend(20),
            posture_result={"score": 60},
            window_days=30,
        )
        assert result["projected_score"] > 60

    def test_negative_score_change_projects_decline(self):
        result = forecast_trust_posture(
            trend_result=self._trend(-20),
            posture_result={"score": 60},
            window_days=30,
        )
        assert result["projected_score"] < 60

    def test_projected_score_clamped_min(self):
        result = forecast_trust_posture(
            trend_result=self._trend(-100),
            posture_result={"score": 10},
            window_days=365,
        )
        assert result["projected_score"] >= 0

    def test_projected_score_clamped_max(self):
        result = forecast_trust_posture(
            trend_result=self._trend(100),
            posture_result={"score": 90},
            window_days=365,
        )
        assert result["projected_score"] <= 100

    def test_projected_posture_from_score(self):
        result = forecast_trust_posture(
            trend_result=self._trend(0),
            posture_result={"score": 95},
        )
        # score_change=0 → stable projection at current score
        assert result["projected_posture"] == "excellent"

    def test_each_output_has_required_keys(self):
        result = forecast_trust_posture()
        for key in (
            "projected_posture",
            "projected_score",
            "current_score",
            "current_posture",
            "score_delta",
            "days",
            "direction",
            "velocity",
            "forecast_confidence",
            "reasoning",
            "intelligence_version",
        ):
            assert key in result, f"Missing key: {key}"

    def test_current_score_matches_posture_result_score(self):
        result = forecast_trust_posture(posture_result={"score": 77})
        assert result["current_score"] == 77

    def test_score_delta_equals_projected_minus_current(self):
        result = forecast_trust_posture(
            trend_result=self._trend(10),
            posture_result={"score": 50},
            window_days=30,
        )
        assert (
            result["score_delta"] == result["projected_score"] - result["current_score"]
        )

    def test_no_posture_result_defaults_current_score_to_50(self):
        result = forecast_trust_posture(trend_result={"trend_available": False})
        assert result["current_score"] == 50

    def test_zero_score_change_projects_stable_at_medium_for_90(self):
        result = forecast_trust_posture(
            trend_result={
                "trend_available": True,
                "score_change": 0,
                "window_days": 90,
                "direction": "stable",
                "velocity": "minimal",
            },
            window_days=90,
        )
        assert result["forecast_confidence"] == "medium"
        assert result["score_delta"] == 0


# ---------------------------------------------------------------------------
# 11. TestGenerateTrustIntelligenceGraph
# ---------------------------------------------------------------------------


class TestGenerateTrustIntelligenceGraph:
    def test_all_none_returns_dict_with_nodes_and_edges(self):
        result = generate_trust_intelligence_graph()
        assert "nodes" in result
        assert "edges" in result

    def test_all_none_has_3_core_nodes(self):
        # posture:0, trend:0, risk:0 always added
        result = generate_trust_intelligence_graph()
        assert result["node_count"] == 3

    def test_posture_result_adds_posture_node(self):
        result = generate_trust_intelligence_graph(
            posture_result={"trust_posture": "healthy", "score": 80}
        )
        types = [n["node_type"] for n in result["nodes"]]
        assert GRAPH_NODE_POSTURE in types

    def test_trend_result_adds_trend_node(self):
        result = generate_trust_intelligence_graph(trend_result={"direction": "stable"})
        types = [n["node_type"] for n in result["nodes"]]
        assert GRAPH_NODE_TREND in types

    def test_risk_result_adds_risk_node(self):
        result = generate_trust_intelligence_graph(risk_result={"risk_level": "none"})
        types = [n["node_type"] for n in result["nodes"]]
        assert GRAPH_NODE_RISK in types

    def test_priorities_add_priority_nodes(self):
        priorities = [
            {
                "priority": 1,
                "issue": "test",
                "impact": "low",
                "trust_delta": 0,
                "reason": "r",
                "evidence": {},
            },
        ]
        result = generate_trust_intelligence_graph(priorities=priorities)
        types = [n["node_type"] for n in result["nodes"]]
        assert GRAPH_NODE_PRIORITY in types

    def test_recommendations_add_recommendation_nodes(self):
        recs = [
            {
                "recommendation": "Do X",
                "justification": "j",
                "trust_impact": "t",
                "applies_to": "any",
                "governance_layer": "test",
            },
        ]
        result = generate_trust_intelligence_graph(recommendations=recs)
        types = [n["node_type"] for n in result["nodes"]]
        assert GRAPH_NODE_RECOMMENDATION in types

    def test_forecast_adds_forecast_node(self):
        result = generate_trust_intelligence_graph(
            forecast_result={"projected_score": 80}
        )
        types = [n["node_type"] for n in result["nodes"]]
        assert GRAPH_NODE_FORECAST in types

    def test_insights_add_insight_nodes(self):
        insights = [
            {
                "category": "drift",
                "severity": "info",
                "insight": "ok",
                "evidence": {},
                "recommended_action": "none",
            }
        ]
        result = generate_trust_intelligence_graph(insights=insights)
        types = [n["node_type"] for n in result["nodes"]]
        assert GRAPH_NODE_INSIGHT in types

    def test_hotspots_add_hotspot_nodes(self):
        hotspots = [
            {"area": "evidence", "severity": "high", "reason": "r", "risk_score": 60}
        ]
        result = generate_trust_intelligence_graph(hotspots=hotspots)
        types = [n["node_type"] for n in result["nodes"]]
        assert GRAPH_NODE_HOTSPOT in types

    def test_node_count_correct(self):
        priorities = [
            {
                "priority": 1,
                "issue": "p1",
                "impact": "low",
                "trust_delta": 0,
                "reason": "",
                "evidence": {},
            },
            {
                "priority": 2,
                "issue": "p2",
                "impact": "low",
                "trust_delta": 0,
                "reason": "",
                "evidence": {},
            },
        ]
        result = generate_trust_intelligence_graph(priorities=priorities)
        # 3 core + 2 priorities = 5
        assert result["node_count"] == 5
        assert len(result["nodes"]) == result["node_count"]

    def test_edge_count_correct(self):
        result = generate_trust_intelligence_graph()
        assert result["edge_count"] == len(result["edges"])

    def test_edges_connect_posture_to_trend(self):
        result = generate_trust_intelligence_graph()
        edge_pairs = [
            (e["source_id"], e["target_id"], e["edge_type"]) for e in result["edges"]
        ]
        assert ("posture:0", "trend:0", "informs_trend") in edge_pairs

    def test_edges_connect_posture_to_risk(self):
        result = generate_trust_intelligence_graph()
        edge_pairs = [
            (e["source_id"], e["target_id"], e["edge_type"]) for e in result["edges"]
        ]
        assert ("posture:0", "risk:0", "informs_risk") in edge_pairs

    def test_each_node_has_required_keys(self):
        result = generate_trust_intelligence_graph()
        for node in result["nodes"]:
            for key in (
                "node_id",
                "node_type",
                "payload",
                "tenant_id",
                "engagement_id",
            ):
                assert key in node

    def test_tenant_id_propagated_to_all_nodes(self):
        result = generate_trust_intelligence_graph(
            tenant_id=TENANT_A,
            insights=[
                {
                    "category": "drift",
                    "severity": "info",
                    "insight": "ok",
                    "evidence": {},
                    "recommended_action": "none",
                }
            ],
        )
        for node in result["nodes"]:
            assert node["tenant_id"] == TENANT_A

    def test_no_cross_tenant_nodes(self):
        result = generate_trust_intelligence_graph(tenant_id=TENANT_A)
        for node in result["nodes"]:
            assert node["tenant_id"] != TENANT_B

    def test_graph_node_type_constants_in_output(self):
        forecast_r = {"projected_score": 80}
        priorities = [
            {
                "priority": 1,
                "issue": "p",
                "impact": "low",
                "trust_delta": 0,
                "reason": "",
                "evidence": {},
            }
        ]
        insights = [
            {
                "category": "general",
                "severity": "info",
                "insight": "ok",
                "evidence": {},
                "recommended_action": "none",
            }
        ]
        hotspots = [
            {"area": "evidence", "severity": "high", "reason": "r", "risk_score": 60}
        ]
        recs = [
            {
                "recommendation": "r",
                "justification": "j",
                "trust_impact": "t",
                "applies_to": "any",
                "governance_layer": "test",
            }
        ]
        result = generate_trust_intelligence_graph(
            forecast_result=forecast_r,
            priorities=priorities,
            insights=insights,
            hotspots=hotspots,
            recommendations=recs,
        )
        all_types = {n["node_type"] for n in result["nodes"]}
        expected = {
            GRAPH_NODE_POSTURE,
            GRAPH_NODE_TREND,
            GRAPH_NODE_RISK,
            GRAPH_NODE_FORECAST,
            GRAPH_NODE_PRIORITY,
            GRAPH_NODE_INSIGHT,
            GRAPH_NODE_HOTSPOT,
            GRAPH_NODE_RECOMMENDATION,
        }
        assert expected == all_types

    def test_graph_tenant_and_engagement_id_in_output(self):
        result = generate_trust_intelligence_graph(
            tenant_id=TENANT_A, engagement_id=ENG_A
        )
        assert result["tenant_id"] == TENANT_A
        assert result["engagement_id"] == ENG_A


# ---------------------------------------------------------------------------
# 12. TestDeterminism
# ---------------------------------------------------------------------------


class TestDeterminism:
    def _conf(self) -> dict[str, Any]:
        return {"confidence_score": 65}

    def _replay(self) -> dict[str, Any]:
        return {"chain_replay_score": 80}

    def _graph(self) -> dict[str, Any]:
        return {"graph_valid": True, "violations": 1}

    def _drift(self) -> dict[str, Any]:
        return {"direction": "improving", "velocity": "moderate"}

    def _snaps(self) -> list[dict[str, Any]]:
        return [
            {"created_at": _ts(10), "score": 60, "confidence": 60},
            {"created_at": _ts(1), "score": 70, "confidence": 70},
        ]

    def test_calculate_trust_posture_deterministic(self):
        kwargs = dict(
            confidence_result=self._conf(),
            replay_result=self._replay(),
            graph_result=self._graph(),
            drift_result=self._drift(),
            tenant_id=TENANT_A,
            engagement_id=ENG_A,
        )
        r1 = calculate_trust_posture(**kwargs)
        r2 = calculate_trust_posture(**kwargs)
        assert r1 == r2

    def test_calculate_trust_trend_deterministic(self):
        snaps = self._snaps()
        r1 = calculate_trust_trend(snaps, window_days=30, tenant_id=TENANT_A)
        r2 = calculate_trust_trend(snaps, window_days=30, tenant_id=TENANT_A)
        assert r1 == r2

    def test_generate_trust_priorities_deterministic(self):
        kwargs = dict(
            confidence_result=self._conf(),
            replay_result=self._replay(),
            drift_result=self._drift(),
            tenant_id=TENANT_A,
        )
        r1 = generate_trust_priorities(**kwargs)
        r2 = generate_trust_priorities(**kwargs)
        assert r1 == r2

    def test_calculate_trust_risk_deterministic(self):
        kwargs = dict(
            confidence_result=self._conf(),
            replay_result=self._replay(),
            graph_result=self._graph(),
            drift_result=self._drift(),
            tenant_id=TENANT_A,
        )
        r1 = calculate_trust_risk(**kwargs)
        r2 = calculate_trust_risk(**kwargs)
        assert r1 == r2

    def test_generate_trust_insights_deterministic(self):
        kwargs = dict(
            confidence_result=self._conf(),
            drift_result=self._drift(),
            tenant_id=TENANT_A,
        )
        r1 = generate_trust_insights(**kwargs)
        r2 = generate_trust_insights(**kwargs)
        assert r1 == r2

    def test_detect_trust_hotspots_deterministic(self):
        risk = {
            "category_scores": {
                "confidence_risk": 60,
                "authority_risk": 0,
                "replay_risk": 70,
                "graph_risk": 0,
                "drift_risk": 0,
                "governance_risk": 0,
                "future_autonomy_risk": 0,
            }
        }
        r1 = detect_trust_hotspots(risk_result=risk)
        r2 = detect_trust_hotspots(risk_result=risk)
        assert r1 == r2

    def test_generate_executive_actions_deterministic(self):
        kwargs = dict(
            posture_result={"trust_posture": "degraded", "score": 30},
            trend_result={"direction": "degrading"},
            risk_result={
                "risk_level": "high",
                "category_scores": {"future_autonomy_risk": 0},
            },
        )
        r1 = generate_executive_actions(**kwargs)
        r2 = generate_executive_actions(**kwargs)
        assert r1 == r2

    def test_generate_governance_recommendations_deterministic(self):
        kwargs = dict(
            posture_result={"trust_posture": "stable", "score": 65},
            risk_result={
                "risk_level": "none",
                "category_scores": {"future_autonomy_risk": 0},
            },
            entity_type="agent",
        )
        r1 = generate_governance_recommendations(**kwargs)
        r2 = generate_governance_recommendations(**kwargs)
        assert r1 == r2

    def test_forecast_trust_posture_deterministic(self):
        trend = {
            "direction": "improving",
            "velocity": "moderate",
            "score_change": 8,
            "window_days": 90,
            "trend_available": True,
        }
        r1 = forecast_trust_posture(
            trend_result=trend,
            posture_result={"score": 60},
            window_days=90,
        )
        r2 = forecast_trust_posture(
            trend_result=trend,
            posture_result={"score": 60},
            window_days=90,
        )
        assert r1 == r2

    def test_generate_trust_intelligence_graph_deterministic(self):
        kwargs = dict(
            posture_result={"trust_posture": "healthy", "score": 80},
            trend_result={"direction": "stable"},
            tenant_id=TENANT_A,
            engagement_id=ENG_A,
        )
        r1 = generate_trust_intelligence_graph(**kwargs)
        r2 = generate_trust_intelligence_graph(**kwargs)
        assert r1 == r2


# ---------------------------------------------------------------------------
# 13. TestCrossTenantIsolation
# ---------------------------------------------------------------------------


class TestCrossTenantIsolation:
    def test_tenant_id_in_posture_output_matches_input(self):
        result = calculate_trust_posture(tenant_id=TENANT_A)
        assert result["tenant_id"] == TENANT_A

    def test_different_tenants_produce_different_tenant_id_in_output(self):
        r_a = calculate_trust_posture(tenant_id=TENANT_A)
        r_b = calculate_trust_posture(tenant_id=TENANT_B)
        assert r_a["tenant_id"] != r_b["tenant_id"]

    def test_trend_tenant_id_preserved(self):
        result = calculate_trust_trend([], tenant_id=TENANT_A)
        assert result["tenant_id"] == TENANT_A

    def test_risk_tenant_id_preserved(self):
        result = calculate_trust_risk(tenant_id=TENANT_B)
        assert result["tenant_id"] == TENANT_B

    def test_priorities_tenant_id_passed_through(self):
        # generate_trust_priorities does not embed tenant_id in items, but should not crash
        result = generate_trust_priorities(tenant_id=TENANT_A)
        assert isinstance(result, list)

    def test_graph_nodes_have_correct_tenant_id(self):
        result = generate_trust_intelligence_graph(tenant_id=TENANT_A)
        for node in result["nodes"]:
            assert node["tenant_id"] == TENANT_A

    def test_recommendations_tenant_id_preserved(self):
        result = generate_governance_recommendations(tenant_id=TENANT_B)
        # tenant_id not in individual recommendation items by spec, but function takes it
        assert isinstance(result, list)

    def test_no_cross_contamination_between_two_tenants(self):
        r_a = calculate_trust_risk(
            confidence_result={"confidence_score": 30},
            tenant_id=TENANT_A,
        )
        r_b = calculate_trust_risk(
            confidence_result={"confidence_score": 80},
            tenant_id=TENANT_B,
        )
        assert r_a["tenant_id"] == TENANT_A
        assert r_b["tenant_id"] == TENANT_B
        assert (
            r_a["category_scores"]["confidence_risk"]
            != r_b["category_scores"]["confidence_risk"]
        )


# ---------------------------------------------------------------------------
# 14. TestCrossEngagementIsolation
# ---------------------------------------------------------------------------


class TestCrossEngagementIsolation:
    def test_engagement_id_in_posture_output(self):
        result = calculate_trust_posture(engagement_id=ENG_A)
        assert result["engagement_id"] == ENG_A

    def test_engagement_id_in_risk_output(self):
        result = calculate_trust_risk(engagement_id=ENG_B)
        assert result["engagement_id"] == ENG_B

    def test_engagement_id_in_graph_nodes(self):
        result = generate_trust_intelligence_graph(engagement_id=ENG_A)
        for node in result["nodes"]:
            assert node["engagement_id"] == ENG_A

    def test_two_calls_different_engagement_ids(self):
        r1 = calculate_trust_posture(engagement_id=ENG_A)
        r2 = calculate_trust_posture(engagement_id=ENG_B)
        assert r1["engagement_id"] != r2["engagement_id"]

    def test_posture_scores_not_affected_by_engagement_id(self):
        r1 = calculate_trust_posture(
            confidence_result={"confidence_score": 70},
            engagement_id=ENG_A,
        )
        r2 = calculate_trust_posture(
            confidence_result={"confidence_score": 70},
            engagement_id=ENG_B,
        )
        assert r1["score"] == r2["score"]


# ---------------------------------------------------------------------------
# 15. TestPerformance
# ---------------------------------------------------------------------------


class TestPerformance:
    def test_100_posture_calculations_under_100ms(self):
        start = time.perf_counter()
        for _ in range(100):
            calculate_trust_posture(
                confidence_result={"confidence_score": 70},
                replay_result={"chain_replay_score": 80},
            )
        elapsed = (time.perf_counter() - start) * 1000
        assert elapsed < 100, f"100 posture calcs took {elapsed:.1f}ms"

    def test_1000_trend_calculations_under_250ms(self):
        snaps = [
            {"created_at": _ts(10), "score": 60},
            {"created_at": _ts(1), "score": 70},
        ]
        start = time.perf_counter()
        for _ in range(1000):
            calculate_trust_trend(snaps, window_days=30)
        elapsed = (time.perf_counter() - start) * 1000
        assert elapsed < 250, f"1000 trend calcs took {elapsed:.1f}ms"

    def test_1000_priority_generations_under_250ms(self):
        start = time.perf_counter()
        for _ in range(1000):
            generate_trust_priorities(
                confidence_result={"confidence_score": 20},
                drift_result={"direction": "degrading"},
            )
        elapsed = (time.perf_counter() - start) * 1000
        assert elapsed < 250, f"1000 priority gens took {elapsed:.1f}ms"

    def test_1000_risk_calculations_under_250ms(self):
        start = time.perf_counter()
        for _ in range(1000):
            calculate_trust_risk(
                confidence_result={"confidence_score": 40},
                replay_result={"chain_replay_score": 60},
            )
        elapsed = (time.perf_counter() - start) * 1000
        assert elapsed < 250, f"1000 risk calcs took {elapsed:.1f}ms"

    def test_1000_insight_generations_under_250ms(self):
        start = time.perf_counter()
        for _ in range(1000):
            generate_trust_insights(
                confidence_result={"confidence_score": 20},
                drift_result={"direction": "degrading"},
            )
        elapsed = (time.perf_counter() - start) * 1000
        assert elapsed < 250, f"1000 insight gens took {elapsed:.1f}ms"

    def test_graph_with_100_priorities_and_100_recs_under_500ms(self):
        priorities = [
            {
                "priority": i,
                "issue": f"p{i}",
                "impact": "low",
                "trust_delta": 0,
                "reason": "",
                "evidence": {},
            }
            for i in range(100)
        ]
        recs = [
            {
                "recommendation": f"r{i}",
                "justification": "j",
                "trust_impact": "t",
                "applies_to": "any",
                "governance_layer": "test",
            }
            for i in range(100)
        ]
        start = time.perf_counter()
        generate_trust_intelligence_graph(priorities=priorities, recommendations=recs)
        elapsed = (time.perf_counter() - start) * 1000
        assert elapsed < 500, f"graph with 200 items took {elapsed:.1f}ms"

    def test_forecast_1000x_under_250ms(self):
        trend = {
            "direction": "improving",
            "velocity": "moderate",
            "score_change": 5,
            "window_days": 90,
            "trend_available": True,
        }
        start = time.perf_counter()
        for _ in range(1000):
            forecast_trust_posture(
                trend_result=trend, posture_result={"score": 60}, window_days=30
            )
        elapsed = (time.perf_counter() - start) * 1000
        assert elapsed < 250, f"1000 forecast calcs took {elapsed:.1f}ms"

    def test_governance_recommendations_1000x_under_250ms(self):
        start = time.perf_counter()
        for _ in range(1000):
            generate_governance_recommendations(
                posture_result={"trust_posture": "stable", "score": 65},
                risk_result={
                    "risk_level": "none",
                    "category_scores": {"future_autonomy_risk": 0},
                },
                entity_type="agent",
            )
        elapsed = (time.perf_counter() - start) * 1000
        assert elapsed < 250, f"1000 governance recs took {elapsed:.1f}ms"


# ---------------------------------------------------------------------------
# 16. TestFutureAgentCompatibility
# ---------------------------------------------------------------------------


class TestFutureAgentCompatibility:
    def test_governance_recommendations_agent_entity_type_works(self):
        result = generate_governance_recommendations(
            posture_result={"trust_posture": "healthy", "score": 80},
            risk_result={
                "risk_level": "none",
                "category_scores": {"future_autonomy_risk": 0},
            },
            entity_type="agent",
        )
        assert isinstance(result, list)
        assert len(result) >= 1

    def test_governance_recommendations_autonomous_system_entity_type_works(self):
        result = generate_governance_recommendations(
            posture_result={"trust_posture": "healthy", "score": 80},
            entity_type="autonomous_system",
        )
        assert isinstance(result, list)

    def test_agent_fleet_entity_type_fallback_does_not_crash(self):
        result = generate_governance_recommendations(entity_type="agent_fleet")
        assert isinstance(result, list)

    def test_posture_works_with_agent_derived_confidence_result(self):
        agent_conf = {
            "confidence_score": 72,
            "entity_type": "agent",
            "agent_id": "agent-0001",
        }
        result = calculate_trust_posture(confidence_result=agent_conf)
        assert result["trust_posture"] in {
            "excellent",
            "healthy",
            "stable",
            "watch",
            "degraded",
            "critical",
        }

    def test_trust_priorities_work_for_agent_context(self):
        result = generate_trust_priorities(
            confidence_result={"confidence_score": 72, "entity_type": "agent"},
            drift_result={"direction": "stable"},
            tenant_id=TENANT_A,
        )
        assert isinstance(result, list)

    def test_intelligence_graph_supports_non_standard_entity_payloads(self):
        posture = {
            "trust_posture": "healthy",
            "score": 80,
            "entity_type": "agent",
            "agent_id": "agent-0001",
        }
        result = generate_trust_intelligence_graph(posture_result=posture)
        posture_node = next(
            n for n in result["nodes"] if n["node_type"] == GRAPH_NODE_POSTURE
        )
        assert posture_node["payload"]["agent_id"] == "agent-0001"

    def test_executive_actions_include_governance_audience_when_autonomy_risk_elevated(
        self,
    ):
        result = generate_executive_actions(
            risk_result={
                "risk_level": "none",
                "category_scores": {"future_autonomy_risk": 60},
            }
        )
        audiences = [a["audience"] for a in result]
        assert "governance" in audiences

    def test_insights_include_autonomy_governance_insight(self):
        risk = {
            "category_scores": {
                "replay_risk": 0,
                "governance_risk": 0,
                "future_autonomy_risk": 60,
            }
        }
        result = generate_trust_insights(risk_result=risk)
        hits = [i for i in result if i["category"] == "governance"]
        assert len(hits) >= 1


# ---------------------------------------------------------------------------
# 17. TestAGIGovernanceCompatibility
# ---------------------------------------------------------------------------


class TestAGIGovernanceCompatibility:
    def test_agi_gets_cryptographic_verification_recommendation(self):
        result = generate_governance_recommendations(entity_type="agi")
        texts = [r["recommendation"] for r in result]
        assert any("cryptographic verification" in t for t in texts)

    def test_agi_posture_below_90_gets_human_approval(self):
        result = generate_governance_recommendations(
            posture_result={"trust_posture": "healthy", "score": 85},
            entity_type="agi",
        )
        texts = [r["recommendation"] for r in result]
        assert any("human approval" in t.lower() for t in texts)

    def test_calculate_trust_posture_works_with_agi_governance_inputs(self):
        result = calculate_trust_posture(
            confidence_result={"confidence_score": 95},
            evidence_authority={"valid": True},
            tenant_id="agi-tenant",
        )
        assert result["trust_posture"] in {
            "excellent",
            "healthy",
            "stable",
            "watch",
            "degraded",
            "critical",
        }

    def test_generate_trust_priorities_works_in_agi_context(self):
        result = generate_trust_priorities(
            confidence_result={"confidence_score": 88},
            drift_result={"direction": "stable"},
        )
        assert isinstance(result, list)

    def test_trust_risk_future_autonomy_elevated_with_low_confidence_agi(self):
        result = calculate_trust_risk(confidence_result={"confidence_score": 30})
        assert result["category_scores"]["future_autonomy_risk"] == 60

    def test_forecast_works_for_agi_planning_window_365_days(self):
        trend = {
            "direction": "improving",
            "velocity": "moderate",
            "score_change": 10,
            "window_days": 90,
            "trend_available": True,
        }
        result = forecast_trust_posture(
            trend_result=trend,
            posture_result={"score": 80},
            window_days=365,
        )
        assert result["days"] == 365
        assert result["forecast_confidence"] == "low"

    def test_intelligence_graph_supports_agi_governance_payload(self):
        posture = {
            "trust_posture": "excellent",
            "score": 95,
            "entity_type": "agi",
            "oversight_required": True,
        }
        result = generate_trust_intelligence_graph(posture_result=posture)
        posture_node = next(
            n for n in result["nodes"] if n["node_type"] == GRAPH_NODE_POSTURE
        )
        assert posture_node["payload"]["entity_type"] == "agi"

    def test_executive_actions_include_governance_for_agi_risk(self):
        result = generate_executive_actions(
            risk_result={
                "risk_level": "none",
                "category_scores": {"future_autonomy_risk": 60},
            }
        )
        audiences = [a["audience"] for a in result]
        assert "governance" in audiences


# ---------------------------------------------------------------------------
# 18. TestSecurityInvariants
# ---------------------------------------------------------------------------


class TestSecurityInvariants:
    """All exported functions must never raise on any combination of inputs."""

    _GARBAGE_INPUTS: list[Any] = [
        None,
        {},
        {"foo": "bar"},
        {"confidence_score": "not_a_number"},
        0,
        "string",
        [],
        [None],
    ]

    def test_calculate_trust_posture_never_raises(self):
        for val in self._GARBAGE_INPUTS:
            try:
                calculate_trust_posture(
                    confidence_result=val
                    if isinstance(val, (dict, type(None)))
                    else None,
                    replay_result=val if isinstance(val, (dict, type(None))) else None,
                )
            except Exception as exc:  # noqa: BLE001
                raise AssertionError(
                    f"calculate_trust_posture raised {exc!r} for input {val!r}"
                ) from exc

    def test_calculate_trust_risk_never_raises(self):
        for val in self._GARBAGE_INPUTS:
            try:
                calculate_trust_risk(
                    confidence_result=val
                    if isinstance(val, (dict, type(None)))
                    else None,
                    replay_result=val if isinstance(val, (dict, type(None))) else None,
                )
            except Exception as exc:
                raise AssertionError(f"calculate_trust_risk raised {exc!r}") from exc

    def test_generate_trust_priorities_never_raises(self):
        for val in self._GARBAGE_INPUTS:
            try:
                generate_trust_priorities(
                    confidence_result=val
                    if isinstance(val, (dict, type(None)))
                    else None,
                    hotspots=val if isinstance(val, (list, type(None))) else None,
                )
            except Exception as exc:
                raise AssertionError(
                    f"generate_trust_priorities raised {exc!r}"
                ) from exc

    def test_generate_trust_insights_never_raises(self):
        for val in self._GARBAGE_INPUTS:
            try:
                generate_trust_insights(
                    confidence_result=val
                    if isinstance(val, (dict, type(None)))
                    else None,
                    hotspots=val if isinstance(val, (list, type(None))) else None,
                )
            except Exception as exc:
                raise AssertionError(f"generate_trust_insights raised {exc!r}") from exc

    def test_detect_trust_hotspots_never_raises(self):
        for val in self._GARBAGE_INPUTS:
            try:
                detect_trust_hotspots(
                    risk_result=val if isinstance(val, (dict, type(None))) else None,
                    confidence_snapshots=val
                    if isinstance(val, (list, type(None)))
                    else None,
                )
            except Exception as exc:
                raise AssertionError(f"detect_trust_hotspots raised {exc!r}") from exc

    def test_generate_executive_actions_never_raises(self):
        for val in self._GARBAGE_INPUTS:
            try:
                generate_executive_actions(
                    posture_result=val if isinstance(val, (dict, type(None))) else None,
                    risk_result=val if isinstance(val, (dict, type(None))) else None,
                )
            except Exception as exc:
                raise AssertionError(
                    f"generate_executive_actions raised {exc!r}"
                ) from exc

    def test_generate_governance_recommendations_never_raises(self):
        for val in self._GARBAGE_INPUTS:
            try:
                generate_governance_recommendations(
                    posture_result=val if isinstance(val, (dict, type(None))) else None,
                    risk_result=val if isinstance(val, (dict, type(None))) else None,
                )
            except Exception as exc:
                raise AssertionError(
                    f"generate_governance_recommendations raised {exc!r}"
                ) from exc

    def test_forecast_trust_posture_never_raises(self):
        for val in self._GARBAGE_INPUTS:
            try:
                forecast_trust_posture(
                    trend_result=val if isinstance(val, (dict, type(None))) else None,
                    posture_result=val if isinstance(val, (dict, type(None))) else None,
                )
            except Exception as exc:
                raise AssertionError(f"forecast_trust_posture raised {exc!r}") from exc

    def test_generate_trust_intelligence_graph_never_raises(self):
        for val in self._GARBAGE_INPUTS:
            try:
                generate_trust_intelligence_graph(
                    posture_result=val if isinstance(val, (dict, type(None))) else None,
                    priorities=val if isinstance(val, (list, type(None))) else None,
                )
            except Exception as exc:
                raise AssertionError(
                    f"generate_trust_intelligence_graph raised {exc!r}"
                ) from exc

    def test_score_always_clamped_0_to_100_across_deterministic_inputs(self):
        for i in range(100):
            score_val = (i * 37) % 200 - 50  # ranges from -50 to 149
            result = calculate_trust_posture(
                confidence_result={"confidence_score": score_val},
                replay_result={"chain_replay_score": score_val},
            )
            assert 0 <= result["score"] <= 100, (
                f"score {result['score']} out of range for input {score_val}"
            )


# ---------------------------------------------------------------------------
# 19. TestEnterpriseScenarios
# ---------------------------------------------------------------------------


class TestEnterpriseScenarios:
    def test_banking_scenario_excellent_posture(self):
        """High confidence, verified chain, no violations → excellent posture."""
        posture = calculate_trust_posture(
            confidence_result={"confidence_score": 95},
            replay_result={"chain_replay_score": 100},
            graph_result={"graph_valid": True, "violations": 0},
            evidence_authority={"valid": True},
            enforcement_result={"allowed": True, "trust_score": 100},
            drift_result={"direction": "stable"},
            tenant_id="banking-tenant",
            engagement_id="eng-banking-001",
        )
        assert posture["trust_posture"] in ("excellent", "healthy")
        assert posture["score"] >= _POSTURE_HEALTHY

    def test_healthcare_scenario_watch_or_stable(self):
        """Moderate confidence, some replay degradation → watch or stable."""
        posture = calculate_trust_posture(
            confidence_result={"confidence_score": 55},
            replay_result={"chain_replay_score": 65},
            graph_result={"graph_valid": True, "violations": 1},
            drift_result={"direction": "stable"},
            tenant_id="healthcare-tenant",
        )
        assert posture["trust_posture"] in ("watch", "stable", "degraded")

    def test_critical_infrastructure_broken_chain_critical_risk(self):
        """Broken chain → critical risk."""
        risk = calculate_trust_risk(
            replay_result={"chain_replay_score": 0},
            confidence_result={"confidence_score": 20},
            graph_result={"graph_valid": False},
            tenant_id="infra-tenant",
        )
        assert risk["risk_level"] in ("critical", "high")
        assert risk["category_scores"]["replay_risk"] == 90

    def test_govcon_authority_downgrade_high_risk(self):
        """Authority invalid → high/critical risk."""
        risk = calculate_trust_risk(
            evidence_authority={"valid": False},
            tenant_id="govcon-tenant",
        )
        assert risk["category_scores"]["authority_risk"] == 80
        assert risk["risk_level"] in ("critical", "high")

    def test_ai_governance_low_posture_gates_triggered(self):
        """Low posture for AI deployment → governance recommendations gate it."""
        recs = generate_governance_recommendations(
            posture_result={"trust_posture": "degraded", "score": 30},
            risk_result={
                "risk_level": "high",
                "category_scores": {"future_autonomy_risk": 60},
            },
            entity_type="agent",
        )
        texts = [r["recommendation"] for r in recs]
        assert any("supervised mode" in t or "trust gates" in t for t in texts)

    def test_full_pipeline_consistent(self):
        """Full pipeline: posture→trend→risk→priorities→insights→executive actions."""
        posture = calculate_trust_posture(
            confidence_result={"confidence_score": 40},
            replay_result={"chain_replay_score": 50},
            drift_result={"direction": "degrading"},
            tenant_id=TENANT_A,
        )
        snaps = [
            {"created_at": _ts(20), "score": 60},
            {"created_at": _ts(5), "score": posture["score"]},
        ]
        trend = calculate_trust_trend(snaps, window_days=30, tenant_id=TENANT_A)
        risk = calculate_trust_risk(
            confidence_result={"confidence_score": 40},
            replay_result={"chain_replay_score": 50},
            drift_result={"direction": "degrading"},
            posture_result=posture,
            tenant_id=TENANT_A,
        )
        priorities = generate_trust_priorities(
            posture_result=posture,
            risk_result=risk,
            drift_result={"direction": "degrading"},
            confidence_result={"confidence_score": 40},
            tenant_id=TENANT_A,
        )
        insights = generate_trust_insights(
            posture_result=posture,
            trend_result=trend,
            risk_result=risk,
            confidence_result={"confidence_score": 40},
            drift_result={"direction": "degrading"},
            tenant_id=TENANT_A,
        )
        actions = generate_executive_actions(
            posture_result=posture,
            trend_result=trend,
            risk_result=risk,
            tenant_id=TENANT_A,
        )
        # Consistency checks
        assert posture["trust_posture"] in {"watch", "degraded", "critical", "stable"}
        assert isinstance(priorities, list)
        assert len(priorities) >= 1
        # Every priority has all required keys
        for p in priorities:
            assert "trust_delta" in p
        # At least one insight with severity >= high
        high_plus = [i for i in insights if i["severity"] in ("critical", "high")]
        assert len(high_plus) >= 1
        # Executive actions are present
        assert len(actions) >= 1


# ---------------------------------------------------------------------------
# 20. TestEdgeCases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_snapshot_list_with_none_items_filtered(self):
        snaps = [None, {"created_at": _ts(5), "score": 60}, None]
        result = calculate_trust_trend(snaps, window_days=30)
        # Only 1 valid snapshot → not enough for trend
        assert result["trend_available"] is False

    def test_drift_result_with_unknown_direction_does_not_crash(self):
        result = calculate_trust_posture(drift_result={"direction": "sideways"})
        assert isinstance(result, dict)
        # Unknown direction → drift_modifier = _DRIFT_STABLE = 0

    def test_graph_result_with_empty_violations_not_counted(self):
        result = calculate_trust_posture(
            graph_result={"graph_valid": True, "violations": []}
        )
        # violations=[] → int([]) raises, so implementation defaults to 0
        # Verify no crash and graph_score is 100 (no violations counted)
        assert result["component_scores"]["graph_score"] == 100

    def test_window_days_zero_defaults_to_90(self):
        snaps = [
            {"created_at": _ts(5), "score": 60},
            {"created_at": _ts(1), "score": 70},
        ]
        result = calculate_trust_trend(snaps, window_days=0)
        assert result["window_days"] == 90

    def test_empty_string_tenant_id_preserved(self):
        result = calculate_trust_posture(tenant_id="")
        assert result["tenant_id"] == ""

    def test_all_scores_100_produces_excellent_posture(self):
        result = calculate_trust_posture(
            confidence_result={"confidence_score": 100},
            replay_result={"chain_replay_score": 100},
            graph_result={"graph_valid": True, "violations": 0},
            evidence_authority={"valid": True},
            enforcement_result={"allowed": True, "trust_score": 100},
            drift_result={"direction": "stable"},
        )
        assert result["trust_posture"] == "excellent"
        assert result["score"] == 100

    def test_confidence_100_with_broken_chain_still_penalized(self):
        without_broken = calculate_trust_posture(
            confidence_result={"confidence_score": 100}
        )
        with_broken = calculate_trust_posture(
            confidence_result={"confidence_score": 100},
            replay_result={"chain_replay_score": 0},
        )
        assert with_broken["score"] < without_broken["score"]

    def test_posture_with_all_modifiers_applied_stays_clamped(self):
        # All-max score + rapidly_improving should not exceed 100
        result = calculate_trust_posture(
            confidence_result={"confidence_score": 100},
            replay_result={"chain_replay_score": 100},
            graph_result={"graph_valid": True, "violations": 0},
            evidence_authority={"valid": True},
            enforcement_result={"allowed": True, "trust_score": 100},
            drift_result={"direction": "rapidly_improving"},
        )
        assert result["score"] <= 100
        # All-zero score + rapidly_degrading should not go below 0
        result2 = calculate_trust_posture(
            confidence_result={"confidence_score": 0},
            replay_result={"chain_replay_score": 0},
            graph_result={"graph_valid": False},
            evidence_authority={"valid": False},
            enforcement_result={"allowed": False},
            drift_result={"direction": "rapidly_degrading"},
        )
        assert result2["score"] >= 0
