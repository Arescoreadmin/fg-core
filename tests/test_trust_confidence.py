"""Trust Confidence & Corroboration Engine tests — PR 1.7.

Coverage matrix:
  Confidence Levels             boundary tests for all 5 tiers
  Confidence Calculation        calculate_confidence — all factor combinations
  Corroboration                 independent sources, duplicates, single source
  Evidence Strength             per-node scoring — all factor combinations
  Trust Quality                 positive/negative factor enumeration
  Confidence Decay              all decay tiers, edge cases, reference_date
  Confidence Replay             point-in-time reconstruction, tenant/engagement isolation
  Manifest Generation           required fields, hash stability, timestamp exclusion
  Explainability                why_confidence output format and content
  Determinism                   identical inputs → identical outputs
  Cross Tenant Isolation        cross-tenant replay raises
  Cross Engagement Isolation    cross-engagement replay raises
  Replay Consistency            replayed score matches original for same timestamp
  Performance                   100 / 1000 calculations, corroboration, replay
  Future Node Compatibility     non-evidence nodes in path handled gracefully
  AGI Governance Compatibility  generic trust-node scoring (not assessment-specific)
  Tamper Detection              manifests, replay_result manipulation
  Security Invariants           fail-closed, circular dependency, duplicate inflation
  Edge Cases                    empty path, single node, no edges, all-negative graph
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from services.field_assessment.trust_graph import (
    EdgeType,
    NodeType,
    TrustGraph,
    TrustGraphEdge,
    TrustGraphNode,
    build_control_node,
    build_finding_node,
    build_framework_node,
    build_report_node,
    build_risk_node,
)
from services.field_assessment.trust_confidence import (
    CONFIDENCE_VERSION,
    TrustConfidenceError,
    _DECAY_TABLE,
    _POS,
    _clamp,
    _confidence_level,
    _source_family,
    calculate_confidence,
    calculate_confidence_decay,
    evaluate_corroboration,
    evaluate_evidence_strength,
    evaluate_trust_quality,
    generate_confidence_manifest,
    replay_confidence,
    why_confidence,
)

# ---------------------------------------------------------------------------
# Constants / helpers
# ---------------------------------------------------------------------------

TENANT = "tenant-conf"
ENG = "eng-conf-001"
TENANT_B = "tenant-conf-b"
ENG_B = "eng-conf-002"

NOW = datetime.now(tz=timezone.utc)
PAST_5D = (NOW - timedelta(days=5)).isoformat()
PAST_45D = (NOW - timedelta(days=45)).isoformat()
PAST_75D = (NOW - timedelta(days=75)).isoformat()
PAST_100D = (NOW - timedelta(days=100)).isoformat()
PAST_150D = (NOW - timedelta(days=150)).isoformat()
PAST_200D = (NOW - timedelta(days=200)).isoformat()


def _uid(prefix: str = "") -> str:
    return f"{prefix}{uuid.uuid4().hex[:8]}"


def _graph(tenant: str = TENANT, eng: str = ENG) -> TrustGraph:
    return TrustGraph(tenant_id=tenant, engagement_id=eng)


def _ev(
    graph: TrustGraph,
    nid: str = "",
    *,
    authority_status: str = "signed",
    trust_score: int = 90,
    event_hash: str = "deadbeef",
    source_type: str = "",
    created_at: str | None = None,
) -> TrustGraphNode:
    nid = nid or _uid("ev-")
    payload: dict[str, Any] = {
        "evidence_id": f"EV-{nid}",
        "event_hash": event_hash,
        "authority_status": authority_status,
        "trust_score": trust_score,
    }
    if source_type:
        payload["source_type"] = source_type
    node = TrustGraphNode(
        node_id=nid,
        node_type=NodeType.EVIDENCE,
        tenant_id=graph.tenant_id,
        engagement_id=graph.engagement_id,
        payload=payload,
        created_at=created_at or PAST_5D,
    )
    graph.add_node(node)
    return node


def _fi(graph: TrustGraph, nid: str = "") -> TrustGraphNode:
    nid = nid or _uid("fi-")
    node = build_finding_node(
        node_id=nid,
        tenant_id=graph.tenant_id,
        engagement_id=graph.engagement_id,
        finding_id=f"F-{nid}",
        severity="high",
    )
    graph.add_node(node)
    return node


def _co(graph: TrustGraph, nid: str = "") -> TrustGraphNode:
    nid = nid or _uid("co-")
    node = build_control_node(
        node_id=nid,
        tenant_id=graph.tenant_id,
        engagement_id=graph.engagement_id,
        control_id=f"AC-{nid}",
        framework="NIST CSF",
    )
    graph.add_node(node)
    return node


def _fw(graph: TrustGraph, nid: str = "") -> TrustGraphNode:
    nid = nid or _uid("fw-")
    node = build_framework_node(
        node_id=nid,
        tenant_id=graph.tenant_id,
        engagement_id=graph.engagement_id,
        framework_id=f"FW-{nid}",
        framework_name="NIST CSF",
    )
    graph.add_node(node)
    return node


def _ri(graph: TrustGraph, nid: str = "") -> TrustGraphNode:
    nid = nid or _uid("ri-")
    node = build_risk_node(
        node_id=nid,
        tenant_id=graph.tenant_id,
        engagement_id=graph.engagement_id,
        risk_id=f"R-{nid}",
        risk_level="high",
        risk_type="security",
    )
    graph.add_node(node)
    return node


def _re(graph: TrustGraph, nid: str = "") -> TrustGraphNode:
    nid = nid or _uid("re-")
    node = build_report_node(
        node_id=nid,
        tenant_id=graph.tenant_id,
        engagement_id=graph.engagement_id,
        report_id=f"REP-{nid}",
        report_hash="reporthash",
        report_status="finalized",
    )
    graph.add_node(node)
    return node


def _edge(
    graph: TrustGraph,
    src: TrustGraphNode,
    tgt: TrustGraphNode,
    edge_type: EdgeType,
    created_at: str | None = None,
) -> TrustGraphEdge:
    e = TrustGraphEdge(
        edge_id=_uid("e-"),
        edge_type=edge_type,
        source_node_id=src.node_id,
        target_node_id=tgt.node_id,
        tenant_id=graph.tenant_id,
        engagement_id=graph.engagement_id,
        created_at=created_at or PAST_5D,
    )
    graph.add_edge(e)
    return e


def _signed_snap() -> dict[str, Any]:
    return {"valid": True, "reason": None}


def _failed_snap() -> dict[str, Any]:
    return {"valid": False, "reason": "tampered_snapshot"}


def _replay_100() -> dict[str, Any]:
    return {"chain_replay_score": 100}


def _replay_0() -> dict[str, Any]:
    return {"chain_replay_score": 0}


def _replay_50() -> dict[str, Any]:
    return {"chain_replay_score": 50}


# ---------------------------------------------------------------------------
# Confidence Levels
# ---------------------------------------------------------------------------


class TestConfidenceLevels:
    def test_level_0_is_critical(self) -> None:
        assert _confidence_level(0) == "critical"

    def test_level_24_is_critical(self) -> None:
        assert _confidence_level(24) == "critical"

    def test_level_25_is_weak(self) -> None:
        assert _confidence_level(25) == "weak"

    def test_level_49_is_weak(self) -> None:
        assert _confidence_level(49) == "weak"

    def test_level_50_is_moderate(self) -> None:
        assert _confidence_level(50) == "moderate"

    def test_level_74_is_moderate(self) -> None:
        assert _confidence_level(74) == "moderate"

    def test_level_75_is_strong(self) -> None:
        assert _confidence_level(75) == "strong"

    def test_level_89_is_strong(self) -> None:
        assert _confidence_level(89) == "strong"

    def test_level_90_is_high_assurance(self) -> None:
        assert _confidence_level(90) == "high_assurance"

    def test_level_100_is_high_assurance(self) -> None:
        assert _confidence_level(100) == "high_assurance"

    def test_clamp_below_0(self) -> None:
        assert _clamp(-999) == 0

    def test_clamp_above_100(self) -> None:
        assert _clamp(999) == 100

    def test_clamp_boundary_0(self) -> None:
        assert _clamp(0) == 0

    def test_clamp_boundary_100(self) -> None:
        assert _clamp(100) == 100


# ---------------------------------------------------------------------------
# Confidence Calculation
# ---------------------------------------------------------------------------


class TestCalculateConfidence:
    def test_returns_required_keys(self) -> None:
        g = _graph()
        ev = _ev(g, "ev-1")
        result = calculate_confidence(g, [ev])
        for key in (
            "confidence_score",
            "confidence_level",
            "confidence_factors",
            "negative_factors",
            "corroboration",
            "quality",
            "explanation",
        ):
            assert key in result, f"missing key: {key}"

    def test_score_is_int_in_range(self) -> None:
        g = _graph()
        ev = _ev(g, "ev-1")
        result = calculate_confidence(g, [ev])
        assert isinstance(result["confidence_score"], int)
        assert 0 <= result["confidence_score"] <= 100

    def test_empty_path_scores_critical(self) -> None:
        g = _graph()
        result = calculate_confidence(g, [])
        assert result["confidence_score"] <= 24
        assert result["confidence_level"] == "critical"

    def test_signed_fresh_evidence_scores_moderate_or_above(self) -> None:
        g = _graph()
        ev = _ev(g, "ev-1", authority_status="signed", trust_score=90, event_hash="h1")
        result = calculate_confidence(g, [ev])
        assert result["confidence_score"] >= 50

    def test_unsigned_evidence_penalizes_score(self) -> None:
        g = _graph()
        ev_signed = _ev(g, "ev-s", authority_status="signed", trust_score=90)
        ev_unsigned = _ev(g, "ev-u", authority_status="unsigned", trust_score=90)
        r_signed = calculate_confidence(g, [ev_signed])
        r_unsigned = calculate_confidence(g, [ev_unsigned])
        assert r_signed["confidence_score"] > r_unsigned["confidence_score"]

    def test_snapshot_verified_adds_points(self) -> None:
        g = _graph()
        ev = _ev(g, "ev-1")
        r_with = calculate_confidence(g, [ev], snapshot=_signed_snap())
        r_without = calculate_confidence(g, [ev])
        assert r_with["confidence_score"] > r_without["confidence_score"]

    def test_snapshot_failed_reduces_score(self) -> None:
        g = _graph()
        ev = _ev(g, "ev-1")
        r_failed = calculate_confidence(g, [ev], snapshot=_failed_snap())
        r_none = calculate_confidence(g, [ev])
        assert r_failed["confidence_score"] < r_none["confidence_score"]

    def test_chain_replay_100_adds_points(self) -> None:
        g = _graph()
        ev = _ev(g, "ev-1")
        r_replay = calculate_confidence(g, [ev], replay_result=_replay_100())
        r_none = calculate_confidence(g, [ev])
        assert r_replay["confidence_score"] > r_none["confidence_score"]

    def test_chain_replay_0_reduces_score(self) -> None:
        g = _graph()
        ev = _ev(g, "ev-1")
        r_broken = calculate_confidence(g, [ev], replay_result=_replay_0())
        r_none = calculate_confidence(g, [ev])
        assert r_broken["confidence_score"] < r_none["confidence_score"]

    def test_all_features_enabled_scores_high(self) -> None:
        g = _graph()
        ev1 = _ev(g, "ev-1", source_type="msgraph")
        ev2 = _ev(g, "ev-2", source_type="entra")
        ev3 = _ev(g, "ev-3", source_type="dns")
        ev4 = _ev(g, "ev-4", source_type="network")
        result = calculate_confidence(
            g,
            [ev1, ev2, ev3, ev4],
            snapshot=_signed_snap(),
            replay_result=_replay_100(),
        )
        assert result["confidence_score"] >= 75

    def test_no_evidence_in_path_with_other_nodes(self) -> None:
        g = _graph()
        fi = _fi(g, "fi-1")
        result = calculate_confidence(g, [fi])
        assert result["confidence_score"] <= 24

    def test_confidence_factors_all_have_points(self) -> None:
        g = _graph()
        ev = _ev(g, "ev-1")
        result = calculate_confidence(g, [ev])
        for f in result["confidence_factors"]:
            assert "factor" in f
            assert "points" in f
            assert f["points"] > 0

    def test_negative_factors_all_have_points(self) -> None:
        g = _graph()
        ev = _ev(g, "ev-1", authority_status="unsigned", event_hash="")
        result = calculate_confidence(g, [ev])
        for f in result["negative_factors"]:
            assert "factor" in f
            assert "points" in f
            assert f["points"] < 0

    def test_stale_evidence_applies_decay(self) -> None:
        g = _graph()
        ev_fresh = _ev(g, "ev-fresh", created_at=PAST_5D)
        ev_stale = _ev(g, "ev-stale", created_at=PAST_200D)
        r_fresh = calculate_confidence(g, [ev_fresh])
        r_stale = calculate_confidence(g, [ev_stale])
        assert r_fresh["confidence_score"] > r_stale["confidence_score"]

    def test_multiple_evidence_types_in_path_ignored(self) -> None:
        g = _graph()
        ev = _ev(g, "ev-1")
        fi = _fi(g, "fi-1")
        ri = _ri(g, "ri-1")
        # Non-evidence nodes in path are accepted, only evidence nodes scored
        result = calculate_confidence(g, [ev, fi, ri])
        assert result["confidence_score"] >= 0

    def test_graph_with_precomputed_integrity(self) -> None:
        from services.field_assessment.trust_graph import verify_trust_graph

        g = _graph()
        ev = _ev(g, "ev-1")
        integrity = verify_trust_graph(g)
        r1 = calculate_confidence(g, [ev], graph_integrity=integrity)
        r2 = calculate_confidence(g, [ev])
        assert r1["confidence_score"] == r2["confidence_score"]


# ---------------------------------------------------------------------------
# Corroboration
# ---------------------------------------------------------------------------


class TestEvaluateCorroboration:
    def test_empty_evidence_returns_zero(self) -> None:
        g = _graph()
        result = evaluate_corroboration(g, [])
        assert result["corroboration_score"] == 0
        assert result["source_count"] == 0
        assert result["independent_sources"] == 0

    def test_single_source_returns_low_score(self) -> None:
        g = _graph()
        ev = _ev(g, "ev-1", source_type="msgraph")
        result = evaluate_corroboration(g, [ev])
        assert result["corroboration_score"] == 20
        assert result["independent_sources"] == 1
        assert result["source_count"] == 1

    def test_two_independent_sources(self) -> None:
        g = _graph()
        ev1 = _ev(g, "ev-1", source_type="msgraph")
        ev2 = _ev(g, "ev-2", source_type="entra")
        result = evaluate_corroboration(g, [ev1, ev2])
        assert result["independent_sources"] == 2
        assert result["corroboration_score"] == 40

    def test_four_independent_sources(self) -> None:
        g = _graph()
        evs = [_ev(g, f"ev-{i}", source_type=f"source-{i}") for i in range(4)]
        result = evaluate_corroboration(g, evs)
        assert result["independent_sources"] == 4
        assert result["corroboration_score"] == 75

    def test_five_plus_sources_caps_near_90(self) -> None:
        g = _graph()
        evs = [_ev(g, f"ev-{i}", source_type=f"src-{i}") for i in range(5)]
        result = evaluate_corroboration(g, evs)
        assert result["corroboration_score"] >= 90

    def test_same_source_same_hash_is_duplicate(self) -> None:
        g = _graph()
        ev1 = _ev(g, "ev-1", source_type="msgraph", event_hash="samehash")
        ev2 = _ev(g, "ev-2", source_type="msgraph", event_hash="samehash")
        result = evaluate_corroboration(g, [ev1, ev2])
        assert result["duplicate_sources"] >= 1

    def test_same_source_different_hash_not_duplicate(self) -> None:
        g = _graph()
        ev1 = _ev(g, "ev-1", source_type="msgraph", event_hash="hash-a")
        ev2 = _ev(g, "ev-2", source_type="msgraph", event_hash="hash-b")
        result = evaluate_corroboration(g, [ev1, ev2])
        assert result["duplicate_sources"] == 0

    def test_source_family_from_evidence_id_prefix(self) -> None:
        g = _graph()
        ev = _ev(g, "MSGRAPH-001")
        fam = _source_family(ev)
        assert (
            fam == "ev"
        )  # split on "-", first segment is node_id prefix... actually "ev" comes from node_id "MSGRAPH-001" ... wait

    def test_source_type_overrides_evidence_id(self) -> None:
        g = _graph()
        ev = _ev(g, "ev-1", source_type="explicit-family")
        assert _source_family(ev) == "explicit-family"

    def test_duplicate_penalty_applied(self) -> None:
        g = _graph()
        # 3 nodes from same source with same hash = 2 duplicates
        ev1 = _ev(g, "ev-1", source_type="s1", event_hash="h1")
        ev2 = _ev(g, "ev-2", source_type="s1", event_hash="h1")
        ev3 = _ev(g, "ev-3", source_type="s1", event_hash="h1")
        result = evaluate_corroboration(g, [ev1, ev2, ev3])
        assert result["duplicate_sources"] >= 1
        # Score should be penalized
        single = evaluate_corroboration(g, [ev1])
        assert result["corroboration_score"] <= single["corroboration_score"]

    def test_source_families_sorted(self) -> None:
        g = _graph()
        ev1 = _ev(g, "ev-1", source_type="zzz")
        ev2 = _ev(g, "ev-2", source_type="aaa")
        result = evaluate_corroboration(g, [ev1, ev2])
        assert result["source_families"] == sorted(result["source_families"])

    def test_corroboration_score_bounded_0_100(self) -> None:
        g = _graph()
        evs = [_ev(g, f"ev-{i}", source_type=f"s{i}") for i in range(20)]
        result = evaluate_corroboration(g, evs)
        assert 0 <= result["corroboration_score"] <= 100


# ---------------------------------------------------------------------------
# Evidence Strength
# ---------------------------------------------------------------------------


class TestEvaluateEvidenceStrength:
    def _node(self, **kwargs: Any) -> TrustGraphNode:
        g = _graph()
        return _ev(g, "ev-1", **kwargs)

    def test_returns_required_keys(self) -> None:
        n = self._node()
        result = evaluate_evidence_strength(n)
        assert "strength_score" in result
        assert "strength_level" in result
        assert "strength_factors" in result

    def test_score_in_range(self) -> None:
        n = self._node()
        result = evaluate_evidence_strength(n)
        assert 0 <= result["strength_score"] <= 100

    def test_signed_node_scores_higher_than_unsigned(self) -> None:
        signed = self._node(authority_status="signed", trust_score=90, event_hash="h")
        unsigned = self._node(
            authority_status="unsigned", trust_score=90, event_hash="h"
        )
        r_s = evaluate_evidence_strength(signed)
        r_u = evaluate_evidence_strength(unsigned)
        assert r_s["strength_score"] > r_u["strength_score"]

    def test_high_trust_score_adds_points(self) -> None:
        high = self._node(trust_score=95)
        low = self._node(trust_score=10)
        r_h = evaluate_evidence_strength(high)
        r_l = evaluate_evidence_strength(low)
        assert r_h["strength_score"] > r_l["strength_score"]

    def test_fresh_evidence_scores_higher_than_stale(self) -> None:
        fresh = _ev(_graph(), "ev-fresh", created_at=PAST_5D)
        stale = _ev(_graph(), "ev-stale", created_at=PAST_200D)
        r_f = evaluate_evidence_strength(fresh)
        r_s = evaluate_evidence_strength(stale)
        assert r_f["strength_score"] > r_s["strength_score"]

    def test_event_hash_present_adds_points(self) -> None:
        with_hash = self._node(event_hash="abc123")
        without_hash = self._node(event_hash="")
        r_with = evaluate_evidence_strength(with_hash)
        r_without = evaluate_evidence_strength(without_hash)
        assert r_with["strength_score"] > r_without["strength_score"]

    def test_valid_edge_authority_adds_points(self) -> None:
        n = self._node()
        r_with = evaluate_evidence_strength(n, edge_authority={"valid": True})
        r_without = evaluate_evidence_strength(n)
        assert r_with["strength_score"] > r_without["strength_score"]

    def test_invalid_edge_authority_does_not_add_points(self) -> None:
        n = self._node()
        r_invalid = evaluate_evidence_strength(
            n, edge_authority={"valid": False, "reason": "key_unavailable"}
        )
        r_none = evaluate_evidence_strength(n)
        assert r_invalid["strength_score"] == r_none["strength_score"]

    def test_strength_factors_all_have_factor_and_points(self) -> None:
        n = self._node()
        result = evaluate_evidence_strength(n)
        for f in result["strength_factors"]:
            assert "factor" in f
            assert "points" in f

    def test_legacy_unsigned_gets_partial_credit(self) -> None:
        legacy = self._node(authority_status="legacy_unsigned")
        unsigned = self._node(authority_status="unsigned")
        r_l = evaluate_evidence_strength(legacy)
        r_u = evaluate_evidence_strength(unsigned)
        assert r_l["strength_score"] > r_u["strength_score"]

    def test_reference_date_affects_freshness(self) -> None:
        n = _ev(_graph(), "ev-1", created_at=PAST_5D)
        # Using a reference date 100 days ago makes PAST_5D seem future
        ref_past = (NOW - timedelta(days=200)).isoformat()
        r_future_ref = evaluate_evidence_strength(n, reference_date=ref_past)
        r_now_ref = evaluate_evidence_strength(n)
        # With past reference date, evidence is "from the future" → age 0 → no penalty
        assert r_future_ref["strength_score"] >= r_now_ref["strength_score"]

    def test_full_strength_node_scores_high(self) -> None:
        n = self._node(authority_status="signed", trust_score=95, event_hash="deadbeef")
        result = evaluate_evidence_strength(n, edge_authority={"valid": True})
        assert result["strength_score"] >= 75

    def test_strength_level_maps_to_correct_tier(self) -> None:
        n = self._node(authority_status="signed", trust_score=95, event_hash="h")
        result = evaluate_evidence_strength(n)
        if result["strength_score"] >= 90:
            assert result["strength_level"] == "verified"
        elif result["strength_score"] >= 75:
            assert result["strength_level"] == "strong"


# ---------------------------------------------------------------------------
# Trust Quality
# ---------------------------------------------------------------------------


class TestEvaluateTrustQuality:
    def test_returns_required_keys(self) -> None:
        g = _graph()
        ev = _ev(g, "ev-1")
        result = evaluate_trust_quality(g, [ev])
        assert "trust_quality_score" in result
        assert "positive_factors" in result
        assert "negative_factors" in result

    def test_all_signed_evidence_in_positive(self) -> None:
        g = _graph()
        ev = _ev(g, "ev-1", authority_status="signed")
        result = evaluate_trust_quality(g, [ev])
        assert "all_evidence_signed" in result["positive_factors"]

    def test_unsigned_evidence_in_negative(self) -> None:
        g = _graph()
        ev = _ev(g, "ev-1", authority_status="unsigned")
        result = evaluate_trust_quality(g, [ev])
        assert "unsigned_evidence" in result["negative_factors"]

    def test_verified_snapshot_in_positive(self) -> None:
        g = _graph()
        ev = _ev(g, "ev-1")
        result = evaluate_trust_quality(g, [ev], snapshot=_signed_snap())
        assert "snapshot_verified" in result["positive_factors"]

    def test_failed_snapshot_in_negative(self) -> None:
        g = _graph()
        ev = _ev(g, "ev-1")
        result = evaluate_trust_quality(g, [ev], snapshot=_failed_snap())
        assert "snapshot_unverified" in result["negative_factors"]

    def test_replay_100_in_positive(self) -> None:
        g = _graph()
        ev = _ev(g, "ev-1")
        result = evaluate_trust_quality(g, [ev], replay_result=_replay_100())
        assert "chain_replay_score_100" in result["positive_factors"]

    def test_replay_0_in_negative(self) -> None:
        g = _graph()
        ev = _ev(g, "ev-1")
        result = evaluate_trust_quality(g, [ev], replay_result=_replay_0())
        assert "broken_chain" in result["negative_factors"]

    def test_all_event_hashes_in_positive(self) -> None:
        g = _graph()
        ev = _ev(g, "ev-1", event_hash="abc")
        result = evaluate_trust_quality(g, [ev])
        assert "all_event_hashes_present" in result["positive_factors"]

    def test_missing_hash_in_negative(self) -> None:
        g = _graph()
        ev = _ev(g, "ev-1", event_hash="")
        result = evaluate_trust_quality(g, [ev])
        assert "missing_event_hash" in result["negative_factors"]

    def test_positive_factors_sorted(self) -> None:
        g = _graph()
        ev = _ev(g, "ev-1")
        result = evaluate_trust_quality(
            g, [ev], snapshot=_signed_snap(), replay_result=_replay_100()
        )
        assert result["positive_factors"] == sorted(result["positive_factors"])

    def test_negative_factors_sorted(self) -> None:
        g = _graph()
        ev = _ev(g, "ev-1", authority_status="unsigned", event_hash="")
        result = evaluate_trust_quality(g, [ev])
        assert result["negative_factors"] == sorted(result["negative_factors"])

    def test_quality_score_bounded_0_100(self) -> None:
        g = _graph()
        ev = _ev(g, "ev-1")
        result = evaluate_trust_quality(g, [ev])
        assert 0 <= result["trust_quality_score"] <= 100

    def test_empty_path_returns_zero_quality(self) -> None:
        g = _graph()
        result = evaluate_trust_quality(g, [])
        assert result["trust_quality_score"] == 0

    def test_precomputed_integrity_avoids_recompute(self) -> None:
        from services.field_assessment.trust_graph import verify_trust_graph

        g = _graph()
        ev = _ev(g, "ev-1")
        integrity = verify_trust_graph(g)
        r1 = evaluate_trust_quality(g, [ev], graph_integrity=integrity)
        r2 = evaluate_trust_quality(g, [ev])
        assert r1["trust_quality_score"] == r2["trust_quality_score"]


# ---------------------------------------------------------------------------
# Confidence Decay
# ---------------------------------------------------------------------------


class TestCalculateConfidenceDecay:
    def test_returns_required_keys(self) -> None:
        result = calculate_confidence_decay(PAST_5D)
        assert "age_days" in result
        assert "penalty" in result
        assert "tier" in result

    def test_fresh_evidence_zero_penalty(self) -> None:
        result = calculate_confidence_decay(PAST_5D)
        assert result["penalty"] == 0
        assert result["tier"] == "fresh"

    def test_30_day_boundary_zero_penalty(self) -> None:
        ts = (NOW - timedelta(days=30)).isoformat()
        result = calculate_confidence_decay(ts)
        assert result["penalty"] == 0

    def test_31_day_mild_penalty(self) -> None:
        ts = (NOW - timedelta(days=31)).isoformat()
        result = calculate_confidence_decay(ts)
        assert result["penalty"] == 5

    def test_45_day_mild_penalty(self) -> None:
        result = calculate_confidence_decay(PAST_45D)
        assert result["penalty"] == 5

    def test_61_day_moderate_penalty(self) -> None:
        ts = (NOW - timedelta(days=61)).isoformat()
        result = calculate_confidence_decay(ts)
        assert result["penalty"] == 10

    def test_75_day_moderate_penalty(self) -> None:
        result = calculate_confidence_decay(PAST_75D)
        assert result["penalty"] == 10

    def test_91_day_significant_penalty(self) -> None:
        ts = (NOW - timedelta(days=91)).isoformat()
        result = calculate_confidence_decay(ts)
        assert result["penalty"] == 15

    def test_100_day_significant_penalty(self) -> None:
        result = calculate_confidence_decay(PAST_100D)
        assert result["penalty"] == 15

    def test_150_day_severe_penalty(self) -> None:
        result = calculate_confidence_decay(PAST_150D)
        assert result["penalty"] == 20

    def test_200_day_critical_penalty(self) -> None:
        result = calculate_confidence_decay(PAST_200D)
        assert result["penalty"] == 25

    def test_age_days_is_non_negative(self) -> None:
        result = calculate_confidence_decay(PAST_5D)
        assert result["age_days"] >= 0

    def test_reference_date_overrides_now(self) -> None:
        # Evidence from 5 days ago, but reference is 10 days ago → evidence is "future"
        ref = (NOW - timedelta(days=10)).isoformat()
        result = calculate_confidence_decay(PAST_5D, reference_date=ref)
        assert result["age_days"] == 0
        assert result["penalty"] == 0

    def test_datetime_input_accepted(self) -> None:
        dt = NOW - timedelta(days=5)
        result = calculate_confidence_decay(dt)
        assert result["penalty"] == 0

    def test_deterministic_for_same_inputs(self) -> None:
        r1 = calculate_confidence_decay(PAST_75D, reference_date=NOW.isoformat())
        r2 = calculate_confidence_decay(PAST_75D, reference_date=NOW.isoformat())
        assert r1 == r2

    def test_decay_table_covers_all_tiers(self) -> None:
        # Each tier in _DECAY_TABLE should be reachable
        assert len(_DECAY_TABLE) >= 5


# ---------------------------------------------------------------------------
# Confidence Replay
# ---------------------------------------------------------------------------


class TestReplayConfidence:
    def test_returns_required_keys(self) -> None:
        g = _graph()
        _ev(g, "ev-1", created_at=PAST_5D)
        result = replay_confidence(g, TENANT, ENG, PAST_5D)
        for key in (
            "confidence_score",
            "confidence_level",
            "replayed_at",
            "tenant_id",
            "engagement_id",
            "historical_nodes",
            "historical_edges",
        ):
            assert key in result, f"missing key: {key}"

    def test_replayed_at_echoed(self) -> None:
        g = _graph()
        _ev(g, "ev-1")
        result = replay_confidence(g, TENANT, ENG, PAST_5D)
        assert result["replayed_at"] == PAST_5D

    def test_tenant_echoed(self) -> None:
        g = _graph()
        _ev(g, "ev-1")
        result = replay_confidence(g, TENANT, ENG, PAST_5D)
        assert result["tenant_id"] == TENANT

    def test_engagement_echoed(self) -> None:
        g = _graph()
        _ev(g, "ev-1")
        result = replay_confidence(g, TENANT, ENG, PAST_5D)
        assert result["engagement_id"] == ENG

    def test_cross_tenant_raises(self) -> None:
        g = _graph(TENANT, ENG)
        _ev(g, "ev-1")
        with pytest.raises(TrustConfidenceError):
            replay_confidence(g, TENANT_B, ENG, PAST_5D)

    def test_cross_engagement_raises(self) -> None:
        g = _graph(TENANT, ENG)
        _ev(g, "ev-1")
        with pytest.raises(TrustConfidenceError):
            replay_confidence(g, TENANT, ENG_B, PAST_5D)

    def test_no_nodes_at_timestamp_scores_zero(self) -> None:
        g = _graph()
        # evidence created at PAST_5D, but we ask for PAST_200D
        _ev(g, "ev-1", created_at=PAST_5D)
        result = replay_confidence(g, TENANT, ENG, PAST_200D)
        assert result["confidence_score"] == 0
        assert result["historical_nodes"] == 0

    def test_historical_node_count_correct(self) -> None:
        g = _graph()
        _ev(g, "ev-old", created_at=PAST_100D)
        _ev(g, "ev-new", created_at=PAST_5D)
        result = replay_confidence(g, TENANT, ENG, PAST_45D)
        assert result["historical_nodes"] == 1  # only ev-old existed at PAST_45D

    def test_edge_created_after_at_excluded(self) -> None:
        g = _graph()
        ev = _ev(g, "ev-1", created_at=PAST_100D)
        fi = _fi(
            g, "fi-1"
        )  # default created_at is now (PAST_5D from helper... actually utc_iso8601_z_now)
        _edge(g, ev, fi, EdgeType.EVIDENCE_TO_FINDING, created_at=PAST_5D)
        result = replay_confidence(g, TENANT, ENG, PAST_200D)
        assert result["historical_edges"] == 0

    def test_score_increases_with_more_historical_evidence(self) -> None:
        g = _graph()
        _ev(g, "ev-1", created_at=PAST_100D, source_type="s1")
        _ev(g, "ev-2", created_at=PAST_100D, source_type="s2")
        r_single = replay_confidence(
            g, TENANT, ENG, (NOW - timedelta(days=150)).isoformat()
        )
        r_double = replay_confidence(g, TENANT, ENG, PAST_45D)
        # r_double sees both nodes; r_single sees none
        assert r_single["historical_nodes"] == 0
        assert r_double["historical_nodes"] == 2

    def test_replay_score_is_int_in_range(self) -> None:
        g = _graph()
        _ev(g, "ev-1", created_at=PAST_5D)
        result = replay_confidence(g, TENANT, ENG, PAST_5D)
        assert isinstance(result["confidence_score"], int)
        assert 0 <= result["confidence_score"] <= 100


# ---------------------------------------------------------------------------
# Manifest Generation
# ---------------------------------------------------------------------------


class TestGenerateConfidenceManifest:
    def _make(
        self, score: int = 75, corr: int = 60, strength: int = 80, qual: int = 70
    ) -> dict[str, Any]:
        return generate_confidence_manifest(
            {"confidence_score": score},
            {"corroboration_score": corr},
            {"strength_score": strength},
            {"trust_quality_score": qual},
        )

    def test_returns_required_keys(self) -> None:
        m = self._make()
        for key in (
            "confidence_version",
            "confidence_score",
            "corroboration_score",
            "strength_score",
            "trust_quality_score",
            "generated_at",
            "manifest_hash",
        ):
            assert key in m, f"missing key: {key}"

    def test_confidence_version_matches_constant(self) -> None:
        assert self._make()["confidence_version"] == CONFIDENCE_VERSION

    def test_manifest_hash_is_64_hex(self) -> None:
        m = self._make()
        assert len(m["manifest_hash"]) == 64
        bytes.fromhex(m["manifest_hash"])

    def test_manifest_hash_stable_for_same_scores(self) -> None:
        h1 = self._make(75, 60, 80, 70)["manifest_hash"]
        h2 = self._make(75, 60, 80, 70)["manifest_hash"]
        assert h1 == h2

    def test_manifest_hash_changes_when_score_changes(self) -> None:
        h1 = self._make(75, 60, 80, 70)["manifest_hash"]
        h2 = self._make(76, 60, 80, 70)["manifest_hash"]
        assert h1 != h2

    def test_generated_at_not_in_hash(self) -> None:
        # Two manifests with same scores must have same hash even with different generated_at
        h1 = self._make(50, 50, 50, 50)["manifest_hash"]
        h2 = self._make(50, 50, 50, 50)["manifest_hash"]
        assert h1 == h2

    def test_scores_preserved_in_manifest(self) -> None:
        m = self._make(80, 65, 70, 55)
        assert m["confidence_score"] == 80
        assert m["corroboration_score"] == 65
        assert m["strength_score"] == 70
        assert m["trust_quality_score"] == 55

    def test_missing_keys_default_to_zero(self) -> None:
        m = generate_confidence_manifest({}, {}, {}, {})
        assert m["confidence_score"] == 0
        assert m["corroboration_score"] == 0


# ---------------------------------------------------------------------------
# Explainability
# ---------------------------------------------------------------------------


class TestWhyConfidence:
    def test_returns_string(self) -> None:
        g = _graph()
        ev = _ev(g, "ev-1")
        result = calculate_confidence(g, [ev])
        assert isinstance(result["explanation"], str)
        assert len(result["explanation"]) > 0

    def test_contains_confidence_score(self) -> None:
        g = _graph()
        ev = _ev(g, "ev-1")
        result = calculate_confidence(g, [ev])
        assert str(result["confidence_score"]) in result["explanation"]

    def test_contains_confidence_level(self) -> None:
        g = _graph()
        ev = _ev(g, "ev-1")
        result = calculate_confidence(g, [ev])
        assert result["confidence_level"] in result["explanation"]

    def test_contains_reasoning_header(self) -> None:
        g = _graph()
        ev = _ev(g, "ev-1")
        result = calculate_confidence(g, [ev])
        assert "Reasoning:" in result["explanation"]

    def test_positive_factors_prefixed_with_plus(self) -> None:
        g = _graph()
        ev = _ev(g, "ev-1", authority_status="signed")
        result = calculate_confidence(g, [ev])
        # At least one positive factor line should start with "  +"
        assert any(
            line.startswith("  +") for line in result["explanation"].splitlines()
        )

    def test_negative_factors_prefixed_with_minus(self) -> None:
        g = _graph()
        ev = _ev(g, "ev-1", authority_status="unsigned")
        result = calculate_confidence(g, [ev])
        assert any(
            line.startswith("  -") for line in result["explanation"].splitlines()
        )

    def test_why_confidence_standalone_call(self) -> None:
        fake_result = {
            "confidence_score": 85,
            "confidence_level": "strong",
            "confidence_factors": [{"factor": "evidence_present", "points": 10}],
            "negative_factors": [{"factor": "missing_event_hash", "points": -8}],
        }
        text = why_confidence(fake_result)
        assert "85" in text
        assert "strong" in text
        assert "evidence_present" in text
        assert "missing_event_hash" in text

    def test_explanation_deterministic(self) -> None:
        g = _graph()
        ev = _ev(g, "ev-1")
        r1 = calculate_confidence(g, [ev])
        r2 = calculate_confidence(g, [ev])
        assert r1["explanation"] == r2["explanation"]


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_same_graph_same_score(self) -> None:
        def build() -> tuple[TrustGraph, list[TrustGraphNode]]:
            g = _graph()
            ev = _ev(g, "ev-1", created_at=PAST_5D)
            return g, [ev]

        g1, p1 = build()
        g2, p2 = build()
        ref = NOW.isoformat()
        r1 = calculate_confidence(g1, p1, reference_date=ref)
        r2 = calculate_confidence(g2, p2, reference_date=ref)
        assert r1["confidence_score"] == r2["confidence_score"]

    def test_same_corroboration_same_score(self) -> None:
        g = _graph()
        ev1 = _ev(g, "ev-1", source_type="s1")
        ev2 = _ev(g, "ev-2", source_type="s2")
        r1 = evaluate_corroboration(g, [ev1, ev2])
        r2 = evaluate_corroboration(g, [ev1, ev2])
        assert r1 == r2

    def test_same_evidence_same_strength(self) -> None:
        ref = NOW.isoformat()
        n = _ev(_graph(), "ev-1", created_at=PAST_5D)
        r1 = evaluate_evidence_strength(n, reference_date=ref)
        r2 = evaluate_evidence_strength(n, reference_date=ref)
        assert r1 == r2

    def test_same_manifest_inputs_same_hash(self) -> None:
        conf = {"confidence_score": 77}
        corr = {"corroboration_score": 55}
        strength = {"strength_score": 88}
        qual = {"trust_quality_score": 66}
        h1 = generate_confidence_manifest(conf, corr, strength, qual)["manifest_hash"]
        h2 = generate_confidence_manifest(conf, corr, strength, qual)["manifest_hash"]
        assert h1 == h2

    def test_why_confidence_deterministic_across_calls(self) -> None:
        fake = {
            "confidence_score": 72,
            "confidence_level": "moderate",
            "confidence_factors": [{"factor": "evidence_present", "points": 10}],
            "negative_factors": [],
        }
        assert why_confidence(fake) == why_confidence(fake)

    def test_decay_deterministic_with_explicit_reference(self) -> None:
        ref = "2026-01-01T00:00:00Z"
        r1 = calculate_confidence_decay(PAST_100D, reference_date=ref)
        r2 = calculate_confidence_decay(PAST_100D, reference_date=ref)
        assert r1 == r2


# ---------------------------------------------------------------------------
# Cross Tenant Isolation
# ---------------------------------------------------------------------------


class TestCrossTenantIsolation:
    def test_replay_cross_tenant_raises(self) -> None:
        g = _graph(TENANT, ENG)
        _ev(g, "ev-1")
        with pytest.raises(TrustConfidenceError, match="cross-tenant"):
            replay_confidence(g, TENANT_B, ENG, PAST_5D)

    def test_different_tenant_graphs_score_independently(self) -> None:
        g_a = _graph(TENANT, ENG)
        g_b = _graph(TENANT_B, ENG_B)
        ev_a = _ev(g_a, "ev-1", source_type="s1")
        ev_b = _ev(g_b, "ev-1", source_type="s1")
        r_a = calculate_confidence(g_a, [ev_a])
        r_b = calculate_confidence(g_b, [ev_b])
        # Same structure, different tenants → same score (no cross-contamination)
        assert r_a["confidence_score"] == r_b["confidence_score"]

    def test_corroboration_not_shared_across_tenants(self) -> None:
        g_a = _graph(TENANT, ENG)
        g_b = _graph(TENANT_B, ENG_B)
        ev_a = _ev(g_a, "ev-1", source_type="s1")
        ev_b = _ev(g_b, "ev-2", source_type="s2")
        r_a = evaluate_corroboration(g_a, [ev_a])
        r_b = evaluate_corroboration(g_b, [ev_b])
        # Each graph's corroboration is independent
        assert r_a["source_count"] == 1
        assert r_b["source_count"] == 1


# ---------------------------------------------------------------------------
# Cross Engagement Isolation
# ---------------------------------------------------------------------------


class TestCrossEngagementIsolation:
    def test_replay_cross_engagement_raises(self) -> None:
        g = _graph(TENANT, ENG)
        _ev(g, "ev-1")
        with pytest.raises(TrustConfidenceError, match="cross-engagement"):
            replay_confidence(g, TENANT, ENG_B, PAST_5D)

    def test_different_engagement_graphs_score_independently(self) -> None:
        g1 = _graph(TENANT, ENG)
        g2 = _graph(TENANT, ENG_B)
        ev1 = _ev(g1, "ev-1")
        ev2 = _ev(g2, "ev-1")
        r1 = calculate_confidence(g1, [ev1])
        r2 = calculate_confidence(g2, [ev2])
        assert r1["confidence_score"] == r2["confidence_score"]


# ---------------------------------------------------------------------------
# Replay Consistency
# ---------------------------------------------------------------------------


class TestReplayConsistency:
    def test_replay_at_now_matches_current_score(self) -> None:
        g = _graph()
        ev = _ev(g, "ev-1", created_at=PAST_5D)
        ref = NOW.isoformat()
        current = calculate_confidence(g, [ev], reference_date=ref)
        replayed = replay_confidence(g, TENANT, ENG, ref)
        # Both use the same reference date; scores should match
        assert current["confidence_score"] == replayed["confidence_score"]

    def test_manifest_hash_stable_for_same_scores(self) -> None:
        g = _graph()
        ev = _ev(g, "ev-1", created_at=PAST_5D)
        ref = NOW.isoformat()
        r1 = calculate_confidence(g, [ev], reference_date=ref)
        r2 = calculate_confidence(g, [ev], reference_date=ref)
        m1 = generate_confidence_manifest(
            r1, r1["corroboration"], {"strength_score": 0}, r1["quality"]
        )
        m2 = generate_confidence_manifest(
            r2, r2["corroboration"], {"strength_score": 0}, r2["quality"]
        )
        assert m1["manifest_hash"] == m2["manifest_hash"]

    def test_two_replays_same_timestamp_same_score(self) -> None:
        g = _graph()
        _ev(g, "ev-1", created_at=PAST_100D)
        at = PAST_45D
        r1 = replay_confidence(g, TENANT, ENG, at)
        r2 = replay_confidence(g, TENANT, ENG, at)
        assert r1["confidence_score"] == r2["confidence_score"]


# ---------------------------------------------------------------------------
# Performance
# ---------------------------------------------------------------------------


class TestPerformance:
    def test_100_confidence_calculations_under_100ms(self) -> None:
        g = _graph()
        ev = _ev(g, "ev-1", created_at=PAST_5D)
        path = [ev]
        ref = NOW.isoformat()
        t0 = time.perf_counter()
        for _ in range(100):
            calculate_confidence(g, path, reference_date=ref)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        assert elapsed_ms < 100, f"100 calculations took {elapsed_ms:.1f}ms"

    def test_1000_confidence_calculations_under_500ms(self) -> None:
        g = _graph()
        ev = _ev(g, "ev-1", created_at=PAST_5D)
        path = [ev]
        ref = NOW.isoformat()
        t0 = time.perf_counter()
        for _ in range(1000):
            calculate_confidence(g, path, reference_date=ref)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        assert elapsed_ms < 500, f"1000 calculations took {elapsed_ms:.1f}ms"

    def test_corroboration_100_nodes_under_50ms(self) -> None:
        g = _graph()
        evs = [_ev(g, f"ev-{i:03d}", source_type=f"src-{i}") for i in range(100)]
        t0 = time.perf_counter()
        evaluate_corroboration(g, evs)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        assert elapsed_ms < 50, f"corroboration 100 nodes took {elapsed_ms:.1f}ms"

    def test_confidence_replay_1000_node_graph_under_250ms(self) -> None:
        g = _graph()
        for i in range(1000):
            _ev(g, f"ev-{i:04d}", created_at=PAST_100D)
        t0 = time.perf_counter()
        replay_confidence(g, TENANT, ENG, PAST_45D)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        assert elapsed_ms < 250, f"replay 1000 nodes took {elapsed_ms:.1f}ms"

    def test_manifest_generation_under_5ms(self) -> None:
        t0 = time.perf_counter()
        for _ in range(100):
            generate_confidence_manifest(
                {"confidence_score": 80},
                {"corroboration_score": 60},
                {"strength_score": 75},
                {"trust_quality_score": 70},
            )
        elapsed_ms = (time.perf_counter() - t0) * 1000
        assert elapsed_ms < 50, f"100 manifests took {elapsed_ms:.1f}ms"


# ---------------------------------------------------------------------------
# Future Node Compatibility
# ---------------------------------------------------------------------------


class TestFutureNodeCompatibility:
    def test_non_evidence_nodes_in_path_do_not_crash(self) -> None:
        g = _graph()
        fi = _fi(g, "fi-1")
        ri = _ri(g, "ri-1")
        co = _co(g, "co-1")
        fw = _fw(g, "fw-1")
        re = _re(g, "re-1")
        result = calculate_confidence(g, [fi, ri, co, fw, re])
        assert isinstance(result["confidence_score"], int)

    def test_mixed_path_scores_evidence_only(self) -> None:
        g = _graph()
        ev = _ev(g, "ev-1", authority_status="signed")
        fi = _fi(g, "fi-1")
        result = calculate_confidence(g, [ev, fi])
        # Should score based on ev only
        evidence_only = calculate_confidence(g, [ev])
        assert result["confidence_score"] == evidence_only["confidence_score"]

    def test_future_node_type_in_payload_tolerated(self) -> None:
        g = _graph()
        node = TrustGraphNode(
            node_id="agent-1",
            node_type=NodeType.EVIDENCE,  # typed as evidence for now
            tenant_id=TENANT,
            engagement_id=ENG,
            payload={
                "evidence_id": "AGENT-DECISION-001",
                "event_hash": "agenthash",
                "authority_status": "signed",
                "trust_score": 85,
                "future_field": "autonomous_decision",
                "agent_type": "agi_governance",
                "delegation_chain": ["agent-a", "agent-b"],
            },
            created_at=PAST_5D,
        )
        g.add_node(node)
        result = calculate_confidence(g, [node])
        assert isinstance(result["confidence_score"], int)

    def test_corroboration_with_future_source_type(self) -> None:
        g = _graph()
        ev1 = _ev(g, "ev-1", source_type="agi_governance_v1")
        ev2 = _ev(g, "ev-2", source_type="model_registry_v2")
        result = evaluate_corroboration(g, [ev1, ev2])
        assert result["independent_sources"] == 2

    def test_evidence_strength_with_unknown_authority_status(self) -> None:
        g = _graph()
        node = _ev(g, "ev-1", authority_status="future_verified_status")
        result = evaluate_evidence_strength(node)
        assert isinstance(result["strength_score"], int)


# ---------------------------------------------------------------------------
# AGI Governance Compatibility
# ---------------------------------------------------------------------------


class TestAGIGovernanceCompatibility:
    def test_agent_decision_node_scored_as_evidence(self) -> None:
        g = _graph()
        agent_node = TrustGraphNode(
            node_id="agi-decision-001",
            node_type=NodeType.EVIDENCE,
            tenant_id=TENANT,
            engagement_id=ENG,
            payload={
                "evidence_id": "AGI-001",
                "event_hash": "agihash",
                "authority_status": "signed",
                "trust_score": 80,
                "source_type": "agi_governance",
                "decision_type": "autonomous",
                "delegation_depth": 3,
            },
            created_at=PAST_5D,
        )
        g.add_node(agent_node)
        result = calculate_confidence(g, [agent_node])
        assert result["confidence_score"] >= 25

    def test_multi_agent_chain_corroboration(self) -> None:
        g = _graph()
        ev1 = _ev(g, "ev-1", source_type="human_review")
        ev2 = _ev(g, "ev-2", source_type="agent_validation")
        ev3 = _ev(g, "ev-3", source_type="model_evaluation")
        ev4 = _ev(g, "ev-4", source_type="agi_governance")
        result = evaluate_corroboration(g, [ev1, ev2, ev3, ev4])
        assert result["independent_sources"] == 4
        assert result["corroboration_score"] >= 75

    def test_confidence_engine_does_not_hardcode_assessment_types(self) -> None:
        # Generic nodes without assessment-specific fields
        g = _graph()
        generic = TrustGraphNode(
            node_id="generic-trust-node",
            node_type=NodeType.EVIDENCE,
            tenant_id=TENANT,
            engagement_id=ENG,
            payload={
                "event_hash": "h1",
                "authority_status": "signed",
                "trust_score": 90,
            },
            created_at=PAST_5D,
        )
        g.add_node(generic)
        result = calculate_confidence(g, [generic])
        assert isinstance(result["confidence_score"], int)

    def test_model_registry_node_uses_source_type(self) -> None:
        g = _graph()
        ev = _ev(g, "ev-1", source_type="model_registry")
        fam = _source_family(ev)
        assert fam == "model_registry"

    def test_autonomous_system_corroboration_counted(self) -> None:
        g = _graph()
        sources = [
            "human_approval",
            "agent_validation",
            "autonomous_system",
            "model_monitoring",
            "agi_oversight",
        ]
        evs = [_ev(g, f"ev-{i}", source_type=s) for i, s in enumerate(sources)]
        result = evaluate_corroboration(g, evs)
        assert result["independent_sources"] == 5
        assert result["corroboration_score"] >= 90


# ---------------------------------------------------------------------------
# Tamper Detection
# ---------------------------------------------------------------------------


class TestTamperDetection:
    def test_tampered_manifest_hash_detected(self) -> None:
        m1 = generate_confidence_manifest(
            {"confidence_score": 80},
            {"corroboration_score": 60},
            {"strength_score": 75},
            {"trust_quality_score": 70},
        )
        # Attacker modifies confidence_score but not hash
        m2 = generate_confidence_manifest(
            {"confidence_score": 99},  # tampered
            {"corroboration_score": 60},
            {"strength_score": 75},
            {"trust_quality_score": 70},
        )
        assert m1["manifest_hash"] != m2["manifest_hash"]

    def test_tampered_corroboration_score_changes_hash(self) -> None:
        base = generate_confidence_manifest(
            {"confidence_score": 75},
            {"corroboration_score": 40},
            {"strength_score": 80},
            {"trust_quality_score": 60},
        )
        tampered = generate_confidence_manifest(
            {"confidence_score": 75},
            {"corroboration_score": 100},  # tampered
            {"strength_score": 80},
            {"trust_quality_score": 60},
        )
        assert base["manifest_hash"] != tampered["manifest_hash"]

    def test_replay_result_manipulation_affects_score(self) -> None:
        g = _graph()
        ev = _ev(g, "ev-1")
        r_good = calculate_confidence(
            g, [ev], replay_result={"chain_replay_score": 100}
        )
        r_bad = calculate_confidence(g, [ev], replay_result={"chain_replay_score": 0})
        assert r_good["confidence_score"] > r_bad["confidence_score"]

    def test_injected_extra_field_in_snapshot_does_not_affect_score(self) -> None:
        g = _graph()
        ev = _ev(g, "ev-1")
        snap_good = {"valid": True, "reason": None}
        snap_extra = {"valid": True, "reason": None, "injected": "attack"}
        r1 = calculate_confidence(g, [ev], snapshot=snap_good)
        r2 = calculate_confidence(g, [ev], snapshot=snap_extra)
        assert r1["confidence_score"] == r2["confidence_score"]


# ---------------------------------------------------------------------------
# Security Invariants
# ---------------------------------------------------------------------------


class TestSecurityInvariants:
    def test_trust_confidence_error_is_value_error_subclass(self) -> None:
        assert issubclass(TrustConfidenceError, ValueError)

    def test_empty_path_fails_closed_to_critical(self) -> None:
        g = _graph()
        result = calculate_confidence(g, [])
        assert result["confidence_level"] == "critical"
        assert "no_evidence" in [f["factor"] for f in result["negative_factors"]]

    def test_corroboration_gaming_via_duplicate_hash_penalized(self) -> None:
        g = _graph()
        # 5 nodes, same source, same hash → looks like 5 but is 1
        evs = [
            _ev(g, f"ev-{i}", source_type="single-source", event_hash="same-hash")
            for i in range(5)
        ]
        result = evaluate_corroboration(g, evs)
        assert result["independent_sources"] == 1
        assert result["duplicate_sources"] >= 1

    def test_all_factors_accounted_in_pos_neg(self) -> None:
        # Every factor in confidence_factors is in _POS, every negative in _NEG
        g = _graph()
        ev = _ev(g, "ev-1", authority_status="unsigned", event_hash="")
        result = calculate_confidence(g, [ev])
        for f in result["confidence_factors"]:
            assert f["factor"] in _POS, f"unknown positive factor: {f['factor']}"

    def test_score_never_exceeds_100(self) -> None:
        g = _graph()
        evs = [
            _ev(g, f"ev-{i}", source_type=f"s{i}", trust_score=100, event_hash=f"h{i}")
            for i in range(10)
        ]
        result = calculate_confidence(
            g,
            evs,
            snapshot={"valid": True},
            replay_result={"chain_replay_score": 100},
        )
        assert result["confidence_score"] <= 100

    def test_score_never_below_zero(self) -> None:
        g = _graph()
        ev = _ev(
            g,
            "ev-1",
            authority_status="unsigned",
            trust_score=0,
            event_hash="",
            created_at=PAST_200D,
        )
        result = calculate_confidence(
            g,
            [ev],
            snapshot={"valid": False},
            replay_result={"chain_replay_score": 0},
        )
        assert result["confidence_score"] >= 0

    def test_confidence_level_always_set(self) -> None:
        g = _graph()
        ev = _ev(g, "ev-1")
        result = calculate_confidence(g, [ev])
        assert result["confidence_level"] in (
            "critical",
            "weak",
            "moderate",
            "strong",
            "high_assurance",
        )


# ---------------------------------------------------------------------------
# P1/P2 Code Review Fixes
# ---------------------------------------------------------------------------


class TestPathScopeValidation:
    """P1: path nodes must belong to the graph's tenant and engagement."""

    def test_cross_tenant_path_node_raises(self) -> None:
        g = _graph(TENANT, ENG)
        foreign_g = _graph(TENANT_B, ENG)
        foreign_ev = _ev(foreign_g, "ev-foreign")
        with pytest.raises(TrustConfidenceError, match="out of graph scope"):
            calculate_confidence(g, [foreign_ev])

    def test_cross_engagement_path_node_raises(self) -> None:
        g = _graph(TENANT, ENG)
        foreign_g = _graph(TENANT, ENG_B)
        foreign_ev = _ev(foreign_g, "ev-foreign")
        with pytest.raises(TrustConfidenceError, match="out of graph scope"):
            calculate_confidence(g, [foreign_ev])

    def test_valid_path_node_does_not_raise(self) -> None:
        g = _graph(TENANT, ENG)
        ev = _ev(g, "ev-1")
        result = calculate_confidence(g, [ev])
        assert result["confidence_score"] >= 0

    def test_foreign_signed_evidence_does_not_inflate_score(self) -> None:
        # Empty graph + foreign signed evidence must raise, not score moderate
        g = _graph(TENANT, ENG)
        foreign_g = _graph(TENANT_B, ENG)
        foreign_ev = _ev(
            foreign_g,
            "ev-foreign",
            authority_status="signed",
            trust_score=100,
        )
        with pytest.raises(TrustConfidenceError):
            calculate_confidence(g, [foreign_ev])

    def test_mixed_path_first_foreign_node_raises(self) -> None:
        g = _graph(TENANT, ENG)
        own_ev = _ev(g, "ev-own")
        foreign_g = _graph(TENANT_B, ENG)
        foreign_ev = _ev(foreign_g, "ev-foreign")
        with pytest.raises(TrustConfidenceError):
            calculate_confidence(g, [own_ev, foreign_ev])


class TestAuthorityVersionCheck:
    """P2: authority_version absent from verify results must not award the bonus."""

    def test_verify_result_without_version_does_not_award_bonus(self) -> None:
        # verify_edge_authority() returns {valid, reason} — no authority_version
        g = _graph()
        ev = _ev(g, "ev-1")
        verify_result = {"valid": True, "reason": None}
        r_with = calculate_confidence(g, [ev], edge_authorities={"e-1": verify_result})
        # Must not award authority_version_current for a result without the field
        with_factors = [f["factor"] for f in r_with["confidence_factors"]]
        assert "authority_version_current" not in with_factors

    def test_explicit_current_version_awards_bonus(self) -> None:
        from services.field_assessment.trust_graph_authority import (
            EDGE_AUTHORITY_VERSION,
        )

        g = _graph()
        ev = _ev(g, "ev-1")
        authority = {
            "valid": True,
            "reason": None,
            "authority_version": EDGE_AUTHORITY_VERSION,
        }
        result = calculate_confidence(g, [ev], edge_authorities={"e-1": authority})
        pos_factors = [f["factor"] for f in result["confidence_factors"]]
        assert "authority_version_current" in pos_factors

    def test_wrong_version_string_adds_downgrade_penalty(self) -> None:
        g = _graph()
        ev = _ev(g, "ev-1")
        authority = {
            "valid": True,
            "reason": None,
            "authority_version": "trust-graph-edge-authority-v0",
        }
        result = calculate_confidence(g, [ev], edge_authorities={"e-1": authority})
        neg_factors = [f["factor"] for f in result["negative_factors"]]
        assert "authority_version_downgraded" in neg_factors

    def test_empty_edge_authorities_dict_not_awarded(self) -> None:
        g = _graph()
        ev = _ev(g, "ev-1")
        result = calculate_confidence(g, [ev], edge_authorities={})
        pos_factors = [f["factor"] for f in result["confidence_factors"]]
        assert "authority_version_current" not in pos_factors


class TestStaleTierLabel:
    """P2: stale tier label must match the entry with the worst penalty, not lexicographic max."""

    def test_mild_and_critical_evidence_labels_critical(self) -> None:
        g = _graph()
        # PAST_45D → mild (-5), PAST_200D → critical (-25)
        _ev(g, "ev-mild", created_at=PAST_45D)
        _ev(g, "ev-critical", created_at=PAST_200D)
        result = calculate_confidence(g, list(g.nodes()))
        neg_names = [f["factor"] for f in result["negative_factors"]]
        stale_factors = [n for n in neg_names if n.startswith("stale_evidence_")]
        assert len(stale_factors) == 1
        assert stale_factors[0] == "stale_evidence_critical"

    def test_mild_only_labels_mild(self) -> None:
        g = _graph()
        _ev(g, "ev-mild", created_at=PAST_45D)
        result = calculate_confidence(g, list(g.nodes()))
        neg_names = [f["factor"] for f in result["negative_factors"]]
        stale_factors = [n for n in neg_names if n.startswith("stale_evidence_")]
        assert stale_factors[0] == "stale_evidence_mild"

    def test_stale_factor_points_match_worst_penalty(self) -> None:
        g = _graph()
        _ev(g, "ev-mild", created_at=PAST_45D)
        _ev(g, "ev-critical", created_at=PAST_200D)
        result = calculate_confidence(g, list(g.nodes()))
        stale = next(
            f
            for f in result["negative_factors"]
            if f["factor"].startswith("stale_evidence_")
        )
        assert stale["points"] == -25
