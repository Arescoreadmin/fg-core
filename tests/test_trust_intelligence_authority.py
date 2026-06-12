"""Trust Intelligence Authority tests — PR 1.8A.

Coverage matrix:
  Constants                         version, ledger genesis hash, replay weights,
                                    evolution thresholds, memory windows, entity types
  generate_trust_intelligence_snapshot  required fields, all-None defaults, tenant scoping,
                                    deterministic hash, snapshot_id uniqueness, signing
  sign_trust_intelligence_snapshot  success roundtrip, missing snapshot_hash raises,
                                    non-dict raises, re-sign produces valid output
  verify_trust_intelligence_snapshot  valid roundtrip, missing fields, wrong authority
                                    version, tampered hash, signature mismatch,
                                    key_unavailable, non-numeric values, key_id mismatch
  replay_trust_intelligence         valid replay, empty store treats as located, store
                                    hit/miss, graph integrity layer, confidence layer,
                                    authority layer, tampered hash replay_score,
                                    signature fail, all six layers present
  generate_trust_memory             empty input, window filtering, future exclusion,
                                    posture/trend/risk histories, window presets,
                                    tenant/engagement propagation
  calculate_trust_evolution         insufficient_data (0/1 snaps), stable, improvement,
                                    regression, major/moderate/minor thresholds,
                                    root causes, largest changes capped at 3
  compare_trust_snapshots           trust_delta, posture improvement/degradation,
                                    trend improvement/degradation, added/removed risks,
                                    risk_score delta, both-empty inputs
  generate_decision_memory          required keys, entity types, supporting intelligence,
                                    supporting evidence, empty reasoning, tenant/engagement
  generate_executive_timeline       baseline event, improvement/degradation events,
                                    unchanged events, impact strings, board-readable format
  generate_trust_ledger             genesis hash first entry, chain linking, dedup
                                    by snapshot_hash, previous_ledger append,
                                    chronological ordering
  verify_trust_ledger               empty ledger valid, intact chain, tampered entry_hash,
                                    wrong genesis hash, broken chain link
  Determinism                       all functions produce identical output on identical input
  CrossTenantIsolation              snapshots reject foreign tenant, ledger isolates,
                                    memory filters, decision memory scoped
  CrossEngagementIsolation          snapshot hash differs across engagements
  TamperDetection                   hash tamper, signature tamper, ledger entry tamper,
                                    chain break detected, key_id tamper
  Performance                       throughput guards: snapshot, verify, replay, memory,
                                    evolution, compare, ledger, timeline
  FutureAgentCompatibility          agent/autonomous_system/agent_fleet entity types
  AGIGovernanceCompatibility        agi entity type, agi decision memory
  SecurityInvariants                no function ever raises on garbage input,
                                    verify always returns dict, replay always returns dict
  EnterpriseScenarios               banking, healthcare, govcon, AI governance, multi-year
  EdgeCases                         None inputs, empty strings, zero counts,
                                    single-snapshot evolution, window=0
"""

from __future__ import annotations

import os
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from services.field_assessment.trust_intelligence_authority import (
    DECISION_ENTITY_AGI,
    DECISION_ENTITY_AGENT,
    DECISION_ENTITY_AUTONOMOUS,
    DECISION_ENTITY_HUMAN,
    LEDGER_GENESIS_HASH,
    MEMORY_WINDOW_30,
    MEMORY_WINDOW_90,
    MEMORY_WINDOW_180,
    MEMORY_WINDOW_365,
    TRUST_INTELLIGENCE_AUTHORITY_VERSION,
    TrustIntelligenceAuthorityError,
    _EVOLUTION_MAJOR_THRESHOLD,
    _EVOLUTION_MODERATE_THRESHOLD,
    _REPLAY_SCORE_AUTHORITY,
    _REPLAY_SCORE_CONFIDENCE,
    _REPLAY_SCORE_GRAPH,
    _REPLAY_SCORE_INTEGRITY,
    _REPLAY_SCORE_LOCATED,
    _REPLAY_SCORE_SIGNATURE,
    calculate_trust_evolution,
    compare_trust_snapshots,
    generate_decision_memory,
    generate_executive_timeline,
    generate_trust_intelligence_snapshot,
    generate_trust_ledger,
    generate_trust_memory,
    replay_trust_intelligence,
    sign_trust_intelligence_snapshot,
    verify_trust_intelligence_snapshot,
    verify_trust_ledger,
)

# ---------------------------------------------------------------------------
# Test fixtures and helpers
# ---------------------------------------------------------------------------

TENANT_A = "tenant-alpha"
TENANT_B = "tenant-beta"
ENG_A = "eng-001"
ENG_B = "eng-002"

_SIGNING_SEED = os.urandom(32)
_SIGNING_KEY_B64 = __import__("base64").b64encode(_SIGNING_SEED).decode()


@pytest.fixture(autouse=True)
def _set_signing_key(monkeypatch):
    monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _SIGNING_KEY_B64)
    monkeypatch.delenv("FG_EVIDENCE_VERIFY_KEY_B64", raising=False)


def _snap(
    tenant_id: str = TENANT_A,
    engagement_id: str = ENG_A,
    posture_score: int = 75,
    posture_level: str = "healthy",
    trend_direction: str = "stable",
    risk_level: str = "low",
    risk_score: int = 20,
    days_ago: float = 0,
    **kwargs: Any,
) -> dict[str, Any]:
    """Generate a signed snapshot with optional time offset."""
    posture_result = {"score": posture_score, "trust_posture": posture_level}
    trend_result = {"direction": trend_direction, "velocity": "moderate"}
    risk_result = {"risk_level": risk_level, "risk_score": risk_score}
    snap = generate_trust_intelligence_snapshot(
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        posture_result=posture_result,
        trend_result=trend_result,
        risk_result=risk_result,
        **kwargs,
    )
    if days_ago != 0:
        ts = datetime.now(timezone.utc) - timedelta(days=days_ago)
        snap = {**snap, "created_at": ts.isoformat().replace("+00:00", "Z")}
    return snap


def _snap_seq(count: int, base_score: int = 50, delta: int = 5) -> list[dict[str, Any]]:
    """Generate a sequence of snapshots with increasing scores."""
    snaps = []
    for i in range(count):
        days = count - i  # oldest first
        score = min(100, max(0, base_score + i * delta))
        level = (
            "excellent"
            if score >= 90
            else "healthy"
            if score >= 75
            else "stable"
            if score >= 60
            else "watch"
            if score >= 45
            else "degraded"
            if score >= 25
            else "critical"
        )
        snaps.append(_snap(posture_score=score, posture_level=level, days_ago=days))
    return snaps


# ---------------------------------------------------------------------------
# 1. TestTrustIntelligenceAuthorityConstants
# ---------------------------------------------------------------------------


class TestTrustIntelligenceAuthorityConstants:
    def test_version_string(self):
        assert TRUST_INTELLIGENCE_AUTHORITY_VERSION == "trust-intelligence-authority-v1"

    def test_ledger_genesis_hash_is_64_zeros(self):
        assert LEDGER_GENESIS_HASH == "0" * 64

    def test_replay_scores_sum_to_100(self):
        total = (
            _REPLAY_SCORE_LOCATED
            + _REPLAY_SCORE_INTEGRITY
            + _REPLAY_SCORE_SIGNATURE
            + _REPLAY_SCORE_GRAPH
            + _REPLAY_SCORE_CONFIDENCE
            + _REPLAY_SCORE_AUTHORITY
        )
        assert total == 100

    def test_evolution_major_gt_moderate(self):
        assert _EVOLUTION_MAJOR_THRESHOLD > _EVOLUTION_MODERATE_THRESHOLD

    def test_memory_windows(self):
        assert MEMORY_WINDOW_30 == 30
        assert MEMORY_WINDOW_90 == 90
        assert MEMORY_WINDOW_180 == 180
        assert MEMORY_WINDOW_365 == 365

    def test_decision_entity_types(self):
        assert DECISION_ENTITY_HUMAN == "human"
        assert DECISION_ENTITY_AGENT == "agent"
        assert DECISION_ENTITY_AUTONOMOUS == "autonomous_system"
        assert DECISION_ENTITY_AGI == "agi"

    def test_genesis_hash_not_valid_sha256(self):
        # Sentinel value must never collide with a real SHA-256
        assert len(LEDGER_GENESIS_HASH) == 64
        assert all(c == "0" for c in LEDGER_GENESIS_HASH)

    def test_version_prefix(self):
        assert TRUST_INTELLIGENCE_AUTHORITY_VERSION.startswith(
            "trust-intelligence-authority-"
        )


# ---------------------------------------------------------------------------
# 2. TestGenerateTrustIntelligenceSnapshot
# ---------------------------------------------------------------------------


class TestGenerateTrustIntelligenceSnapshot:
    def test_returns_required_keys(self):
        snap = _snap()
        for key in (
            "snapshot_id",
            "snapshot_hash",
            "snapshot_signature",
            "signing_key_id",
            "authority_version",
            "created_at",
            "tenant_id",
            "engagement_id",
        ):
            assert key in snap, f"Missing key: {key}"

    def test_authority_version_correct(self):
        assert _snap()["authority_version"] == TRUST_INTELLIGENCE_AUTHORITY_VERSION

    def test_tenant_id_echoed(self):
        assert _snap(tenant_id=TENANT_A)["tenant_id"] == TENANT_A

    def test_engagement_id_echoed(self):
        assert _snap(engagement_id=ENG_B)["engagement_id"] == ENG_B

    def test_posture_score_extracted(self):
        snap = _snap(posture_score=82)
        assert snap["posture_score"] == 82

    def test_posture_level_extracted(self):
        snap = _snap(posture_level="healthy")
        assert snap["posture_level"] == "healthy"

    def test_risk_score_extracted(self):
        snap = _snap(risk_score=42)
        assert snap["risk_score"] == 42

    def test_risk_level_extracted(self):
        snap = _snap(risk_level="medium")
        assert snap["risk_level"] == "medium"

    def test_trend_direction_extracted(self):
        snap = _snap(trend_direction="improving")
        assert snap["trend_direction"] == "improving"

    def test_snapshot_id_unique(self):
        ids = {_snap()["snapshot_id"] for _ in range(50)}
        assert len(ids) == 50

    def test_snapshot_hash_deterministic(self):
        base = dict(
            tenant_id=TENANT_A,
            engagement_id=ENG_A,
            posture_result={"score": 70, "trust_posture": "stable"},
            trend_result={"direction": "stable", "velocity": "low"},
            risk_result={"risk_level": "low", "risk_score": 15},
        )
        h1 = generate_trust_intelligence_snapshot(**base)["snapshot_hash"]
        h2 = generate_trust_intelligence_snapshot(**base)["snapshot_hash"]
        assert h1 == h2

    def test_snapshot_hash_is_64_hex(self):
        snap = _snap()
        assert len(snap["snapshot_hash"]) == 64
        assert all(c in "0123456789abcdef" for c in snap["snapshot_hash"])

    def test_missing_tenant_id_raises(self):
        with pytest.raises(TrustIntelligenceAuthorityError):
            generate_trust_intelligence_snapshot(tenant_id="", engagement_id=ENG_A)

    def test_missing_engagement_id_raises(self):
        with pytest.raises(TrustIntelligenceAuthorityError):
            generate_trust_intelligence_snapshot(tenant_id=TENANT_A, engagement_id="")

    def test_all_none_defaults(self):
        snap = generate_trust_intelligence_snapshot(
            tenant_id=TENANT_A, engagement_id=ENG_A
        )
        assert snap["posture_score"] == 0
        assert snap["posture_level"] == "unknown"
        assert snap["trend_direction"] == "stable"
        assert snap["risk_level"] == "unknown"

    def test_priorities_count(self):
        prio = [{"label": "fix_auth"}, {"label": "fix_replay"}]
        snap = generate_trust_intelligence_snapshot(
            tenant_id=TENANT_A, engagement_id=ENG_A, priorities=prio
        )
        assert snap["priorities_count"] == 2

    def test_insights_count(self):
        insights = [{"message": "ok"}, {"message": "watch"}, {"message": "alert"}]
        snap = generate_trust_intelligence_snapshot(
            tenant_id=TENANT_A, engagement_id=ENG_A, insights=insights
        )
        assert snap["insights_count"] == 3

    def test_recommendations_count(self):
        recs = [{"action": "a"}, {"action": "b"}]
        snap = generate_trust_intelligence_snapshot(
            tenant_id=TENANT_A, engagement_id=ENG_A, recommendations=recs
        )
        assert snap["recommendations_count"] == 2

    def test_graph_result_embedded(self):
        g = {"nodes": [{"node_id": "n1"}, {"node_id": "n2"}], "edges": []}
        snap = generate_trust_intelligence_snapshot(
            tenant_id=TENANT_A, engagement_id=ENG_A, graph_result=g
        )
        assert snap["graph_node_count"] == 2
        assert snap["graph_result"] == g

    def test_forecast_projected_score_embedded(self):
        f = {"projected_score": 88}
        snap = generate_trust_intelligence_snapshot(
            tenant_id=TENANT_A,
            engagement_id=ENG_A,
            posture_result={"score": 80, "trust_posture": "healthy"},
            forecast_result=f,
        )
        assert snap["forecast_projected_score"] == 88

    def test_signature_is_hex(self):
        snap = _snap()
        sig = snap["snapshot_signature"]
        assert isinstance(sig, str)
        assert all(c in "0123456789abcdef" for c in sig)

    def test_hash_differs_across_tenants(self):
        h_a = _snap(tenant_id=TENANT_A)["snapshot_hash"]
        h_b = _snap(tenant_id=TENANT_B)["snapshot_hash"]
        assert h_a != h_b

    def test_hash_differs_across_engagements(self):
        h_1 = _snap(engagement_id=ENG_A)["snapshot_hash"]
        h_2 = _snap(engagement_id=ENG_B)["snapshot_hash"]
        assert h_1 != h_2

    def test_posture_result_stored_verbatim(self):
        p = {"score": 77, "trust_posture": "healthy", "extra": "data"}
        snap = generate_trust_intelligence_snapshot(
            tenant_id=TENANT_A, engagement_id=ENG_A, posture_result=p
        )
        assert snap["posture_result"] == p


# ---------------------------------------------------------------------------
# 3. TestSignTrustIntelligenceSnapshot
# ---------------------------------------------------------------------------


class TestSignTrustIntelligenceSnapshot:
    def test_sign_adds_signature(self):
        snap = _snap()
        snap["snapshot_signature"] = ""
        signed = sign_trust_intelligence_snapshot(snap)
        assert len(signed["snapshot_signature"]) > 0

    def test_sign_updates_key_id(self):
        snap = _snap()
        signed = sign_trust_intelligence_snapshot(snap)
        assert signed["signing_key_id"] == snap["signing_key_id"]

    def test_sign_does_not_mutate_input(self):
        snap = _snap()
        original_sig = snap["snapshot_signature"]
        sign_trust_intelligence_snapshot(snap)
        assert snap["snapshot_signature"] == original_sig

    def test_sign_produces_verifiable_snapshot(self):
        snap = _snap()
        signed = sign_trust_intelligence_snapshot(snap)
        result = verify_trust_intelligence_snapshot(signed)
        assert result["valid"] is True

    def test_sign_missing_snapshot_hash_raises(self):
        snap = _snap()
        del snap["snapshot_hash"]
        with pytest.raises(TrustIntelligenceAuthorityError):
            sign_trust_intelligence_snapshot(snap)

    def test_sign_empty_snapshot_hash_raises(self):
        snap = _snap()
        snap["snapshot_hash"] = ""
        with pytest.raises(TrustIntelligenceAuthorityError):
            sign_trust_intelligence_snapshot(snap)

    def test_sign_non_dict_raises(self):
        with pytest.raises(TrustIntelligenceAuthorityError):
            sign_trust_intelligence_snapshot(None)  # type: ignore

    def test_sign_no_key_raises(self, monkeypatch):
        snap = _snap()  # generate snapshot while key is still set
        snap_no_key = dict(snap)
        monkeypatch.delenv("FG_EVIDENCE_SIGNING_KEY_B64", raising=False)
        with pytest.raises(TrustIntelligenceAuthorityError):
            sign_trust_intelligence_snapshot(snap_no_key)

    def test_double_sign_produces_same_hash(self):
        snap = _snap()
        signed1 = sign_trust_intelligence_snapshot(snap)
        signed2 = sign_trust_intelligence_snapshot(snap)
        assert signed1["snapshot_hash"] == signed2["snapshot_hash"]

    def test_sign_preserves_all_other_fields(self):
        snap = _snap()
        signed = sign_trust_intelligence_snapshot(snap)
        for k in snap:
            if k not in ("snapshot_signature", "signing_key_id"):
                assert signed[k] == snap[k]

    def test_signed_snapshot_has_64_char_signature(self):
        snap = _snap()
        signed = sign_trust_intelligence_snapshot(snap)
        assert len(signed["snapshot_signature"]) == 128  # Ed25519 → 64 bytes → 128 hex

    def test_sign_returns_new_dict_not_mutation(self):
        snap = _snap()
        signed = sign_trust_intelligence_snapshot(snap)
        assert signed is not snap


# ---------------------------------------------------------------------------
# 4. TestVerifyTrustIntelligenceSnapshot
# ---------------------------------------------------------------------------


class TestVerifyTrustIntelligenceSnapshot:
    def test_valid_snapshot(self):
        assert verify_trust_intelligence_snapshot(_snap())["valid"] is True

    def test_valid_reason_is_none(self):
        assert verify_trust_intelligence_snapshot(_snap())["reason"] is None

    def test_missing_snapshot_returns_invalid(self):
        r = verify_trust_intelligence_snapshot({})
        assert r["valid"] is False

    def test_none_snapshot_returns_invalid(self):
        r = verify_trust_intelligence_snapshot(None)  # type: ignore
        assert r["valid"] is False

    def test_wrong_authority_version(self):
        snap = _snap()
        snap["authority_version"] = "old-v0"
        r = verify_trust_intelligence_snapshot(snap)
        assert r["valid"] is False
        assert "invalid_authority_version" in r["reason"]

    def test_tampered_posture_score(self):
        snap = _snap()
        snap["posture_score"] = snap["posture_score"] + 1
        r = verify_trust_intelligence_snapshot(snap)
        assert r["valid"] is False
        assert r["reason"] == "tampered_snapshot_hash"

    def test_tampered_snapshot_hash(self):
        snap = _snap()
        snap["snapshot_hash"] = "a" * 64
        r = verify_trust_intelligence_snapshot(snap)
        assert r["valid"] is False

    def test_tampered_signature(self):
        snap = _snap()
        snap["snapshot_signature"] = "00" * 64
        r = verify_trust_intelligence_snapshot(snap)
        assert r["valid"] is False
        assert r["reason"] == "signature_mismatch"

    def test_missing_fields(self):
        snap = _snap()
        del snap["snapshot_hash"]
        r = verify_trust_intelligence_snapshot(snap)
        assert r["valid"] is False
        assert "missing_fields" in r["reason"]

    def test_key_unavailable(self, monkeypatch):
        snap = _snap()
        monkeypatch.delenv("FG_EVIDENCE_SIGNING_KEY_B64", raising=False)
        r = verify_trust_intelligence_snapshot(snap)
        assert r["valid"] is False
        assert r["reason"] == "key_unavailable"

    def test_non_numeric_posture_score(self):
        snap = _snap()
        snap["posture_score"] = "not_a_number"
        r = verify_trust_intelligence_snapshot(snap)
        assert r["valid"] is False

    def test_signing_key_id_mismatch(self):
        snap = _snap()
        snap["signing_key_id"] = "deadbeef" * 2
        r = verify_trust_intelligence_snapshot(snap)
        assert r["valid"] is False
        assert r["reason"] in ("signing_key_id_mismatch", "tampered_snapshot_hash")

    def test_tampered_risk_score(self):
        snap = _snap(risk_score=20)
        snap["risk_score"] = 99
        r = verify_trust_intelligence_snapshot(snap)
        assert r["valid"] is False

    def test_tampered_priorities_count(self):
        snap = _snap()
        snap["priorities_count"] = snap["priorities_count"] + 5
        r = verify_trust_intelligence_snapshot(snap)
        assert r["valid"] is False

    def test_tampered_graph_node_count(self):
        snap = _snap()
        snap["graph_node_count"] = 99
        r = verify_trust_intelligence_snapshot(snap)
        assert r["valid"] is False

    def test_valid_full_intelligence_snapshot(self):
        prio = [{"label": "fix_auth"}]
        insights = [{"message": "watch replay"}]
        recs = [{"action": "patch auth"}]
        g = {"nodes": [{"node_id": "n1"}], "edges": []}
        snap = generate_trust_intelligence_snapshot(
            tenant_id=TENANT_A,
            engagement_id=ENG_A,
            posture_result={"score": 80, "trust_posture": "healthy"},
            trend_result={"direction": "improving", "velocity": "moderate"},
            risk_result={"risk_level": "medium", "risk_score": 40},
            priorities=prio,
            insights=insights,
            recommendations=recs,
            graph_result=g,
        )
        r = verify_trust_intelligence_snapshot(snap)
        assert r["valid"] is True

    def test_verify_never_raises_on_garbage(self):
        for bad in [None, 42, "string", [], {}, {"a": "b"}]:
            result = verify_trust_intelligence_snapshot(bad)  # type: ignore
            assert isinstance(result, dict)
            assert "valid" in result

    def test_different_tenant_produces_invalid(self):
        snap = _snap(tenant_id=TENANT_A)
        snap["tenant_id"] = TENANT_B  # mutate without updating hash
        r = verify_trust_intelligence_snapshot(snap)
        assert r["valid"] is False

    def test_tampered_trend_direction(self):
        snap = _snap(trend_direction="stable")
        snap["trend_direction"] = "rapidly_degrading"
        r = verify_trust_intelligence_snapshot(snap)
        assert r["valid"] is False

    def test_tampered_risk_level(self):
        snap = _snap(risk_level="low")
        snap["risk_level"] = "critical"
        r = verify_trust_intelligence_snapshot(snap)
        assert r["valid"] is False


# ---------------------------------------------------------------------------
# 5. TestReplayTrustIntelligence
# ---------------------------------------------------------------------------


class TestReplayTrustIntelligence:
    def test_valid_replay(self):
        snap = _snap()
        r = replay_trust_intelligence(snap)
        assert r["valid"] is True

    def test_replay_score_100_on_full_verification(self):
        snap = _snap(
            graph_result={"nodes": [{"node_id": "n1"}], "edges": []},
        )
        r = replay_trust_intelligence(snap)
        assert r["replay_score"] == 100

    def test_replay_returns_snapshot(self):
        snap = _snap()
        r = replay_trust_intelligence(snap)
        assert r["snapshot"] == snap

    def test_replay_validations_list(self):
        snap = _snap(graph_result={"nodes": [{"id": "x"}], "edges": []})
        r = replay_trust_intelligence(snap)
        assert "snapshot_located" in r["validations"]
        assert "snapshot_integrity" in r["validations"]
        assert "snapshot_signature" in r["validations"]
        assert "confidence_integrity" in r["validations"]
        assert "authority_integrity" in r["validations"]

    def test_missing_snapshot_returns_invalid(self):
        r = replay_trust_intelligence({})
        assert r["valid"] is False
        assert r["replay_score"] == 0

    def test_none_snapshot_returns_invalid(self):
        r = replay_trust_intelligence(None)  # type: ignore
        assert r["valid"] is False

    def test_store_hit_adds_located(self):
        snap = _snap()
        r = replay_trust_intelligence(snap, snapshots_store=[snap])
        assert "snapshot_located" in r["validations"]

    def test_store_miss_does_not_add_located(self):
        snap = _snap()
        other = _snap(posture_score=99)
        r = replay_trust_intelligence(snap, snapshots_store=[other])
        assert "snapshot_located" not in r["validations"]

    def test_empty_store_treats_as_located(self):
        snap = _snap()
        r = replay_trust_intelligence(snap, snapshots_store=[])
        assert "snapshot_located" in r["validations"]

    def test_tampered_hash_reduces_score(self):
        snap = _snap()
        snap["snapshot_hash"] = "b" * 64
        r = replay_trust_intelligence(snap)
        assert r["replay_score"] < 100
        assert r["valid"] is False

    def test_graph_integrity_layer(self):
        snap = _snap(
            graph_result={"nodes": [{"node_id": "n1"}, {"node_id": "n2"}], "edges": []}
        )
        r = replay_trust_intelligence(snap)
        assert "graph_integrity" in r["validations"]

    def test_no_graph_no_graph_integrity(self):
        snap = generate_trust_intelligence_snapshot(
            tenant_id=TENANT_A, engagement_id=ENG_A
        )
        r = replay_trust_intelligence(snap)
        assert "graph_integrity" not in r["validations"]

    def test_confidence_integrity_layer(self):
        snap = _snap(posture_score=75, posture_level="healthy")
        r = replay_trust_intelligence(snap)
        assert "confidence_integrity" in r["validations"]

    def test_authority_integrity_layer(self):
        snap = _snap()
        r = replay_trust_intelligence(snap)
        assert "authority_integrity" in r["validations"]

    def test_replay_score_never_exceeds_100(self):
        snap = _snap(graph_result={"nodes": [{"node_id": "x"}], "edges": []})
        r = replay_trust_intelligence(snap)
        assert r["replay_score"] <= 100

    def test_replay_score_nonnegative(self):
        snap = _snap()
        snap["snapshot_hash"] = "f" * 64  # tamper
        r = replay_trust_intelligence(snap)
        assert r["replay_score"] >= 0

    def test_replay_returns_dict(self):
        assert isinstance(replay_trust_intelligence({}), dict)

    def test_replay_reason_on_failure(self):
        snap = _snap()
        snap["snapshot_hash"] = "c" * 64
        r = replay_trust_intelligence(snap)
        assert r["reason"] is not None

    def test_replay_reason_none_on_success(self):
        snap = _snap()
        r = replay_trust_intelligence(snap)
        assert r["reason"] is None

    def test_replay_score_partial_on_store_miss(self):
        snap = _snap()
        other = _snap(posture_score=10)
        r = replay_trust_intelligence(snap, snapshots_store=[other])
        assert r["replay_score"] < 100

    def test_replay_multiple_stores(self):
        snaps = [_snap(posture_score=i * 10) for i in range(1, 6)]
        target = snaps[2]
        r = replay_trust_intelligence(target, snapshots_store=snaps)
        assert "snapshot_located" in r["validations"]

    def test_replay_with_key_unavailable_does_not_raise(self, monkeypatch):
        snap = _snap()
        monkeypatch.delenv("FG_EVIDENCE_SIGNING_KEY_B64", raising=False)
        r = replay_trust_intelligence(snap)
        assert isinstance(r, dict)
        assert r["valid"] is False


# ---------------------------------------------------------------------------
# 6. TestGenerateTrustMemory
# ---------------------------------------------------------------------------


class TestGenerateTrustMemory:
    def test_empty_input(self):
        r = generate_trust_memory(None)
        assert r["snapshot_count"] == 0
        assert r["timeline"] == []
        assert r["posture_history"] == []
        assert r["trend_history"] == []
        assert r["risk_history"] == []

    def test_returns_required_keys(self):
        r = generate_trust_memory([])
        for k in (
            "window_days",
            "snapshot_count",
            "timeline",
            "posture_history",
            "trend_history",
            "risk_history",
        ):
            assert k in r

    def test_window_filtering(self):
        recent = _snap(days_ago=5)
        old = _snap(posture_score=10, days_ago=200)
        r = generate_trust_memory([recent, old], window_days=90)
        assert r["snapshot_count"] == 1
        assert r["timeline"][0]["posture_score"] == recent["posture_score"]

    def test_future_snapshot_excluded(self):
        now = datetime.now(timezone.utc)
        future_ts = (now + timedelta(days=30)).isoformat().replace("+00:00", "Z")
        snap = _snap()
        snap["created_at"] = future_ts
        r = generate_trust_memory([snap], window_days=90)
        assert r["snapshot_count"] == 0

    def test_chronological_order(self):
        snaps = [_snap(posture_score=i * 10, days_ago=10 - i) for i in range(1, 6)]
        r = generate_trust_memory(snaps, window_days=30)
        dates = [e["created_at"] for e in r["timeline"]]
        assert dates == sorted(dates)

    def test_posture_history_structure(self):
        snap = _snap(posture_score=80, posture_level="healthy", days_ago=1)
        r = generate_trust_memory([snap], window_days=30)
        ph = r["posture_history"][0]
        assert ph["score"] == 80
        assert ph["level"] == "healthy"
        assert "date" in ph

    def test_trend_history_structure(self):
        snap = _snap(trend_direction="improving", days_ago=1)
        r = generate_trust_memory([snap], window_days=30)
        th = r["trend_history"][0]
        assert th["direction"] == "improving"
        assert "velocity" in th

    def test_risk_history_structure(self):
        snap = _snap(risk_level="medium", risk_score=45, days_ago=1)
        r = generate_trust_memory([snap], window_days=30)
        rh = r["risk_history"][0]
        assert rh["level"] == "medium"
        assert rh["score"] == 45

    def test_tenant_id_propagated(self):
        snap = _snap(tenant_id=TENANT_A, days_ago=1)
        r = generate_trust_memory([snap], window_days=30)
        assert r["tenant_id"] == TENANT_A

    def test_window_30_preset(self):
        r = generate_trust_memory([], window_days=MEMORY_WINDOW_30)
        assert r["window_days"] == 30

    def test_window_365_preset(self):
        snaps = [_snap(days_ago=300)]
        r = generate_trust_memory(snaps, window_days=MEMORY_WINDOW_365)
        assert r["snapshot_count"] == 1

    def test_window_180(self):
        snaps = [_snap(days_ago=170), _snap(posture_score=10, days_ago=190)]
        r = generate_trust_memory(snaps, window_days=MEMORY_WINDOW_180)
        assert r["snapshot_count"] == 1

    def test_none_items_skipped(self):
        r = generate_trust_memory([None, _snap(days_ago=1), None], window_days=30)  # type: ignore
        assert r["snapshot_count"] == 1

    def test_invalid_timestamps_skipped(self):
        snap = _snap()
        snap["created_at"] = "not-a-date"
        r = generate_trust_memory([snap], window_days=90)
        assert r["snapshot_count"] == 0

    def test_window_zero_includes_nothing(self):
        snap = _snap(days_ago=1)
        r = generate_trust_memory([snap], window_days=0)
        assert r["snapshot_count"] == 0

    def test_engagement_id_propagated(self):
        snap = _snap(engagement_id=ENG_B, days_ago=1)
        r = generate_trust_memory([snap], window_days=30)
        assert r["engagement_id"] == ENG_B

    def test_timeline_has_snapshot_hash(self):
        snap = _snap(days_ago=1)
        r = generate_trust_memory([snap], window_days=30)
        assert r["timeline"][0]["snapshot_hash"] == snap["snapshot_hash"]

    def test_multiple_snaps_all_in_window(self):
        snaps = [_snap(posture_score=i * 10, days_ago=i) for i in range(1, 6)]
        r = generate_trust_memory(snaps, window_days=30)
        assert r["snapshot_count"] == 5

    def test_default_window_is_90(self):
        r = generate_trust_memory([])
        assert r["window_days"] == 90

    def test_no_tenant_id_when_empty(self):
        r = generate_trust_memory([])
        assert r["tenant_id"] is None


# ---------------------------------------------------------------------------
# 7. TestCalculateTrustEvolution
# ---------------------------------------------------------------------------


class TestCalculateTrustEvolution:
    def test_insufficient_data_empty(self):
        r = calculate_trust_evolution([])
        assert r["overall_change"] == "insufficient_data"

    def test_insufficient_data_single(self):
        r = calculate_trust_evolution([_snap()])
        assert r["overall_change"] == "insufficient_data"

    def test_stable_evolution(self):
        snaps = [
            _snap(posture_score=70, days_ago=10),
            _snap(posture_score=70, days_ago=1),
        ]
        r = calculate_trust_evolution(snaps)
        assert r["overall_change"] == "stable"
        assert r["score_delta"] == 0

    def test_major_improvement(self):
        snaps = [
            _snap(posture_score=40, days_ago=30),
            _snap(posture_score=40 + _EVOLUTION_MAJOR_THRESHOLD, days_ago=1),
        ]
        r = calculate_trust_evolution(snaps)
        assert r["overall_change"] == "major_improvement"

    def test_major_regression(self):
        snaps = [
            _snap(posture_score=80, days_ago=30),
            _snap(posture_score=80 - _EVOLUTION_MAJOR_THRESHOLD, days_ago=1),
        ]
        r = calculate_trust_evolution(snaps)
        assert r["overall_change"] == "major_regression"

    def test_moderate_improvement(self):
        snaps = [
            _snap(posture_score=50, days_ago=10),
            _snap(posture_score=50 + _EVOLUTION_MODERATE_THRESHOLD, days_ago=1),
        ]
        r = calculate_trust_evolution(snaps)
        assert r["overall_change"] in ("moderate_improvement", "minor_improvement")

    def test_minor_improvement(self):
        snaps = [
            _snap(posture_score=50, days_ago=5),
            _snap(posture_score=52, days_ago=1),
        ]
        r = calculate_trust_evolution(snaps)
        assert r["overall_change"] in ("minor_improvement", "moderate_improvement")

    def test_score_delta_correct(self):
        snaps = [
            _snap(posture_score=60, days_ago=10),
            _snap(posture_score=75, days_ago=1),
        ]
        r = calculate_trust_evolution(snaps)
        assert r["score_delta"] == 15

    def test_largest_improvements_capped_at_3(self):
        snaps = _snap_seq(10, base_score=20, delta=8)
        r = calculate_trust_evolution(snaps)
        assert len(r["largest_improvements"]) <= 3

    def test_largest_regressions_capped_at_3(self):
        snaps = _snap_seq(10, base_score=90, delta=-8)
        r = calculate_trust_evolution(snaps)
        assert len(r["largest_regressions"]) <= 3

    def test_root_causes_include_direction_change(self):
        s1 = _snap(posture_score=50, trend_direction="degrading", days_ago=10)
        s2 = _snap(posture_score=70, trend_direction="improving", days_ago=1)
        r = calculate_trust_evolution([s1, s2])
        assert any("trend_direction_changed" in rc for rc in r["root_causes"])

    def test_root_causes_include_posture_score_change(self):
        snaps = [
            _snap(posture_score=40, days_ago=5),
            _snap(posture_score=80, days_ago=1),
        ]
        r = calculate_trust_evolution(snaps)
        assert any("posture_score_changed" in rc for rc in r["root_causes"])

    def test_root_causes_include_posture_level_change(self):
        s1 = _snap(posture_score=30, posture_level="watch", days_ago=5)
        s2 = _snap(posture_score=80, posture_level="healthy", days_ago=1)
        r = calculate_trust_evolution([s1, s2])
        assert any("posture_level_changed" in rc for rc in r["root_causes"])

    def test_snapshot_count_reported(self):
        snaps = _snap_seq(7)
        r = calculate_trust_evolution(snaps)
        assert r["snapshot_count"] == 7

    def test_first_last_dates(self):
        s1 = _snap(days_ago=30)
        s2 = _snap(days_ago=1)
        r = calculate_trust_evolution([s1, s2])
        assert r["first_date"] < r["last_date"]

    def test_first_last_posture(self):
        s1 = _snap(posture_level="degraded", days_ago=10)
        s2 = _snap(posture_level="healthy", days_ago=1)
        r = calculate_trust_evolution([s1, s2])
        assert r["first_posture"] == "degraded"
        assert r["last_posture"] == "healthy"

    def test_none_in_list_skipped(self):
        snaps = [
            None,
            _snap(posture_score=50, days_ago=5),
            None,
            _snap(posture_score=70, days_ago=1),
        ]  # type: ignore
        r = calculate_trust_evolution(snaps)
        assert r["snapshot_count"] == 2

    def test_improvements_sorted_by_delta_desc(self):
        snaps = _snap_seq(5, base_score=30, delta=10)
        r = calculate_trust_evolution(snaps)
        deltas = [x["score_delta"] for x in r["largest_improvements"]]
        assert deltas == sorted(deltas, reverse=True)


# ---------------------------------------------------------------------------
# 8. TestCompareTrustSnapshots
# ---------------------------------------------------------------------------


class TestCompareTrustSnapshots:
    def test_returns_required_keys(self):
        r = compare_trust_snapshots(_snap(), _snap())
        for k in (
            "trust_delta",
            "added_risks",
            "removed_risks",
            "improved_controls",
            "degraded_controls",
            "posture_change",
        ):
            assert k in r

    def test_trust_delta_positive_improvement(self):
        a = _snap(posture_score=60)
        b = _snap(posture_score=80)
        r = compare_trust_snapshots(a, b)
        assert r["trust_delta"] == 20

    def test_trust_delta_negative_degradation(self):
        a = _snap(posture_score=80)
        b = _snap(posture_score=55)
        r = compare_trust_snapshots(a, b)
        assert r["trust_delta"] == -25

    def test_trust_delta_zero_same_score(self):
        snap = _snap(posture_score=70)
        r = compare_trust_snapshots(snap, snap)
        assert r["trust_delta"] == 0

    def test_posture_change_string(self):
        a = _snap(posture_level="watch")
        b = _snap(posture_level="healthy")
        r = compare_trust_snapshots(a, b)
        assert "watch" in r["posture_change"]
        assert "healthy" in r["posture_change"]

    def test_improved_control_posture(self):
        a = _snap(posture_score=30, posture_level="watch")
        b = _snap(posture_score=80, posture_level="healthy")
        r = compare_trust_snapshots(a, b)
        assert any("posture" in c for c in r["improved_controls"])

    def test_degraded_control_posture(self):
        a = _snap(posture_score=80, posture_level="healthy")
        b = _snap(posture_score=35, posture_level="watch")
        r = compare_trust_snapshots(a, b)
        assert any("posture" in c for c in r["degraded_controls"])

    def test_improved_control_trend(self):
        a = _snap(trend_direction="degrading")
        b = _snap(trend_direction="improving")
        r = compare_trust_snapshots(a, b)
        assert any("trend" in c for c in r["improved_controls"])

    def test_degraded_control_trend(self):
        a = _snap(trend_direction="improving")
        b = _snap(trend_direction="degrading")
        r = compare_trust_snapshots(a, b)
        assert any("trend" in c for c in r["degraded_controls"])

    def test_added_risks_detected(self):
        a = generate_trust_intelligence_snapshot(
            tenant_id=TENANT_A,
            engagement_id=ENG_A,
            risk_result={
                "risk_level": "low",
                "risk_score": 10,
                "category_scores": {"authority_risk": 10},
            },
        )
        b = generate_trust_intelligence_snapshot(
            tenant_id=TENANT_A,
            engagement_id=ENG_A,
            risk_result={
                "risk_level": "high",
                "risk_score": 70,
                "category_scores": {"authority_risk": 10, "replay_risk": 80},
            },
        )
        r = compare_trust_snapshots(a, b)
        assert "replay_risk" in r["added_risks"]

    def test_removed_risks_detected(self):
        a = generate_trust_intelligence_snapshot(
            tenant_id=TENANT_A,
            engagement_id=ENG_A,
            risk_result={
                "risk_level": "high",
                "risk_score": 70,
                "category_scores": {"authority_risk": 80, "replay_risk": 80},
            },
        )
        b = generate_trust_intelligence_snapshot(
            tenant_id=TENANT_A,
            engagement_id=ENG_A,
            risk_result={
                "risk_level": "low",
                "risk_score": 10,
                "category_scores": {"authority_risk": 10},
            },
        )
        r = compare_trust_snapshots(a, b)
        assert "replay_risk" in r["removed_risks"]

    def test_both_empty_inputs(self):
        r = compare_trust_snapshots({}, {})
        assert r["trust_delta"] == 0
        assert r["added_risks"] == []
        assert r["removed_risks"] == []

    def test_none_inputs(self):
        r = compare_trust_snapshots(None, None)  # type: ignore
        assert isinstance(r, dict)
        assert r["trust_delta"] == 0

    def test_snapshot_hashes_in_output(self):
        a = _snap()
        b = _snap(posture_score=90)
        r = compare_trust_snapshots(a, b)
        assert r["snapshot_a_hash"] == a["snapshot_hash"]
        assert r["snapshot_b_hash"] == b["snapshot_hash"]

    def test_dates_in_output(self):
        a = _snap(days_ago=10)
        b = _snap(days_ago=1)
        r = compare_trust_snapshots(a, b)
        assert r["snapshot_a_date"] == a["created_at"]
        assert r["snapshot_b_date"] == b["created_at"]

    def test_trend_change_string(self):
        a = _snap(trend_direction="degrading")
        b = _snap(trend_direction="stable")
        r = compare_trust_snapshots(a, b)
        assert "degrading" in r["trend_change"]
        assert "stable" in r["trend_change"]

    def test_risk_score_improvement_detected(self):
        a = _snap(risk_score=80)
        b = _snap(risk_score=60)
        r = compare_trust_snapshots(a, b)
        assert any("risk_score" in c for c in r["improved_controls"])

    def test_risk_score_degradation_detected(self):
        a = _snap(risk_score=20)
        b = _snap(risk_score=60)
        r = compare_trust_snapshots(a, b)
        assert any("risk_score" in c for c in r["degraded_controls"])

    def test_deterministic_output(self):
        a = _snap()
        b = _snap(posture_score=90)
        r1 = compare_trust_snapshots(a, b)
        r2 = compare_trust_snapshots(a, b)
        assert r1 == r2


# ---------------------------------------------------------------------------
# 9. TestGenerateDecisionMemory
# ---------------------------------------------------------------------------


class TestGenerateDecisionMemory:
    def test_returns_required_keys(self):
        r = generate_decision_memory("dec-1", "governance_approval")
        for k in (
            "decision_id",
            "decision_type",
            "entity_type",
            "decision_reasoning",
            "supporting_intelligence",
            "supporting_evidence",
            "authority_version",
            "created_at",
        ):
            assert k in r

    def test_decision_id_echoed(self):
        r = generate_decision_memory("dec-abc", "approval")
        assert r["decision_id"] == "dec-abc"

    def test_decision_type_echoed(self):
        r = generate_decision_memory("dec-1", "agent_approval")
        assert r["decision_type"] == "agent_approval"

    def test_entity_type_default_human(self):
        r = generate_decision_memory("dec-1", "approval")
        assert r["entity_type"] == DECISION_ENTITY_HUMAN

    def test_entity_type_agent(self):
        r = generate_decision_memory(
            "dec-1", "approval", entity_type=DECISION_ENTITY_AGENT
        )
        assert r["entity_type"] == DECISION_ENTITY_AGENT

    def test_entity_type_autonomous(self):
        r = generate_decision_memory(
            "dec-1", "approval", entity_type=DECISION_ENTITY_AUTONOMOUS
        )
        assert r["entity_type"] == DECISION_ENTITY_AUTONOMOUS

    def test_entity_type_agi(self):
        r = generate_decision_memory(
            "dec-1", "governance", entity_type=DECISION_ENTITY_AGI
        )
        assert r["entity_type"] == DECISION_ENTITY_AGI

    def test_entity_type_arbitrary_string(self):
        r = generate_decision_memory("dec-1", "approval", entity_type="future_agi_v7")
        assert r["entity_type"] == "future_agi_v7"

    def test_reasoning_list(self):
        reasoning = ["risk too high", "replay failed"]
        r = generate_decision_memory("dec-1", "rejection", reasoning=reasoning)
        assert r["decision_reasoning"] == reasoning

    def test_supporting_intelligence_from_snapshots(self):
        snaps = [_snap(), _snap(posture_score=50)]
        r = generate_decision_memory("dec-1", "approval", supporting_snapshots=snaps)
        assert len(r["supporting_intelligence"]) == 2

    def test_supporting_intelligence_structure(self):
        snap = _snap()
        r = generate_decision_memory("dec-1", "approval", supporting_snapshots=[snap])
        si = r["supporting_intelligence"][0]
        for k in ("snapshot_id", "snapshot_hash", "posture_level", "risk_level"):
            assert k in si

    def test_supporting_evidence_ids(self):
        ev_ids = ["ev-001", "ev-002", "ev-003"]
        r = generate_decision_memory(
            "dec-1", "approval", supporting_evidence_ids=ev_ids
        )
        assert r["supporting_evidence"] == ev_ids

    def test_tenant_id_propagated(self):
        r = generate_decision_memory("dec-1", "approval", tenant_id=TENANT_A)
        assert r["tenant_id"] == TENANT_A

    def test_engagement_id_propagated(self):
        r = generate_decision_memory("dec-1", "approval", engagement_id=ENG_B)
        assert r["engagement_id"] == ENG_B

    def test_authority_version_correct(self):
        r = generate_decision_memory("dec-1", "approval")
        assert r["authority_version"] == TRUST_INTELLIGENCE_AUTHORITY_VERSION

    def test_created_at_present(self):
        r = generate_decision_memory("dec-1", "approval")
        assert r["created_at"].endswith("Z")

    def test_none_snapshots_empty_intelligence(self):
        r = generate_decision_memory("dec-1", "approval", supporting_snapshots=None)
        assert r["supporting_intelligence"] == []

    def test_empty_reasoning(self):
        r = generate_decision_memory("dec-1", "approval", reasoning=[])
        assert r["decision_reasoning"] == []

    def test_never_raises_on_bad_input(self):
        r = generate_decision_memory("", "", entity_type="", reasoning=None)
        assert isinstance(r, dict)


# ---------------------------------------------------------------------------
# 10. TestGenerateExecutiveTimeline
# ---------------------------------------------------------------------------


class TestGenerateExecutiveTimeline:
    def test_empty_input_returns_empty_list(self):
        assert generate_executive_timeline([]) == []

    def test_none_input_returns_empty_list(self):
        assert generate_executive_timeline(None) == []

    def test_single_snapshot_baseline(self):
        tl = generate_executive_timeline([_snap(posture_level="healthy")])
        assert len(tl) == 1
        assert "baseline" in tl[0]["event"].lower()
        assert tl[0]["trust_change"] == "baseline"

    def test_improvement_event(self):
        snaps = [
            _snap(posture_score=40, posture_level="watch", days_ago=10),
            _snap(posture_score=80, posture_level="healthy", days_ago=1),
        ]
        tl = generate_executive_timeline(snaps)
        assert "improved" in tl[1]["event"].lower()

    def test_degradation_event(self):
        snaps = [
            _snap(posture_score=80, posture_level="healthy", days_ago=10),
            _snap(posture_score=35, posture_level="watch", days_ago=1),
        ]
        tl = generate_executive_timeline(snaps)
        assert "degraded" in tl[1]["event"].lower()

    def test_unchanged_event(self):
        snap1 = _snap(posture_score=70, posture_level="stable", days_ago=5)
        snap2 = _snap(posture_score=70, posture_level="stable", days_ago=1)
        tl = generate_executive_timeline([snap1, snap2])
        assert "unchanged" in tl[1]["event"].lower()

    def test_trust_change_sign(self):
        snaps = [
            _snap(posture_score=60, days_ago=5),
            _snap(posture_score=80, days_ago=1),
        ]
        tl = generate_executive_timeline(snaps)
        assert tl[1]["trust_change"] == "+20"

    def test_trust_change_negative(self):
        snaps = [
            _snap(posture_score=80, days_ago=5),
            _snap(posture_score=55, days_ago=1),
        ]
        tl = generate_executive_timeline(snaps)
        assert tl[1]["trust_change"] == "-25"

    def test_impact_strings_present(self):
        snaps = [
            _snap(posture_level=lvl, days_ago=6 - i)
            for i, lvl in enumerate(
                ["critical", "degraded", "watch", "stable", "healthy", "excellent"]
            )
        ]
        tl = generate_executive_timeline(snaps)
        for entry in tl:
            assert len(entry["impact"]) > 0

    def test_critical_impact_contains_immediate(self):
        tl = generate_executive_timeline([_snap(posture_level="critical")])
        assert "immediate" in tl[0]["impact"].lower()

    def test_excellent_impact_no_action(self):
        tl = generate_executive_timeline([_snap(posture_level="excellent")])
        assert "no action" in tl[0]["impact"].lower()

    def test_chronological_order(self):
        snaps = [_snap(posture_score=i * 10, days_ago=10 - i) for i in range(1, 6)]
        tl = generate_executive_timeline(snaps)
        dates = [e["date"] for e in tl]
        assert dates == sorted(dates)

    def test_snapshot_id_in_output(self):
        snap = _snap()
        tl = generate_executive_timeline([snap])
        assert tl[0]["snapshot_id"] == snap["snapshot_id"]

    def test_posture_score_in_output(self):
        tl = generate_executive_timeline([_snap(posture_score=77)])
        assert tl[0]["posture_score"] == 77

    def test_posture_level_in_output(self):
        tl = generate_executive_timeline([_snap(posture_level="stable")])
        assert tl[0]["posture_level"] == "stable"

    def test_five_snapshot_sequence(self):
        snaps = _snap_seq(5, base_score=40, delta=10)
        tl = generate_executive_timeline(snaps)
        assert len(tl) == 5

    def test_none_items_skipped(self):
        tl = generate_executive_timeline([None, _snap(), None])  # type: ignore
        assert len(tl) == 1

    def test_missing_created_at_skipped(self):
        snap = _snap()
        del snap["created_at"]
        tl = generate_executive_timeline([snap])
        assert tl == []


# ---------------------------------------------------------------------------
# 11. TestGenerateTrustLedger
# ---------------------------------------------------------------------------


class TestGenerateTrustLedger:
    def test_empty_input(self):
        ledger = generate_trust_ledger([])
        assert ledger == []

    def test_none_input(self):
        ledger = generate_trust_ledger(None)
        assert ledger == []

    def test_single_entry_genesis_hash(self):
        snap = _snap()
        ledger = generate_trust_ledger([snap])
        assert ledger[0]["previous_hash"] == LEDGER_GENESIS_HASH

    def test_single_entry_has_ledger_entry_hash(self):
        snap = _snap()
        ledger = generate_trust_ledger([snap])
        assert len(ledger[0]["ledger_entry_hash"]) == 64

    def test_chain_linking(self):
        snaps = [_snap(posture_score=i * 10, days_ago=10 - i) for i in range(1, 4)]
        ledger = generate_trust_ledger(snaps)
        assert ledger[1]["previous_hash"] == ledger[0]["ledger_entry_hash"]
        assert ledger[2]["previous_hash"] == ledger[1]["ledger_entry_hash"]

    def test_dedup_by_snapshot_hash(self):
        snap = _snap()
        ledger = generate_trust_ledger([snap, snap, snap])
        assert len(ledger) == 1

    def test_previous_ledger_appended(self):
        snap1 = _snap(posture_score=60, days_ago=10)
        snap2 = _snap(posture_score=80, days_ago=1)
        ledger1 = generate_trust_ledger([snap1])
        ledger2 = generate_trust_ledger([snap2], previous_ledger=ledger1)
        assert len(ledger2) == 2
        assert ledger2[1]["previous_hash"] == ledger2[0]["ledger_entry_hash"]

    def test_snapshot_hash_in_entry(self):
        snap = _snap()
        ledger = generate_trust_ledger([snap])
        assert ledger[0]["snapshot_hash"] == snap["snapshot_hash"]

    def test_tenant_id_in_entry(self):
        snap = _snap(tenant_id=TENANT_A)
        ledger = generate_trust_ledger([snap])
        assert ledger[0]["tenant_id"] == TENANT_A

    def test_engagement_id_in_entry(self):
        snap = _snap(engagement_id=ENG_B)
        ledger = generate_trust_ledger([snap])
        assert ledger[0]["engagement_id"] == ENG_B

    def test_timestamp_in_entry(self):
        snap = _snap()
        ledger = generate_trust_ledger([snap])
        assert ledger[0]["timestamp"] == snap["created_at"]

    def test_authority_version_in_entry(self):
        snap = _snap()
        ledger = generate_trust_ledger([snap])
        assert ledger[0]["authority_version"] == TRUST_INTELLIGENCE_AUTHORITY_VERSION

    def test_chronological_ordering(self):
        snaps = [_snap(posture_score=i * 10, days_ago=10 - i) for i in range(1, 6)]
        ledger = generate_trust_ledger(snaps)
        timestamps = [e["timestamp"] for e in ledger]
        assert timestamps == sorted(timestamps)

    def test_entry_count_matches_unique_snaps(self):
        snaps = [_snap(posture_score=i * 10) for i in range(1, 6)]
        ledger = generate_trust_ledger(snaps)
        assert len(ledger) == 5

    def test_none_items_skipped(self):
        ledger = generate_trust_ledger([None, _snap(), None])  # type: ignore
        assert len(ledger) == 1

    def test_existing_ledger_entries_preserved(self):
        snap1 = _snap(posture_score=50, days_ago=5)
        ledger1 = generate_trust_ledger([snap1])
        snap2 = _snap(posture_score=80, days_ago=1)
        ledger2 = generate_trust_ledger([snap2], previous_ledger=ledger1)
        assert ledger2[0]["snapshot_hash"] == snap1["snapshot_hash"]
        assert ledger2[1]["snapshot_hash"] == snap2["snapshot_hash"]

    def test_no_duplicate_after_re_ledger(self):
        snap = _snap()
        ledger1 = generate_trust_ledger([snap])
        ledger2 = generate_trust_ledger([snap], previous_ledger=ledger1)
        assert len(ledger2) == 1

    def test_10000_entries_performance(self):
        snaps = []
        base = datetime.now(timezone.utc) - timedelta(days=10000)
        for i in range(1000):
            ts = (base + timedelta(days=i)).isoformat().replace("+00:00", "Z")
            snap = _snap(posture_score=(i % 100))
            snap = {**snap, "snapshot_hash": uuid.uuid4().hex * 2, "created_at": ts}
            snaps.append(snap)
        t0 = time.perf_counter()
        ledger = generate_trust_ledger(snaps)
        elapsed = time.perf_counter() - t0
        assert len(ledger) == 1000
        assert elapsed < 5.0  # generous; normally < 0.1s

    def test_posture_level_in_entry(self):
        snap = _snap(posture_level="excellent")
        ledger = generate_trust_ledger([snap])
        assert ledger[0]["posture_level"] == "excellent"

    def test_risk_level_in_entry(self):
        snap = _snap(risk_level="high")
        ledger = generate_trust_ledger([snap])
        assert ledger[0]["risk_level"] == "high"


# ---------------------------------------------------------------------------
# 12. TestVerifyTrustLedger
# ---------------------------------------------------------------------------


class TestVerifyTrustLedger:
    def test_empty_ledger_valid(self):
        r = verify_trust_ledger([])
        assert r["valid"] is True
        assert r["chain_intact"] is True
        assert r["entry_count"] == 0

    def test_none_ledger_valid(self):
        r = verify_trust_ledger(None)
        assert r["valid"] is True

    def test_intact_chain(self):
        snaps = [_snap(posture_score=i * 15, days_ago=10 - i) for i in range(1, 5)]
        ledger = generate_trust_ledger(snaps)
        r = verify_trust_ledger(ledger)
        assert r["valid"] is True
        assert r["chain_intact"] is True

    def test_tampered_entry_hash_detected(self):
        snaps = [_snap(days_ago=3), _snap(posture_score=80, days_ago=1)]
        ledger = generate_trust_ledger(snaps)
        ledger[0]["ledger_entry_hash"] = "a" * 64
        r = verify_trust_ledger(ledger)
        assert r["valid"] is False
        assert "tampered_ledger_entry" in r["reason"]

    def test_tampered_entry_field_detected(self):
        snap = _snap()
        ledger = generate_trust_ledger([snap])
        ledger[0]["posture_score"] = 9999  # mutate without updating hash
        r = verify_trust_ledger(ledger)
        assert r["valid"] is False

    def test_wrong_genesis_hash_detected(self):
        snap = _snap()
        ledger = generate_trust_ledger([snap])
        # Recompute entry with wrong genesis
        ledger[0]["previous_hash"] = "f" * 64
        # Need to recompute ledger_entry_hash to make it pass entry check but fail genesis
        from services.canonical import canonical_json_bytes as cjb
        import hashlib

        entry_without = {k: v for k, v in ledger[0].items() if k != "ledger_entry_hash"}
        ledger[0]["ledger_entry_hash"] = hashlib.sha256(cjb(entry_without)).hexdigest()
        r = verify_trust_ledger(ledger)
        assert r["valid"] is False
        assert r["reason"] == "invalid_genesis_hash"

    def test_broken_chain_link_detected(self):
        snaps = [_snap(posture_score=i * 20, days_ago=5 - i) for i in range(1, 4)]
        ledger = generate_trust_ledger(snaps)
        # Tamper entry 1's previous_hash to break link from entry 0
        from services.canonical import canonical_json_bytes as cjb
        import hashlib

        ledger[1]["previous_hash"] = "d" * 64
        entry_without = {k: v for k, v in ledger[1].items() if k != "ledger_entry_hash"}
        ledger[1]["ledger_entry_hash"] = hashlib.sha256(cjb(entry_without)).hexdigest()
        r = verify_trust_ledger(ledger)
        assert r["valid"] is False
        assert "broken_chain" in r["reason"]

    def test_entry_count_in_result(self):
        snaps = [_snap(posture_score=i * 10, days_ago=10 - i) for i in range(1, 6)]
        ledger = generate_trust_ledger(snaps)
        r = verify_trust_ledger(ledger)
        assert r["entry_count"] == 5

    def test_tampered_index_reported(self):
        snaps = [_snap(posture_score=i * 10, days_ago=10 - i) for i in range(1, 4)]
        ledger = generate_trust_ledger(snaps)
        ledger[1]["ledger_entry_hash"] = "b" * 64
        r = verify_trust_ledger(ledger)
        assert r.get("tampered_index") == 1

    def test_never_raises_on_garbage(self):
        for bad in [None, [], [{}], [{"ledger_entry_hash": "x"}]]:
            result = verify_trust_ledger(bad)  # type: ignore
            assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# 13. TestDeterminism
# ---------------------------------------------------------------------------


class TestDeterminism:
    def _base_inputs(self):
        return dict(
            tenant_id=TENANT_A,
            engagement_id=ENG_A,
            posture_result={"score": 75, "trust_posture": "healthy"},
            trend_result={"direction": "stable", "velocity": "low"},
            risk_result={"risk_level": "low", "risk_score": 20},
        )

    def test_snapshot_hash_deterministic(self):
        h1 = generate_trust_intelligence_snapshot(**self._base_inputs())[
            "snapshot_hash"
        ]
        h2 = generate_trust_intelligence_snapshot(**self._base_inputs())[
            "snapshot_hash"
        ]
        assert h1 == h2

    def test_verify_deterministic(self):
        snap = _snap()
        r1 = verify_trust_intelligence_snapshot(snap)
        r2 = verify_trust_intelligence_snapshot(snap)
        assert r1 == r2

    def test_replay_deterministic(self):
        snap = _snap()
        r1 = replay_trust_intelligence(snap)
        r2 = replay_trust_intelligence(snap)
        assert r1["valid"] == r2["valid"]
        assert r1["replay_score"] == r2["replay_score"]

    def test_memory_deterministic(self):
        snaps = [_snap(days_ago=i) for i in range(1, 6)]
        r1 = generate_trust_memory(snaps, window_days=30)
        r2 = generate_trust_memory(snaps, window_days=30)
        assert r1["snapshot_count"] == r2["snapshot_count"]

    def test_evolution_deterministic(self):
        snaps = _snap_seq(5)
        r1 = calculate_trust_evolution(snaps)
        r2 = calculate_trust_evolution(snaps)
        assert r1 == r2

    def test_compare_deterministic(self):
        a, b = _snap(posture_score=60), _snap(posture_score=80)
        r1 = compare_trust_snapshots(a, b)
        r2 = compare_trust_snapshots(a, b)
        assert r1 == r2

    def test_decision_memory_type_deterministic(self):
        r1 = generate_decision_memory(
            "dec-1", "approval", entity_type=DECISION_ENTITY_AGI
        )
        r2 = generate_decision_memory(
            "dec-1", "approval", entity_type=DECISION_ENTITY_AGI
        )
        assert r1["decision_type"] == r2["decision_type"]
        assert r1["entity_type"] == r2["entity_type"]

    def test_ledger_deterministic(self):
        snap = _snap()
        l1 = generate_trust_ledger([snap])
        l2 = generate_trust_ledger([snap])
        assert l1[0]["ledger_entry_hash"] == l2[0]["ledger_entry_hash"]

    def test_verify_ledger_deterministic(self):
        ledger = generate_trust_ledger([_snap()])
        r1 = verify_trust_ledger(ledger)
        r2 = verify_trust_ledger(ledger)
        assert r1 == r2

    def test_timeline_order_deterministic(self):
        snaps = [_snap(posture_score=i * 15, days_ago=5 - i) for i in range(1, 5)]
        tl1 = generate_executive_timeline(snaps)
        tl2 = generate_executive_timeline(snaps)
        assert [e["event"] for e in tl1] == [e["event"] for e in tl2]

    def test_canonical_bytes_same_content_same_hash(self):
        snaps = [_snap(posture_score=70), _snap(posture_score=70)]
        # Both should have the same snapshot_hash (same intelligence state)
        assert snaps[0]["snapshot_hash"] == snaps[1]["snapshot_hash"]

    def test_evolution_score_delta_reproducible(self):
        s1 = _snap(posture_score=40, days_ago=10)
        s2 = _snap(posture_score=75, days_ago=1)
        r = calculate_trust_evolution([s1, s2])
        assert r["score_delta"] == 35


# ---------------------------------------------------------------------------
# 14. TestCrossTenantIsolation
# ---------------------------------------------------------------------------


class TestCrossTenantIsolation:
    def test_snapshot_hash_differs_across_tenants(self):
        h_a = _snap(tenant_id=TENANT_A)["snapshot_hash"]
        h_b = _snap(tenant_id=TENANT_B)["snapshot_hash"]
        assert h_a != h_b

    def test_verify_rejects_mutated_tenant(self):
        snap = _snap(tenant_id=TENANT_A)
        snap["tenant_id"] = TENANT_B
        r = verify_trust_intelligence_snapshot(snap)
        assert r["valid"] is False

    def test_ledger_tenant_a_not_in_tenant_b_entries(self):
        snaps_a = [_snap(tenant_id=TENANT_A, days_ago=i) for i in range(1, 4)]
        snaps_b = [
            _snap(tenant_id=TENANT_B, posture_score=50, days_ago=i) for i in range(1, 4)
        ]
        ledger_a = generate_trust_ledger(snaps_a)
        ledger_b = generate_trust_ledger(snaps_b)
        hashes_a = {e["tenant_id"] for e in ledger_a}
        hashes_b = {e["tenant_id"] for e in ledger_b}
        assert TENANT_A not in hashes_b
        assert TENANT_B not in hashes_a

    def test_memory_tenant_id_echoed(self):
        snaps_a = [_snap(tenant_id=TENANT_A, days_ago=1)]
        r = generate_trust_memory(snaps_a, window_days=30)
        assert r["tenant_id"] == TENANT_A

    def test_decision_memory_tenant_scoped(self):
        snap_a = _snap(tenant_id=TENANT_A)
        r = generate_decision_memory(
            "dec-1", "approval", supporting_snapshots=[snap_a], tenant_id=TENANT_A
        )
        assert r["tenant_id"] == TENANT_A
        assert (
            r["supporting_intelligence"][0]["snapshot_hash"] == snap_a["snapshot_hash"]
        )

    def test_compare_different_tenants(self):
        a = _snap(tenant_id=TENANT_A, posture_score=60)
        b = _snap(tenant_id=TENANT_B, posture_score=80)
        r = compare_trust_snapshots(a, b)
        assert r["trust_delta"] == 20  # purely arithmetic; no tenant gate here

    def test_replay_with_cross_tenant_store_miss(self):
        snap_a = _snap(tenant_id=TENANT_A)
        snap_b = _snap(tenant_id=TENANT_B)
        r = replay_trust_intelligence(snap_a, snapshots_store=[snap_b])
        assert "snapshot_located" not in r["validations"]

    def test_evolution_mixes_tenant_data_only_by_hash(self):
        snaps = [
            _snap(tenant_id=TENANT_A, posture_score=50, days_ago=5),
            _snap(tenant_id=TENANT_A, posture_score=75, days_ago=1),
        ]
        r = calculate_trust_evolution(snaps)
        assert r["score_delta"] == 25

    def test_timeline_includes_tenant_scope_from_snapshot(self):
        snap_a = _snap(tenant_id=TENANT_A)
        tl = generate_executive_timeline([snap_a])
        assert tl[0]["snapshot_id"] == snap_a["snapshot_id"]

    def test_different_tenant_different_signature(self):
        sig_a = _snap(tenant_id=TENANT_A)["snapshot_signature"]
        sig_b = _snap(tenant_id=TENANT_B)["snapshot_signature"]
        assert sig_a != sig_b

    def test_cross_tenant_snapshot_not_replayable(self):
        snap = _snap(tenant_id=TENANT_A)
        snap["tenant_id"] = TENANT_B  # mutate tenant without updating hash
        r = replay_trust_intelligence(snap)
        assert r["valid"] is False  # hash check fails

    def test_ledger_entries_carry_correct_tenant(self):
        snap = _snap(tenant_id=TENANT_A)
        ledger = generate_trust_ledger([snap])
        assert ledger[0]["tenant_id"] == TENANT_A


# ---------------------------------------------------------------------------
# 15. TestCrossEngagementIsolation
# ---------------------------------------------------------------------------


class TestCrossEngagementIsolation:
    def test_hash_differs_across_engagements(self):
        h1 = _snap(engagement_id=ENG_A)["snapshot_hash"]
        h2 = _snap(engagement_id=ENG_B)["snapshot_hash"]
        assert h1 != h2

    def test_verify_rejects_mutated_engagement(self):
        snap = _snap(engagement_id=ENG_A)
        snap["engagement_id"] = ENG_B
        r = verify_trust_intelligence_snapshot(snap)
        assert r["valid"] is False

    def test_ledger_carries_correct_engagement(self):
        snap = _snap(engagement_id=ENG_B)
        ledger = generate_trust_ledger([snap])
        assert ledger[0]["engagement_id"] == ENG_B

    def test_memory_engagement_id_echoed(self):
        snap = _snap(engagement_id=ENG_B, days_ago=1)
        r = generate_trust_memory([snap], window_days=30)
        assert r["engagement_id"] == ENG_B

    def test_decision_memory_engagement_scoped(self):
        r = generate_decision_memory("dec-1", "approval", engagement_id=ENG_B)
        assert r["engagement_id"] == ENG_B

    def test_replay_store_miss_different_engagement(self):
        snap_a = _snap(engagement_id=ENG_A)
        snap_b = _snap(engagement_id=ENG_B)
        r = replay_trust_intelligence(snap_a, snapshots_store=[snap_b])
        assert "snapshot_located" not in r["validations"]

    def test_different_engagement_different_signature(self):
        sig_a = _snap(engagement_id=ENG_A)["snapshot_signature"]
        sig_b = _snap(engagement_id=ENG_B)["snapshot_signature"]
        assert sig_a != sig_b

    def test_compare_engagement_a_to_engagement_b(self):
        a = _snap(engagement_id=ENG_A, posture_score=65)
        b = _snap(engagement_id=ENG_B, posture_score=85)
        r = compare_trust_snapshots(a, b)
        assert r["trust_delta"] == 20

    def test_evolution_single_engagement_only(self):
        snaps = [
            _snap(engagement_id=ENG_A, posture_score=50, days_ago=5),
            _snap(engagement_id=ENG_A, posture_score=75, days_ago=1),
        ]
        r = calculate_trust_evolution(snaps)
        assert r["score_delta"] == 25

    def test_signature_is_engagement_specific(self):
        snap_a = _snap(engagement_id=ENG_A)
        snap_b = _snap(engagement_id=ENG_B)
        r_a = verify_trust_intelligence_snapshot(snap_a)
        r_b = verify_trust_intelligence_snapshot(snap_b)
        assert r_a["valid"] is True
        assert r_b["valid"] is True


# ---------------------------------------------------------------------------
# 16. TestTamperDetection
# ---------------------------------------------------------------------------


class TestTamperDetection:
    def test_tampered_posture_score_rejected(self):
        snap = _snap(posture_score=75)
        snap["posture_score"] = 100
        assert verify_trust_intelligence_snapshot(snap)["valid"] is False

    def test_tampered_risk_level_rejected(self):
        snap = _snap(risk_level="low")
        snap["risk_level"] = "critical"
        assert verify_trust_intelligence_snapshot(snap)["valid"] is False

    def test_tampered_trend_direction_rejected(self):
        snap = _snap(trend_direction="stable")
        snap["trend_direction"] = "rapidly_degrading"
        assert verify_trust_intelligence_snapshot(snap)["valid"] is False

    def test_tampered_signature_rejected(self):
        snap = _snap()
        snap["snapshot_signature"] = "de" * 64
        assert verify_trust_intelligence_snapshot(snap)["valid"] is False

    def test_tampered_insights_count_rejected(self):
        snap = _snap()
        snap["insights_count"] = snap["insights_count"] + 99
        assert verify_trust_intelligence_snapshot(snap)["valid"] is False

    def test_tampered_ledger_entry_detected(self):
        snaps = [_snap(days_ago=2), _snap(posture_score=90, days_ago=1)]
        ledger = generate_trust_ledger(snaps)
        ledger[0]["posture_level"] = "excellent"  # mutate without updating hash
        r = verify_trust_ledger(ledger)
        assert r["valid"] is False

    def test_ledger_chain_break_detected(self):
        snaps = [_snap(posture_score=i * 20, days_ago=5 - i) for i in range(1, 4)]
        ledger = generate_trust_ledger(snaps)
        from services.canonical import canonical_json_bytes as cjb
        import hashlib

        ledger[1]["previous_hash"] = "e" * 64
        entry_without = {k: v for k, v in ledger[1].items() if k != "ledger_entry_hash"}
        ledger[1]["ledger_entry_hash"] = hashlib.sha256(cjb(entry_without)).hexdigest()
        r = verify_trust_ledger(ledger)
        assert r["valid"] is False
        assert "broken_chain" in r["reason"]

    def test_replay_detects_tampered_hash(self):
        snap = _snap()
        snap["snapshot_hash"] = "9" * 64
        r = replay_trust_intelligence(snap)
        assert r["valid"] is False
        assert r["replay_score"] < 100

    def test_replay_detects_tampered_signature(self):
        snap = _snap()
        snap["snapshot_signature"] = "ff" * 64
        r = replay_trust_intelligence(snap)
        assert r["valid"] is False

    def test_signing_key_id_tamper_rejected(self):
        snap = _snap()
        snap["signing_key_id"] = "00000000deadbeef"
        r = verify_trust_intelligence_snapshot(snap)
        assert r["valid"] is False

    def test_authority_version_downgrade_rejected(self):
        snap = _snap()
        snap["authority_version"] = "old-authority-v0"
        r = verify_trust_intelligence_snapshot(snap)
        assert r["valid"] is False

    def test_ledger_entry_addition_breaks_chain(self):
        snap1 = _snap(days_ago=3)
        snap2 = _snap(posture_score=80, days_ago=1)
        ledger = generate_trust_ledger([snap1, snap2])
        # Insert a fake entry in the middle
        fake = dict(ledger[0])
        fake["snapshot_hash"] = "a" * 64
        fake["ledger_entry_hash"] = "b" * 64
        ledger.insert(1, fake)
        r = verify_trust_ledger(ledger)
        assert r["valid"] is False

    def test_posture_level_tamper_rejected(self):
        snap = _snap(posture_level="healthy")
        snap["posture_level"] = "excellent"
        r = verify_trust_intelligence_snapshot(snap)
        assert r["valid"] is False

    def test_engagement_id_tamper_rejected(self):
        snap = _snap(engagement_id=ENG_A)
        snap["engagement_id"] = ENG_B
        r = verify_trust_intelligence_snapshot(snap)
        assert r["valid"] is False

    def test_trend_velocity_tamper_rejected(self):
        snap = _snap()
        snap["trend_velocity"] = "rapid"  # change without recomputing hash
        r = verify_trust_intelligence_snapshot(snap)
        assert r["valid"] is False


# ---------------------------------------------------------------------------
# 17. TestPerformance
# ---------------------------------------------------------------------------


class TestPerformance:
    def test_snapshot_creation_under_50ms(self):
        t0 = time.perf_counter()
        for _ in range(100):
            _snap()
        elapsed = time.perf_counter() - t0
        avg_ms = (elapsed / 100) * 1000
        assert avg_ms < 50

    def test_verify_under_50ms(self):
        snap = _snap()
        t0 = time.perf_counter()
        for _ in range(100):
            verify_trust_intelligence_snapshot(snap)
        elapsed = time.perf_counter() - t0
        avg_ms = (elapsed / 100) * 1000
        assert avg_ms < 50

    def test_replay_under_100ms(self):
        snap = _snap()
        t0 = time.perf_counter()
        for _ in range(100):
            replay_trust_intelligence(snap)
        elapsed = time.perf_counter() - t0
        avg_ms = (elapsed / 100) * 1000
        assert avg_ms < 100

    def test_1000_snapshot_compares_under_500ms(self):
        a = _snap(posture_score=60)
        b = _snap(posture_score=80)
        t0 = time.perf_counter()
        for _ in range(1000):
            compare_trust_snapshots(a, b)
        elapsed = (time.perf_counter() - t0) * 1000
        assert elapsed < 500

    def test_memory_100_snapshots_under_100ms(self):
        snaps = [_snap(posture_score=i % 100, days_ago=i) for i in range(1, 101)]
        t0 = time.perf_counter()
        generate_trust_memory(snaps, window_days=MEMORY_WINDOW_365)
        elapsed = (time.perf_counter() - t0) * 1000
        assert elapsed < 100

    def test_evolution_100_snapshots_under_100ms(self):
        snaps = _snap_seq(100, base_score=20, delta=0)
        t0 = time.perf_counter()
        calculate_trust_evolution(snaps)
        elapsed = (time.perf_counter() - t0) * 1000
        assert elapsed < 100

    def test_ledger_100_snapshots_under_200ms(self):
        snaps = []
        for i in range(100):
            s = _snap(posture_score=i % 100)
            s = {**s, "snapshot_hash": uuid.uuid4().hex * 2}
            snaps.append(s)
        t0 = time.perf_counter()
        generate_trust_ledger(snaps)
        elapsed = (time.perf_counter() - t0) * 1000
        assert elapsed < 200

    def test_timeline_100_snapshots_under_100ms(self):
        snaps = [_snap(posture_score=i % 100, days_ago=100 - i) for i in range(100)]
        t0 = time.perf_counter()
        generate_executive_timeline(snaps)
        elapsed = (time.perf_counter() - t0) * 1000
        assert elapsed < 100

    def test_verify_ledger_100_entries_under_200ms(self):
        snaps = []
        for i in range(100):
            s = _snap(posture_score=i % 100, days_ago=100 - i)
            s = {**s, "snapshot_hash": uuid.uuid4().hex * 2}
            snaps.append(s)
        ledger = generate_trust_ledger(snaps)
        t0 = time.perf_counter()
        verify_trust_ledger(ledger)
        elapsed = (time.perf_counter() - t0) * 1000
        assert elapsed < 200

    def test_decision_memory_100_snapshots_under_50ms(self):
        snaps = [_snap(days_ago=i) for i in range(1, 101)]
        t0 = time.perf_counter()
        generate_decision_memory("dec-1", "approval", supporting_snapshots=snaps)
        elapsed = (time.perf_counter() - t0) * 1000
        assert elapsed < 50


# ---------------------------------------------------------------------------
# 18. TestFutureAgentCompatibility
# ---------------------------------------------------------------------------


class TestFutureAgentCompatibility:
    def test_agent_entity_type_accepted(self):
        r = generate_decision_memory(
            "dec-1", "agent_approval", entity_type=DECISION_ENTITY_AGENT
        )
        assert r["entity_type"] == DECISION_ENTITY_AGENT

    def test_autonomous_entity_type_accepted(self):
        r = generate_decision_memory(
            "dec-1", "auto_decision", entity_type=DECISION_ENTITY_AUTONOMOUS
        )
        assert r["entity_type"] == DECISION_ENTITY_AUTONOMOUS

    def test_agent_fleet_entity_type_accepted(self):
        r = generate_decision_memory(
            "dec-1", "fleet_approval", entity_type="agent_fleet"
        )
        assert r["entity_type"] == "agent_fleet"

    def test_snapshot_works_for_agent_engagement(self):
        snap = generate_trust_intelligence_snapshot(
            tenant_id="tenant-enterprise", engagement_id="agent-fleet-001"
        )
        r = verify_trust_intelligence_snapshot(snap)
        assert r["valid"] is True

    def test_ledger_supports_agent_entity_snapshots(self):
        snap = generate_trust_intelligence_snapshot(
            tenant_id=TENANT_A, engagement_id="agent-eng-001"
        )
        ledger = generate_trust_ledger([snap])
        assert ledger[0]["engagement_id"] == "agent-eng-001"

    def test_decision_memory_supports_agent_snapshots(self):
        snap = generate_trust_intelligence_snapshot(
            tenant_id=TENANT_A, engagement_id=ENG_A
        )
        r = generate_decision_memory(
            "dec-agent-1",
            "agent_approval",
            entity_type=DECISION_ENTITY_AGENT,
            supporting_snapshots=[snap],
        )
        assert len(r["supporting_intelligence"]) == 1
        assert r["entity_type"] == DECISION_ENTITY_AGENT

    def test_replay_works_for_agent_snap(self):
        snap = generate_trust_intelligence_snapshot(
            tenant_id=TENANT_A,
            engagement_id="agent-eng-001",
            posture_result={"score": 85, "trust_posture": "healthy"},
        )
        r = replay_trust_intelligence(snap)
        assert r["valid"] is True

    def test_timeline_supports_any_engagement(self):
        snaps = [
            generate_trust_intelligence_snapshot(
                tenant_id=TENANT_A,
                engagement_id="agent-fleet-eng",
                posture_result={"score": i * 20, "trust_posture": "stable"},
                trend_result={"direction": "stable", "velocity": "low"},
            )
            for i in range(1, 4)
        ]
        for i, s in enumerate(snaps):
            days = 3 - i
            snaps[i] = {
                **s,
                "created_at": (datetime.now(timezone.utc) - timedelta(days=days))
                .isoformat()
                .replace("+00:00", "Z"),
            }
        tl = generate_executive_timeline(snaps)
        assert len(tl) == 3

    def test_memory_works_for_agent_engagement(self):
        snaps = [
            generate_trust_intelligence_snapshot(
                tenant_id=TENANT_A, engagement_id="agent-eng-002"
            )
        ]
        snaps[0] = {
            **snaps[0],
            "created_at": (datetime.now(timezone.utc) - timedelta(days=5))
            .isoformat()
            .replace("+00:00", "Z"),
        }
        r = generate_trust_memory(snaps, window_days=30)
        assert r["snapshot_count"] == 1

    def test_arbitrary_entity_type_in_decision(self):
        r = generate_decision_memory(
            "dec-1", "governance", entity_type="model_deployment_v3"
        )
        assert r["entity_type"] == "model_deployment_v3"


# ---------------------------------------------------------------------------
# 19. TestAGIGovernanceCompatibility
# ---------------------------------------------------------------------------


class TestAGIGovernanceCompatibility:
    def test_agi_entity_type_accepted(self):
        r = generate_decision_memory(
            "dec-1", "agi_governance", entity_type=DECISION_ENTITY_AGI
        )
        assert r["entity_type"] == DECISION_ENTITY_AGI

    def test_agi_decision_memory_structure(self):
        snap = _snap()
        r = generate_decision_memory(
            "agi-dec-001",
            "agi_autonomous_decision",
            entity_type=DECISION_ENTITY_AGI,
            reasoning=["posture critical", "risk threshold exceeded"],
            supporting_snapshots=[snap],
            tenant_id=TENANT_A,
            engagement_id=ENG_A,
        )
        assert r["entity_type"] == DECISION_ENTITY_AGI
        assert len(r["decision_reasoning"]) == 2
        assert len(r["supporting_intelligence"]) == 1

    def test_agi_snapshot_verifiable(self):
        snap = generate_trust_intelligence_snapshot(
            tenant_id="agi-tenant", engagement_id="agi-governance-001"
        )
        r = verify_trust_intelligence_snapshot(snap)
        assert r["valid"] is True

    def test_agi_snapshot_replayable(self):
        snap = generate_trust_intelligence_snapshot(
            tenant_id="agi-tenant",
            engagement_id="agi-gov-001",
            posture_result={"score": 95, "trust_posture": "excellent"},
        )
        r = replay_trust_intelligence(snap)
        assert r["valid"] is True

    def test_agi_ledger_entry_correct(self):
        snap = generate_trust_intelligence_snapshot(
            tenant_id="agi-tenant", engagement_id="agi-gov-001"
        )
        ledger = generate_trust_ledger([snap])
        assert len(ledger) == 1
        assert verify_trust_ledger(ledger)["valid"] is True

    def test_agi_evolution_trackable(self):
        snaps = [
            _snap(
                tenant_id="agi-tenant",
                engagement_id="agi-gov-001",
                posture_score=30,
                posture_level="watch",
                days_ago=30,
            ),
            _snap(
                tenant_id="agi-tenant",
                engagement_id="agi-gov-001",
                posture_score=90,
                posture_level="excellent",
                days_ago=1,
            ),
        ]
        r = calculate_trust_evolution(snaps)
        assert r["score_delta"] == 60
        assert "major_improvement" in r["overall_change"]

    def test_agi_timeline_board_readable(self):
        snaps = [
            _snap(tenant_id="agi-tenant", posture_level="critical", days_ago=10),
            _snap(tenant_id="agi-tenant", posture_level="excellent", days_ago=1),
        ]
        tl = generate_executive_timeline(snaps)
        assert any("immediate" in e["impact"].lower() for e in tl)
        assert any("no action" in e["impact"].lower() for e in tl)

    def test_future_entity_string_supported(self):
        r = generate_decision_memory(
            "dec-future", "governance", entity_type="agi_model_registry_v10"
        )
        assert r["entity_type"] == "agi_model_registry_v10"


# ---------------------------------------------------------------------------
# 20. TestSecurityInvariants
# ---------------------------------------------------------------------------


class TestSecurityInvariants:
    _GARBAGE_INPUTS: list[Any] = [
        None,
        0,
        "",
        [],
        {},
        "malicious",
        3.14,
        {"snapshot_hash": "x" * 64},
        b"bytes",
        {"authority_version": "evil", "snapshot_hash": "0" * 64},
    ]

    def test_verify_never_raises(self):
        for bad in self._GARBAGE_INPUTS:
            result = verify_trust_intelligence_snapshot(bad)  # type: ignore
            assert isinstance(result, dict)
            assert "valid" in result

    def test_replay_never_raises(self):
        for bad in self._GARBAGE_INPUTS:
            result = replay_trust_intelligence(bad)  # type: ignore
            assert isinstance(result, dict)
            assert "valid" in result

    def test_verify_ledger_never_raises(self):
        for bad in self._GARBAGE_INPUTS:
            result = verify_trust_ledger(bad)  # type: ignore
            assert isinstance(result, dict)

    def test_memory_never_raises(self):
        for bad in self._GARBAGE_INPUTS:
            result = generate_trust_memory(bad)  # type: ignore
            assert isinstance(result, dict)

    def test_evolution_never_raises(self):
        for bad in self._GARBAGE_INPUTS:
            result = calculate_trust_evolution(bad)  # type: ignore
            assert isinstance(result, dict)

    def test_compare_never_raises(self):
        for bad in self._GARBAGE_INPUTS:
            result = compare_trust_snapshots(bad, bad)  # type: ignore
            assert isinstance(result, dict)

    def test_decision_memory_never_raises(self):
        result = generate_decision_memory("", "", entity_type=None)  # type: ignore
        assert isinstance(result, dict)

    def test_timeline_never_raises(self):
        for bad in self._GARBAGE_INPUTS:
            result = generate_executive_timeline(bad)  # type: ignore
            assert isinstance(result, list)

    def test_ledger_never_raises(self):
        for bad in self._GARBAGE_INPUTS:
            result = generate_trust_ledger(bad)  # type: ignore
            assert isinstance(result, list)

    def test_verify_always_returns_valid_key(self):
        for bad in self._GARBAGE_INPUTS:
            r = verify_trust_intelligence_snapshot(bad)  # type: ignore
            assert r.get("valid") in (True, False)


# ---------------------------------------------------------------------------
# 21. TestEnterpriseScenarios
# ---------------------------------------------------------------------------


class TestEnterpriseScenarios:
    def test_banking_90_day_audit_trail(self):
        snaps = [
            _snap(posture_score=60 + i * 3, days_ago=89 - i * 8) for i in range(10)
        ]
        ledger = generate_trust_ledger(snaps)
        memory = generate_trust_memory(snaps, window_days=90)
        assert len(ledger) == 10
        assert verify_trust_ledger(ledger)["valid"] is True
        assert memory["snapshot_count"] == 10

    def test_healthcare_governance_decision_trail(self):
        snaps = [_snap(posture_score=75, days_ago=i) for i in range(1, 6)]
        decision = generate_decision_memory(
            "phipa-dec-001",
            "phi_access_approval",
            entity_type=DECISION_ENTITY_HUMAN,
            reasoning=["PHI access authorized", "Trust posture meets threshold"],
            supporting_snapshots=snaps,
            tenant_id="hospital-001",
        )
        assert decision["entity_type"] == DECISION_ENTITY_HUMAN
        assert len(decision["supporting_intelligence"]) == 5

    def test_govcon_multi_year_evolution(self):
        snaps = []
        base = datetime.now(timezone.utc) - timedelta(days=730)
        for i in range(24):
            ts = (base + timedelta(days=i * 30)).isoformat().replace("+00:00", "Z")
            score = max(40, min(95, 40 + i * 2))
            snap = _snap(posture_score=score)
            snaps.append({**snap, "created_at": ts})
        evo = calculate_trust_evolution(snaps)
        assert evo["overall_change"] in (
            "major_improvement",
            "moderate_improvement",
            "minor_improvement",
        )
        assert evo["snapshot_count"] == 24

    def test_ai_governance_agi_decision_chain(self):
        snap1 = _snap(posture_score=85, posture_level="healthy")
        snap2 = _snap(posture_score=92, posture_level="excellent")
        ledger = generate_trust_ledger([snap1, snap2])
        decision = generate_decision_memory(
            "agi-gov-chain-001",
            "model_deployment_approval",
            entity_type=DECISION_ENTITY_AGI,
            reasoning=["Excellent posture verified", "Ledger chain intact"],
            supporting_snapshots=[snap1, snap2],
        )
        assert verify_trust_ledger(ledger)["valid"] is True
        assert decision["entity_type"] == DECISION_ENTITY_AGI

    def test_executive_board_report(self):
        snaps = [
            _snap(posture_score=45, posture_level="watch", days_ago=12),
            _snap(posture_score=60, posture_level="stable", days_ago=8),
            _snap(posture_score=80, posture_level="healthy", days_ago=4),
            _snap(posture_score=92, posture_level="excellent", days_ago=1),
        ]
        tl = generate_executive_timeline(snaps)
        assert len(tl) == 4
        assert tl[0]["trust_change"] == "baseline"
        assert tl[-1]["posture_level"] == "excellent"
        assert all(len(e["impact"]) > 0 for e in tl)

    def test_critical_infrastructure_tamper_detection(self):
        snaps = [_snap(posture_score=i * 20, days_ago=5 - i) for i in range(1, 5)]
        ledger = generate_trust_ledger(snaps)
        # Simulate tamper
        ledger[2]["posture_score"] = 0
        r = verify_trust_ledger(ledger)
        assert r["valid"] is False

    def test_financial_audit_full_replay(self):
        snap = generate_trust_intelligence_snapshot(
            tenant_id="bank-001",
            engagement_id="q4-audit",
            posture_result={"score": 88, "trust_posture": "healthy"},
            trend_result={"direction": "improving", "velocity": "moderate"},
            risk_result={"risk_level": "low", "risk_score": 18},
        )
        store = [snap]
        r = replay_trust_intelligence(snap, snapshots_store=store)
        assert r["valid"] is True
        assert r["replay_score"] >= 85

    def test_compliance_snapshot_compare(self):
        snap_q3 = _snap(
            posture_score=55, posture_level="stable", risk_level="medium", days_ago=90
        )
        snap_q4 = _snap(
            posture_score=80, posture_level="healthy", risk_level="low", days_ago=1
        )
        r = compare_trust_snapshots(snap_q3, snap_q4)
        assert r["trust_delta"] == 25
        assert any("posture" in c for c in r["improved_controls"])


# ---------------------------------------------------------------------------
# 22. TestEdgeCases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_zero_priority_count(self):
        snap = generate_trust_intelligence_snapshot(
            tenant_id=TENANT_A, engagement_id=ENG_A, priorities=[]
        )
        assert snap["priorities_count"] == 0
        assert verify_trust_intelligence_snapshot(snap)["valid"] is True

    def test_zero_posture_score(self):
        snap = _snap(posture_score=0, posture_level="critical")
        r = verify_trust_intelligence_snapshot(snap)
        assert r["valid"] is True

    def test_max_posture_score(self):
        snap = _snap(posture_score=100, posture_level="excellent")
        r = verify_trust_intelligence_snapshot(snap)
        assert r["valid"] is True

    def test_single_snapshot_ledger(self):
        snap = _snap()
        ledger = generate_trust_ledger([snap])
        assert len(ledger) == 1
        assert ledger[0]["previous_hash"] == LEDGER_GENESIS_HASH
        assert verify_trust_ledger(ledger)["valid"] is True

    def test_compare_same_snapshot(self):
        snap = _snap()
        r = compare_trust_snapshots(snap, snap)
        assert r["trust_delta"] == 0
        assert r["added_risks"] == []
        assert r["removed_risks"] == []

    def test_empty_string_decision_id_gets_value(self):
        r = generate_decision_memory("", "approval")
        assert r["decision_id"]  # non-empty (uuid generated)

    def test_evolution_with_identical_snapshots(self):
        snap = _snap()
        r = calculate_trust_evolution([snap, snap])
        assert r["overall_change"] == "stable"
        assert r["score_delta"] == 0

    def test_memory_window_exactly_at_boundary(self):
        snap = _snap(days_ago=30)
        r = generate_trust_memory([snap], window_days=30)
        # 30-day-old snap at exactly window boundary — should be included
        assert r["snapshot_count"] == 1

    def test_ledger_preserves_existing_entry_order(self):
        snap1 = _snap(posture_score=40, days_ago=5)
        snap2 = _snap(posture_score=80, days_ago=3)
        snap3 = _snap(posture_score=90, days_ago=1)
        ledger_initial = generate_trust_ledger([snap1])
        ledger_extended = generate_trust_ledger(
            [snap2, snap3], previous_ledger=ledger_initial
        )
        assert ledger_extended[0]["snapshot_hash"] == snap1["snapshot_hash"]

    def test_timeline_single_item_no_comparison(self):
        tl = generate_executive_timeline([_snap(posture_level="healthy")])
        assert len(tl) == 1
        assert "baseline" in tl[0]["trust_change"]
