"""Tests for PR 18.4 — Governance Orchestration change detection."""

from __future__ import annotations

import pytest
from sqlalchemy.orm import Session

from api.db import get_engine
from services.governance_orchestration.change_detection import (
    assess_change_significance,
    classify_change,
    detect_changes,
    record_change_event,
)
from services.governance_orchestration.engine import (
    GovernanceOrchestrationEngine,
)
from services.governance_orchestration.impact_analysis import (
    analyze_impact,
    compute_governance_score_delta,
    estimate_control_effectiveness_delta,
    estimate_risk_reduction,
)
from services.governance_orchestration.models import ChangeType
from services.governance_orchestration.schemas import (
    CreateChangeDetectionRequest,
)


_TENANT = "tenant-go-ch-001"


@pytest.fixture()
def db(build_app):
    build_app(auth_enabled=False)
    engine = get_engine()
    with Session(engine) as session:
        yield session


@pytest.fixture()
def svc(db):
    return GovernanceOrchestrationEngine(db, tenant_id=_TENANT)


# ---------------------------------------------------------------------------
# detect_changes
# ---------------------------------------------------------------------------


def test_CH_1_detect_empty_context(db):
    assert detect_changes(db, _TENANT, {}) == []


def test_CH_2_detect_evidence_change(db):
    changes = detect_changes(db, _TENANT, {"evidence_delta": {"a": 1}})
    assert any(c["change_type"] == "EVIDENCE_CHANGE" for c in changes)


def test_CH_3_detect_control_change(db):
    changes = detect_changes(db, _TENANT, {"control_delta": {"a": 1}})
    assert any(c["change_type"] == "CONTROL_CHANGE" for c in changes)


def test_CH_4_detect_risk_change(db):
    changes = detect_changes(db, _TENANT, {"risk_delta": {"a": 1}})
    assert any(c["change_type"] == "RISK_CHANGE" for c in changes)


def test_CH_5_detect_policy_change(db):
    changes = detect_changes(db, _TENANT, {"policy_delta": {"a": 1}})
    assert any(c["change_type"] == "POLICY_CHANGE" for c in changes)


def test_CH_6_detect_framework_change(db):
    changes = detect_changes(db, _TENANT, {"framework_delta": {"a": 1}})
    assert any(c["change_type"] == "FRAMEWORK_CHANGE" for c in changes)


def test_CH_7_detect_trust_change(db):
    changes = detect_changes(db, _TENANT, {"trust_delta": {"a": 1}})
    assert any(c["change_type"] == "TRUST_CHANGE" for c in changes)


def test_CH_8_detect_multi(db):
    changes = detect_changes(
        db,
        _TENANT,
        {"evidence_delta": {"a": 1}, "risk_delta": {"a": 1}},
    )
    assert len(changes) == 2


def test_CH_9_detect_returns_impact_level(db):
    changes = detect_changes(db, _TENANT, {"evidence_delta": {"severity_delta": 50}})
    assert "impact_level" in changes[0]


def test_CH_10_detect_context_none_safe(db):
    assert detect_changes(db, _TENANT, None) == []


# ---------------------------------------------------------------------------
# classify_change
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [m.value for m in ChangeType],
)
def test_CH_11_classify_valid(value):
    assert classify_change({"change_type": value}) == value


def test_CH_12_classify_unknown_defaults_policy():
    assert classify_change({"change_type": "UNKNOWN"}) == "POLICY_CHANGE"


def test_CH_13_classify_missing_key_defaults_policy():
    assert classify_change({}) == "POLICY_CHANGE"


def test_CH_14_classify_non_dict_defaults_policy():
    assert classify_change("nope") == "POLICY_CHANGE"  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# assess_change_significance
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "delta,expected",
    [
        (0, "NONE"),
        (5, "LOW"),
        (15, "MEDIUM"),
        (30, "HIGH"),
        (50, "CRITICAL"),
    ],
)
def test_CH_15_significance_ranges(delta, expected):
    result = assess_change_significance({"change_data": {"delta": delta}})
    assert result == expected


def test_CH_16_significance_severity_delta_key():
    result = assess_change_significance({"change_data": {"severity_delta": 60}})
    assert result == "CRITICAL"


def test_CH_17_significance_no_data():
    assert assess_change_significance({}) == "NONE"


def test_CH_18_significance_non_dict():
    assert assess_change_significance("x") == "LOW"


def test_CH_19_significance_non_numeric():
    result = assess_change_significance({"change_data": {"delta": "not a number"}})
    assert result == "NONE"


# ---------------------------------------------------------------------------
# record_change_event
# ---------------------------------------------------------------------------


def test_CH_20_record_change(db):
    result = record_change_event(
        db, _TENANT, {"change_type": "EVIDENCE_CHANGE", "change_data": {"delta": 5}}
    )
    db.commit()
    assert result["change_type"] == "EVIDENCE_CHANGE"
    assert result["impact_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL", "NONE")


def test_CH_21_record_change_persists_id(db):
    result = record_change_event(db, _TENANT, {"change_type": "CONTROL_CHANGE"})
    db.commit()
    assert len(result["id"]) >= 32


# ---------------------------------------------------------------------------
# Engine wrappers
# ---------------------------------------------------------------------------


def test_CH_22_engine_create_change_detection(svc):
    r = svc.create_change_detection(
        CreateChangeDetectionRequest(change_type="EVIDENCE_CHANGE"),
        actor_id="x",
    )
    assert r.change_type == "EVIDENCE_CHANGE"


def test_CH_23_engine_list(svc):
    svc.create_change_detection(
        CreateChangeDetectionRequest(change_type="EVIDENCE_CHANGE"),
        actor_id="x",
    )
    resp = svc.list_change_detections()
    assert resp.total >= 1


def test_CH_24_engine_list_filter(svc):
    svc.create_change_detection(
        CreateChangeDetectionRequest(change_type="EVIDENCE_CHANGE"),
        actor_id="x",
    )
    svc.create_change_detection(
        CreateChangeDetectionRequest(change_type="CONTROL_CHANGE"),
        actor_id="x",
    )
    resp = svc.list_change_detections(change_type="EVIDENCE_CHANGE")
    for c in resp.items:
        assert c.change_type == "EVIDENCE_CHANGE"


def test_CH_25_engine_change_timeline(svc):
    r = svc.create_change_detection(
        CreateChangeDetectionRequest(change_type="EVIDENCE_CHANGE"),
        actor_id="x",
    )
    tl = svc.get_timeline(entity_type="change_detection", entity_id=r.id)
    assert any(e.event_type == "change_recorded" for e in tl.events)


# ---------------------------------------------------------------------------
# Impact analysis
# ---------------------------------------------------------------------------


def test_CH_26_analyze_impact_shape(db):
    result = analyze_impact(db, _TENANT, "EVIDENCE_CHANGE", {})
    for key in (
        "tenant_id",
        "change_type",
        "impact_level",
        "governance_score_delta",
        "control_effectiveness_delta",
        "risk_reduction",
        "affected_controls",
        "affected_evidence",
        "recommendations",
    ):
        assert key in result


def test_CH_27_analyze_impact_recommendations_list(db):
    result = analyze_impact(db, _TENANT, "RISK_CHANGE", {})
    assert isinstance(result["recommendations"], list)


def test_CH_28_score_delta_zero_by_default():
    assert compute_governance_score_delta({"score": 80}, {"score": 80}) == 0.0


def test_CH_29_score_delta_positive():
    result = compute_governance_score_delta({"score": 70}, {"score": 90})
    assert result == 20.0


def test_CH_30_control_delta_default_zero():
    assert estimate_control_effectiveness_delta({}) == 0.0


def test_CH_31_control_delta_from_change_data():
    assert estimate_control_effectiveness_delta({"control_delta": 12.5}) == 12.5


def test_CH_32_risk_reduction_default_zero():
    assert estimate_risk_reduction({}) == 0.0


def test_CH_33_risk_reduction_from_change_data():
    assert estimate_risk_reduction({"risk_reduction": 3.14}) == 3.14


def test_CH_34_analyze_impact_deterministic(db):
    a = analyze_impact(db, _TENANT, "EVIDENCE_CHANGE", {"magnitude": 1.0})
    b = analyze_impact(db, _TENANT, "EVIDENCE_CHANGE", {"magnitude": 1.0})
    assert a == b


def test_CH_35_analyze_high_magnitude_high_impact(db):
    result = analyze_impact(db, _TENANT, "RISK_CHANGE", {"magnitude": 3.0})
    assert result["impact_level"] in {"CRITICAL", "HIGH", "MEDIUM"}


def test_CH_36_analyze_control_change_recommends_control_effectiveness(db):
    result = analyze_impact(db, _TENANT, "CONTROL_CHANGE", {"magnitude": 1.0})
    assert "Recompute control effectiveness" in result["recommendations"]
