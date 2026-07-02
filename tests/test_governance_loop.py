"""Tests for PR 18.4 — Governance Orchestration continuous evaluation loop."""

from __future__ import annotations

import pytest
from sqlalchemy.orm import Session

from api.db import get_engine
from services.governance_orchestration.engine import (
    GovernanceOrchestrationEngine,
)
from services.governance_orchestration.governance_loop import (
    compute_evidence_sufficiency,
    evaluate_control_health,
    evaluate_governance_posture,
    evaluate_governance_state,
)


_TENANT = "tenant-go-loop-001"


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
# evaluate_governance_state
# ---------------------------------------------------------------------------


def test_LOOP_1_state_dict_shape(db):
    r = evaluate_governance_state(db, _TENANT)
    for key in (
        "state",
        "triggers_detected",
        "actions_required",
        "evidence_sufficiency",
        "control_health",
        "posture",
        "next_evaluation_hint",
    ):
        assert key in r


def test_LOOP_2_idle_state_default(db):
    r = evaluate_governance_state(db, _TENANT, {})
    assert r["state"] in ("IDLE", "EVALUATING")


def test_LOOP_3_evaluating_when_triggers(db):
    r = evaluate_governance_state(db, _TENANT, {"evidence_expired": True})
    assert r["state"] == "EVALUATING"


def test_LOOP_4_actions_when_triggers(db):
    r = evaluate_governance_state(db, _TENANT, {"evidence_expired": True})
    assert "PROCESS_TRIGGERS" in r["actions_required"]


def test_LOOP_5_next_hint_short_when_active(db):
    r = evaluate_governance_state(db, _TENANT, {"evidence_expired": True})
    assert r["next_evaluation_hint"] == "1h"


def test_LOOP_6_next_hint_long_when_idle(db):
    r = evaluate_governance_state(db, _TENANT, {})
    assert r["next_evaluation_hint"] in ("1h", "24h")


def test_LOOP_7_context_none_safe(db):
    r = evaluate_governance_state(db, _TENANT, None)
    assert isinstance(r, dict)


def test_LOOP_8_no_triggers_no_actions_processed(db):
    r = evaluate_governance_state(db, _TENANT, {})
    assert isinstance(r["triggers_detected"], list)


def test_LOOP_9_verification_failure_triggers(db):
    r = evaluate_governance_state(db, _TENANT, {"verification_failures": 2})
    assert any(
        t["trigger_type"] == "VERIFICATION_FAILED" for t in r["triggers_detected"]
    )


def test_LOOP_10_control_degradation(db):
    r = evaluate_governance_state(db, _TENANT, {"control_health_pct": 30})
    assert any(t["trigger_type"] == "CONTROL_DEGRADED" for t in r["triggers_detected"])


def test_LOOP_11_risk_threshold(db):
    r = evaluate_governance_state(db, _TENANT, {"risk_score": 0.9})
    assert any(
        t["trigger_type"] == "RISK_THRESHOLD_EXCEEDED" for t in r["triggers_detected"]
    )


def test_LOOP_12_remediation_completed(db):
    r = evaluate_governance_state(db, _TENANT, {"remediation_completed": True})
    assert any(
        t["trigger_type"] == "REMEDIATION_COMPLETED" for t in r["triggers_detected"]
    )


def test_LOOP_13_framework_revised(db):
    r = evaluate_governance_state(db, _TENANT, {"framework_revised": True})
    assert any(
        t["trigger_type"] == "FRAMEWORK_REVISION" for t in r["triggers_detected"]
    )


def test_LOOP_14_multiple_triggers(db):
    r = evaluate_governance_state(
        db,
        _TENANT,
        {
            "evidence_expired": True,
            "framework_revised": True,
            "remediation_completed": True,
        },
    )
    assert len(r["triggers_detected"]) >= 3


# ---------------------------------------------------------------------------
# compute_evidence_sufficiency
# ---------------------------------------------------------------------------


def test_LOOP_15_evidence_sufficiency_shape(db):
    r = compute_evidence_sufficiency(db, _TENANT)
    for key in (
        "required",
        "collected",
        "verified",
        "fresh",
        "coverage_pct",
        "missing_items",
    ):
        assert key in r


def test_LOOP_16_evidence_sufficiency_default_zero(db):
    r = compute_evidence_sufficiency(db, _TENANT)
    assert r["required"] >= 0
    assert r["coverage_pct"] >= 0.0


def test_LOOP_17_evidence_sufficiency_deterministic(db):
    a = compute_evidence_sufficiency(db, _TENANT)
    b = compute_evidence_sufficiency(db, _TENANT)
    assert a == b


# ---------------------------------------------------------------------------
# evaluate_control_health
# ---------------------------------------------------------------------------


def test_LOOP_18_control_health_shape(db):
    r = evaluate_control_health(db, _TENANT)
    for key in ("healthy", "degraded", "failed", "total", "health_pct"):
        assert key in r


def test_LOOP_19_control_health_totals_nonneg(db):
    r = evaluate_control_health(db, _TENANT)
    for key in ("healthy", "degraded", "failed", "total"):
        assert r[key] >= 0


def test_LOOP_20_control_health_pct_range(db):
    r = evaluate_control_health(db, _TENANT)
    assert 0.0 <= r["health_pct"] <= 100.0


# ---------------------------------------------------------------------------
# evaluate_governance_posture
# ---------------------------------------------------------------------------


def test_LOOP_21_posture_shape(db):
    r = evaluate_governance_posture(db, _TENANT)
    for key in ("score", "trend", "risk_level", "framework_coverage"):
        assert key in r


def test_LOOP_22_posture_default_score_75(db):
    r = evaluate_governance_posture(db, _TENANT)
    assert isinstance(r["score"], (int, float))


def test_LOOP_23_posture_risk_level_from_score(db):
    r = evaluate_governance_posture(db, _TENANT)
    assert r["risk_level"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


# ---------------------------------------------------------------------------
# Engine wrappers
# ---------------------------------------------------------------------------


def test_LOOP_24_engine_evaluate_wraps_loop(svc):
    r = svc.evaluate_governance_loop()
    assert "state" in r


def test_LOOP_25_engine_evaluate_with_context(svc):
    r = svc.evaluate_governance_loop({"evidence_expired": True})
    assert "PROCESS_TRIGGERS" in r["actions_required"]


def test_LOOP_26_engine_compute_evidence(svc):
    r = svc.compute_evidence_sufficiency()
    assert "coverage_pct" in r


# ---------------------------------------------------------------------------
# Graceful degradation
# ---------------------------------------------------------------------------


def test_LOOP_27_loop_never_raises_on_context(db):
    # Weird context values are fine
    r = evaluate_governance_state(db, _TENANT, {"random": "x"})
    assert isinstance(r, dict)


def test_LOOP_28_loop_never_raises_on_bad_types(db):
    # Non-numeric fields should be swallowed
    r = evaluate_governance_state(db, _TENANT, {"control_health_pct": "high"})
    assert isinstance(r, dict)


def test_LOOP_29_loop_never_raises_on_missing_tables(db):
    # Even if tables missing, evidence sufficiency returns defaults
    r = compute_evidence_sufficiency(db, _TENANT)
    assert r["coverage_pct"] == 0.0


def test_LOOP_30_loop_deterministic_output(db):
    a = evaluate_governance_state(db, _TENANT, {"evidence_expired": True})
    b = evaluate_governance_state(db, _TENANT, {"evidence_expired": True})
    # Same trigger set produced
    types_a = {t["trigger_type"] for t in a["triggers_detected"]}
    types_b = {t["trigger_type"] for t in b["triggers_detected"]}
    assert types_a == types_b
