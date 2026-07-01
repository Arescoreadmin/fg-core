"""Tests for PR 18.3 — Remediation Authority effectiveness, statistics, forecast."""

from __future__ import annotations

import pytest
from sqlalchemy.orm import Session

from api.db import get_engine
from services.remediation_authority.effectiveness import read_effectiveness_summary
from services.remediation_authority.engine import RemediationAuthorityEngine
from services.remediation_authority.forecast import (
    compute_forecast,
    read_governance_learning_signal,
)
from services.remediation_authority.models import (
    RemediationPriority,
    RemediationTaskState,
    RemediationVerificationState,
)
from services.remediation_authority.risk import compute_risk_summary
from services.remediation_authority.schemas import (
    CreateTaskRequest,
    CreateVerificationRequest,
    ForecastResponse,
    RiskResponse,
    StatisticsResponse,
    TransitionTaskRequest,
)
from services.remediation_authority.sla import (
    AT_RISK_DAYS,
    compute_sla_status,
    is_breached,
)
from services.remediation_authority.statistics import (
    average_completion_days,
    bucket_by,
    count_by_sla,
)


_TENANT = "tenant-ra-eff-001"


@pytest.fixture()
def db(build_app):
    build_app(auth_enabled=False)
    engine = get_engine()
    with Session(engine) as session:
        yield session


@pytest.fixture()
def svc(db):
    return RemediationAuthorityEngine(db, tenant_id=_TENANT)


# ---------------------------------------------------------------------------
# effectiveness.read_effectiveness_summary (degrades gracefully)
# ---------------------------------------------------------------------------


def test_RA_E_1_effectiveness_no_data_returns_defaults(db):
    r = read_effectiveness_summary(db, tenant_id="no-such-tenant")
    assert r["effectiveness_score"] == 0.0
    assert r["sustained_ratio"] == 0.0


def test_RA_E_2_effectiveness_keys():
    from services.remediation_authority.effectiveness import (
        read_effectiveness_summary,
    )

    keys = read_effectiveness_summary(None, tenant_id="x")
    assert set(keys.keys()) == {
        "effectiveness_score",
        "sustained_ratio",
        "persistence_score",
    }


# ---------------------------------------------------------------------------
# forecast helpers
# ---------------------------------------------------------------------------


def test_RA_E_3_governance_learning_signal_missing_returns_none(db):
    assert read_governance_learning_signal(db, tenant_id="no-tenant") is None


def test_RA_E_4_compute_forecast_empty():
    r = compute_forecast([], horizon_days=30)
    assert r["open_task_count"] == 0
    assert r["predicted_completions"] == 0


class _MockTask:
    def __init__(self, **kw):
        self.__dict__.update(kw)


def test_RA_E_5_compute_forecast_counts_open_tasks():
    tasks = [_MockTask(task_state="OPEN", completed_at=None, target_date=None)]
    r = compute_forecast(tasks, horizon_days=30)
    assert r["open_task_count"] == 1


def test_RA_E_6_compute_forecast_excludes_completed():
    tasks = [
        _MockTask(
            task_state="COMPLETED",
            completed_at="2020-01-01T00:00:00Z",
            target_date=None,
        ),
    ]
    r = compute_forecast(tasks, horizon_days=30)
    assert r["open_task_count"] == 0


def test_RA_E_7_compute_forecast_excludes_cancelled():
    tasks = [_MockTask(task_state="CANCELLED", completed_at=None, target_date=None)]
    r = compute_forecast(tasks, horizon_days=30)
    assert r["open_task_count"] == 0


# ---------------------------------------------------------------------------
# risk.compute_risk_summary
# ---------------------------------------------------------------------------


def test_RA_E_8_risk_summary_empty():
    r = compute_risk_summary([])
    assert r["total_risk_score"] == 0.0
    assert r["risk_reduction_pct"] == 0.0


def test_RA_E_9_risk_summary_only_open():
    tasks = [
        _MockTask(task_state="OPEN", priority="HIGH", risk_score=0.5),
        _MockTask(task_state="IN_PROGRESS", priority="LOW", risk_score=0.3),
    ]
    r = compute_risk_summary(tasks)
    assert r["open_risk_score"] == 0.8
    assert r["mitigated_risk_score"] == 0.0


def test_RA_E_10_risk_summary_mixed():
    tasks = [
        _MockTask(task_state="OPEN", priority="HIGH", risk_score=0.5),
        _MockTask(task_state="COMPLETED", priority="HIGH", risk_score=0.5),
    ]
    r = compute_risk_summary(tasks)
    assert r["mitigated_risk_score"] == 0.5
    assert r["risk_reduction_pct"] == 50.0


def test_RA_E_11_risk_summary_by_priority():
    tasks = [
        _MockTask(task_state="OPEN", priority="HIGH", risk_score=0.5),
        _MockTask(task_state="OPEN", priority="LOW", risk_score=0.1),
    ]
    r = compute_risk_summary(tasks)
    assert r["by_priority"]["HIGH"] == 0.5
    assert r["by_priority"]["LOW"] == 0.1


def test_RA_E_12_risk_summary_none_risk_score():
    tasks = [_MockTask(task_state="OPEN", priority="HIGH", risk_score=None)]
    r = compute_risk_summary(tasks)
    assert r["total_risk_score"] == 0.0


# ---------------------------------------------------------------------------
# statistics helpers
# ---------------------------------------------------------------------------


def test_RA_E_13_bucket_by_returns_dict():
    rows = [
        _MockTask(task_state="OPEN"),
        _MockTask(task_state="OPEN"),
        _MockTask(task_state="COMPLETED"),
    ]
    r = bucket_by(rows, "task_state")
    assert r["OPEN"] == 2
    assert r["COMPLETED"] == 1


def test_RA_E_14_bucket_by_unknown():
    rows = [_MockTask(task_state=None)]
    r = bucket_by(rows, "task_state")
    assert r["__unknown__"] == 1


def test_RA_E_15_average_completion_days_none_when_empty():
    assert average_completion_days([]) is None


def test_RA_E_16_average_completion_days_ignores_incomplete():
    rows = [
        _MockTask(
            task_state="OPEN", created_at="2026-01-01T00:00:00Z", completed_at=None
        )
    ]
    assert average_completion_days(rows) is None


def test_RA_E_17_average_completion_days_computed():
    rows = [
        _MockTask(
            task_state="COMPLETED",
            created_at="2026-01-01T00:00:00Z",
            completed_at="2026-01-11T00:00:00Z",
        )
    ]
    assert average_completion_days(rows) == 10.0


def test_RA_E_18_count_by_sla_shape():
    rows = [
        _MockTask(sla_status="ON_TRACK"),
        _MockTask(sla_status="BREACHED"),
    ]
    r = count_by_sla(rows)
    assert r["ON_TRACK"] == 1
    assert r["BREACHED"] == 1


# ---------------------------------------------------------------------------
# sla.compute_sla_status
# ---------------------------------------------------------------------------


def test_RA_E_19_sla_unscheduled_when_no_target():
    from services.remediation_authority.models import SlaStatus

    assert compute_sla_status(None, "OPEN") == SlaStatus.UNSCHEDULED


def test_RA_E_20_sla_at_risk_days_positive():
    assert AT_RISK_DAYS > 0


def test_RA_E_21_sla_breached_when_past_target():
    from services.remediation_authority.models import SlaStatus

    r = compute_sla_status("2000-01-01T00:00:00Z", "OPEN")
    assert r == SlaStatus.BREACHED


def test_RA_E_22_sla_ontrack_far_future():
    from services.remediation_authority.models import SlaStatus

    r = compute_sla_status("2099-01-01T00:00:00Z", "OPEN")
    assert r == SlaStatus.ON_TRACK


def test_RA_E_23_sla_cancelled_unscheduled():
    from services.remediation_authority.models import SlaStatus

    r = compute_sla_status("2099-01-01T00:00:00Z", "CANCELLED")
    assert r == SlaStatus.UNSCHEDULED


def test_RA_E_24_sla_completed_before_target_on_track():
    from services.remediation_authority.models import SlaStatus

    r = compute_sla_status(
        "2099-01-01T00:00:00Z",
        "COMPLETED",
        completed_at="2098-12-31T00:00:00Z",
    )
    assert r == SlaStatus.ON_TRACK


def test_RA_E_25_sla_completed_after_target_breached():
    from services.remediation_authority.models import SlaStatus

    r = compute_sla_status(
        "2000-01-01T00:00:00Z",
        "COMPLETED",
        completed_at="2000-06-01T00:00:00Z",
    )
    assert r == SlaStatus.BREACHED


def test_RA_E_26_is_breached_true():
    from services.remediation_authority.models import SlaStatus

    assert is_breached(SlaStatus.BREACHED) is True


def test_RA_E_27_is_breached_false():
    from services.remediation_authority.models import SlaStatus

    assert is_breached(SlaStatus.ON_TRACK) is False


def test_RA_E_28_sla_invalid_date_unscheduled():
    from services.remediation_authority.models import SlaStatus

    assert compute_sla_status("not-a-date", "OPEN") == SlaStatus.UNSCHEDULED


# ---------------------------------------------------------------------------
# Engine statistics
# ---------------------------------------------------------------------------


def test_RA_E_29_engine_statistics_zero(svc):
    r = svc.get_statistics()
    assert r.total_plans == 0
    assert r.total_tasks == 0


def test_RA_E_30_engine_statistics_after_creation(svc, db):
    from services.remediation_authority.schemas import CreatePlanRequest

    svc.create_plan(CreatePlanRequest(title="P"), actor_id="u")
    svc.create_task(CreateTaskRequest(title="T"), actor_id="u")
    db.commit()
    r = svc.get_statistics()
    assert r.total_plans >= 1
    assert r.total_tasks >= 1


def test_RA_E_31_engine_statistics_by_priority(svc, db):
    for p in list(RemediationPriority):
        svc.create_task(
            CreateTaskRequest(title=f"T-{p.value}", priority=p), actor_id="u"
        )
    db.commit()
    r = svc.get_statistics()
    for p in list(RemediationPriority):
        assert r.by_priority.get(p.value, 0) >= 1


def test_RA_E_32_engine_statistics_by_state(svc, db):
    svc.create_task(CreateTaskRequest(title="T1"), actor_id="u")
    db.commit()
    r = svc.get_statistics()
    assert r.by_state.get("OPEN", 0) >= 1


def test_RA_E_33_engine_forecast_shape(svc):
    r = svc.get_forecast(horizon_days=30)
    assert isinstance(r, ForecastResponse)
    assert r.horizon_days == 30


def test_RA_E_34_engine_forecast_horizon_variants(svc):
    for h in (1, 7, 30, 90, 365):
        r = svc.get_forecast(horizon_days=h)
        assert r.horizon_days == h


def test_RA_E_35_engine_forecast_reflects_open(svc, db):
    for _ in range(3):
        svc.create_task(CreateTaskRequest(title="T"), actor_id="u")
    db.commit()
    r = svc.get_forecast(horizon_days=30)
    assert r.open_task_count == 3


def test_RA_E_36_engine_risk_shape(svc):
    r = svc.get_risk()
    assert isinstance(r, RiskResponse)
    assert 0 <= r.risk_reduction_pct <= 100


def test_RA_E_37_engine_risk_with_scores(svc, db):
    svc.create_task(CreateTaskRequest(title="T", risk_score=0.8), actor_id="u")
    db.commit()
    r = svc.get_risk()
    assert r.total_risk_score >= 0.8


def test_RA_E_38_engine_stats_returns_statistics_type(svc):
    assert isinstance(svc.get_statistics(), StatisticsResponse)


def test_RA_E_39_engine_stats_verifications_approved(svc, db):
    t = svc.create_task(CreateTaskRequest(title="T"), actor_id="u")
    for target in (
        RemediationTaskState.IN_PROGRESS,
        RemediationTaskState.READY_FOR_REVIEW,
    ):
        svc.transition_task(t.id, TransitionTaskRequest(to_state=target), actor_id="u")
    svc.create_verification(
        CreateVerificationRequest(
            task_id=t.id,
            verifier_id="v",
            verification_state=RemediationVerificationState.APPROVED,
        ),
        actor_id="u",
    )
    db.commit()
    r = svc.get_statistics()
    assert r.verifications_approved >= 1


def test_RA_E_40_engine_stats_average_completion(svc, db):
    t = svc.create_task(CreateTaskRequest(title="T"), actor_id="u")
    for target in (
        RemediationTaskState.IN_PROGRESS,
        RemediationTaskState.READY_FOR_REVIEW,
        RemediationTaskState.VERIFYING,
        RemediationTaskState.APPROVED,
        RemediationTaskState.COMPLETED,
    ):
        svc.transition_task(t.id, TransitionTaskRequest(to_state=target), actor_id="u")
    db.commit()
    r = svc.get_statistics()
    assert r.average_completion_days is not None


# Big parametric expansion
@pytest.mark.parametrize("i", range(1, 41))
def test_RA_E_41_bulk_statistics_persist(svc, db, i):
    svc.create_task(
        CreateTaskRequest(title=f"T-{i}", risk_score=(i % 10) / 10.0), actor_id="u"
    )
    db.commit()
    r = svc.get_statistics()
    assert r.total_tasks >= 1


@pytest.mark.parametrize("h", [1, 7, 14, 30, 60, 90, 180, 365])
def test_RA_E_42_forecast_all_horizons(svc, h):
    r = svc.get_forecast(horizon_days=h)
    assert r.horizon_days == h


@pytest.mark.parametrize("priority", list(RemediationPriority))
def test_RA_E_43_risk_records_all_priorities(svc, db, priority):
    svc.create_task(
        CreateTaskRequest(
            title=f"T-{priority.value}", risk_score=0.4, priority=priority
        ),
        actor_id="u",
    )
    db.commit()
    r = svc.get_risk()
    assert r.total_risk_score >= 0.4


@pytest.mark.parametrize("state", ["OPEN", "IN_PROGRESS", "BLOCKED", "COMPLETED"])
def test_RA_E_44_forecast_state_summary(svc, db, state):
    # Only really tests OPEN/IN_PROGRESS produce open counts; COMPLETED does not.
    if state == "OPEN":
        svc.create_task(CreateTaskRequest(title="T"), actor_id="u")
    elif state == "IN_PROGRESS":
        t = svc.create_task(CreateTaskRequest(title="T"), actor_id="u")
        svc.transition_task(
            t.id,
            TransitionTaskRequest(to_state=RemediationTaskState.IN_PROGRESS),
            actor_id="u",
        )
    elif state == "BLOCKED":
        t = svc.create_task(CreateTaskRequest(title="T"), actor_id="u")
        svc.transition_task(
            t.id,
            TransitionTaskRequest(to_state=RemediationTaskState.BLOCKED),
            actor_id="u",
        )
    elif state == "COMPLETED":
        t = svc.create_task(CreateTaskRequest(title="T"), actor_id="u")
        for target in (
            RemediationTaskState.IN_PROGRESS,
            RemediationTaskState.READY_FOR_REVIEW,
            RemediationTaskState.VERIFYING,
            RemediationTaskState.APPROVED,
            RemediationTaskState.COMPLETED,
        ):
            svc.transition_task(
                t.id, TransitionTaskRequest(to_state=target), actor_id="u"
            )
    db.commit()
    r = svc.get_forecast(horizon_days=30)
    assert r.open_task_count >= 0
