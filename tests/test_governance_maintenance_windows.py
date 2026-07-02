"""Tests for PR 18.4 — Governance Orchestration maintenance windows."""

from __future__ import annotations

import pytest
from sqlalchemy.orm import Session

from api.db import get_engine
from services.governance_orchestration.engine import (
    GovernanceOrchestrationEngine,
)
from services.governance_orchestration.maintenance_windows import (
    check_blackout_period,
    close_maintenance_window,
    get_active_window,
    is_in_maintenance_window,
    open_maintenance_window,
)
from services.governance_orchestration.schemas import (
    CreateMaintenanceWindowRequest,
    GovernanceOrchestrationInvalidTransition,
    GovernanceOrchestrationNotFound,
    GovernanceOrchestrationValidationError,
)
from services.governance_orchestration.trigger_engine import (
    is_trigger_active_for_tenant,
)


_TENANT = "tenant-go-mw-001"


@pytest.fixture()
def db(build_app):
    build_app(auth_enabled=False)
    engine = get_engine()
    with Session(engine) as session:
        yield session


@pytest.fixture()
def svc(db):
    return GovernanceOrchestrationEngine(db, tenant_id=_TENANT)


def _win(svc, name="mw", starts="2020-01-01T00:00:00Z", ends="2099-01-01T00:00:00Z"):
    return svc.create_maintenance_window(
        CreateMaintenanceWindowRequest(
            name=name, starts_at=starts, ends_at=ends
        ),
        actor_id="x",
    )


# ---------------------------------------------------------------------------
# create / list / get
# ---------------------------------------------------------------------------


def test_MW_1_create(svc):
    mw = _win(svc)
    assert mw.window_state == "SCHEDULED"


def test_MW_2_get(svc):
    mw = _win(svc)
    got = svc.get_maintenance_window(mw.id)
    assert got.id == mw.id


def test_MW_3_get_not_found(svc):
    with pytest.raises(GovernanceOrchestrationNotFound):
        svc.get_maintenance_window("missing")


def test_MW_4_list(svc):
    _win(svc, name="a")
    _win(svc, name="b")
    resp = svc.list_maintenance_windows()
    assert resp.total >= 2


def test_MW_5_list_by_state(svc):
    _win(svc, name="a")
    resp = svc.list_maintenance_windows(window_state="SCHEDULED")
    for w in resp.items:
        assert w.window_state == "SCHEDULED"


def test_MW_6_starts_after_ends_raises(svc):
    with pytest.raises(GovernanceOrchestrationValidationError):
        svc.create_maintenance_window(
            CreateMaintenanceWindowRequest(
                name="bad",
                starts_at="2099-01-01T00:00:00Z",
                ends_at="2020-01-01T00:00:00Z",
            ),
            actor_id="x",
        )


# ---------------------------------------------------------------------------
# open / close
# ---------------------------------------------------------------------------


def test_MW_7_open(svc):
    mw = _win(svc)
    opened = svc.open_maintenance_window(mw.id, actor_id="x")
    assert opened.window_state == "ACTIVE"


def test_MW_8_open_twice_raises(svc):
    mw = _win(svc)
    svc.open_maintenance_window(mw.id, actor_id="x")
    with pytest.raises(GovernanceOrchestrationInvalidTransition):
        svc.open_maintenance_window(mw.id, actor_id="x")


def test_MW_9_close(svc):
    mw = _win(svc)
    svc.open_maintenance_window(mw.id, actor_id="x")
    closed = svc.close_maintenance_window(mw.id, actor_id="x")
    assert closed.window_state == "COMPLETED"


def test_MW_10_close_scheduled_ok(svc):
    mw = _win(svc)
    closed = svc.close_maintenance_window(mw.id, actor_id="x")
    assert closed.window_state == "COMPLETED"


def test_MW_11_close_completed_raises(svc):
    mw = _win(svc)
    svc.close_maintenance_window(mw.id, actor_id="x")
    with pytest.raises(GovernanceOrchestrationInvalidTransition):
        svc.close_maintenance_window(mw.id, actor_id="x")


# ---------------------------------------------------------------------------
# is_in_maintenance_window / get_active_window
# ---------------------------------------------------------------------------


def test_MW_12_no_active_windows(db):
    assert is_in_maintenance_window(db, _TENANT) is False


def test_MW_13_active_after_open(db, svc):
    mw = _win(svc)
    svc.open_maintenance_window(mw.id, actor_id="x")
    assert is_in_maintenance_window(db, _TENANT) is True


def test_MW_14_active_window_returned(db, svc):
    mw = _win(svc)
    svc.open_maintenance_window(mw.id, actor_id="x")
    active = get_active_window(db, _TENANT)
    assert active is not None
    assert active["id"] == mw.id


def test_MW_15_get_active_none_when_no_windows(db):
    assert get_active_window(db, _TENANT) is None


def test_MW_16_check_time_outside_window(db, svc):
    _win(svc, starts="2020-01-01T00:00:00Z", ends="2020-01-02T00:00:00Z")
    # Not opened, so not in window regardless of time
    assert is_in_maintenance_window(db, _TENANT, "2020-01-01T12:00:00Z") is False


def test_MW_17_check_blackout_period_default_false():
    assert check_blackout_period("t", "2026-01-01T00:00:00Z") is False


def test_MW_18_check_blackout_empty_time_false():
    assert check_blackout_period("t", "") is False


def test_MW_19_check_blackout_empty_tenant_false():
    assert check_blackout_period("", "2026-01-01T00:00:00Z") is False


# ---------------------------------------------------------------------------
# Trigger suppression during maintenance windows
# ---------------------------------------------------------------------------


def test_MW_20_trigger_suppression_when_active(db, svc):
    mw = _win(svc)
    svc.open_maintenance_window(mw.id, actor_id="x")
    # is_trigger_active_for_tenant returns False when a maintenance window is active
    assert is_trigger_active_for_tenant(db, _TENANT, "MANUAL_REQUEST") is False


def test_MW_21_trigger_active_when_no_windows(db):
    assert is_trigger_active_for_tenant(db, _TENANT, "MANUAL_REQUEST") is True


# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------


def test_MW_22_creation_appends_timeline(svc):
    mw = _win(svc)
    tl = svc.get_timeline(entity_type="maintenance_window", entity_id=mw.id)
    assert any(e.event_type == "window_created" for e in tl.events)


def test_MW_23_open_appends_timeline(svc):
    mw = _win(svc)
    svc.open_maintenance_window(mw.id, actor_id="x")
    tl = svc.get_timeline(entity_type="maintenance_window", entity_id=mw.id)
    assert any(e.event_type == "window_opened" for e in tl.events)


def test_MW_24_close_appends_timeline(svc):
    mw = _win(svc)
    svc.close_maintenance_window(mw.id, actor_id="x")
    tl = svc.get_timeline(entity_type="maintenance_window", entity_id=mw.id)
    assert any(e.event_type == "window_closed" for e in tl.events)


# ---------------------------------------------------------------------------
# Helpers direct
# ---------------------------------------------------------------------------


def test_MW_25_open_not_found_helper(db):
    with pytest.raises(GovernanceOrchestrationNotFound):
        open_maintenance_window(db, _TENANT, "missing")


def test_MW_26_close_not_found_helper(db):
    with pytest.raises(GovernanceOrchestrationNotFound):
        close_maintenance_window(db, _TENANT, "missing")
