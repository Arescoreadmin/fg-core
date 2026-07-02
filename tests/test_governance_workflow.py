"""Tests for PR 18.4 — Governance Orchestration workflow coordinator."""

from __future__ import annotations

import pytest
from sqlalchemy.orm import Session

from api.db import get_engine
from services.governance_orchestration.engine import (
    GovernanceOrchestrationEngine,
)
from services.governance_orchestration.repository import (
    GovernanceOrchestrationRepository,
)
from services.governance_orchestration.schemas import (
    CreateWorkflowRequest,
    GovernanceOrchestrationInvalidTransition,
    GovernanceOrchestrationNotFound,
    GovernanceOrchestrationWorkflowError,
)
from services.governance_orchestration.workflow import WorkflowCoordinator


_TENANT = "tenant-go-wf-001"
_TENANT_B = "tenant-go-wf-002"


@pytest.fixture()
def db(build_app):
    build_app(auth_enabled=False)
    engine = get_engine()
    with Session(engine) as session:
        yield session


@pytest.fixture()
def svc(db):
    return GovernanceOrchestrationEngine(db, tenant_id=_TENANT)


@pytest.fixture()
def coord():
    return WorkflowCoordinator()


def _make_wf(svc, name="wf"):
    return svc.create_workflow(CreateWorkflowRequest(name=name), actor_id="tester")


# ---------------------------------------------------------------------------
# Coordinator lifecycle
# ---------------------------------------------------------------------------


def test_WF_1_start_pending_to_running(db, svc, coord):
    wf = _make_wf(svc)
    result = coord.start_workflow(db, _TENANT, wf.id)
    assert result["workflow_state"] == "RUNNING"


def test_WF_2_start_missing_workflow(db, coord):
    with pytest.raises(GovernanceOrchestrationNotFound):
        coord.start_workflow(db, _TENANT, "does-not-exist")


def test_WF_3_cancel_from_pending(db, svc, coord):
    wf = _make_wf(svc)
    result = coord.cancel_workflow(db, _TENANT, wf.id)
    assert result["workflow_state"] == "CANCELLED"


def test_WF_4_cancel_from_running(db, svc, coord):
    wf = _make_wf(svc)
    coord.start_workflow(db, _TENANT, wf.id)
    result = coord.cancel_workflow(db, _TENANT, wf.id)
    assert result["workflow_state"] == "CANCELLED"


def test_WF_5_pause_only_from_running(db, svc, coord):
    wf = _make_wf(svc)
    with pytest.raises(GovernanceOrchestrationInvalidTransition):
        coord.pause_workflow(db, _TENANT, wf.id)


def test_WF_6_pause_from_running(db, svc, coord):
    wf = _make_wf(svc)
    coord.start_workflow(db, _TENANT, wf.id)
    result = coord.pause_workflow(db, _TENANT, wf.id)
    assert result["workflow_state"] == "PAUSED"


def test_WF_7_resume_from_paused(db, svc, coord):
    wf = _make_wf(svc)
    coord.start_workflow(db, _TENANT, wf.id)
    coord.pause_workflow(db, _TENANT, wf.id)
    result = coord.advance_workflow(db, _TENANT, wf.id, "resume")
    assert result["workflow_state"] == "RUNNING"


def test_WF_8_complete_from_running(db, svc, coord):
    wf = _make_wf(svc)
    coord.start_workflow(db, _TENANT, wf.id)
    result = coord.advance_workflow(db, _TENANT, wf.id, "complete")
    assert result["workflow_state"] == "COMPLETED"


def test_WF_9_fail_from_running(db, svc, coord):
    wf = _make_wf(svc)
    coord.start_workflow(db, _TENANT, wf.id)
    result = coord.advance_workflow(db, _TENANT, wf.id, "fail")
    assert result["workflow_state"] == "FAILED"


def test_WF_10_wait_approval_from_running(db, svc, coord):
    wf = _make_wf(svc)
    coord.start_workflow(db, _TENANT, wf.id)
    result = coord.advance_workflow(db, _TENANT, wf.id, "wait_approval")
    assert result["workflow_state"] == "WAITING_APPROVAL"


def test_WF_11_approve_from_waiting(db, svc, coord):
    wf = _make_wf(svc)
    coord.start_workflow(db, _TENANT, wf.id)
    coord.advance_workflow(db, _TENANT, wf.id, "wait_approval")
    result = coord.advance_workflow(db, _TENANT, wf.id, "approve")
    assert result["workflow_state"] == "RUNNING"


def test_WF_12_reject_from_waiting(db, svc, coord):
    wf = _make_wf(svc)
    coord.start_workflow(db, _TENANT, wf.id)
    coord.advance_workflow(db, _TENANT, wf.id, "wait_approval")
    result = coord.advance_workflow(db, _TENANT, wf.id, "reject")
    assert result["workflow_state"] == "FAILED"


def test_WF_13_cannot_transition_from_terminal_completed(db, svc, coord):
    wf = _make_wf(svc)
    coord.start_workflow(db, _TENANT, wf.id)
    coord.advance_workflow(db, _TENANT, wf.id, "complete")
    with pytest.raises(GovernanceOrchestrationInvalidTransition):
        coord.advance_workflow(db, _TENANT, wf.id, "start")


def test_WF_14_cannot_transition_from_terminal_cancelled(db, svc, coord):
    wf = _make_wf(svc)
    coord.cancel_workflow(db, _TENANT, wf.id)
    with pytest.raises(GovernanceOrchestrationInvalidTransition):
        coord.start_workflow(db, _TENANT, wf.id)


def test_WF_15_invalid_event(db, svc, coord):
    wf = _make_wf(svc)
    with pytest.raises(GovernanceOrchestrationInvalidTransition):
        coord.advance_workflow(db, _TENANT, wf.id, "unknown")


def test_WF_16_empty_event_raises(db, svc, coord):
    wf = _make_wf(svc)
    with pytest.raises(GovernanceOrchestrationWorkflowError):
        coord.advance_workflow(db, _TENANT, wf.id, "")


def test_WF_17_get_summary(db, svc, coord):
    wf = _make_wf(svc)
    summary = coord.get_workflow_summary(db, _TENANT, wf.id)
    assert summary["id"] == wf.id


def test_WF_18_get_summary_not_found(db, coord):
    with pytest.raises(GovernanceOrchestrationNotFound):
        coord.get_workflow_summary(db, _TENANT, "does-not-exist")


def test_WF_19_tenant_isolation(db, svc, coord):
    wf = _make_wf(svc)
    with pytest.raises(GovernanceOrchestrationNotFound):
        coord.start_workflow(db, _TENANT_B, wf.id)


def test_WF_20_terminal_sets_completed_at(db, svc, coord):
    wf = _make_wf(svc)
    result = coord.cancel_workflow(db, _TENANT, wf.id)
    assert result["completed_at"] is not None


# ---------------------------------------------------------------------------
# Engine wrapper — advance / pause / cancel via engine
# ---------------------------------------------------------------------------


def test_WF_21_engine_advance(svc):
    wf = _make_wf(svc)
    result = svc.advance_workflow(wf.id, "start", actor_id="a")
    assert result.workflow_state == "RUNNING"


def test_WF_22_engine_pause(svc):
    wf = _make_wf(svc)
    svc.advance_workflow(wf.id, "start", actor_id="a")
    result = svc.pause_workflow(wf.id, actor_id="a")
    assert result.workflow_state == "PAUSED"


def test_WF_23_engine_cancel(svc):
    wf = _make_wf(svc)
    result = svc.cancel_workflow(wf.id, actor_id="a")
    assert result.workflow_state == "CANCELLED"


def test_WF_24_engine_pause_invalid(svc):
    wf = _make_wf(svc)
    with pytest.raises(GovernanceOrchestrationInvalidTransition):
        svc.pause_workflow(wf.id, actor_id="a")


def test_WF_25_engine_advance_not_found(svc):
    with pytest.raises(GovernanceOrchestrationNotFound):
        svc.advance_workflow("does-not-exist", "start", actor_id="a")


# ---------------------------------------------------------------------------
# Parametric state graph checks
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "from_state,event,to_state",
    [
        ("PENDING", "start", "RUNNING"),
        ("PENDING", "cancel", "CANCELLED"),
        ("RUNNING", "complete", "COMPLETED"),
        ("RUNNING", "fail", "FAILED"),
        ("RUNNING", "cancel", "CANCELLED"),
        ("RUNNING", "wait_approval", "WAITING_APPROVAL"),
        ("RUNNING", "pause", "PAUSED"),
        ("WAITING_APPROVAL", "approve", "RUNNING"),
        ("WAITING_APPROVAL", "reject", "FAILED"),
        ("WAITING_APPROVAL", "cancel", "CANCELLED"),
        ("PAUSED", "resume", "RUNNING"),
        ("PAUSED", "cancel", "CANCELLED"),
    ],
)
def test_WF_26_state_graph_positive(from_state, event, to_state, db, coord):
    repo = GovernanceOrchestrationRepository(db, _TENANT)
    wf = repo.create_workflow(name="wf", workflow_state=from_state)
    db.commit()
    result = coord.advance_workflow(db, _TENANT, wf.id, event)
    assert result["workflow_state"] == to_state


@pytest.mark.parametrize(
    "from_state,event",
    [
        ("PENDING", "complete"),
        ("PENDING", "pause"),
        ("PENDING", "approve"),
        ("RUNNING", "start"),
        ("RUNNING", "resume"),
        ("COMPLETED", "start"),
        ("FAILED", "start"),
        ("CANCELLED", "start"),
        ("ROLLED_BACK", "start"),
    ],
)
def test_WF_27_state_graph_invalid(from_state, event, db, coord):
    repo = GovernanceOrchestrationRepository(db, _TENANT)
    wf = repo.create_workflow(name="wf", workflow_state=from_state)
    db.commit()
    with pytest.raises(GovernanceOrchestrationInvalidTransition):
        coord.advance_workflow(db, _TENANT, wf.id, event)


# ---------------------------------------------------------------------------
# Timeline effects
# ---------------------------------------------------------------------------


def test_WF_28_workflow_creation_appends_timeline(svc):
    wf = _make_wf(svc)
    tl = svc.get_timeline(entity_type="workflow", entity_id=wf.id)
    assert any(e.event_type == "workflow_created" for e in tl.events)


def test_WF_29_workflow_advance_appends_timeline(svc):
    wf = _make_wf(svc)
    svc.advance_workflow(wf.id, "start", actor_id="a")
    tl = svc.get_timeline(entity_type="workflow", entity_id=wf.id)
    assert any(
        e.event_type == "workflow_event_start" for e in tl.events
    )


def test_WF_30_workflow_cancel_appends_timeline(svc):
    wf = _make_wf(svc)
    svc.cancel_workflow(wf.id, actor_id="a")
    tl = svc.get_timeline(entity_type="workflow", entity_id=wf.id)
    assert any(e.event_type == "workflow_event_cancel" for e in tl.events)
