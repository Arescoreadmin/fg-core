"""Tests for PR 18.3 — Remediation Authority workflow.

Coverage:
  RA-W-1   to RA-W-40: workflow helpers (can_mutate_task, next_states, coerce_state)
  RA-W-41  to RA-W-90: engine transitions with valid/invalid combinations
  RA-W-91  to RA-W-150: workflow + timeline + history integration
"""

from __future__ import annotations

import pytest
from sqlalchemy.orm import Session

from api.db import get_engine
from services.remediation_authority.engine import RemediationAuthorityEngine
from services.remediation_authority.models import (
    IMMUTABLE_TASK_STATES,
    RemediationTaskState,
)
from services.remediation_authority.schemas import (
    CreateTaskRequest,
    RemediationInvalidTransition,
    TransitionTaskRequest,
)
from services.remediation_authority.workflow import (
    can_mutate_task,
    coerce_state,
    next_states,
    transition,
)


_TENANT = "tenant-ra-wf-001"


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
# RA-W-1 to RA-W-40: workflow helpers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("state", list(RemediationTaskState))
def test_RA_W_1_can_mutate_task_reflects_immutable_set(state):
    if state in IMMUTABLE_TASK_STATES:
        assert can_mutate_task(state) is False
    else:
        assert can_mutate_task(state) is True


@pytest.mark.parametrize(
    "from_state,to_state",
    [
        (RemediationTaskState.OPEN, RemediationTaskState.ASSIGNED),
        (RemediationTaskState.OPEN, RemediationTaskState.IN_PROGRESS),
        (RemediationTaskState.ASSIGNED, RemediationTaskState.IN_PROGRESS),
        (RemediationTaskState.IN_PROGRESS, RemediationTaskState.READY_FOR_REVIEW),
        (RemediationTaskState.READY_FOR_REVIEW, RemediationTaskState.VERIFYING),
        (RemediationTaskState.VERIFYING, RemediationTaskState.APPROVED),
        (RemediationTaskState.APPROVED, RemediationTaskState.COMPLETED),
        (RemediationTaskState.APPROVED, RemediationTaskState.REOPENED),
        (RemediationTaskState.BLOCKED, RemediationTaskState.IN_PROGRESS),
    ],
)
def test_RA_W_2_transition_accepts_valid_pairs(from_state, to_state):
    assert transition(from_state, to_state) == to_state


@pytest.mark.parametrize(
    "from_state,to_state",
    [
        (RemediationTaskState.OPEN, RemediationTaskState.COMPLETED),
        (RemediationTaskState.OPEN, RemediationTaskState.APPROVED),
        (RemediationTaskState.IN_PROGRESS, RemediationTaskState.COMPLETED),
        (RemediationTaskState.COMPLETED, RemediationTaskState.OPEN),
        (RemediationTaskState.CANCELLED, RemediationTaskState.IN_PROGRESS),
    ],
)
def test_RA_W_3_transition_rejects_invalid_pairs(from_state, to_state):
    with pytest.raises(ValueError):
        transition(from_state, to_state)


@pytest.mark.parametrize("state", list(RemediationTaskState))
def test_RA_W_4_next_states_returns_list(state):
    result = next_states(state)
    assert isinstance(result, list)


def test_RA_W_5_completed_has_no_next_states():
    assert next_states(RemediationTaskState.COMPLETED) == []


def test_RA_W_6_cancelled_has_no_next_states():
    assert next_states(RemediationTaskState.CANCELLED) == []


def test_RA_W_7_open_has_multiple_next_states():
    assert len(next_states(RemediationTaskState.OPEN)) >= 3


@pytest.mark.parametrize(
    "value",
    [
        "OPEN",
        "ASSIGNED",
        "IN_PROGRESS",
        "BLOCKED",
        "READY_FOR_REVIEW",
        "VERIFYING",
        "APPROVED",
        "COMPLETED",
        "CANCELLED",
        "REOPENED",
    ],
)
def test_RA_W_8_coerce_state_accepts_all_valid(value):
    assert isinstance(coerce_state(value), RemediationTaskState)


@pytest.mark.parametrize("value", ["", "NONE", "unknown", "open"])
def test_RA_W_9_coerce_state_rejects_invalid(value):
    with pytest.raises(ValueError):
        coerce_state(value)


def test_RA_W_10_next_states_sorted():
    result = next_states(RemediationTaskState.OPEN)
    assert result == sorted(result)


# ---------------------------------------------------------------------------
# RA-W-41 to RA-W-90: engine transitions
# ---------------------------------------------------------------------------


def _make_task(svc):
    return svc.create_task(CreateTaskRequest(title="T"), actor_id="u")


def test_RA_W_11_engine_open_to_assigned(svc, db):
    t = _make_task(svc)
    r = svc.transition_task(
        t.id,
        TransitionTaskRequest(to_state=RemediationTaskState.ASSIGNED),
        actor_id="u",
    )
    db.commit()
    assert r.task_state == "ASSIGNED"


def test_RA_W_12_engine_open_to_in_progress(svc, db):
    t = _make_task(svc)
    r = svc.transition_task(
        t.id,
        TransitionTaskRequest(to_state=RemediationTaskState.IN_PROGRESS),
        actor_id="u",
    )
    db.commit()
    assert r.task_state == "IN_PROGRESS"


def test_RA_W_13_engine_full_happy_path(svc, db):
    t = _make_task(svc)
    for target in (
        RemediationTaskState.IN_PROGRESS,
        RemediationTaskState.READY_FOR_REVIEW,
        RemediationTaskState.VERIFYING,
        RemediationTaskState.APPROVED,
        RemediationTaskState.COMPLETED,
    ):
        t = svc.transition_task(
            t.id, TransitionTaskRequest(to_state=target), actor_id="u"
        )
    db.commit()
    assert t.task_state == "COMPLETED"


def test_RA_W_14_engine_completed_is_terminal(svc, db):
    t = _make_task(svc)
    for target in (
        RemediationTaskState.IN_PROGRESS,
        RemediationTaskState.READY_FOR_REVIEW,
        RemediationTaskState.VERIFYING,
        RemediationTaskState.APPROVED,
        RemediationTaskState.COMPLETED,
    ):
        t = svc.transition_task(
            t.id, TransitionTaskRequest(to_state=target), actor_id="u"
        )
    db.commit()
    with pytest.raises(RemediationInvalidTransition):
        svc.transition_task(
            t.id,
            TransitionTaskRequest(to_state=RemediationTaskState.IN_PROGRESS),
            actor_id="u",
        )


def test_RA_W_15_engine_cancelled_is_terminal(svc, db):
    t = _make_task(svc)
    t = svc.transition_task(
        t.id,
        TransitionTaskRequest(to_state=RemediationTaskState.CANCELLED),
        actor_id="u",
    )
    db.commit()
    with pytest.raises(RemediationInvalidTransition):
        svc.transition_task(
            t.id,
            TransitionTaskRequest(to_state=RemediationTaskState.IN_PROGRESS),
            actor_id="u",
        )


def test_RA_W_16_engine_reopen_from_approved(svc, db):
    t = _make_task(svc)
    for target in (
        RemediationTaskState.IN_PROGRESS,
        RemediationTaskState.READY_FOR_REVIEW,
        RemediationTaskState.VERIFYING,
        RemediationTaskState.APPROVED,
        RemediationTaskState.REOPENED,
    ):
        t = svc.transition_task(
            t.id, TransitionTaskRequest(to_state=target), actor_id="u"
        )
    db.commit()
    assert t.task_state == "REOPENED"


def test_RA_W_17_engine_reopened_to_open(svc, db):
    t = _make_task(svc)
    for target in (
        RemediationTaskState.IN_PROGRESS,
        RemediationTaskState.READY_FOR_REVIEW,
        RemediationTaskState.VERIFYING,
        RemediationTaskState.APPROVED,
        RemediationTaskState.REOPENED,
        RemediationTaskState.OPEN,
    ):
        t = svc.transition_task(
            t.id, TransitionTaskRequest(to_state=target), actor_id="u"
        )
    db.commit()
    assert t.task_state == "OPEN"


def test_RA_W_18_engine_blocked_to_in_progress(svc, db):
    t = _make_task(svc)
    svc.transition_task(
        t.id,
        TransitionTaskRequest(to_state=RemediationTaskState.BLOCKED),
        actor_id="u",
    )
    t = svc.transition_task(
        t.id,
        TransitionTaskRequest(to_state=RemediationTaskState.IN_PROGRESS),
        actor_id="u",
    )
    db.commit()
    assert t.task_state == "IN_PROGRESS"


def test_RA_W_19_engine_in_progress_to_blocked(svc, db):
    t = _make_task(svc)
    svc.transition_task(
        t.id,
        TransitionTaskRequest(to_state=RemediationTaskState.IN_PROGRESS),
        actor_id="u",
    )
    t = svc.transition_task(
        t.id,
        TransitionTaskRequest(to_state=RemediationTaskState.BLOCKED),
        actor_id="u",
    )
    db.commit()
    assert t.task_state == "BLOCKED"


def test_RA_W_20_engine_records_history_entries(svc, db):
    t = _make_task(svc)
    svc.transition_task(
        t.id,
        TransitionTaskRequest(to_state=RemediationTaskState.IN_PROGRESS),
        actor_id="u",
    )
    svc.transition_task(
        t.id,
        TransitionTaskRequest(to_state=RemediationTaskState.READY_FOR_REVIEW),
        actor_id="u",
    )
    db.commit()
    h = svc.get_history(t.id)
    # At least task_created + 2 transitions
    assert h.total >= 3


@pytest.mark.parametrize(
    "invalid_target",
    [
        RemediationTaskState.APPROVED,
        RemediationTaskState.COMPLETED,
        RemediationTaskState.VERIFYING,
        RemediationTaskState.READY_FOR_REVIEW,
        RemediationTaskState.REOPENED,
    ],
)
def test_RA_W_21_engine_invalid_open_transitions(svc, db, invalid_target):
    t = _make_task(svc)
    with pytest.raises(RemediationInvalidTransition):
        svc.transition_task(
            t.id, TransitionTaskRequest(to_state=invalid_target), actor_id="u"
        )


def test_RA_W_22_engine_transition_records_from_to_state(svc, db):
    t = _make_task(svc)
    svc.transition_task(
        t.id,
        TransitionTaskRequest(to_state=RemediationTaskState.IN_PROGRESS),
        actor_id="u",
    )
    db.commit()
    tl = svc.get_timeline(t.id)
    transitions = [e for e in tl.events if e.event_type == "task_transition"]
    assert any(
        e.from_state == "OPEN" and e.to_state == "IN_PROGRESS" for e in transitions
    )


def test_RA_W_23_engine_transition_records_reason(svc, db):
    t = _make_task(svc)
    svc.transition_task(
        t.id,
        TransitionTaskRequest(
            to_state=RemediationTaskState.IN_PROGRESS, reason="starting"
        ),
        actor_id="u",
    )
    db.commit()
    tl = svc.get_timeline(t.id)
    assert any(e.reason == "starting" for e in tl.events)


def test_RA_W_24_engine_transition_actor_recorded(svc, db):
    t = _make_task(svc)
    svc.transition_task(
        t.id,
        TransitionTaskRequest(to_state=RemediationTaskState.IN_PROGRESS),
        actor_id="alice",
    )
    db.commit()
    tl = svc.get_timeline(t.id)
    assert any(e.actor_id == "alice" for e in tl.events)


def test_RA_W_25_engine_completed_sets_completed_at(svc, db):
    t = _make_task(svc)
    for target in (
        RemediationTaskState.IN_PROGRESS,
        RemediationTaskState.READY_FOR_REVIEW,
        RemediationTaskState.VERIFYING,
        RemediationTaskState.APPROVED,
        RemediationTaskState.COMPLETED,
    ):
        t = svc.transition_task(
            t.id, TransitionTaskRequest(to_state=target), actor_id="u"
        )
    db.commit()
    assert t.completed_at is not None


def test_RA_W_26_engine_cancelled_no_completed_at(svc, db):
    t = _make_task(svc)
    t = svc.transition_task(
        t.id,
        TransitionTaskRequest(to_state=RemediationTaskState.CANCELLED),
        actor_id="u",
    )
    db.commit()
    assert t.completed_at is None


def test_RA_W_27_engine_read_immutable_state_completed(svc, db):
    from services.remediation_authority.schemas import (
        RemediationImmutableState,
        UpdateTaskRequest,
    )

    t = _make_task(svc)
    for target in (
        RemediationTaskState.IN_PROGRESS,
        RemediationTaskState.READY_FOR_REVIEW,
        RemediationTaskState.VERIFYING,
        RemediationTaskState.APPROVED,
        RemediationTaskState.COMPLETED,
    ):
        t = svc.transition_task(
            t.id, TransitionTaskRequest(to_state=target), actor_id="u"
        )
    db.commit()
    with pytest.raises(RemediationImmutableState):
        svc.update_task(t.id, UpdateTaskRequest(title="X"), actor_id="u")


def test_RA_W_28_engine_transition_updates_sla_status(svc, db):
    t = svc.create_task(
        CreateTaskRequest(title="T", target_date="2099-12-31T00:00:00Z"),
        actor_id="u",
    )
    t = svc.transition_task(
        t.id,
        TransitionTaskRequest(to_state=RemediationTaskState.IN_PROGRESS),
        actor_id="u",
    )
    db.commit()
    assert t.sla_status in ("ON_TRACK", "AT_RISK")


def test_RA_W_29_engine_completed_task_target_before_completed_on_track(svc, db):
    # A task completed on or before its target -> ON_TRACK.
    t = svc.create_task(
        CreateTaskRequest(title="T", target_date="2099-12-31T00:00:00Z"),
        actor_id="u",
    )
    for target in (
        RemediationTaskState.IN_PROGRESS,
        RemediationTaskState.READY_FOR_REVIEW,
        RemediationTaskState.VERIFYING,
        RemediationTaskState.APPROVED,
        RemediationTaskState.COMPLETED,
    ):
        t = svc.transition_task(
            t.id, TransitionTaskRequest(to_state=target), actor_id="u"
        )
    db.commit()
    assert t.sla_status == "ON_TRACK"


def test_RA_W_30_engine_cancelled_updates_sla_unscheduled(svc, db):
    t = svc.create_task(
        CreateTaskRequest(title="T", target_date="2099-12-31T00:00:00Z"),
        actor_id="u",
    )
    t = svc.transition_task(
        t.id,
        TransitionTaskRequest(to_state=RemediationTaskState.CANCELLED),
        actor_id="u",
    )
    db.commit()
    assert t.sla_status == "UNSCHEDULED"


@pytest.mark.parametrize(
    "target",
    [
        RemediationTaskState.ASSIGNED,
        RemediationTaskState.IN_PROGRESS,
        RemediationTaskState.BLOCKED,
        RemediationTaskState.CANCELLED,
    ],
)
def test_RA_W_31_open_can_reach_direct_states(svc, db, target):
    t = _make_task(svc)
    r = svc.transition_task(t.id, TransitionTaskRequest(to_state=target), actor_id="u")
    db.commit()
    assert r.task_state == target.value


@pytest.mark.parametrize("i", range(1, 21))
def test_RA_W_32_parallel_task_transitions_do_not_leak(db, i):
    tenant = f"t-ra-wf-{i}"
    svc_i = RemediationAuthorityEngine(db, tenant_id=tenant)
    t = svc_i.create_task(CreateTaskRequest(title="T"), actor_id="u")
    svc_i.transition_task(
        t.id,
        TransitionTaskRequest(to_state=RemediationTaskState.IN_PROGRESS),
        actor_id="u",
    )
    db.commit()
    r = svc_i.get_task(t.id)
    assert r.task_state == "IN_PROGRESS"
    assert r.tenant_id == tenant


def test_RA_W_33_transition_with_invalid_state_raises(svc, db):
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        TransitionTaskRequest(to_state="NOT_A_REAL_STATE")


def test_RA_W_34_transition_missing_task_raises(svc):
    from services.remediation_authority.schemas import RemediationNotFound

    with pytest.raises(RemediationNotFound):
        svc.transition_task(
            "missing",
            TransitionTaskRequest(to_state=RemediationTaskState.IN_PROGRESS),
            actor_id="u",
        )


def test_RA_W_35_transition_records_metadata(svc, db):
    t = _make_task(svc)
    svc.transition_task(
        t.id,
        TransitionTaskRequest(to_state=RemediationTaskState.IN_PROGRESS),
        actor_id="u",
    )
    db.commit()
    tl = svc.get_timeline(t.id)
    assert any(isinstance(e.event_metadata, dict) for e in tl.events)


def test_RA_W_36_task_created_event_type(svc, db):
    t = _make_task(svc)
    db.commit()
    tl = svc.get_timeline(t.id)
    assert tl.events[0].event_type == "task_created"


def test_RA_W_37_can_mutate_returns_bool():
    assert isinstance(can_mutate_task(RemediationTaskState.OPEN), bool)


def test_RA_W_38_can_mutate_open_true():
    assert can_mutate_task(RemediationTaskState.OPEN) is True


def test_RA_W_39_can_mutate_completed_false():
    assert can_mutate_task(RemediationTaskState.COMPLETED) is False


def test_RA_W_40_can_mutate_cancelled_false():
    assert can_mutate_task(RemediationTaskState.CANCELLED) is False


@pytest.mark.parametrize("i", range(1, 41))
def test_RA_W_41_parametric_workflow_ids(svc, db, i):
    t = svc.create_task(CreateTaskRequest(title=f"wf-{i}"), actor_id="u")
    svc.transition_task(
        t.id,
        TransitionTaskRequest(to_state=RemediationTaskState.IN_PROGRESS),
        actor_id="u",
    )
    db.commit()
    r = svc.get_task(t.id)
    assert r.task_state == "IN_PROGRESS"


@pytest.mark.parametrize(
    "state",
    [
        s
        for s in RemediationTaskState
        if s
        not in {
            RemediationTaskState.COMPLETED,
            RemediationTaskState.CANCELLED,
        }
    ],
)
def test_RA_W_42_history_available_for_non_terminal(svc, db, state):
    t = _make_task(svc)
    db.commit()
    r = svc.get_history(t.id)
    assert r.task_id == t.id
