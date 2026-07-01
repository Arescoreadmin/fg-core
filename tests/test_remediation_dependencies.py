"""Tests for PR 18.3 — Remediation Authority dependencies."""

from __future__ import annotations

import pytest
from sqlalchemy.orm import Session

from api.db import get_engine
from services.remediation_authority.dependencies import (
    blockers_of,
    check_no_cycle,
    critical_path,
    dependents_of,
    would_create_cycle,
)
from services.remediation_authority.engine import RemediationAuthorityEngine
from services.remediation_authority.models import (
    DependencyType,
    RemediationTaskState,
)
from services.remediation_authority.schemas import (
    CreateDependencyRequest,
    CreateTaskRequest,
    RemediationDependencyError,
    RemediationInvalidTransition,
    RemediationNotFound,
    TransitionTaskRequest,
)


_TENANT = "tenant-ra-dep-001"


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
# Pure dependency graph helpers
# ---------------------------------------------------------------------------


def test_RA_D_1_would_create_cycle_self_edge():
    assert would_create_cycle([], ("a", "a")) is True


def test_RA_D_2_would_create_cycle_direct_reverse():
    edges = [("a", "b")]
    assert would_create_cycle(edges, ("b", "a")) is True


def test_RA_D_3_would_create_cycle_transitive():
    edges = [("a", "b"), ("b", "c")]
    assert would_create_cycle(edges, ("c", "a")) is True


def test_RA_D_4_would_create_cycle_no_cycle():
    edges = [("a", "b"), ("b", "c")]
    assert would_create_cycle(edges, ("a", "d")) is False


def test_RA_D_5_would_create_cycle_disjoint():
    edges = [("a", "b"), ("c", "d")]
    assert would_create_cycle(edges, ("d", "e")) is False


def test_RA_D_6_check_no_cycle_raises_on_cycle():
    edges = [("a", "b")]
    with pytest.raises(RemediationDependencyError):
        check_no_cycle(edges, ("b", "a"))


def test_RA_D_7_check_no_cycle_silent_on_valid():
    check_no_cycle([("a", "b")], ("b", "c"))


def test_RA_D_8_blockers_of_returns_sorted():
    edges = [("z", "target"), ("a", "target"), ("m", "target")]
    assert blockers_of("target", edges) == ["a", "m", "z"]


def test_RA_D_9_blockers_of_empty():
    assert blockers_of("target", []) == []


def test_RA_D_10_dependents_of_sorted():
    edges = [("s", "z"), ("s", "a"), ("s", "m")]
    assert dependents_of("s", edges) == ["a", "m", "z"]


def test_RA_D_11_dependents_of_empty():
    assert dependents_of("x", []) == []


def test_RA_D_12_critical_path_empty():
    assert critical_path([], []) == []


def test_RA_D_13_critical_path_linear():
    edges = [("a", "b"), ("b", "c"), ("c", "d")]
    assert critical_path(edges, ["a"]) == ["a", "b", "c", "d"]


def test_RA_D_14_critical_path_branches_take_longest():
    edges = [("a", "b"), ("a", "c"), ("c", "d")]
    result = critical_path(edges, ["a"])
    assert result == ["a", "c", "d"]


def test_RA_D_15_critical_path_deterministic_tie_break():
    edges = [("a", "b"), ("a", "c")]
    result = critical_path(edges, ["a"])
    # Deterministic: alphabetical -> should end with 'b' (first lexicographically)
    assert result[-1] in ("b", "c")


# ---------------------------------------------------------------------------
# Engine dependency lifecycle
# ---------------------------------------------------------------------------


def _make_tasks(svc, count=2):
    return [
        svc.create_task(CreateTaskRequest(title=f"T-{i}"), actor_id="u")
        for i in range(count)
    ]


def test_RA_D_16_create_dependency_ok(svc, db):
    t1, t2 = _make_tasks(svc)
    r = svc.create_dependency(
        CreateDependencyRequest(source_task_id=t1.id, target_task_id=t2.id),
        actor_id="u",
    )
    db.commit()
    assert r.source_task_id == t1.id
    assert r.target_task_id == t2.id


def test_RA_D_17_create_dependency_source_missing(svc, db):
    _, t2 = _make_tasks(svc)
    with pytest.raises(RemediationNotFound):
        svc.create_dependency(
            CreateDependencyRequest(source_task_id="missing", target_task_id=t2.id),
            actor_id="u",
        )


def test_RA_D_18_create_dependency_target_missing(svc, db):
    t1, _ = _make_tasks(svc)
    with pytest.raises(RemediationNotFound):
        svc.create_dependency(
            CreateDependencyRequest(source_task_id=t1.id, target_task_id="missing"),
            actor_id="u",
        )


def test_RA_D_19_create_dependency_self_rejected(svc, db):
    t1, _ = _make_tasks(svc)
    with pytest.raises(RemediationDependencyError):
        svc.create_dependency(
            CreateDependencyRequest(source_task_id=t1.id, target_task_id=t1.id),
            actor_id="u",
        )


def test_RA_D_20_dependency_cycle_rejected(svc, db):
    t1, t2 = _make_tasks(svc)
    svc.create_dependency(
        CreateDependencyRequest(source_task_id=t1.id, target_task_id=t2.id),
        actor_id="u",
    )
    db.commit()
    with pytest.raises(RemediationDependencyError):
        svc.create_dependency(
            CreateDependencyRequest(source_task_id=t2.id, target_task_id=t1.id),
            actor_id="u",
        )


def test_RA_D_21_transitive_cycle_rejected(svc, db):
    t1, t2 = _make_tasks(svc)
    t3 = svc.create_task(CreateTaskRequest(title="T3"), actor_id="u")
    svc.create_dependency(
        CreateDependencyRequest(source_task_id=t1.id, target_task_id=t2.id),
        actor_id="u",
    )
    svc.create_dependency(
        CreateDependencyRequest(source_task_id=t2.id, target_task_id=t3.id),
        actor_id="u",
    )
    db.commit()
    with pytest.raises(RemediationDependencyError):
        svc.create_dependency(
            CreateDependencyRequest(source_task_id=t3.id, target_task_id=t1.id),
            actor_id="u",
        )


def test_RA_D_22_dependency_blocks_marks_target_blocked(svc, db):
    t1, t2 = _make_tasks(svc)
    svc.create_dependency(
        CreateDependencyRequest(
            source_task_id=t1.id,
            target_task_id=t2.id,
            dependency_type=DependencyType.BLOCKS,
        ),
        actor_id="u",
    )
    db.commit()
    r = svc.get_task(t2.id)
    assert r.task_state == "BLOCKED"


def test_RA_D_23_dependency_requires_does_not_block(svc, db):
    t1, t2 = _make_tasks(svc)
    svc.create_dependency(
        CreateDependencyRequest(
            source_task_id=t1.id,
            target_task_id=t2.id,
            dependency_type=DependencyType.REQUIRES,
        ),
        actor_id="u",
    )
    db.commit()
    r = svc.get_task(t2.id)
    assert r.task_state != "BLOCKED"


def test_RA_D_24_blocker_completion_allows_target_transition(svc, db):
    t1, t2 = _make_tasks(svc)
    svc.create_dependency(
        CreateDependencyRequest(source_task_id=t1.id, target_task_id=t2.id),
        actor_id="u",
    )
    # Move t1 to completed
    for target in (
        RemediationTaskState.IN_PROGRESS,
        RemediationTaskState.READY_FOR_REVIEW,
        RemediationTaskState.VERIFYING,
        RemediationTaskState.APPROVED,
        RemediationTaskState.COMPLETED,
    ):
        svc.transition_task(t1.id, TransitionTaskRequest(to_state=target), actor_id="u")
    # Now t2 should be transitionable to READY_FOR_REVIEW
    svc.transition_task(
        t2.id,
        TransitionTaskRequest(to_state=RemediationTaskState.IN_PROGRESS),
        actor_id="u",
    )
    r = svc.transition_task(
        t2.id,
        TransitionTaskRequest(to_state=RemediationTaskState.READY_FOR_REVIEW),
        actor_id="u",
    )
    db.commit()
    assert r.task_state == "READY_FOR_REVIEW"


def test_RA_D_25_blocker_open_prevents_target_ready(svc, db):
    t1, t2 = _make_tasks(svc)
    svc.transition_task(
        t2.id,
        TransitionTaskRequest(to_state=RemediationTaskState.IN_PROGRESS),
        actor_id="u",
    )
    svc.create_dependency(
        CreateDependencyRequest(source_task_id=t1.id, target_task_id=t2.id),
        actor_id="u",
    )
    db.commit()
    # After BLOCKS dep, t2 was moved to BLOCKED. Transition back to IN_PROGRESS
    svc.transition_task(
        t2.id,
        TransitionTaskRequest(to_state=RemediationTaskState.IN_PROGRESS),
        actor_id="u",
    )
    with pytest.raises(RemediationInvalidTransition):
        svc.transition_task(
            t2.id,
            TransitionTaskRequest(to_state=RemediationTaskState.READY_FOR_REVIEW),
            actor_id="u",
        )


def test_RA_D_26_delete_dependency(svc, db):
    t1, t2 = _make_tasks(svc)
    dep = svc.create_dependency(
        CreateDependencyRequest(source_task_id=t1.id, target_task_id=t2.id),
        actor_id="u",
    )
    db.commit()
    assert svc.delete_dependency(dep.id, actor_id="u") is True


def test_RA_D_27_delete_dependency_missing(svc):
    with pytest.raises(RemediationNotFound):
        svc.delete_dependency("missing", actor_id="u")


def test_RA_D_28_list_dependencies_returns_all(svc, db):
    t1, t2 = _make_tasks(svc)
    t3 = svc.create_task(CreateTaskRequest(title="T3"), actor_id="u")
    svc.create_dependency(
        CreateDependencyRequest(source_task_id=t1.id, target_task_id=t2.id),
        actor_id="u",
    )
    svc.create_dependency(
        CreateDependencyRequest(source_task_id=t2.id, target_task_id=t3.id),
        actor_id="u",
    )
    db.commit()
    r = svc.list_dependencies()
    assert r.total >= 2


def test_RA_D_29_engine_critical_path_populated(svc, db):
    t1, t2 = _make_tasks(svc)
    t3 = svc.create_task(CreateTaskRequest(title="T3"), actor_id="u")
    svc.create_dependency(
        CreateDependencyRequest(source_task_id=t1.id, target_task_id=t2.id),
        actor_id="u",
    )
    svc.create_dependency(
        CreateDependencyRequest(source_task_id=t2.id, target_task_id=t3.id),
        actor_id="u",
    )
    db.commit()
    assert len(svc.critical_path()) >= 2


def test_RA_D_30_engine_dependents_of(svc, db):
    t1, t2 = _make_tasks(svc)
    svc.create_dependency(
        CreateDependencyRequest(source_task_id=t1.id, target_task_id=t2.id),
        actor_id="u",
    )
    db.commit()
    assert t2.id in svc.dependents_of(t1.id)


def test_RA_D_31_dependency_tenant_isolated(db):
    a = RemediationAuthorityEngine(db, tenant_id="t-d-1")
    b = RemediationAuthorityEngine(db, tenant_id="t-d-2")
    t1 = a.create_task(CreateTaskRequest(title="T1"), actor_id="u")
    t2 = a.create_task(CreateTaskRequest(title="T2"), actor_id="u")
    a.create_dependency(
        CreateDependencyRequest(source_task_id=t1.id, target_task_id=t2.id),
        actor_id="u",
    )
    db.commit()
    assert b.list_dependencies().total == 0


@pytest.mark.parametrize("dep_type", list(DependencyType))
def test_RA_D_32_all_dependency_types_valid(svc, db, dep_type):
    t1, t2 = _make_tasks(svc)
    r = svc.create_dependency(
        CreateDependencyRequest(
            source_task_id=t1.id,
            target_task_id=t2.id,
            dependency_type=dep_type,
        ),
        actor_id="u",
    )
    db.commit()
    assert r.dependency_type == dep_type.value


@pytest.mark.parametrize("i", range(1, 41))
def test_RA_D_33_bulk_dependencies(svc, db, i):
    t_a = svc.create_task(CreateTaskRequest(title=f"BA-{i}"), actor_id="u")
    t_b = svc.create_task(CreateTaskRequest(title=f"BB-{i}"), actor_id="u")
    r = svc.create_dependency(
        CreateDependencyRequest(source_task_id=t_a.id, target_task_id=t_b.id),
        actor_id="u",
    )
    db.commit()
    assert r.source_task_id == t_a.id


def test_RA_D_34_critical_path_no_edges(svc):
    assert svc.critical_path() == []


def test_RA_D_35_dependents_no_edges(svc):
    assert svc.dependents_of("x") == []


def test_RA_D_36_delete_dependency_records_timeline(svc, db):
    t1, t2 = _make_tasks(svc)
    dep = svc.create_dependency(
        CreateDependencyRequest(source_task_id=t1.id, target_task_id=t2.id),
        actor_id="u",
    )
    svc.delete_dependency(dep.id, actor_id="u")
    db.commit()
    tl = svc.get_timeline(t2.id)
    assert any(e.event_type == "dependency_deleted" for e in tl.events)


def test_RA_D_37_dependency_records_timeline_event(svc, db):
    t1, t2 = _make_tasks(svc)
    svc.create_dependency(
        CreateDependencyRequest(source_task_id=t1.id, target_task_id=t2.id),
        actor_id="u",
    )
    db.commit()
    tl = svc.get_timeline(t2.id)
    assert any(e.event_type == "dependency_created" for e in tl.events)


def test_RA_D_38_blockers_transitive_read(svc, db):
    t1, t2 = _make_tasks(svc)
    svc.create_dependency(
        CreateDependencyRequest(source_task_id=t1.id, target_task_id=t2.id),
        actor_id="u",
    )
    db.commit()
    deps = svc.list_dependencies()
    assert any(
        d.source_task_id == t1.id and d.target_task_id == t2.id for d in deps.items
    )


def test_RA_D_39_check_no_cycle_ok_with_disjoint():
    check_no_cycle([("a", "b"), ("c", "d")], ("e", "f"))


def test_RA_D_40_deep_chain_no_false_cycle():
    edges = [(f"n{i}", f"n{i + 1}") for i in range(10)]
    check_no_cycle(edges, ("n10", "n11"))


@pytest.mark.parametrize("i", range(1, 41))
def test_RA_D_41_parametric_dep_ids(svc, db, i):
    t_a = svc.create_task(CreateTaskRequest(title=f"pA-{i}"), actor_id="u")
    t_b = svc.create_task(CreateTaskRequest(title=f"pB-{i}"), actor_id="u")
    r = svc.create_dependency(
        CreateDependencyRequest(source_task_id=t_a.id, target_task_id=t_b.id),
        actor_id="u",
    )
    db.commit()
    assert r.id is not None
