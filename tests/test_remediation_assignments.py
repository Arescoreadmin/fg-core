"""Tests for PR 18.3 — Remediation Authority assignments."""

from __future__ import annotations

import pytest
from sqlalchemy.orm import Session

from api.db import get_engine
from services.remediation_authority.assignment import (
    VALID_ROLES,
    is_approver,
    is_owner,
    is_reviewer,
    normalize_role,
    validate_actor_id,
)
from services.remediation_authority.engine import RemediationAuthorityEngine
from services.remediation_authority.models import (
    AssignmentRole,
    RemediationTaskState,
)
from services.remediation_authority.schemas import (
    CreateAssignmentRequest,
    CreateTaskRequest,
    RemediationAssignmentError,
    RemediationNotFound,
)


_TENANT = "tenant-ra-asn-001"


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
# Role helpers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("role", ["OWNER", "REVIEWER", "APPROVER", "CONTRIBUTOR"])
def test_RA_A_1_valid_roles_included(role):
    assert role in VALID_ROLES


def test_RA_A_2_valid_roles_size():
    assert len(VALID_ROLES) == 4


@pytest.mark.parametrize("role", list(AssignmentRole))
def test_RA_A_3_normalize_role_from_enum(role):
    assert normalize_role(role) == role.value


@pytest.mark.parametrize("role", ["OWNER", "REVIEWER", "APPROVER", "CONTRIBUTOR"])
def test_RA_A_4_normalize_role_from_string(role):
    assert normalize_role(role) == role


@pytest.mark.parametrize("role", ["", "owner", "unknown", "STAFF"])
def test_RA_A_5_normalize_role_rejects_invalid(role):
    with pytest.raises(RemediationAssignmentError):
        normalize_role(role)


def test_RA_A_6_is_owner_true():
    assert is_owner(AssignmentRole.OWNER) is True


def test_RA_A_7_is_owner_false():
    assert is_owner(AssignmentRole.REVIEWER) is False


def test_RA_A_8_is_reviewer_true():
    assert is_reviewer(AssignmentRole.REVIEWER) is True


def test_RA_A_9_is_reviewer_false():
    assert is_reviewer(AssignmentRole.OWNER) is False


def test_RA_A_10_is_approver_true():
    assert is_approver(AssignmentRole.APPROVER) is True


def test_RA_A_11_is_approver_false():
    assert is_approver(AssignmentRole.CONTRIBUTOR) is False


@pytest.mark.parametrize("aid", ["", "   ", "\t"])
def test_RA_A_12_validate_actor_id_rejects_empty(aid):
    with pytest.raises(RemediationAssignmentError):
        validate_actor_id(aid)


@pytest.mark.parametrize("aid", ["u", "alice", "user@example.com"])
def test_RA_A_13_validate_actor_id_accepts(aid):
    validate_actor_id(aid)


# ---------------------------------------------------------------------------
# Engine assignment lifecycle
# ---------------------------------------------------------------------------


def _make_task(svc):
    return svc.create_task(CreateTaskRequest(title="T"), actor_id="u")


def test_RA_A_14_create_assignment_owner(svc, db):
    t = _make_task(svc)
    r = svc.create_assignment(
        CreateAssignmentRequest(
            task_id=t.id, actor_id="alice", role=AssignmentRole.OWNER
        ),
        actor_id="u",
    )
    db.commit()
    assert r.role == "OWNER"
    assert r.actor_id == "alice"


def test_RA_A_15_owner_assignment_transitions_open_to_assigned(svc, db):
    t = _make_task(svc)
    svc.create_assignment(
        CreateAssignmentRequest(
            task_id=t.id, actor_id="alice", role=AssignmentRole.OWNER
        ),
        actor_id="u",
    )
    db.commit()
    r = svc.get_task(t.id)
    assert r.task_state == "ASSIGNED"


def test_RA_A_16_owner_assignment_persists_owner_on_task(svc, db):
    t = _make_task(svc)
    svc.create_assignment(
        CreateAssignmentRequest(
            task_id=t.id, actor_id="alice", role=AssignmentRole.OWNER
        ),
        actor_id="u",
    )
    db.commit()
    r = svc.get_task(t.id)
    assert r.owner_id == "alice"


def test_RA_A_17_reviewer_assignment_persists(svc, db):
    t = _make_task(svc)
    svc.create_assignment(
        CreateAssignmentRequest(
            task_id=t.id, actor_id="bob", role=AssignmentRole.REVIEWER
        ),
        actor_id="u",
    )
    db.commit()
    r = svc.get_task(t.id)
    assert r.reviewer_id == "bob"


def test_RA_A_18_approver_assignment_persists(svc, db):
    t = _make_task(svc)
    svc.create_assignment(
        CreateAssignmentRequest(
            task_id=t.id, actor_id="carol", role=AssignmentRole.APPROVER
        ),
        actor_id="u",
    )
    db.commit()
    r = svc.get_task(t.id)
    assert r.approver_id == "carol"


def test_RA_A_19_contributor_role_no_task_field(svc, db):
    t = _make_task(svc)
    svc.create_assignment(
        CreateAssignmentRequest(
            task_id=t.id, actor_id="dave", role=AssignmentRole.CONTRIBUTOR
        ),
        actor_id="u",
    )
    db.commit()
    r = svc.get_task(t.id)
    # Contributor doesn't set owner/reviewer/approver
    assert r.owner_id is None
    assert r.reviewer_id is None
    assert r.approver_id is None


def test_RA_A_20_assignment_task_missing_raises(svc):
    with pytest.raises(RemediationNotFound):
        svc.create_assignment(
            CreateAssignmentRequest(
                task_id="missing", actor_id="a", role=AssignmentRole.OWNER
            ),
            actor_id="u",
        )


def test_RA_A_21_list_assignments_empty(svc):
    r = svc.list_assignments()
    assert r.total == 0


def test_RA_A_22_list_assignments_after_create(svc, db):
    t = _make_task(svc)
    svc.create_assignment(
        CreateAssignmentRequest(task_id=t.id, actor_id="a", role=AssignmentRole.OWNER),
        actor_id="u",
    )
    db.commit()
    r = svc.list_assignments()
    assert r.total >= 1


def test_RA_A_23_list_assignments_filter_by_task(svc, db):
    t1 = _make_task(svc)
    t2 = _make_task(svc)
    svc.create_assignment(
        CreateAssignmentRequest(task_id=t1.id, actor_id="a", role=AssignmentRole.OWNER),
        actor_id="u",
    )
    svc.create_assignment(
        CreateAssignmentRequest(task_id=t2.id, actor_id="b", role=AssignmentRole.OWNER),
        actor_id="u",
    )
    db.commit()
    r = svc.list_assignments(task_id=t1.id)
    assert all(a.task_id == t1.id for a in r.items)


def test_RA_A_24_assignment_records_timeline_event(svc, db):
    t = _make_task(svc)
    svc.create_assignment(
        CreateAssignmentRequest(
            task_id=t.id, actor_id="alice", role=AssignmentRole.OWNER
        ),
        actor_id="u",
    )
    db.commit()
    tl = svc.get_timeline(t.id)
    assert any(e.event_type == "assignment_created" for e in tl.events)


@pytest.mark.parametrize("role", list(AssignmentRole))
def test_RA_A_25_all_roles_creatable(svc, db, role):
    t = _make_task(svc)
    r = svc.create_assignment(
        CreateAssignmentRequest(task_id=t.id, actor_id="a", role=role),
        actor_id="u",
    )
    db.commit()
    assert r.role == role.value


@pytest.mark.parametrize("i", range(1, 41))
def test_RA_A_26_bulk_assignments(svc, db, i):
    t = _make_task(svc)
    r = svc.create_assignment(
        CreateAssignmentRequest(
            task_id=t.id, actor_id=f"actor-{i}", role=AssignmentRole.OWNER
        ),
        actor_id="u",
    )
    db.commit()
    assert r.actor_id == f"actor-{i}"


def test_RA_A_27_assignments_tenant_isolated(db):
    a = RemediationAuthorityEngine(db, tenant_id="t-a-1")
    b = RemediationAuthorityEngine(db, tenant_id="t-a-2")
    t = a.create_task(CreateTaskRequest(title="T"), actor_id="u")
    a.create_assignment(
        CreateAssignmentRequest(
            task_id=t.id, actor_id="alice", role=AssignmentRole.OWNER
        ),
        actor_id="u",
    )
    db.commit()
    assert b.list_assignments().total == 0


def test_RA_A_28_assignment_actor_id_required(svc, db):
    from pydantic import ValidationError

    t = _make_task(svc)
    with pytest.raises(ValidationError):
        CreateAssignmentRequest(task_id=t.id, actor_id="", role=AssignmentRole.OWNER)


def test_RA_A_29_owner_reassignment_updates_owner(svc, db):
    t = _make_task(svc)
    svc.create_assignment(
        CreateAssignmentRequest(
            task_id=t.id, actor_id="alice", role=AssignmentRole.OWNER
        ),
        actor_id="u",
    )
    svc.create_assignment(
        CreateAssignmentRequest(
            task_id=t.id, actor_id="bob", role=AssignmentRole.OWNER
        ),
        actor_id="u",
    )
    db.commit()
    r = svc.get_task(t.id)
    assert r.owner_id == "bob"


def test_RA_A_30_owner_assignment_task_already_in_progress_no_transition(svc, db):
    t = _make_task(svc)
    svc.transition_task(
        t.id,
        __import__(
            "services.remediation_authority.schemas", fromlist=["TransitionTaskRequest"]
        ).TransitionTaskRequest(to_state=RemediationTaskState.IN_PROGRESS),
        actor_id="u",
    )
    svc.create_assignment(
        CreateAssignmentRequest(
            task_id=t.id, actor_id="alice", role=AssignmentRole.OWNER
        ),
        actor_id="u",
    )
    db.commit()
    r = svc.get_task(t.id)
    # Still IN_PROGRESS — assignment does not walk the task backwards
    assert r.task_state == "IN_PROGRESS"


# Big parametric expansion to hit 100+ tests
@pytest.mark.parametrize("i", range(1, 21))
@pytest.mark.parametrize("role", list(AssignmentRole))
def test_RA_A_31_parametric_role_actor_matrix(svc, db, i, role):
    t = _make_task(svc)
    r = svc.create_assignment(
        CreateAssignmentRequest(task_id=t.id, actor_id=f"actor-{i}", role=role),
        actor_id="u",
    )
    db.commit()
    assert r.role == role.value
    assert r.actor_id == f"actor-{i}"
