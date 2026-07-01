"""Tests for PR 18.3 — Remediation Authority verification lifecycle."""

from __future__ import annotations

import pytest
from sqlalchemy.orm import Session

from api.db import get_engine
from services.remediation_authority.engine import RemediationAuthorityEngine
from services.remediation_authority.models import (
    RemediationTaskState,
    RemediationVerificationState,
)
from services.remediation_authority.schemas import (
    CreateTaskRequest,
    CreateVerificationRequest,
    RemediationNotFound,
    RemediationVerificationError,
    TransitionTaskRequest,
)
from services.remediation_authority.verification import (
    TERMINAL_VERIFICATION_STATES,
    approval_completes_task,
    can_transition_task_to_verifying,
    is_terminal,
    normalize_state,
)


_TENANT = "tenant-ra-ver-001"


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
# Pure verification helpers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("state", ["APPROVED", "REJECTED", "EXPIRED"])
def test_RA_V_1_is_terminal_true(state):
    assert is_terminal(state) is True


@pytest.mark.parametrize("state", ["PENDING", "IN_REVIEW"])
def test_RA_V_2_is_terminal_false(state):
    assert is_terminal(state) is False


def test_RA_V_3_terminal_set_size():
    assert len(TERMINAL_VERIFICATION_STATES) == 3


@pytest.mark.parametrize("state", list(RemediationVerificationState))
def test_RA_V_4_normalize_state_accepts_all_valid(state):
    assert normalize_state(state.value) == state.value


@pytest.mark.parametrize("state", ["", "unknown", "approved", "IN-REVIEW"])
def test_RA_V_5_normalize_state_rejects_invalid(state):
    with pytest.raises(RemediationVerificationError):
        normalize_state(state)


def test_RA_V_6_can_transition_to_verifying_from_ready():
    assert can_transition_task_to_verifying("READY_FOR_REVIEW") is True


@pytest.mark.parametrize(
    "state", ["OPEN", "IN_PROGRESS", "BLOCKED", "COMPLETED", "CANCELLED"]
)
def test_RA_V_7_can_transition_to_verifying_false(state):
    assert can_transition_task_to_verifying(state) is False


def test_RA_V_8_approval_completes_task_true():
    assert approval_completes_task("VERIFYING", "APPROVED") is True


@pytest.mark.parametrize(
    "task,ver",
    [
        ("OPEN", "APPROVED"),
        ("VERIFYING", "REJECTED"),
        ("VERIFYING", "PENDING"),
        ("IN_PROGRESS", "APPROVED"),
    ],
)
def test_RA_V_9_approval_completes_task_false(task, ver):
    assert approval_completes_task(task, ver) is False


# ---------------------------------------------------------------------------
# Engine verification lifecycle
# ---------------------------------------------------------------------------


def _ready_task(svc):
    """Create a task and walk it to READY_FOR_REVIEW."""
    t = svc.create_task(CreateTaskRequest(title="T"), actor_id="u")
    for target in (
        RemediationTaskState.IN_PROGRESS,
        RemediationTaskState.READY_FOR_REVIEW,
    ):
        t = svc.transition_task(
            t.id, TransitionTaskRequest(to_state=target), actor_id="u"
        )
    return t


def test_RA_V_10_create_verification_ok(svc, db):
    t = _ready_task(svc)
    r = svc.create_verification(
        CreateVerificationRequest(
            task_id=t.id,
            verifier_id="v",
            verification_state=RemediationVerificationState.IN_REVIEW,
        ),
        actor_id="u",
    )
    db.commit()
    assert r.verification_state == "IN_REVIEW"


def test_RA_V_11_in_review_moves_task_to_verifying(svc, db):
    t = _ready_task(svc)
    svc.create_verification(
        CreateVerificationRequest(
            task_id=t.id,
            verifier_id="v",
            verification_state=RemediationVerificationState.IN_REVIEW,
        ),
        actor_id="u",
    )
    db.commit()
    r = svc.get_task(t.id)
    assert r.task_state == "VERIFYING"


def test_RA_V_12_approval_moves_task_to_approved(svc, db):
    t = _ready_task(svc)
    svc.create_verification(
        CreateVerificationRequest(
            task_id=t.id,
            verifier_id="v",
            verification_state=RemediationVerificationState.IN_REVIEW,
        ),
        actor_id="u",
    )
    svc.create_verification(
        CreateVerificationRequest(
            task_id=t.id,
            verifier_id="v",
            verification_state=RemediationVerificationState.APPROVED,
        ),
        actor_id="u",
    )
    db.commit()
    r = svc.get_task(t.id)
    assert r.task_state == "APPROVED"


def test_RA_V_13_rejection_moves_verifying_back_to_in_progress(svc, db):
    t = _ready_task(svc)
    svc.create_verification(
        CreateVerificationRequest(
            task_id=t.id,
            verifier_id="v",
            verification_state=RemediationVerificationState.IN_REVIEW,
        ),
        actor_id="u",
    )
    svc.create_verification(
        CreateVerificationRequest(
            task_id=t.id,
            verifier_id="v",
            verification_state=RemediationVerificationState.REJECTED,
        ),
        actor_id="u",
    )
    db.commit()
    r = svc.get_task(t.id)
    assert r.task_state == "IN_PROGRESS"


def test_RA_V_14_missing_task_raises(svc):
    with pytest.raises(RemediationNotFound):
        svc.create_verification(
            CreateVerificationRequest(task_id="missing", verifier_id="v"),
            actor_id="u",
        )


def test_RA_V_15_verification_recorded(svc, db):
    t = _ready_task(svc)
    r = svc.create_verification(
        CreateVerificationRequest(task_id=t.id, verifier_id="v", notes="looks fine"),
        actor_id="u",
    )
    db.commit()
    assert r.notes == "looks fine"


def test_RA_V_16_verification_tenant_isolated(db):
    a = RemediationAuthorityEngine(db, tenant_id="t-v-1")
    b = RemediationAuthorityEngine(db, tenant_id="t-v-2")
    t = a.create_task(CreateTaskRequest(title="T"), actor_id="u")
    a.transition_task(
        t.id,
        TransitionTaskRequest(to_state=RemediationTaskState.IN_PROGRESS),
        actor_id="u",
    )
    a.transition_task(
        t.id,
        TransitionTaskRequest(to_state=RemediationTaskState.READY_FOR_REVIEW),
        actor_id="u",
    )
    a.create_verification(
        CreateVerificationRequest(task_id=t.id, verifier_id="v"),
        actor_id="u",
    )
    db.commit()
    assert b.list_verifications().total == 0


def test_RA_V_17_list_verifications_empty(svc):
    assert svc.list_verifications().total == 0


def test_RA_V_18_list_verifications_after_create(svc, db):
    t = _ready_task(svc)
    svc.create_verification(
        CreateVerificationRequest(task_id=t.id, verifier_id="v"),
        actor_id="u",
    )
    db.commit()
    assert svc.list_verifications().total >= 1


def test_RA_V_19_list_verifications_filter_by_task(svc, db):
    t1 = _ready_task(svc)
    t2 = _ready_task(svc)
    svc.create_verification(
        CreateVerificationRequest(task_id=t1.id, verifier_id="v"),
        actor_id="u",
    )
    svc.create_verification(
        CreateVerificationRequest(task_id=t2.id, verifier_id="v"),
        actor_id="u",
    )
    db.commit()
    r = svc.list_verifications(task_id=t1.id)
    assert all(v.task_id == t1.id for v in r.items)


def test_RA_V_20_verification_records_timeline(svc, db):
    t = _ready_task(svc)
    svc.create_verification(
        CreateVerificationRequest(task_id=t.id, verifier_id="v"),
        actor_id="u",
    )
    db.commit()
    tl = svc.get_timeline(t.id)
    assert any(e.event_type == "verification_created" for e in tl.events)


@pytest.mark.parametrize("state", list(RemediationVerificationState))
def test_RA_V_21_all_verification_states_recordable(svc, db, state):
    t = _ready_task(svc)
    r = svc.create_verification(
        CreateVerificationRequest(
            task_id=t.id, verifier_id="v", verification_state=state
        ),
        actor_id="u",
    )
    db.commit()
    assert r.verification_state == state.value


def test_RA_V_22_full_approval_chain(svc, db):
    """Full approval chain: OPEN -> IN_PROGRESS -> READY -> VERIFYING (via
    IN_REVIEW verification) -> APPROVED (via APPROVED verification) -> COMPLETED
    (via transition).
    """
    t = _ready_task(svc)
    svc.create_verification(
        CreateVerificationRequest(
            task_id=t.id,
            verifier_id="v",
            verification_state=RemediationVerificationState.IN_REVIEW,
        ),
        actor_id="u",
    )
    svc.create_verification(
        CreateVerificationRequest(
            task_id=t.id,
            verifier_id="v",
            verification_state=RemediationVerificationState.APPROVED,
        ),
        actor_id="u",
    )
    r = svc.transition_task(
        t.id,
        TransitionTaskRequest(to_state=RemediationTaskState.COMPLETED),
        actor_id="u",
    )
    db.commit()
    assert r.task_state == "COMPLETED"


def test_RA_V_23_verification_evidence_id_recorded(svc, db):
    t = _ready_task(svc)
    r = svc.create_verification(
        CreateVerificationRequest(task_id=t.id, verifier_id="v", evidence_id="ev-123"),
        actor_id="u",
    )
    db.commit()
    assert r.evidence_id == "ev-123"


@pytest.mark.parametrize("i", range(1, 41))
def test_RA_V_24_bulk_verifications(svc, db, i):
    t = _ready_task(svc)
    r = svc.create_verification(
        CreateVerificationRequest(task_id=t.id, verifier_id=f"v-{i}"),
        actor_id="u",
    )
    db.commit()
    assert r.verifier_id == f"v-{i}"


def test_RA_V_25_in_review_from_non_ready_task_does_not_move(svc, db):
    t = svc.create_task(CreateTaskRequest(title="T"), actor_id="u")
    svc.create_verification(
        CreateVerificationRequest(
            task_id=t.id,
            verifier_id="v",
            verification_state=RemediationVerificationState.IN_REVIEW,
        ),
        actor_id="u",
    )
    db.commit()
    r = svc.get_task(t.id)
    # Task was not READY_FOR_REVIEW; state unchanged.
    assert r.task_state == "OPEN"


def test_RA_V_26_rejected_from_non_verifying_task_leaves_state(svc, db):
    t = svc.create_task(CreateTaskRequest(title="T"), actor_id="u")
    svc.create_verification(
        CreateVerificationRequest(
            task_id=t.id,
            verifier_id="v",
            verification_state=RemediationVerificationState.REJECTED,
        ),
        actor_id="u",
    )
    db.commit()
    r = svc.get_task(t.id)
    assert r.task_state == "OPEN"


def test_RA_V_27_pending_from_ready_does_not_move(svc, db):
    t = _ready_task(svc)
    svc.create_verification(
        CreateVerificationRequest(
            task_id=t.id,
            verifier_id="v",
            verification_state=RemediationVerificationState.PENDING,
        ),
        actor_id="u",
    )
    db.commit()
    r = svc.get_task(t.id)
    assert r.task_state == "READY_FOR_REVIEW"


def test_RA_V_28_expired_records_state_only(svc, db):
    t = _ready_task(svc)
    r = svc.create_verification(
        CreateVerificationRequest(
            task_id=t.id,
            verifier_id="v",
            verification_state=RemediationVerificationState.EXPIRED,
        ),
        actor_id="u",
    )
    db.commit()
    assert r.verification_state == "EXPIRED"


@pytest.mark.parametrize("i", range(1, 21))
@pytest.mark.parametrize("state", list(RemediationVerificationState))
def test_RA_V_29_verification_state_matrix(svc, db, i, state):
    t = svc.create_task(CreateTaskRequest(title=f"vt-{i}-{state.value}"), actor_id="u")
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
    r = svc.create_verification(
        CreateVerificationRequest(
            task_id=t.id, verifier_id=f"v-{i}", verification_state=state
        ),
        actor_id="u",
    )
    db.commit()
    assert r.verification_state == state.value
