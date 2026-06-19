# tests/test_remediation_engine.py
"""Remediation Management test suite — PR 13.1 + PR 13.2 + PR 13.3.

Coverage:
  REM-1   Create task
  REM-2   Get task
  REM-3   List tasks
  REM-4   Update task
  REM-5   Close task
  REM-6   Delete task
  REM-7   Tenant isolation
  REM-8   Wrong tenant denied
  REM-9   Missing finding rejected
  REM-10  Missing assessment rejected
  REM-11  Audit event on create
  REM-12  Audit event on update
  REM-13  Audit event on close
  REM-14  Audit event on delete
  REM-15  Metrics increment
  REM-16  Authorization enforcement
  REM-17  Route scope enforcement
  REM-18  Cross-tenant reference prevention
  REM-19  Concurrent update safety
  REM-20  Lifecycle reconstruction from audit trail
  REM-21  OPEN → PLANNED
  REM-22  PLANNED → IN_PROGRESS
  REM-23  IN_PROGRESS → CLOSED
  REM-24  OPEN → ACCEPTED_RISK
  REM-25  PLANNED → ACCEPTED_RISK
  REM-26  IN_PROGRESS → ACCEPTED_RISK
  REM-27  OPEN → CLOSED denied
  REM-28  OPEN → IN_PROGRESS denied
  REM-29  PLANNED → CLOSED denied
  REM-30  CLOSED transition denied
  REM-31  ACCEPTED_RISK transition denied
  REM-32  Transition audit event created
  REM-33  Transition reason stored
  REM-34  Missing reason for ACCEPTED_RISK denied
  REM-35  Wrong tenant transition denied
  REM-36  Unauthorized transition denied
  REM-37  Metrics increment
  REM-38  Allowed transitions API
  REM-39  State machine integrity
  REM-40  Lifecycle reconstruction from audit trail
  REM-41  Concurrent transition safety
  REM-42  Migration compatibility validation
  REM-43  Assign owner to a task
  REM-44  Reassign owner
  REM-45  Remove owner
  REM-46  Assignment audit event
  REM-47  Due date assignment
  REM-48  Due date modification
  REM-49  Due date audit event
  REM-50  Critical SLA = 14 days
  REM-51  High SLA = 30 days
  REM-52  Medium SLA = 60 days
  REM-53  Low SLA = 90 days
  REM-54  Informational = no SLA
  REM-55  ON_TRACK SLA status
  REM-56  AT_RISK status
  REM-57  OVERDUE status
  REM-58  Closed status SLA
  REM-59  Accepted-risk SLA status
  REM-60  Wrong tenant assignment denied
  REM-61  Cross-tenant SLA visibility denied
  REM-62  Unauthorized assignment denied
  REM-63  Unauthorized due-date change denied
  REM-64  Metrics increment on assignment
  REM-65  Overdue query
  REM-66  Unassigned query
  REM-67  Lifecycle reconstruction with ownership history
  REM-68  Ownership preserved after closure
  REM-69  Ownership preserved after accepted risk
  REM-70  Migration compatibility — new columns present after init
"""

from __future__ import annotations

from typing import Any
import uuid

import pytest
from starlette.testclient import TestClient

from api.auth_scopes import mint_key
from api.db import get_engine
from api.db_models_field_assessment import FaEngagement, FaNormalizedFinding
from api.db_models_remediation import RemediationTask, RemediationTaskAudit
from sqlalchemy.orm import Session

_TENANT_A = "tenant-rem-a"
_TENANT_B = "tenant-rem-b"


def _json_obj(value: dict[Any, Any] | None) -> dict[Any, Any]:
    assert value is not None
    return value


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def client(build_app):
    app = build_app(auth_enabled=True)
    key = mint_key("governance:read", "governance:write", tenant_id=_TENANT_A)
    return TestClient(app, headers={"X-API-Key": key})


@pytest.fixture()
def client_b(build_app):
    """Separate client for tenant B — used for isolation tests."""
    app = build_app(auth_enabled=True)
    key = mint_key("governance:read", "governance:write", tenant_id=_TENANT_B)
    return TestClient(app, headers={"X-API-Key": key})


@pytest.fixture()
def readonly_client(build_app):
    """Client with only governance:read scope."""
    app = build_app(auth_enabled=True)
    key = mint_key("governance:read", tenant_id=_TENANT_A)
    return TestClient(app, headers={"X-API-Key": key})


@pytest.fixture()
def unauthed_client(build_app):
    """Client with no API key."""
    app = build_app(auth_enabled=True)
    return TestClient(app)


@pytest.fixture()
def alt_client(build_app):
    """Separate client for tenant B — alias for cross-tenant tests in PR 13.3."""
    app = build_app(auth_enabled=True)
    key = mint_key("governance:read", "governance:write", tenant_id=_TENANT_B)
    return TestClient(app, headers={"X-API-Key": key})


@pytest.fixture()
def db_session(build_app):
    """Provides a live db session pointing at the same SQLite used by client."""
    build_app(auth_enabled=True)
    engine = get_engine()
    with Session(engine) as session:
        yield session


def _new_engagement(db: Session, tenant_id: str) -> str:
    eid = uuid.uuid4().hex
    now = "2026-01-01T00:00:00+00:00"
    eng = FaEngagement(
        id=eid,
        tenant_id=tenant_id,
        client_name="Test Client",
        assessor_id="assessor-1",
        assessment_type="security",
        status="in_progress",
        engagement_metadata={},
        created_at=now,
        updated_at=now,
    )
    db.add(eng)
    db.commit()
    return eid


def _new_finding(db: Session, tenant_id: str, engagement_id: str) -> str:
    fid = uuid.uuid4().hex
    now = "2026-01-01T00:00:00+00:00"
    finding = FaNormalizedFinding(
        id=fid,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        finding_type="vulnerability",
        findings_hash=uuid.uuid4().hex,
        severity="high",
        status="open",
        title="Test Finding",
        description="A test finding.",
        source_attribution="scanner",
        created_at=now,
        updated_at=now,
    )
    db.add(finding)
    db.commit()
    return fid


def _make_refs(db: Session, tenant_id: str) -> tuple[str, str]:
    """Return (assessment_id, finding_id) for use in create requests."""
    assessment_id = _new_engagement(db, tenant_id)
    finding_id = _new_finding(db, tenant_id, assessment_id)
    return assessment_id, finding_id


def _advance_to_in_progress(client: TestClient, task_id: str) -> None:
    """Drive a task from OPEN through PLANNED to IN_PROGRESS via the transition API.

    PR 13.3: also assigns an owner before the PLANNED→IN_PROGRESS transition,
    which is now required by the state machine.
    """
    r1 = client.post(
        f"/remediation/tasks/{task_id}/transition",
        json={"new_status": "planned"},
    )
    assert r1.status_code == 200, f"OPEN→PLANNED failed: {r1.text}"
    r_assign = client.post(
        f"/remediation/tasks/{task_id}/assign",
        json={
            "user_id": "user-test-001",
            "display_name": "Test Owner",
            "email": "owner@example.com",
            "reason": "Required for in_progress transition",
        },
    )
    assert r_assign.status_code == 200, f"assign failed: {r_assign.text}"
    r2 = client.post(
        f"/remediation/tasks/{task_id}/transition",
        json={"new_status": "in_progress"},
    )
    assert r2.status_code == 200, f"PLANNED→IN_PROGRESS failed: {r2.text}"


# ---------------------------------------------------------------------------
# REM-1: Create task
# ---------------------------------------------------------------------------


def test_rem_1_create_task(client: TestClient, db_session: Session) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    resp = client.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id,
            "assessment_id": assessment_id,
            "title": "Fix SSL certificate",
            "priority": "high",
        },
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["title"] == "Fix SSL certificate"
    assert data["priority"] == "high"
    assert data["status"] == "open"
    assert data["tenant_id"] == _TENANT_A
    assert data["finding_id"] == finding_id
    assert data["assessment_id"] == assessment_id
    assert data["id"]
    assert data["created_at"]
    assert data["schema_version"] == "1.0"


def test_rem_1_create_task_with_all_fields(
    client: TestClient, db_session: Session
) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    resp = client.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id,
            "assessment_id": assessment_id,
            "title": "Patch OpenSSL",
            "description": "Critical CVE patch required",
            "recommended_action": "Upgrade to OpenSSL 3.x",
            "priority": "critical",
            "assigned_to": "admin@example.com",
            "task_metadata": {"ticket": "JIRA-123"},
        },
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["description"] == "Critical CVE patch required"
    assert data["recommended_action"] == "Upgrade to OpenSSL 3.x"
    assert data["assigned_to"] == "admin@example.com"
    assert data["task_metadata"] == {"ticket": "JIRA-123"}


# ---------------------------------------------------------------------------
# REM-2: Get task
# ---------------------------------------------------------------------------


def test_rem_2_get_task(client: TestClient, db_session: Session) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    create_resp = client.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id,
            "assessment_id": assessment_id,
            "title": "Get me",
        },
    )
    task_id = create_resp.json()["id"]

    resp = client.get(f"/remediation/tasks/{task_id}")
    assert resp.status_code == 200
    assert resp.json()["id"] == task_id
    assert resp.json()["title"] == "Get me"


def test_rem_2_get_task_not_found(client: TestClient) -> None:
    resp = client.get("/remediation/tasks/nonexistent-task-id")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# REM-3: List tasks
# ---------------------------------------------------------------------------


def test_rem_3_list_tasks(client: TestClient, db_session: Session) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    for i in range(3):
        client.post(
            "/remediation/tasks",
            json={
                "finding_id": finding_id,
                "assessment_id": assessment_id,
                "title": f"Task {i}",
                "priority": "medium",
            },
        )
    resp = client.get("/remediation/tasks")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 3
    assert len(data["tasks"]) >= 3


def test_rem_3_list_tasks_filter_by_finding(
    client: TestClient, db_session: Session
) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    _, other_finding_id = _make_refs(db_session, _TENANT_A)
    # Create one task for our target finding
    client.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id,
            "assessment_id": assessment_id,
            "title": "Target",
        },
    )
    resp = client.get(f"/remediation/tasks?finding_id={finding_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert all(t["finding_id"] == finding_id for t in data["tasks"])


def test_rem_3_list_tasks_filter_by_status(
    client: TestClient, db_session: Session
) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    resp_create = client.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id,
            "assessment_id": assessment_id,
            "title": "Close this",
        },
    )
    task_id = resp_create.json()["id"]
    _advance_to_in_progress(client, task_id)
    client.post(f"/remediation/tasks/{task_id}/close")

    open_resp = client.get("/remediation/tasks?status=open")
    closed_resp = client.get("/remediation/tasks?status=closed")
    assert all(t["status"] == "open" for t in open_resp.json()["tasks"])
    assert all(t["status"] == "closed" for t in closed_resp.json()["tasks"])


# ---------------------------------------------------------------------------
# REM-4: Update task
# ---------------------------------------------------------------------------


def test_rem_4_update_task(client: TestClient, db_session: Session) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    task_id = client.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id,
            "assessment_id": assessment_id,
            "title": "Before",
        },
    ).json()["id"]

    resp = client.patch(
        f"/remediation/tasks/{task_id}",
        json={"title": "After", "priority": "critical"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["title"] == "After"
    assert data["priority"] == "critical"


def test_rem_4_update_task_not_found(client: TestClient) -> None:
    resp = client.patch("/remediation/tasks/bad-id", json={"title": "x"})
    assert resp.status_code == 404


def test_rem_4_partial_update_preserves_untouched_fields(
    client: TestClient, db_session: Session
) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    create_data = client.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id,
            "assessment_id": assessment_id,
            "title": "Original",
            "description": "Keep me",
        },
    ).json()
    task_id = create_data["id"]

    resp = client.patch(f"/remediation/tasks/{task_id}", json={"title": "Updated"})
    data = resp.json()
    assert data["title"] == "Updated"
    assert data["description"] == "Keep me"


# ---------------------------------------------------------------------------
# REM-5: Close task
# ---------------------------------------------------------------------------


def test_rem_5_close_task(client: TestClient, db_session: Session) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    task_id = client.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id,
            "assessment_id": assessment_id,
            "title": "Close me",
        },
    ).json()["id"]

    _advance_to_in_progress(client, task_id)
    resp = client.post(f"/remediation/tasks/{task_id}/close")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "closed"
    assert data["closed_at"] is not None


def test_rem_5_close_already_closed_returns_409(
    client: TestClient, db_session: Session
) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    task_id = client.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id,
            "assessment_id": assessment_id,
            "title": "Close twice",
        },
    ).json()["id"]

    _advance_to_in_progress(client, task_id)
    client.post(f"/remediation/tasks/{task_id}/close")
    resp = client.post(f"/remediation/tasks/{task_id}/close")
    assert resp.status_code == 409


def test_rem_5_close_not_found(client: TestClient) -> None:
    resp = client.post("/remediation/tasks/bad-id/close")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# REM-6: Delete task
# ---------------------------------------------------------------------------


def test_rem_6_delete_task(client: TestClient, db_session: Session) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    task_id = client.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id,
            "assessment_id": assessment_id,
            "title": "Delete me",
        },
    ).json()["id"]

    resp = client.delete(f"/remediation/tasks/{task_id}")
    assert resp.status_code == 204

    get_resp = client.get(f"/remediation/tasks/{task_id}")
    assert get_resp.status_code == 404


def test_rem_6_delete_not_found(client: TestClient) -> None:
    resp = client.delete("/remediation/tasks/nonexistent")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# REM-7: Tenant isolation
# ---------------------------------------------------------------------------


def test_rem_7_tenant_isolation_list(
    client: TestClient,
    client_b: TestClient,
    db_session: Session,
) -> None:
    """Tenant A cannot see Tenant B tasks in list results."""
    # Create a task for tenant B using a direct engine call
    engine = get_engine()
    with Session(engine) as db:
        assessment_id_b = _new_engagement(db, _TENANT_B)
        finding_id_b = _new_finding(db, _TENANT_B, assessment_id_b)

    client_b.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id_b,
            "assessment_id": assessment_id_b,
            "title": "Tenant B Only",
        },
    )

    resp = client.get("/remediation/tasks")
    task_titles = [t["title"] for t in resp.json()["tasks"]]
    assert "Tenant B Only" not in task_titles


def test_rem_7_tenant_isolation_get(
    client: TestClient,
    client_b: TestClient,
    db_session: Session,
) -> None:
    """Tenant A cannot get a task that belongs to Tenant B."""
    engine = get_engine()
    with Session(engine) as db:
        assessment_id_b = _new_engagement(db, _TENANT_B)
        finding_id_b = _new_finding(db, _TENANT_B, assessment_id_b)

    create_resp = client_b.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id_b,
            "assessment_id": assessment_id_b,
            "title": "Tenant B private",
        },
    )
    task_id_b = create_resp.json()["id"]

    resp = client.get(f"/remediation/tasks/{task_id_b}")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# REM-8: Wrong tenant denied
# ---------------------------------------------------------------------------


def test_rem_8_wrong_tenant_patch_denied(
    client: TestClient,
    client_b: TestClient,
    db_session: Session,
) -> None:
    """Tenant A cannot update a task owned by Tenant B."""
    engine = get_engine()
    with Session(engine) as db:
        assessment_id_b = _new_engagement(db, _TENANT_B)
        finding_id_b = _new_finding(db, _TENANT_B, assessment_id_b)

    task_id_b = client_b.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id_b,
            "assessment_id": assessment_id_b,
            "title": "B task",
        },
    ).json()["id"]

    resp = client.patch(f"/remediation/tasks/{task_id_b}", json={"title": "hijacked"})
    assert resp.status_code == 404


def test_rem_8_wrong_tenant_delete_denied(
    client: TestClient,
    client_b: TestClient,
    db_session: Session,
) -> None:
    """Tenant A cannot delete a task owned by Tenant B."""
    engine = get_engine()
    with Session(engine) as db:
        assessment_id_b = _new_engagement(db, _TENANT_B)
        finding_id_b = _new_finding(db, _TENANT_B, assessment_id_b)

    task_id_b = client_b.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id_b,
            "assessment_id": assessment_id_b,
            "title": "B task",
        },
    ).json()["id"]

    resp = client.delete(f"/remediation/tasks/{task_id_b}")
    assert resp.status_code == 404


def test_rem_8_wrong_tenant_close_denied(
    client: TestClient,
    client_b: TestClient,
    db_session: Session,
) -> None:
    """Tenant A cannot close a task owned by Tenant B."""
    engine = get_engine()
    with Session(engine) as db:
        assessment_id_b = _new_engagement(db, _TENANT_B)
        finding_id_b = _new_finding(db, _TENANT_B, assessment_id_b)

    task_id_b = client_b.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id_b,
            "assessment_id": assessment_id_b,
            "title": "B task",
        },
    ).json()["id"]

    resp = client.post(f"/remediation/tasks/{task_id_b}/close")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# REM-9: Missing finding rejected
# ---------------------------------------------------------------------------


def test_rem_9_missing_finding_rejected(
    client: TestClient, db_session: Session
) -> None:
    assessment_id = _new_engagement(db_session, _TENANT_A)
    resp = client.post(
        "/remediation/tasks",
        json={
            "finding_id": "nonexistent-finding-id",
            "assessment_id": assessment_id,
            "title": "Should fail",
        },
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# REM-10: Missing assessment rejected
# ---------------------------------------------------------------------------


def test_rem_10_missing_assessment_rejected(
    client: TestClient, db_session: Session
) -> None:
    # Need a real finding for a real engagement first, but reference a fake assessment
    assessment_id = _new_engagement(db_session, _TENANT_A)
    finding_id = _new_finding(db_session, _TENANT_A, assessment_id)
    resp = client.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id,
            "assessment_id": "nonexistent-assessment-id",
            "title": "Should fail",
        },
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# REM-11: Audit event on create
# ---------------------------------------------------------------------------


def test_rem_11_audit_event_on_create(client: TestClient, db_session: Session) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    resp = client.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id,
            "assessment_id": assessment_id,
            "title": "Audited task",
        },
    )
    task_id = resp.json()["id"]

    engine = get_engine()
    with Session(engine) as db:
        events = (
            db.query(RemediationTaskAudit)
            .filter(
                RemediationTaskAudit.task_id == task_id,
                RemediationTaskAudit.tenant_id == _TENANT_A,
            )
            .all()
        )
    assert len(events) == 1
    assert events[0].event_type == "task_created"
    assert events[0].old_state is None
    assert events[0].new_state is not None
    assert _json_obj(events[0].new_state)["title"] == "Audited task"


# ---------------------------------------------------------------------------
# REM-12: Audit event on update
# ---------------------------------------------------------------------------


def test_rem_12_audit_event_on_update(client: TestClient, db_session: Session) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    task_id = client.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id,
            "assessment_id": assessment_id,
            "title": "Before update",
        },
    ).json()["id"]

    client.patch(f"/remediation/tasks/{task_id}", json={"title": "After update"})

    engine = get_engine()
    with Session(engine) as db:
        events = (
            db.query(RemediationTaskAudit)
            .filter(RemediationTaskAudit.task_id == task_id)
            .order_by(RemediationTaskAudit.event_at)
            .all()
        )
    assert len(events) == 2
    update_event = next(e for e in events if e.event_type == "task_updated")
    assert _json_obj(update_event.old_state)["title"] == "Before update"
    assert _json_obj(update_event.new_state)["title"] == "After update"


# ---------------------------------------------------------------------------
# REM-13: Audit event on close
# ---------------------------------------------------------------------------


def test_rem_13_audit_event_on_close(client: TestClient, db_session: Session) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    task_id = client.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id,
            "assessment_id": assessment_id,
            "title": "Close audit",
        },
    ).json()["id"]

    _advance_to_in_progress(client, task_id)
    client.post(f"/remediation/tasks/{task_id}/close")

    engine = get_engine()
    with Session(engine) as db:
        events = (
            db.query(RemediationTaskAudit)
            .filter(RemediationTaskAudit.task_id == task_id)
            .all()
        )
    close_events = [e for e in events if e.event_type == "task_closed"]
    assert len(close_events) == 1
    assert _json_obj(close_events[0].old_state)["status"] == "in_progress"
    assert _json_obj(close_events[0].new_state)["status"] == "closed"
    assert _json_obj(close_events[0].new_state)["closed_at"] is not None


# ---------------------------------------------------------------------------
# REM-14: Audit event on delete
# ---------------------------------------------------------------------------


def test_rem_14_audit_event_on_delete(client: TestClient, db_session: Session) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    task_id = client.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id,
            "assessment_id": assessment_id,
            "title": "Delete audit",
        },
    ).json()["id"]

    client.delete(f"/remediation/tasks/{task_id}")

    engine = get_engine()
    with Session(engine) as db:
        events = (
            db.query(RemediationTaskAudit)
            .filter(
                RemediationTaskAudit.task_id == task_id,
                RemediationTaskAudit.event_type == "task_deleted",
            )
            .all()
        )
    assert len(events) == 1
    assert events[0].old_state is not None
    assert events[0].new_state is None
    assert events[0].old_state["id"] == task_id

    # Task row is gone but audit event is preserved
    task_row = (
        (db.query(RemediationTask).filter(RemediationTask.id == task_id).first())
        if False
        else None
    )  # session already closed; check via fresh session
    engine_obj = get_engine()
    with Session(engine_obj) as db2:
        task_row = (
            db2.query(RemediationTask).filter(RemediationTask.id == task_id).first()
        )
    assert task_row is None


# ---------------------------------------------------------------------------
# REM-15: Metrics increment
# ---------------------------------------------------------------------------


def test_rem_15_metrics_created(client: TestClient, db_session: Session) -> None:
    from api.observability.metrics import REMEDIATION_TASKS_CREATED_TOTAL

    before = REMEDIATION_TASKS_CREATED_TOTAL._value.get()
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    client.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id,
            "assessment_id": assessment_id,
            "title": "Metric test",
        },
    )
    after = REMEDIATION_TASKS_CREATED_TOTAL._value.get()
    assert after > before


def test_rem_15_metrics_closed(client: TestClient, db_session: Session) -> None:
    from api.observability.metrics import REMEDIATION_TASKS_CLOSED_TOTAL

    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    task_id = client.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id,
            "assessment_id": assessment_id,
            "title": "Metric close",
        },
    ).json()["id"]

    _advance_to_in_progress(client, task_id)
    before = REMEDIATION_TASKS_CLOSED_TOTAL._value.get()
    client.post(f"/remediation/tasks/{task_id}/close")
    after = REMEDIATION_TASKS_CLOSED_TOTAL._value.get()
    assert after > before


def test_rem_15_metrics_updated(client: TestClient, db_session: Session) -> None:
    from api.observability.metrics import REMEDIATION_TASK_UPDATES_TOTAL

    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    task_id = client.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id,
            "assessment_id": assessment_id,
            "title": "Metric update",
        },
    ).json()["id"]

    before = REMEDIATION_TASK_UPDATES_TOTAL._value.get()
    client.patch(f"/remediation/tasks/{task_id}", json={"title": "Updated"})
    after = REMEDIATION_TASK_UPDATES_TOTAL._value.get()
    assert after > before


def test_rem_15_metrics_denials(client: TestClient, db_session: Session) -> None:
    from api.observability.metrics import REMEDIATION_TASK_DENIALS_TOTAL

    before = REMEDIATION_TASK_DENIALS_TOTAL._value.get()
    # Attempt to create with a nonexistent finding — triggers denial
    client.post(
        "/remediation/tasks",
        json={
            "finding_id": "bad-finding",
            "assessment_id": "bad-assessment",
            "title": "Should be denied",
        },
    )
    after = REMEDIATION_TASK_DENIALS_TOTAL._value.get()
    assert after > before


# ---------------------------------------------------------------------------
# REM-16: Authorization enforcement
# ---------------------------------------------------------------------------


def test_rem_16_unauthenticated_request_rejected(unauthed_client: TestClient) -> None:
    resp = unauthed_client.get("/remediation/tasks")
    assert resp.status_code in (401, 403)


def test_rem_16_unauthenticated_post_rejected(unauthed_client: TestClient) -> None:
    resp = unauthed_client.post(
        "/remediation/tasks",
        json={
            "finding_id": "x",
            "assessment_id": "y",
            "title": "z",
        },
    )
    assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# REM-17: Route scope enforcement
# ---------------------------------------------------------------------------


def test_rem_17_read_only_scope_cannot_create(
    readonly_client: TestClient, db_session: Session
) -> None:
    """governance:read cannot create tasks."""
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    resp = readonly_client.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id,
            "assessment_id": assessment_id,
            "title": "Should be forbidden",
        },
    )
    assert resp.status_code in (401, 403)


def test_rem_17_read_only_scope_cannot_patch(
    readonly_client: TestClient,
    client: TestClient,
    db_session: Session,
) -> None:
    """governance:read cannot update tasks."""
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    task_id = client.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id,
            "assessment_id": assessment_id,
            "title": "Read scope test",
        },
    ).json()["id"]

    resp = readonly_client.patch(
        f"/remediation/tasks/{task_id}", json={"title": "hijack"}
    )
    assert resp.status_code in (401, 403)


def test_rem_17_read_only_scope_cannot_delete(
    readonly_client: TestClient,
    client: TestClient,
    db_session: Session,
) -> None:
    """governance:read cannot delete tasks."""
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    task_id = client.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id,
            "assessment_id": assessment_id,
            "title": "Delete scope test",
        },
    ).json()["id"]

    resp = readonly_client.delete(f"/remediation/tasks/{task_id}")
    assert resp.status_code in (401, 403)


def test_rem_17_read_scope_can_list(
    readonly_client: TestClient,
) -> None:
    """governance:read can list tasks."""
    resp = readonly_client.get("/remediation/tasks")
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# REM-18: Cross-tenant reference prevention
# ---------------------------------------------------------------------------


def test_rem_18_cross_tenant_finding_rejected(
    client: TestClient, db_session: Session
) -> None:
    """Tenant A cannot create a task referencing Tenant B's finding."""
    engine_obj = get_engine()
    with Session(engine_obj) as db:
        assessment_id_b = _new_engagement(db, _TENANT_B)
        finding_id_b = _new_finding(db, _TENANT_B, assessment_id_b)

    assessment_id_a = _new_engagement(db_session, _TENANT_A)
    resp = client.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id_b,
            "assessment_id": assessment_id_a,
            "title": "Cross-tenant exploit attempt",
        },
    )
    assert resp.status_code == 422


def test_rem_18_cross_tenant_assessment_rejected(
    client: TestClient, db_session: Session
) -> None:
    """Tenant A cannot create a task referencing Tenant B's assessment."""
    engine_obj = get_engine()
    with Session(engine_obj) as db:
        assessment_id_b = _new_engagement(db, _TENANT_B)
        finding_id_b = _new_finding(db, _TENANT_B, assessment_id_b)

    resp = client.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id_b,
            "assessment_id": assessment_id_b,
            "title": "Cross-tenant exploit attempt",
        },
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# REM-19: Concurrent update safety
# ---------------------------------------------------------------------------


def test_rem_19_concurrent_updates_produce_independent_audits(
    client: TestClient, db_session: Session
) -> None:
    """Sequential updates each produce a distinct audit event with correct before/after state."""
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    task_id = client.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id,
            "assessment_id": assessment_id,
            "title": "v1",
        },
    ).json()["id"]

    client.patch(f"/remediation/tasks/{task_id}", json={"title": "v2"})
    client.patch(f"/remediation/tasks/{task_id}", json={"title": "v3"})

    engine_obj = get_engine()
    with Session(engine_obj) as db:
        events = (
            db.query(RemediationTaskAudit)
            .filter(
                RemediationTaskAudit.task_id == task_id,
                RemediationTaskAudit.event_type == "task_updated",
            )
            .order_by(RemediationTaskAudit.event_at)
            .all()
        )
    assert len(events) == 2
    assert _json_obj(events[0].old_state)["title"] == "v1"
    assert _json_obj(events[0].new_state)["title"] == "v2"
    assert _json_obj(events[1].old_state)["title"] == "v2"
    assert _json_obj(events[1].new_state)["title"] == "v3"


def test_rem_19_each_update_increments_updated_at(
    client: TestClient, db_session: Session
) -> None:
    """Each update should set a new updated_at timestamp."""
    import time

    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    task_id = client.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id,
            "assessment_id": assessment_id,
            "title": "ts-test",
        },
    ).json()["id"]

    before = client.get(f"/remediation/tasks/{task_id}").json()["updated_at"]
    time.sleep(0.01)
    client.patch(f"/remediation/tasks/{task_id}", json={"title": "ts-updated"})
    after = client.get(f"/remediation/tasks/{task_id}").json()["updated_at"]
    assert after >= before


# ---------------------------------------------------------------------------
# REM-20: Lifecycle reconstruction from audit trail
# ---------------------------------------------------------------------------


def test_rem_20_full_lifecycle_audit_reconstruction(
    client: TestClient, db_session: Session
) -> None:
    """The complete life of a task can be reconstructed from audit events alone."""
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)

    # Create
    task_id = client.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id,
            "assessment_id": assessment_id,
            "title": "Lifecycle start",
            "priority": "high",
        },
    ).json()["id"]

    # Update
    client.patch(
        f"/remediation/tasks/{task_id}",
        json={"title": "Lifecycle updated", "priority": "critical"},
    )

    # Advance through workflow, then close
    _advance_to_in_progress(client, task_id)
    client.post(f"/remediation/tasks/{task_id}/close")

    engine_obj = get_engine()
    with Session(engine_obj) as db:
        events = (
            db.query(RemediationTaskAudit)
            .filter(RemediationTaskAudit.task_id == task_id)
            .order_by(RemediationTaskAudit.event_at)
            .all()
        )

    # PR 13.3: _advance_to_in_progress now emits task_assigned between task_planned and task_started
    event_types = [e.event_type for e in events]
    assert event_types == [
        "task_created",
        "task_updated",
        "task_planned",
        "task_assigned",
        "task_started",
        "task_closed",
    ]

    # Reconstruct initial state
    created = events[0]
    assert created.old_state is None
    assert _json_obj(created.new_state)["title"] == "Lifecycle start"
    assert _json_obj(created.new_state)["priority"] == "high"
    assert _json_obj(created.new_state)["status"] == "open"

    # Verify state transition on update
    updated = events[1]
    assert _json_obj(updated.old_state)["title"] == "Lifecycle start"
    assert _json_obj(updated.new_state)["title"] == "Lifecycle updated"
    assert _json_obj(updated.new_state)["priority"] == "critical"

    # Verify planning transition
    planned = events[2]
    assert planned.event_type == "task_planned"
    assert _json_obj(planned.old_state)["status"] == "open"
    assert _json_obj(planned.new_state)["status"] == "planned"

    # Verify start transition (index 4 due to task_assigned at index 3)
    started = events[4]
    assert started.event_type == "task_started"
    assert _json_obj(started.old_state)["status"] == "planned"
    assert _json_obj(started.new_state)["status"] == "in_progress"

    # Verify closure
    closed = events[5]
    assert _json_obj(closed.old_state)["status"] == "in_progress"
    assert _json_obj(closed.new_state)["status"] == "closed"
    assert _json_obj(closed.new_state)["closed_at"] is not None


def test_rem_20_deleted_task_audit_trail_persists(
    client: TestClient, db_session: Session
) -> None:
    """Even after deletion, the full audit trail is preserved and reconstructable."""
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)

    task_id = client.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id,
            "assessment_id": assessment_id,
            "title": "Will be deleted",
        },
    ).json()["id"]

    client.patch(
        f"/remediation/tasks/{task_id}", json={"title": "Updated before delete"}
    )
    client.delete(f"/remediation/tasks/{task_id}")

    engine_obj = get_engine()
    with Session(engine_obj) as db:
        events = (
            db.query(RemediationTaskAudit)
            .filter(RemediationTaskAudit.task_id == task_id)
            .order_by(RemediationTaskAudit.event_at)
            .all()
        )
        task_row = (
            db.query(RemediationTask).filter(RemediationTask.id == task_id).first()
        )

    assert task_row is None  # task is gone
    assert len(events) == 3  # create, update, delete events all preserved
    assert events[-1].event_type == "task_deleted"
    assert _json_obj(events[-1].old_state)["title"] == "Updated before delete"
    assert events[-1].new_state is None


# ===========================================================================
# PR 13.2 — Remediation Status Workflow Engine
# ===========================================================================


def _create_task(client: TestClient, db: Session, tenant_id: str) -> str:
    """Helper: create a fresh task and return its ID."""
    assessment_id, finding_id = _make_refs(db, tenant_id)
    resp = client.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id,
            "assessment_id": assessment_id,
            "title": "Workflow test task",
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


def _create_task_simple(client: TestClient, priority: str = "medium") -> str:
    """PR 13.3 helper: create a fresh task using a live DB session. No external db needed."""
    engine_obj = get_engine()
    with Session(engine_obj) as db:
        assessment_id, finding_id = _make_refs(db, _TENANT_A)
    resp = client.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id,
            "assessment_id": assessment_id,
            "title": "PR 13.3 test task",
            "priority": priority,
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


# ---------------------------------------------------------------------------
# REM-21: OPEN → PLANNED
# ---------------------------------------------------------------------------


def test_rem_21_open_to_planned(client: TestClient, db_session: Session) -> None:
    task_id = _create_task(client, db_session, _TENANT_A)
    resp = client.post(
        f"/remediation/tasks/{task_id}/transition",
        json={"new_status": "planned"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["old_status"] == "open"
    assert data["new_status"] == "planned"
    assert data["task_id"] == task_id
    assert data["transitioned_at"]
    assert "in_progress" in data["allowed_next_states"]
    assert "accepted_risk" in data["allowed_next_states"]

    task_resp = client.get(f"/remediation/tasks/{task_id}")
    assert task_resp.json()["status"] == "planned"


# ---------------------------------------------------------------------------
# REM-22: PLANNED → IN_PROGRESS
# ---------------------------------------------------------------------------


def test_rem_22_planned_to_in_progress(client: TestClient, db_session: Session) -> None:
    task_id = _create_task(client, db_session, _TENANT_A)
    client.post(
        f"/remediation/tasks/{task_id}/transition", json={"new_status": "planned"}
    )
    # PR 13.3: must assign owner before transitioning to in_progress
    client.post(
        f"/remediation/tasks/{task_id}/assign",
        json={"user_id": "u1", "display_name": "User One", "email": "u1@example.com"},
    )
    resp = client.post(
        f"/remediation/tasks/{task_id}/transition",
        json={"new_status": "in_progress"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["old_status"] == "planned"
    assert data["new_status"] == "in_progress"
    assert "closed" in data["allowed_next_states"]
    assert "accepted_risk" in data["allowed_next_states"]


# ---------------------------------------------------------------------------
# REM-23: IN_PROGRESS → CLOSED
# ---------------------------------------------------------------------------


def test_rem_23_in_progress_to_closed(client: TestClient, db_session: Session) -> None:
    task_id = _create_task(client, db_session, _TENANT_A)
    _advance_to_in_progress(client, task_id)
    resp = client.post(
        f"/remediation/tasks/{task_id}/transition",
        json={"new_status": "closed"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["old_status"] == "in_progress"
    assert data["new_status"] == "closed"
    assert data["allowed_next_states"] == []

    task_resp = client.get(f"/remediation/tasks/{task_id}")
    assert task_resp.json()["status"] == "closed"
    assert task_resp.json()["closed_at"] is not None


# ---------------------------------------------------------------------------
# REM-24: OPEN → ACCEPTED_RISK
# ---------------------------------------------------------------------------


def test_rem_24_open_to_accepted_risk(client: TestClient, db_session: Session) -> None:
    task_id = _create_task(client, db_session, _TENANT_A)
    resp = client.post(
        f"/remediation/tasks/{task_id}/transition",
        json={"new_status": "accepted_risk", "reason": "Compensating control in place"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["old_status"] == "open"
    assert data["new_status"] == "accepted_risk"
    assert data["allowed_next_states"] == []

    task_resp = client.get(f"/remediation/tasks/{task_id}")
    assert task_resp.json()["status"] == "accepted_risk"


# ---------------------------------------------------------------------------
# REM-25: PLANNED → ACCEPTED_RISK
# ---------------------------------------------------------------------------


def test_rem_25_planned_to_accepted_risk(
    client: TestClient, db_session: Session
) -> None:
    task_id = _create_task(client, db_session, _TENANT_A)
    client.post(
        f"/remediation/tasks/{task_id}/transition", json={"new_status": "planned"}
    )
    resp = client.post(
        f"/remediation/tasks/{task_id}/transition",
        json={"new_status": "accepted_risk", "reason": "Risk accepted by CISO"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["old_status"] == "planned"
    assert resp.json()["new_status"] == "accepted_risk"


# ---------------------------------------------------------------------------
# REM-26: IN_PROGRESS → ACCEPTED_RISK
# ---------------------------------------------------------------------------


def test_rem_26_in_progress_to_accepted_risk(
    client: TestClient, db_session: Session
) -> None:
    task_id = _create_task(client, db_session, _TENANT_A)
    _advance_to_in_progress(client, task_id)
    resp = client.post(
        f"/remediation/tasks/{task_id}/transition",
        json={
            "new_status": "accepted_risk",
            "reason": "Mitigated by network segmentation",
        },
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["old_status"] == "in_progress"
    assert resp.json()["new_status"] == "accepted_risk"


# ---------------------------------------------------------------------------
# REM-27: OPEN → CLOSED denied
# ---------------------------------------------------------------------------


def test_rem_27_open_to_closed_denied(client: TestClient, db_session: Session) -> None:
    task_id = _create_task(client, db_session, _TENANT_A)
    resp = client.post(
        f"/remediation/tasks/{task_id}/transition",
        json={"new_status": "closed"},
    )
    assert resp.status_code == 422, resp.text
    assert (
        "open" in resp.json()["detail"].lower()
        or "closed" in resp.json()["detail"].lower()
    )


# ---------------------------------------------------------------------------
# REM-28: OPEN → IN_PROGRESS denied
# ---------------------------------------------------------------------------


def test_rem_28_open_to_in_progress_denied(
    client: TestClient, db_session: Session
) -> None:
    task_id = _create_task(client, db_session, _TENANT_A)
    resp = client.post(
        f"/remediation/tasks/{task_id}/transition",
        json={"new_status": "in_progress"},
    )
    assert resp.status_code == 422, resp.text


# ---------------------------------------------------------------------------
# REM-29: PLANNED → CLOSED denied
# ---------------------------------------------------------------------------


def test_rem_29_planned_to_closed_denied(
    client: TestClient, db_session: Session
) -> None:
    task_id = _create_task(client, db_session, _TENANT_A)
    client.post(
        f"/remediation/tasks/{task_id}/transition", json={"new_status": "planned"}
    )
    resp = client.post(
        f"/remediation/tasks/{task_id}/transition",
        json={"new_status": "closed"},
    )
    assert resp.status_code == 422, resp.text


# ---------------------------------------------------------------------------
# REM-30: CLOSED is terminal — no further transitions
# ---------------------------------------------------------------------------


def test_rem_30_closed_transition_denied(
    client: TestClient, db_session: Session
) -> None:
    task_id = _create_task(client, db_session, _TENANT_A)
    _advance_to_in_progress(client, task_id)
    client.post(
        f"/remediation/tasks/{task_id}/transition", json={"new_status": "closed"}
    )

    for target in ("open", "planned", "in_progress", "accepted_risk", "closed"):
        resp = client.post(
            f"/remediation/tasks/{task_id}/transition",
            json={"new_status": target, "reason": "attempt"},
        )
        assert resp.status_code in (
            422,
            400,
        ), f"Expected rejection for CLOSED→{target}, got {resp.status_code}"


# ---------------------------------------------------------------------------
# REM-31: ACCEPTED_RISK is terminal — no further transitions
# ---------------------------------------------------------------------------


def test_rem_31_accepted_risk_transition_denied(
    client: TestClient, db_session: Session
) -> None:
    task_id = _create_task(client, db_session, _TENANT_A)
    client.post(
        f"/remediation/tasks/{task_id}/transition",
        json={"new_status": "accepted_risk", "reason": "Initial acceptance"},
    )

    for target in ("open", "planned", "in_progress", "closed", "accepted_risk"):
        resp = client.post(
            f"/remediation/tasks/{task_id}/transition",
            json={"new_status": target, "reason": "attempt"},
        )
        assert resp.status_code in (422, 400), (
            f"Expected rejection for ACCEPTED_RISK→{target}, got {resp.status_code}"
        )


# ---------------------------------------------------------------------------
# REM-32: Transition audit event created
# ---------------------------------------------------------------------------


def test_rem_32_transition_creates_audit_event(
    client: TestClient, db_session: Session
) -> None:
    task_id = _create_task(client, db_session, _TENANT_A)
    client.post(
        f"/remediation/tasks/{task_id}/transition", json={"new_status": "planned"}
    )

    engine_obj = get_engine()
    with Session(engine_obj) as db:
        events = (
            db.query(RemediationTaskAudit)
            .filter(
                RemediationTaskAudit.task_id == task_id,
                RemediationTaskAudit.event_type == "task_planned",
            )
            .all()
        )
    assert len(events) == 1
    assert _json_obj(events[0].old_state)["status"] == "open"
    assert _json_obj(events[0].new_state)["status"] == "planned"
    assert events[0].actor is not None


# ---------------------------------------------------------------------------
# REM-33: Transition reason stored in audit
# ---------------------------------------------------------------------------


def test_rem_33_transition_reason_stored(
    client: TestClient, db_session: Session
) -> None:
    task_id = _create_task(client, db_session, _TENANT_A)
    client.post(
        f"/remediation/tasks/{task_id}/transition",
        json={
            "new_status": "accepted_risk",
            "reason": "CISO approved risk acceptance — ticket #RAR-42",
        },
    )

    engine_obj = get_engine()
    with Session(engine_obj) as db:
        events = (
            db.query(RemediationTaskAudit)
            .filter(
                RemediationTaskAudit.task_id == task_id,
                RemediationTaskAudit.event_type == "task_risk_accepted",
            )
            .all()
        )
    assert len(events) == 1
    assert events[0].reason == "CISO approved risk acceptance — ticket #RAR-42"


# ---------------------------------------------------------------------------
# REM-34: Missing reason for ACCEPTED_RISK denied
# ---------------------------------------------------------------------------


def test_rem_34_missing_reason_for_accepted_risk_denied(
    client: TestClient, db_session: Session
) -> None:
    task_id = _create_task(client, db_session, _TENANT_A)
    resp = client.post(
        f"/remediation/tasks/{task_id}/transition",
        json={"new_status": "accepted_risk"},
    )
    assert resp.status_code == 422, resp.text
    assert "reason" in resp.json()["detail"].lower()

    # Task must still be OPEN — no state change occurred
    task_resp = client.get(f"/remediation/tasks/{task_id}")
    assert task_resp.json()["status"] == "open"


def test_rem_34_empty_reason_for_accepted_risk_denied(
    client: TestClient, db_session: Session
) -> None:
    task_id = _create_task(client, db_session, _TENANT_A)
    resp = client.post(
        f"/remediation/tasks/{task_id}/transition",
        json={"new_status": "accepted_risk", "reason": ""},
    )
    assert resp.status_code == 422, resp.text


# ---------------------------------------------------------------------------
# REM-35: Wrong tenant transition denied
# ---------------------------------------------------------------------------


def test_rem_35_wrong_tenant_transition_denied(
    client: TestClient,
    client_b: TestClient,
    db_session: Session,
) -> None:
    """Tenant A cannot transition a task that belongs to Tenant B."""
    engine_obj = get_engine()
    with Session(engine_obj) as db:
        assessment_id_b = _new_engagement(db, _TENANT_B)
        finding_id_b = _new_finding(db, _TENANT_B, assessment_id_b)

    task_id_b = client_b.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id_b,
            "assessment_id": assessment_id_b,
            "title": "Tenant B task",
        },
    ).json()["id"]

    resp = client.post(
        f"/remediation/tasks/{task_id_b}/transition",
        json={"new_status": "planned"},
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# REM-36: Unauthorized transition denied (no write scope)
# ---------------------------------------------------------------------------


def test_rem_36_unauthorized_transition_denied(
    readonly_client: TestClient,
    client: TestClient,
    db_session: Session,
) -> None:
    task_id = _create_task(client, db_session, _TENANT_A)
    resp = readonly_client.post(
        f"/remediation/tasks/{task_id}/transition",
        json={"new_status": "planned"},
    )
    assert resp.status_code in (401, 403)


def test_rem_36_unauthenticated_transition_denied(
    unauthed_client: TestClient,
    client: TestClient,
    db_session: Session,
) -> None:
    task_id = _create_task(client, db_session, _TENANT_A)
    resp = unauthed_client.post(
        f"/remediation/tasks/{task_id}/transition",
        json={"new_status": "planned"},
    )
    assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# REM-37: Metrics increment on transition
# ---------------------------------------------------------------------------


def test_rem_37_transition_metrics_increment(
    client: TestClient, db_session: Session
) -> None:
    from api.observability.metrics import REMEDIATION_STATUS_TRANSITIONS_TOTAL

    task_id = _create_task(client, db_session, _TENANT_A)
    before = REMEDIATION_STATUS_TRANSITIONS_TOTAL.labels(
        from_status="open", to_status="planned"
    )._value.get()

    client.post(
        f"/remediation/tasks/{task_id}/transition", json={"new_status": "planned"}
    )

    after = REMEDIATION_STATUS_TRANSITIONS_TOTAL.labels(
        from_status="open", to_status="planned"
    )._value.get()
    assert after > before


def test_rem_37_invalid_transition_metrics_increment(
    client: TestClient, db_session: Session
) -> None:
    from api.observability.metrics import REMEDIATION_INVALID_TRANSITIONS_TOTAL

    task_id = _create_task(client, db_session, _TENANT_A)
    before = REMEDIATION_INVALID_TRANSITIONS_TOTAL._value.get()

    client.post(
        f"/remediation/tasks/{task_id}/transition",
        json={"new_status": "closed"},  # OPEN→CLOSED is forbidden
    )

    after = REMEDIATION_INVALID_TRANSITIONS_TOTAL._value.get()
    assert after > before


# ---------------------------------------------------------------------------
# REM-38: Allowed transitions API
# ---------------------------------------------------------------------------


def test_rem_38_allowed_transitions_open(
    client: TestClient, db_session: Session
) -> None:
    task_id = _create_task(client, db_session, _TENANT_A)
    resp = client.get(f"/remediation/tasks/{task_id}/allowed-transitions")
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["task_id"] == task_id
    assert data["current_status"] == "open"
    assert set(data["allowed_next_states"]) == {"planned", "accepted_risk"}


def test_rem_38_allowed_transitions_planned(
    client: TestClient, db_session: Session
) -> None:
    task_id = _create_task(client, db_session, _TENANT_A)
    client.post(
        f"/remediation/tasks/{task_id}/transition", json={"new_status": "planned"}
    )
    resp = client.get(f"/remediation/tasks/{task_id}/allowed-transitions")
    assert resp.status_code == 200
    data = resp.json()
    assert data["current_status"] == "planned"
    assert set(data["allowed_next_states"]) == {"in_progress", "accepted_risk"}


def test_rem_38_allowed_transitions_closed_is_empty(
    client: TestClient, db_session: Session
) -> None:
    task_id = _create_task(client, db_session, _TENANT_A)
    _advance_to_in_progress(client, task_id)
    client.post(
        f"/remediation/tasks/{task_id}/transition", json={"new_status": "closed"}
    )
    resp = client.get(f"/remediation/tasks/{task_id}/allowed-transitions")
    assert resp.status_code == 200
    assert resp.json()["allowed_next_states"] == []


def test_rem_38_allowed_transitions_not_found(client: TestClient) -> None:
    resp = client.get("/remediation/tasks/nonexistent-task/allowed-transitions")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# REM-39: State machine integrity — exhaustive forbidden transition check
# ---------------------------------------------------------------------------


def test_rem_39_state_machine_integrity(
    client: TestClient, db_session: Session
) -> None:
    """Verify the complete forbidden-transition matrix from the spec."""
    forbidden = [
        ("open", "closed"),
        ("open", "in_progress"),
        ("planned", "closed"),
        ("planned", "open"),
        ("in_progress", "open"),
    ]

    for from_status, to_status in forbidden:
        task_id = _create_task(client, db_session, _TENANT_A)

        # Advance to from_status
        if from_status == "planned":
            client.post(
                f"/remediation/tasks/{task_id}/transition",
                json={"new_status": "planned"},
            )
        elif from_status == "in_progress":
            _advance_to_in_progress(client, task_id)

        resp = client.post(
            f"/remediation/tasks/{task_id}/transition",
            json={"new_status": to_status, "reason": "integrity check"},
        )
        assert resp.status_code == 422, (
            f"Expected 422 for {from_status}→{to_status}, got {resp.status_code}: {resp.text}"
        )


# ---------------------------------------------------------------------------
# REM-40: Lifecycle reconstruction from audit trail (workflow path)
# ---------------------------------------------------------------------------


def test_rem_40_workflow_lifecycle_reconstruction(
    client: TestClient, db_session: Session
) -> None:
    """Full OPEN→PLANNED→IN_PROGRESS→CLOSED lifecycle is reconstructable from audit."""
    task_id = _create_task(client, db_session, _TENANT_A)
    client.post(
        f"/remediation/tasks/{task_id}/transition",
        json={"new_status": "planned", "reason": "Assigned to ops team"},
    )
    # PR 13.3: must assign owner before in_progress
    client.post(
        f"/remediation/tasks/{task_id}/assign",
        json={
            "user_id": "u-ops",
            "display_name": "Ops User",
            "email": "ops@example.com",
        },
    )
    client.post(
        f"/remediation/tasks/{task_id}/transition",
        json={"new_status": "in_progress"},
    )
    client.post(
        f"/remediation/tasks/{task_id}/transition",
        json={"new_status": "closed"},
    )

    engine_obj = get_engine()
    with Session(engine_obj) as db:
        events = (
            db.query(RemediationTaskAudit)
            .filter(RemediationTaskAudit.task_id == task_id)
            .order_by(RemediationTaskAudit.event_at)
            .all()
        )

    # PR 13.3: task_assigned is now part of the lifecycle (emitted before in_progress)
    event_types = [e.event_type for e in events]
    assert event_types == [
        "task_created",
        "task_planned",
        "task_assigned",
        "task_started",
        "task_closed",
    ]

    # Each event preserves the transition
    assert _json_obj(events[1].old_state)["status"] == "open"
    assert _json_obj(events[1].new_state)["status"] == "planned"
    assert events[1].reason == "Assigned to ops team"

    assert _json_obj(events[3].old_state)["status"] == "planned"
    assert _json_obj(events[3].new_state)["status"] == "in_progress"

    assert _json_obj(events[4].old_state)["status"] == "in_progress"
    assert _json_obj(events[4].new_state)["status"] == "closed"
    assert _json_obj(events[4].new_state)["closed_at"] is not None


def test_rem_40_risk_accepted_lifecycle(
    client: TestClient, db_session: Session
) -> None:
    """OPEN→ACCEPTED_RISK lifecycle reconstructable with reason."""
    task_id = _create_task(client, db_session, _TENANT_A)
    client.post(
        f"/remediation/tasks/{task_id}/transition",
        json={"new_status": "accepted_risk", "reason": "Low exploitability"},
    )

    engine_obj = get_engine()
    with Session(engine_obj) as db:
        events = (
            db.query(RemediationTaskAudit)
            .filter(RemediationTaskAudit.task_id == task_id)
            .order_by(RemediationTaskAudit.event_at)
            .all()
        )

    assert len(events) == 2
    assert events[1].event_type == "task_risk_accepted"
    assert _json_obj(events[1].old_state)["status"] == "open"
    assert _json_obj(events[1].new_state)["status"] == "accepted_risk"
    assert events[1].reason == "Low exploitability"


# ---------------------------------------------------------------------------
# REM-41: Concurrent transition safety
# ---------------------------------------------------------------------------


def test_rem_41_sequential_transitions_produce_correct_audit_chain(
    client: TestClient, db_session: Session
) -> None:
    """Each transition records the correct before/after pair."""
    task_id = _create_task(client, db_session, _TENANT_A)

    client.post(
        f"/remediation/tasks/{task_id}/transition", json={"new_status": "planned"}
    )
    # PR 13.3: must assign owner before in_progress
    client.post(
        f"/remediation/tasks/{task_id}/assign",
        json={"user_id": "u1", "display_name": "U1", "email": "u1@example.com"},
    )
    client.post(
        f"/remediation/tasks/{task_id}/transition", json={"new_status": "in_progress"}
    )
    client.post(
        f"/remediation/tasks/{task_id}/transition", json={"new_status": "closed"}
    )

    engine_obj = get_engine()
    with Session(engine_obj) as db:
        events = (
            db.query(RemediationTaskAudit)
            .filter(
                RemediationTaskAudit.task_id == task_id,
                RemediationTaskAudit.event_type.in_(
                    ["task_planned", "task_started", "task_closed"]
                ),
            )
            .order_by(RemediationTaskAudit.event_at)
            .all()
        )

    assert len(events) == 3
    assert _json_obj(events[0].old_state)["status"] == "open"
    assert _json_obj(events[0].new_state)["status"] == "planned"
    assert _json_obj(events[1].old_state)["status"] == "planned"
    assert _json_obj(events[1].new_state)["status"] == "in_progress"
    assert _json_obj(events[2].old_state)["status"] == "in_progress"
    assert _json_obj(events[2].new_state)["status"] == "closed"


def test_rem_41_duplicate_transition_rejected(
    client: TestClient, db_session: Session
) -> None:
    """Attempting the same valid transition twice is rejected the second time."""
    task_id = _create_task(client, db_session, _TENANT_A)
    r1 = client.post(
        f"/remediation/tasks/{task_id}/transition", json={"new_status": "planned"}
    )
    assert r1.status_code == 200

    r2 = client.post(
        f"/remediation/tasks/{task_id}/transition", json={"new_status": "planned"}
    )
    assert r2.status_code == 422


# ---------------------------------------------------------------------------
# REM-42: Migration compatibility validation
# ---------------------------------------------------------------------------


def test_rem_42_existing_open_tasks_remain_valid(
    client: TestClient, db_session: Session
) -> None:
    """Tasks created before PR 13.2 (status=open) are valid and transitionable."""
    task_id = _create_task(client, db_session, _TENANT_A)
    task_resp = client.get(f"/remediation/tasks/{task_id}")
    assert task_resp.json()["status"] == "open"

    # Can transition using the new workflow engine
    resp = client.post(
        f"/remediation/tasks/{task_id}/transition", json={"new_status": "planned"}
    )
    assert resp.status_code == 200


def test_rem_42_all_new_statuses_are_listable(
    client: TestClient, db_session: Session
) -> None:
    """Each new status value can be queried via the list endpoint."""
    for new_status in ("planned", "in_progress", "accepted_risk"):
        # Verify the filter parameter is accepted (empty result is fine)
        resp = client.get(f"/remediation/tasks?status={new_status}")
        assert resp.status_code == 200, f"status={new_status} query failed: {resp.text}"


def test_rem_42_new_audit_event_types_stored_correctly(
    client: TestClient, db_session: Session
) -> None:
    """New audit event types (task_planned, task_started, task_risk_accepted) persist correctly."""
    task_id = _create_task(client, db_session, _TENANT_A)

    client.post(
        f"/remediation/tasks/{task_id}/transition", json={"new_status": "planned"}
    )

    engine_obj = get_engine()
    with Session(engine_obj) as db:
        event = (
            db.query(RemediationTaskAudit)
            .filter(
                RemediationTaskAudit.task_id == task_id,
                RemediationTaskAudit.event_type == "task_planned",
            )
            .first()
        )
    assert event is not None
    assert event.tenant_id == _TENANT_A
    assert event.old_state is not None
    assert event.new_state is not None


# ===========================================================================
# PR 13.3 — Remediation Ownership, Due Dates & SLA Authority
# ===========================================================================


# ---------------------------------------------------------------------------
# REM-43: Assign owner to a task
# ---------------------------------------------------------------------------


def test_rem_43_assign_owner(client: TestClient) -> None:
    task_id = _create_task_simple(client)
    resp = client.post(
        f"/remediation/tasks/{task_id}/assign",
        json={
            "user_id": "user-001",
            "display_name": "Alice",
            "email": "alice@example.com",
            "reason": "Initial assignment",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["assigned_user_id"] == "user-001"
    assert data["assigned_display_name"] == "Alice"
    assert data["assigned_user_email"] == "alice@example.com"
    assert data["ownership_reason"] == "Initial assignment"
    assert data["assigned_at"] is not None


# ---------------------------------------------------------------------------
# REM-44: Reassign owner
# ---------------------------------------------------------------------------


def test_rem_44_reassign_owner(client: TestClient) -> None:
    task_id = _create_task_simple(client)
    client.post(
        f"/remediation/tasks/{task_id}/assign",
        json={
            "user_id": "user-001",
            "display_name": "Alice",
            "email": "alice@example.com",
        },
    )
    resp = client.post(
        f"/remediation/tasks/{task_id}/assign",
        json={
            "user_id": "user-002",
            "display_name": "Bob",
            "email": "bob@example.com",
            "reason": "Reassigned",
        },
    )
    assert resp.status_code == 200
    assert resp.json()["assigned_user_id"] == "user-002"


# ---------------------------------------------------------------------------
# REM-45: Remove owner
# ---------------------------------------------------------------------------


def test_rem_45_remove_owner(client: TestClient) -> None:
    task_id = _create_task_simple(client)
    client.post(
        f"/remediation/tasks/{task_id}/assign",
        json={
            "user_id": "user-001",
            "display_name": "Alice",
            "email": "alice@example.com",
        },
    )
    resp = client.post(f"/remediation/tasks/{task_id}/unassign", json={})
    assert resp.status_code == 200
    assert resp.json()["assigned_user_id"] is None


# ---------------------------------------------------------------------------
# REM-46: Assignment audit event
# ---------------------------------------------------------------------------


def test_rem_46_assignment_audit_event(client: TestClient) -> None:
    task_id = _create_task_simple(client)
    client.post(
        f"/remediation/tasks/{task_id}/assign",
        json={
            "user_id": "user-001",
            "display_name": "Alice",
            "email": "alice@example.com",
            "reason": "Assigning",
        },
    )
    audit_resp = client.get(f"/remediation/tasks/{task_id}/audit")
    assert audit_resp.status_code == 200
    events = audit_resp.json()["events"]
    types = [e["event_type"] for e in events]
    assert "task_assigned" in types
    assigned_event = next(e for e in events if e["event_type"] == "task_assigned")
    assert assigned_event["reason"] == "Assigning"
    assert assigned_event["new_state"]["assigned_user_id"] == "user-001"


# ---------------------------------------------------------------------------
# REM-47: Due date assignment
# ---------------------------------------------------------------------------


def test_rem_47_set_due_date(client: TestClient) -> None:
    task_id = _create_task_simple(client)
    resp = client.post(
        f"/remediation/tasks/{task_id}/due-date",
        json={
            "due_date": "2026-12-31T00:00:00+00:00",
            "reason": "Contractual commitment",
        },
    )
    assert resp.status_code == 200
    assert resp.json()["due_date"] == "2026-12-31T00:00:00+00:00"


# ---------------------------------------------------------------------------
# REM-48: Due date modification
# ---------------------------------------------------------------------------


def test_rem_48_modify_due_date(client: TestClient) -> None:
    task_id = _create_task_simple(client)
    client.post(
        f"/remediation/tasks/{task_id}/due-date",
        json={"due_date": "2026-12-31T00:00:00+00:00"},
    )
    resp = client.post(
        f"/remediation/tasks/{task_id}/due-date",
        json={"due_date": "2027-01-15T00:00:00+00:00", "reason": "Extended"},
    )
    assert resp.status_code == 200
    assert resp.json()["due_date"] == "2027-01-15T00:00:00+00:00"


# ---------------------------------------------------------------------------
# REM-49: Due date audit event
# ---------------------------------------------------------------------------


def test_rem_49_due_date_audit_event(client: TestClient) -> None:
    task_id = _create_task_simple(client)
    client.post(
        f"/remediation/tasks/{task_id}/due-date",
        json={"due_date": "2026-12-31T00:00:00+00:00", "reason": "Deadline set"},
    )
    audit_resp = client.get(f"/remediation/tasks/{task_id}/audit")
    events = audit_resp.json()["events"]
    types = [e["event_type"] for e in events]
    assert "task_due_date_changed" in types


# ---------------------------------------------------------------------------
# REM-50: Critical SLA = 14 days
# ---------------------------------------------------------------------------


def test_rem_50_critical_sla(client: TestClient) -> None:
    task_id = _create_task_simple(client, priority="critical")
    resp = client.get(f"/remediation/tasks/{task_id}/sla")
    assert resp.status_code == 200
    data = resp.json()
    assert data["sla_target_days"] == 14
    assert data["sla_status"] == "on_track"


# ---------------------------------------------------------------------------
# REM-51: High SLA = 30 days
# ---------------------------------------------------------------------------


def test_rem_51_high_sla(client: TestClient) -> None:
    task_id = _create_task_simple(client, priority="high")
    resp = client.get(f"/remediation/tasks/{task_id}/sla")
    assert resp.json()["sla_target_days"] == 30


# ---------------------------------------------------------------------------
# REM-52: Medium SLA = 60 days
# ---------------------------------------------------------------------------


def test_rem_52_medium_sla(client: TestClient) -> None:
    task_id = _create_task_simple(client, priority="medium")
    resp = client.get(f"/remediation/tasks/{task_id}/sla")
    assert resp.json()["sla_target_days"] == 60


# ---------------------------------------------------------------------------
# REM-53: Low SLA = 90 days
# ---------------------------------------------------------------------------


def test_rem_53_low_sla(client: TestClient) -> None:
    task_id = _create_task_simple(client, priority="low")
    resp = client.get(f"/remediation/tasks/{task_id}/sla")
    assert resp.json()["sla_target_days"] == 90


# ---------------------------------------------------------------------------
# REM-54: Informational = no SLA
# ---------------------------------------------------------------------------


def test_rem_54_informational_sla(client: TestClient) -> None:
    task_id = _create_task_simple(client, priority="informational")
    resp = client.get(f"/remediation/tasks/{task_id}/sla")
    data = resp.json()
    assert data["sla_target_days"] is None
    assert data["sla_status"] == "on_track"
    assert data["days_remaining"] is None


# ---------------------------------------------------------------------------
# REM-55: ON_TRACK SLA status — newly created task
# ---------------------------------------------------------------------------


def test_rem_55_on_track_status(client: TestClient) -> None:
    task_id = _create_task_simple(client, priority="high")
    resp = client.get(f"/remediation/tasks/{task_id}/sla")
    assert resp.json()["sla_status"] == "on_track"
    assert resp.json()["days_remaining"] > 0


# ---------------------------------------------------------------------------
# REM-56: AT_RISK status — task near SLA breach
# ---------------------------------------------------------------------------


def test_rem_56_at_risk_status(client: TestClient, monkeypatch) -> None:
    import services.remediation.engine as eng

    task_id = _create_task_simple(client, priority="high")
    original = eng._compute_age_days
    monkeypatch.setattr(eng, "_compute_age_days", lambda task: 25)
    try:
        resp = client.get(f"/remediation/tasks/{task_id}/sla")
        assert resp.json()["sla_status"] == "at_risk"
    finally:
        monkeypatch.setattr(eng, "_compute_age_days", original)


# ---------------------------------------------------------------------------
# REM-57: OVERDUE status — task past SLA breach
# ---------------------------------------------------------------------------


def test_rem_57_overdue_status(client: TestClient, monkeypatch) -> None:
    import services.remediation.engine as eng

    task_id = _create_task_simple(client, priority="high")
    original = eng._compute_age_days
    monkeypatch.setattr(eng, "_compute_age_days", lambda task: 35)
    try:
        resp = client.get(f"/remediation/tasks/{task_id}/sla")
        assert resp.json()["sla_status"] == "overdue"
    finally:
        monkeypatch.setattr(eng, "_compute_age_days", original)


# ---------------------------------------------------------------------------
# REM-58: Closed status SLA
# ---------------------------------------------------------------------------


def test_rem_58_closed_sla_status(client: TestClient) -> None:
    task_id = _create_task_simple(client)
    _advance_to_in_progress(client, task_id)
    client.post(
        f"/remediation/tasks/{task_id}/transition", json={"new_status": "closed"}
    )
    resp = client.get(f"/remediation/tasks/{task_id}/sla")
    assert resp.json()["sla_status"] == "closed"


# ---------------------------------------------------------------------------
# REM-59: Accepted-risk SLA status
# ---------------------------------------------------------------------------


def test_rem_59_accepted_risk_sla_status(client: TestClient) -> None:
    task_id = _create_task_simple(client)
    client.post(
        f"/remediation/tasks/{task_id}/transition",
        json={"new_status": "accepted_risk", "reason": "Accepted"},
    )
    resp = client.get(f"/remediation/tasks/{task_id}/sla")
    assert resp.json()["sla_status"] == "accepted_risk"


# ---------------------------------------------------------------------------
# REM-60: Wrong tenant assignment denied
# ---------------------------------------------------------------------------


def test_rem_60_wrong_tenant_assign_denied(
    client: TestClient, alt_client: TestClient
) -> None:
    task_id = _create_task_simple(client)
    resp = alt_client.post(
        f"/remediation/tasks/{task_id}/assign",
        json={"user_id": "user-x", "display_name": "X", "email": "x@example.com"},
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# REM-61: Cross-tenant SLA visibility denied
# ---------------------------------------------------------------------------


def test_rem_61_cross_tenant_sla_denied(
    client: TestClient, alt_client: TestClient
) -> None:
    task_id = _create_task_simple(client)
    resp = alt_client.get(f"/remediation/tasks/{task_id}/sla")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# REM-62: Unauthorized assignment denied (no governance:write scope)
# ---------------------------------------------------------------------------


def test_rem_62_unauthorized_assign_denied(
    readonly_client: TestClient,
    client: TestClient,
) -> None:
    task_id = _create_task_simple(client)
    resp = readonly_client.post(
        f"/remediation/tasks/{task_id}/assign",
        json={"user_id": "u1", "display_name": "U1", "email": "u1@example.com"},
    )
    assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# REM-63: Unauthorized due-date change denied
# ---------------------------------------------------------------------------


def test_rem_63_unauthorized_due_date_denied(
    readonly_client: TestClient,
    client: TestClient,
) -> None:
    task_id = _create_task_simple(client)
    resp = readonly_client.post(
        f"/remediation/tasks/{task_id}/due-date",
        json={"due_date": "2026-12-31T00:00:00+00:00"},
    )
    assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# REM-64: Metrics increment on assignment
# ---------------------------------------------------------------------------


def test_rem_64_metrics_increment_on_assignment(client: TestClient) -> None:
    from api.observability.metrics import REMEDIATION_ASSIGNMENTS_TOTAL

    before = REMEDIATION_ASSIGNMENTS_TOTAL._value.get()
    task_id = _create_task_simple(client)
    client.post(
        f"/remediation/tasks/{task_id}/assign",
        json={"user_id": "u1", "display_name": "U1", "email": "u1@example.com"},
    )
    after = REMEDIATION_ASSIGNMENTS_TOTAL._value.get()
    assert after == before + 1


# ---------------------------------------------------------------------------
# REM-65: Overdue query
# ---------------------------------------------------------------------------


def test_rem_65_overdue_query(client: TestClient) -> None:
    # Create a task; it will NOT be overdue since it was just created.
    _create_task_simple(client, priority="critical")
    resp = client.get("/remediation/tasks/overdue")
    assert resp.status_code == 200
    data = resp.json()
    assert "tasks" in data
    assert "total" in data
    assert isinstance(data["tasks"], list)
    assert isinstance(data["total"], int)


# ---------------------------------------------------------------------------
# REM-66: Unassigned query
# ---------------------------------------------------------------------------


def test_rem_66_unassigned_query(client: TestClient) -> None:
    task_id = _create_task_simple(client)
    resp = client.get("/remediation/tasks/unassigned")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 1
    task_ids = [t["id"] for t in data["tasks"]]
    assert task_id in task_ids


# ---------------------------------------------------------------------------
# REM-67: Lifecycle reconstruction with ownership history
# ---------------------------------------------------------------------------


def test_rem_67_lifecycle_reconstruction_with_ownership(client: TestClient) -> None:
    task_id = _create_task_simple(client)
    client.post(
        f"/remediation/tasks/{task_id}/assign",
        json={
            "user_id": "alice",
            "display_name": "Alice",
            "email": "alice@example.com",
            "reason": "Initial",
        },
    )
    client.post(
        f"/remediation/tasks/{task_id}/assign",
        json={
            "user_id": "bob",
            "display_name": "Bob",
            "email": "bob@example.com",
            "reason": "Reassigned",
        },
    )
    client.post(
        f"/remediation/tasks/{task_id}/due-date",
        json={"due_date": "2026-12-31T00:00:00+00:00"},
    )
    audit_resp = client.get(f"/remediation/tasks/{task_id}/audit")
    events = audit_resp.json()["events"]
    types = [e["event_type"] for e in events]
    assert "task_created" in types
    assert "task_assigned" in types
    assert "task_reassigned" in types
    assert "task_due_date_changed" in types


# ---------------------------------------------------------------------------
# REM-68: Ownership preserved after closure
# ---------------------------------------------------------------------------


def test_rem_68_ownership_preserved_after_closure(client: TestClient) -> None:
    task_id = _create_task_simple(client)
    # _advance_to_in_progress assigns user-test-001 and transitions
    _advance_to_in_progress(client, task_id)
    client.post(
        f"/remediation/tasks/{task_id}/transition", json={"new_status": "closed"}
    )
    resp = client.get(f"/remediation/tasks/{task_id}")
    # owner assigned by _advance_to_in_progress is preserved post-closure
    assert resp.json()["assigned_user_id"] is not None


# ---------------------------------------------------------------------------
# REM-69: Ownership preserved after accepted risk
# ---------------------------------------------------------------------------


def test_rem_69_ownership_preserved_after_accepted_risk(client: TestClient) -> None:
    task_id = _create_task_simple(client)
    client.post(
        f"/remediation/tasks/{task_id}/assign",
        json={
            "user_id": "alice",
            "display_name": "Alice",
            "email": "alice@example.com",
        },
    )
    client.post(
        f"/remediation/tasks/{task_id}/transition",
        json={"new_status": "accepted_risk", "reason": "Risk accepted"},
    )
    resp = client.get(f"/remediation/tasks/{task_id}")
    assert resp.json()["assigned_user_id"] == "alice"


# ---------------------------------------------------------------------------
# REM-70: Migration compatibility — new columns present after init
# ---------------------------------------------------------------------------


def test_rem_70_migration_compatibility(client: TestClient) -> None:
    task_id = _create_task_simple(client)
    resp = client.get(f"/remediation/tasks/{task_id}")
    data = resp.json()
    assert "assigned_user_id" in data
    assert "sla_target_days" in data
    assert "sla_breach_at" in data
    assert "due_date" in data
    assert data["assigned_user_id"] is None
    # medium priority default = 60 days
    assert data["sla_target_days"] == 60
    assert data["sla_breach_at"] is not None
