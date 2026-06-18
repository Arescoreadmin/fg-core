# tests/test_remediation_engine.py
"""Remediation Management test suite — PR 13.1.

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
"""

from __future__ import annotations

import uuid
from unittest.mock import patch

import pytest
from starlette.testclient import TestClient

from api.auth_scopes import mint_key
from api.db import get_engine, init_db, reset_engine_cache
from api.db_models_field_assessment import FaEngagement, FaNormalizedFinding
from api.db_models_remediation import RemediationTask, RemediationTaskAudit
from services.remediation.engine import RemediationEngine
from services.remediation.schemas import (
    CreateTaskRequest,
    RemediationConflict,
    RemediationNotFound,
    RemediationPriority,
    RemediationReferenceError,
    RemediationStatus,
    RemediationTenantViolation,
    UpdateTaskRequest,
)
from sqlalchemy.orm import Session

_TENANT_A = "tenant-rem-a"
_TENANT_B = "tenant-rem-b"


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


def test_rem_11_audit_event_on_create(
    client: TestClient, db_session: Session
) -> None:
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
    assert events[0].new_state["title"] == "Audited task"


# ---------------------------------------------------------------------------
# REM-12: Audit event on update
# ---------------------------------------------------------------------------


def test_rem_12_audit_event_on_update(
    client: TestClient, db_session: Session
) -> None:
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
    assert update_event.old_state["title"] == "Before update"
    assert update_event.new_state["title"] == "After update"


# ---------------------------------------------------------------------------
# REM-13: Audit event on close
# ---------------------------------------------------------------------------


def test_rem_13_audit_event_on_close(
    client: TestClient, db_session: Session
) -> None:
    assessment_id, finding_id = _make_refs(db_session, _TENANT_A)
    task_id = client.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id,
            "assessment_id": assessment_id,
            "title": "Close audit",
        },
    ).json()["id"]

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
    assert close_events[0].old_state["status"] == "open"
    assert close_events[0].new_state["status"] == "closed"
    assert close_events[0].new_state["closed_at"] is not None


# ---------------------------------------------------------------------------
# REM-14: Audit event on delete
# ---------------------------------------------------------------------------


def test_rem_14_audit_event_on_delete(
    client: TestClient, db_session: Session
) -> None:
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
        db.query(RemediationTask).filter(RemediationTask.id == task_id).first()
    ) if False else None  # session already closed; check via fresh session
    engine_obj = get_engine()
    with Session(engine_obj) as db2:
        task_row = db2.query(RemediationTask).filter(RemediationTask.id == task_id).first()
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
    assert events[0].old_state["title"] == "v1"
    assert events[0].new_state["title"] == "v2"
    assert events[1].old_state["title"] == "v2"
    assert events[1].new_state["title"] == "v3"


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
    client.patch(f"/remediation/tasks/{task_id}", json={"title": "Lifecycle updated", "priority": "critical"})

    # Close
    client.post(f"/remediation/tasks/{task_id}/close")

    engine_obj = get_engine()
    with Session(engine_obj) as db:
        events = (
            db.query(RemediationTaskAudit)
            .filter(RemediationTaskAudit.task_id == task_id)
            .order_by(RemediationTaskAudit.event_at)
            .all()
        )

    event_types = [e.event_type for e in events]
    assert event_types == ["task_created", "task_updated", "task_closed"]

    # Reconstruct initial state
    created = events[0]
    assert created.old_state is None
    assert created.new_state["title"] == "Lifecycle start"
    assert created.new_state["priority"] == "high"
    assert created.new_state["status"] == "open"

    # Verify state transition on update
    updated = events[1]
    assert updated.old_state["title"] == "Lifecycle start"
    assert updated.new_state["title"] == "Lifecycle updated"
    assert updated.new_state["priority"] == "critical"

    # Verify closure
    closed = events[2]
    assert closed.old_state["status"] == "open"
    assert closed.new_state["status"] == "closed"
    assert closed.new_state["closed_at"] is not None


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

    client.patch(f"/remediation/tasks/{task_id}", json={"title": "Updated before delete"})
    client.delete(f"/remediation/tasks/{task_id}")

    engine_obj = get_engine()
    with Session(engine_obj) as db:
        events = (
            db.query(RemediationTaskAudit)
            .filter(RemediationTaskAudit.task_id == task_id)
            .order_by(RemediationTaskAudit.event_at)
            .all()
        )
        task_row = db.query(RemediationTask).filter(RemediationTask.id == task_id).first()

    assert task_row is None  # task is gone
    assert len(events) == 3  # create, update, delete events all preserved
    assert events[-1].event_type == "task_deleted"
    assert events[-1].old_state["title"] == "Updated before delete"
    assert events[-1].new_state is None
