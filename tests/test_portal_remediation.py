# tests/test_portal_remediation.py
"""Portal Remediation Integration tests — PR 13.4.

REM-71  Portal dashboard — open count
REM-72  Portal dashboard — closed count
REM-73  Portal dashboard — overdue tasks surfaced
REM-74  Portal dashboard — accepted risk count
REM-75  Portal dashboard — cross-tenant isolation
REM-76  Portal dashboard — requires auth
REM-77  Portal task detail — full projection returned
REM-78  Portal task detail — internal fields excluded
REM-79  Portal task detail — cross-tenant denied
REM-80  Portal task detail — not found returns 404
REM-81  Add comment — creates comment
REM-82  Add comment — requires auth
REM-83  Edit comment — updates body and sets is_edited
REM-84  Edit comment — wrong tenant denied
REM-85  Edit comment — not found returns 404
REM-86  Submit evidence — happy path
REM-87  Submit evidence — creates audit event
REM-88  Submit evidence — wrong tenant denied
REM-89  Submit evidence — duplicate sha256 returns 409
REM-90  Acknowledge ownership — happy path
REM-91  Acknowledge ownership — creates audit event
REM-92  Acknowledge ownership — wrong tenant denied
REM-93  Acknowledge already-acknowledged task returns 200
REM-94  Portal audit trail — contains all events
REM-95  Portal audit trail — wrong tenant denied
REM-96  Comment isolation — tenant A cannot see tenant B comments
REM-97  Evidence isolation — tenant A cannot see tenant B evidence
REM-98  Metrics increment on comment add
REM-99  Metrics increment on evidence upload
REM-100 Portal audit projection — only portal events returned
"""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

# ---------------------------------------------------------------------------
# Import helpers — reuse fixtures from conftest / test_remediation_engine
# ---------------------------------------------------------------------------


def _make_app():
    import os

    os.environ.setdefault("FG_ENV", "test")
    os.environ.setdefault("FG_KEY_PEPPER", "test-pepper-value-32chars-exactly!")

    from api.main import build_app
    from api.db import reset_engine_cache

    reset_engine_cache()

    import tempfile
    import pathlib

    db_path = pathlib.Path(tempfile.mkdtemp()) / "fg-portal-test.db"
    os.environ["FG_SQLITE_PATH"] = str(db_path)
    reset_engine_cache()

    app = build_app()
    from api.db import get_engine
    from api.db import init_db

    init_db(get_engine())
    return app


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def app():
    return _make_app()


@pytest.fixture(scope="module")
def client(app):
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


@pytest.fixture(scope="module")
def api_key(client):
    """Create a tenant-bound API key for tenant-a."""
    resp = client.post(
        "/control-plane/api-keys",
        json={
            "name": "portal-test-key",
            "scopes": ["governance:read", "governance:write"],
            "tenant_id": "tenant-portal-a",
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["secret"]


@pytest.fixture(scope="module")
def alt_api_key(client):
    """Create a tenant-bound API key for tenant-b (cross-tenant tests)."""
    resp = client.post(
        "/control-plane/api-keys",
        json={
            "name": "portal-test-key-b",
            "scopes": ["governance:read", "governance:write"],
            "tenant_id": "tenant-portal-b",
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["secret"]


def _auth(key: str) -> dict:
    return {"X-API-Key": key}


# ---------------------------------------------------------------------------
# Helpers: create a remediation task through the internal API
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def finding_and_assessment(client, api_key):
    """Create a finding + assessment for tenant-portal-a."""
    eng_resp = client.post(
        "/field-assessment/engagements",
        json={"name": "Portal Test Engagement", "description": "test"},
        headers=_auth(api_key),
    )
    assert eng_resp.status_code == 201, eng_resp.text
    assessment_id = eng_resp.json()["id"]

    finding_resp = client.post(
        f"/field-assessment/engagements/{assessment_id}/findings",
        json={
            "title": "Portal Test Finding",
            "severity": "high",
            "category": "access_control",
            "description": "test finding",
        },
        headers=_auth(api_key),
    )
    assert finding_resp.status_code == 201, finding_resp.text
    finding_id = finding_resp.json()["id"]
    return assessment_id, finding_id


@pytest.fixture(scope="module")
def task_id(client, api_key, finding_and_assessment):
    """Create a remediation task and return its ID."""
    assessment_id, finding_id = finding_and_assessment
    resp = client.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id,
            "assessment_id": assessment_id,
            "title": "Portal Test Task",
            "description": "Test remediation for portal",
            "priority": "high",
        },
        headers=_auth(api_key),
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


# ---------------------------------------------------------------------------
# REM-71: Portal dashboard — open count
# ---------------------------------------------------------------------------


def test_rem_71_portal_dashboard_open_count(client, api_key, task_id):
    """REM-71  Portal dashboard returns open_count >= 1 after task creation."""
    resp = client.get("/portal/remediation", headers=_auth(api_key))
    assert resp.status_code == 200
    data = resp.json()
    assert data["open_count"] >= 1
    assert "planned_count" in data
    assert "in_progress_count" in data
    assert "closed_count" in data
    assert "accepted_risk_count" in data
    assert "overdue_count" in data
    assert "unassigned_count" in data
    assert isinstance(data["recent_open"], list)
    assert isinstance(data["overdue_tasks"], list)


# ---------------------------------------------------------------------------
# REM-72: Portal dashboard — closed count
# ---------------------------------------------------------------------------


def test_rem_72_portal_dashboard_closed_count(client, api_key):
    """REM-72  Dashboard closed_count is a non-negative integer."""
    resp = client.get("/portal/remediation", headers=_auth(api_key))
    assert resp.status_code == 200
    assert resp.json()["closed_count"] >= 0


# ---------------------------------------------------------------------------
# REM-73: Portal dashboard — overdue_tasks list
# ---------------------------------------------------------------------------


def test_rem_73_portal_dashboard_overdue_list(client, api_key):
    """REM-73  Dashboard overdue_tasks list is present and a list."""
    resp = client.get("/portal/remediation", headers=_auth(api_key))
    assert resp.status_code == 200
    assert isinstance(resp.json()["overdue_tasks"], list)


# ---------------------------------------------------------------------------
# REM-74: Portal dashboard — accepted_risk_count
# ---------------------------------------------------------------------------


def test_rem_74_portal_dashboard_accepted_risk(client, api_key):
    """REM-74  Dashboard accepted_risk_count is a non-negative integer."""
    resp = client.get("/portal/remediation", headers=_auth(api_key))
    assert resp.status_code == 200
    assert resp.json()["accepted_risk_count"] >= 0


# ---------------------------------------------------------------------------
# REM-75: Portal dashboard — cross-tenant isolation
# ---------------------------------------------------------------------------


def test_rem_75_portal_dashboard_cross_tenant_isolation(
    client, api_key, alt_api_key, task_id
):
    """REM-75  Tenant B dashboard does not count Tenant A tasks."""
    resp_a = client.get("/portal/remediation", headers=_auth(api_key))
    resp_b = client.get("/portal/remediation", headers=_auth(alt_api_key))
    assert resp_a.status_code == 200
    assert resp_b.status_code == 200
    # Tenant B has no tasks — open_count must differ
    assert resp_a.json()["open_count"] > resp_b.json()["open_count"]


# ---------------------------------------------------------------------------
# REM-76: Portal dashboard — requires auth
# ---------------------------------------------------------------------------


def test_rem_76_portal_dashboard_requires_auth(client):
    """REM-76  Dashboard returns 401/403 without credentials."""
    resp = client.get("/portal/remediation")
    assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# REM-77: Portal task detail — full projection returned
# ---------------------------------------------------------------------------


def test_rem_77_portal_task_detail_full_projection(client, api_key, task_id):
    """REM-77  Task detail returns all portal-safe fields."""
    resp = client.get(f"/portal/remediation/tasks/{task_id}", headers=_auth(api_key))
    assert resp.status_code == 200
    data = resp.json()
    for field in (
        "id",
        "title",
        "priority",
        "status",
        "sla_status",
        "comment_count",
        "evidence_count",
    ):
        assert field in data, f"Missing field: {field}"
    assert data["id"] == task_id


# ---------------------------------------------------------------------------
# REM-78: Portal task detail — internal fields excluded
# ---------------------------------------------------------------------------


def test_rem_78_portal_task_detail_excludes_internal_fields(client, api_key, task_id):
    """REM-78  Task detail excludes internal fields like assigned_user_id, created_by, schema_version."""
    resp = client.get(f"/portal/remediation/tasks/{task_id}", headers=_auth(api_key))
    assert resp.status_code == 200
    data = resp.json()
    for internal_field in (
        "assigned_user_id",
        "assigned_user_email",
        "created_by",
        "schema_version",
        "task_metadata",
        "assigned_to",
    ):
        assert internal_field not in data, f"Internal field exposed: {internal_field}"


# ---------------------------------------------------------------------------
# REM-79: Portal task detail — cross-tenant denied
# ---------------------------------------------------------------------------


def test_rem_79_portal_task_detail_cross_tenant_denied(client, alt_api_key, task_id):
    """REM-79  Tenant B cannot view Tenant A task — returns 404."""
    resp = client.get(
        f"/portal/remediation/tasks/{task_id}", headers=_auth(alt_api_key)
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# REM-80: Portal task detail — not found returns 404
# ---------------------------------------------------------------------------


def test_rem_80_portal_task_detail_not_found(client, api_key):
    """REM-80  Non-existent task returns 404."""
    resp = client.get(
        "/portal/remediation/tasks/nonexistent-task-id", headers=_auth(api_key)
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# REM-81: Add comment — creates comment
# ---------------------------------------------------------------------------


def test_rem_81_add_comment(client, api_key, task_id):
    """REM-81  Adding a comment returns 201 with comment data."""
    resp = client.post(
        f"/portal/remediation/tasks/{task_id}/comments",
        json={"body": "We have started remediation.", "author": "jane.doe@example.com"},
        headers=_auth(api_key),
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["body"] == "We have started remediation."
    assert data["author"] == "jane.doe@example.com"
    assert data["is_edited"] is False
    assert "id" in data


# ---------------------------------------------------------------------------
# REM-82: Add comment — requires auth
# ---------------------------------------------------------------------------


def test_rem_82_add_comment_requires_auth(client, task_id):
    """REM-82  Adding a comment without auth returns 401/403."""
    resp = client.post(
        f"/portal/remediation/tasks/{task_id}/comments",
        json={"body": "No auth.", "author": "anon"},
    )
    assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# REM-83: Edit comment — updates body and sets is_edited
# ---------------------------------------------------------------------------


def test_rem_83_edit_comment(client, api_key, task_id):
    """REM-83  Editing a comment updates body and sets is_edited=True."""
    add_resp = client.post(
        f"/portal/remediation/tasks/{task_id}/comments",
        json={"body": "Initial body.", "author": "editor@example.com"},
        headers=_auth(api_key),
    )
    assert add_resp.status_code == 201
    comment_id = add_resp.json()["id"]

    edit_resp = client.patch(
        f"/portal/remediation/tasks/{task_id}/comments/{comment_id}",
        json={"body": "Updated body."},
        headers=_auth(api_key),
    )
    assert edit_resp.status_code == 200
    data = edit_resp.json()
    assert data["body"] == "Updated body."
    assert data["is_edited"] is True


# ---------------------------------------------------------------------------
# REM-84: Edit comment — wrong tenant denied
# ---------------------------------------------------------------------------


def test_rem_84_edit_comment_wrong_tenant_denied(client, api_key, alt_api_key, task_id):
    """REM-84  Tenant B cannot edit Tenant A comment — 404."""
    add_resp = client.post(
        f"/portal/remediation/tasks/{task_id}/comments",
        json={"body": "Tenant A comment.", "author": "a@example.com"},
        headers=_auth(api_key),
    )
    assert add_resp.status_code == 201
    comment_id = add_resp.json()["id"]

    edit_resp = client.patch(
        f"/portal/remediation/tasks/{task_id}/comments/{comment_id}",
        json={"body": "Hostile edit."},
        headers=_auth(alt_api_key),
    )
    assert edit_resp.status_code == 404


# ---------------------------------------------------------------------------
# REM-85: Edit comment — not found returns 404
# ---------------------------------------------------------------------------


def test_rem_85_edit_comment_not_found(client, api_key, task_id):
    """REM-85  Editing a non-existent comment returns 404."""
    resp = client.patch(
        f"/portal/remediation/tasks/{task_id}/comments/nonexistent-comment-id",
        json={"body": "Ghost edit."},
        headers=_auth(api_key),
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# REM-86: Submit evidence — happy path
# ---------------------------------------------------------------------------


def test_rem_86_submit_evidence(client, api_key, task_id):
    """REM-86  Submitting evidence returns 201 with evidence data."""
    resp = client.post(
        f"/portal/remediation/tasks/{task_id}/evidence",
        json={
            "filename": "patch-screenshot.png",
            "content_type": "image/png",
            "sha256": "a" * 64,
            "submitted_by": "admin@example.com",
            "classification": "screenshot",
            "description": "Patch applied evidence",
        },
        headers=_auth(api_key),
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["filename"] == "patch-screenshot.png"
    assert data["sha256"] == "a" * 64
    assert data["verification_state"] == "pending"


# ---------------------------------------------------------------------------
# REM-87: Submit evidence — creates audit event
# ---------------------------------------------------------------------------


def test_rem_87_submit_evidence_creates_audit(client, api_key, task_id):
    """REM-87  Evidence submission creates a portal audit event."""
    client.post(
        f"/portal/remediation/tasks/{task_id}/evidence",
        json={
            "filename": "log-export.txt",
            "content_type": "text/plain",
            "sha256": "b" * 64,
            "submitted_by": "auditor@example.com",
        },
        headers=_auth(api_key),
    )
    audit_resp = client.get(
        f"/portal/remediation/tasks/{task_id}/audit",
        headers=_auth(api_key),
    )
    assert audit_resp.status_code == 200
    events = audit_resp.json()["events"]
    event_types = [e["event_type"] for e in events]
    assert "portal_evidence_uploaded" in event_types


# ---------------------------------------------------------------------------
# REM-88: Submit evidence — wrong tenant denied
# ---------------------------------------------------------------------------


def test_rem_88_submit_evidence_wrong_tenant_denied(client, alt_api_key, task_id):
    """REM-88  Tenant B cannot submit evidence for Tenant A task — 404."""
    resp = client.post(
        f"/portal/remediation/tasks/{task_id}/evidence",
        json={
            "filename": "hostile.png",
            "content_type": "image/png",
            "sha256": "c" * 64,
            "submitted_by": "attacker@evil.com",
        },
        headers=_auth(alt_api_key),
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# REM-89: Submit evidence — duplicate sha256 returns 409
# ---------------------------------------------------------------------------


def test_rem_89_duplicate_evidence_sha256_returns_409(client, api_key, task_id):
    """REM-89  Submitting evidence with duplicate sha256 for same task returns 409."""
    sha = "d" * 64
    first = client.post(
        f"/portal/remediation/tasks/{task_id}/evidence",
        json={
            "filename": "first.pdf",
            "content_type": "application/pdf",
            "sha256": sha,
            "submitted_by": "u@e.com",
        },
        headers=_auth(api_key),
    )
    assert first.status_code == 201
    second = client.post(
        f"/portal/remediation/tasks/{task_id}/evidence",
        json={
            "filename": "dupe.pdf",
            "content_type": "application/pdf",
            "sha256": sha,
            "submitted_by": "u@e.com",
        },
        headers=_auth(api_key),
    )
    assert second.status_code == 409


# ---------------------------------------------------------------------------
# REM-90: Acknowledge ownership — happy path
# ---------------------------------------------------------------------------


def test_rem_90_acknowledge_ownership(client, api_key, task_id):
    """REM-90  Acknowledging ownership returns 200 with acknowledgement data."""
    resp = client.post(
        f"/portal/remediation/tasks/{task_id}/acknowledge",
        json={
            "acknowledged_by": "owner@example.com",
            "acknowledgement_note": "I confirm I own this remediation.",
        },
        headers=_auth(api_key),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["acknowledged_by"] == "owner@example.com"
    assert data["task_id"] == task_id
    assert "acknowledged_at" in data
    assert "task_status" in data
    assert "sla_status" in data


# ---------------------------------------------------------------------------
# REM-91: Acknowledge ownership — creates audit event
# ---------------------------------------------------------------------------


def test_rem_91_acknowledge_ownership_creates_audit(client, api_key, task_id):
    """REM-91  Acknowledgement creates portal_owner_acknowledged audit event."""
    client.post(
        f"/portal/remediation/tasks/{task_id}/acknowledge",
        json={"acknowledged_by": "owner2@example.com"},
        headers=_auth(api_key),
    )
    audit_resp = client.get(
        f"/portal/remediation/tasks/{task_id}/audit",
        headers=_auth(api_key),
    )
    event_types = [e["event_type"] for e in audit_resp.json()["events"]]
    assert "portal_owner_acknowledged" in event_types


# ---------------------------------------------------------------------------
# REM-92: Acknowledge ownership — wrong tenant denied
# ---------------------------------------------------------------------------


def test_rem_92_acknowledge_wrong_tenant_denied(client, alt_api_key, task_id):
    """REM-92  Tenant B cannot acknowledge Tenant A task — 404."""
    resp = client.post(
        f"/portal/remediation/tasks/{task_id}/acknowledge",
        json={"acknowledged_by": "attacker@evil.com"},
        headers=_auth(alt_api_key),
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# REM-93: Acknowledge already-acknowledged task returns 200
# ---------------------------------------------------------------------------


def test_rem_93_acknowledge_idempotent(client, api_key, task_id):
    """REM-93  Acknowledging a task twice both return 200 (idempotent)."""
    for _ in range(2):
        resp = client.post(
            f"/portal/remediation/tasks/{task_id}/acknowledge",
            json={"acknowledged_by": "repeat-owner@example.com"},
            headers=_auth(api_key),
        )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# REM-94: Portal audit trail — contains all events
# ---------------------------------------------------------------------------


def test_rem_94_portal_audit_trail_completeness(client, api_key, task_id):
    """REM-94  Audit trail contains task_viewed, comment_added, evidence_uploaded, owner_acknowledged."""
    resp = client.get(
        f"/portal/remediation/tasks/{task_id}/audit", headers=_auth(api_key)
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["task_id"] == task_id
    event_types = {e["event_type"] for e in data["events"]}
    assert "portal_task_viewed" in event_types
    assert "portal_comment_added" in event_types
    assert "portal_evidence_uploaded" in event_types
    assert "portal_owner_acknowledged" in event_types


# ---------------------------------------------------------------------------
# REM-95: Portal audit trail — wrong tenant denied
# ---------------------------------------------------------------------------


def test_rem_95_portal_audit_wrong_tenant_denied(client, alt_api_key, task_id):
    """REM-95  Tenant B cannot view Tenant A portal audit — 404."""
    resp = client.get(
        f"/portal/remediation/tasks/{task_id}/audit",
        headers=_auth(alt_api_key),
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# REM-96: Comment isolation
# ---------------------------------------------------------------------------


def test_rem_96_comment_isolation(client, api_key, alt_api_key, task_id):
    """REM-96  Tenant B listing comments for Tenant A task gets 404."""
    resp = client.get(
        f"/portal/remediation/tasks/{task_id}/comments",
        headers=_auth(alt_api_key),
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# REM-97: Evidence isolation
# ---------------------------------------------------------------------------


def test_rem_97_evidence_isolation(client, api_key, alt_api_key, task_id):
    """REM-97  Tenant B listing evidence for Tenant A task gets 404."""
    resp = client.get(
        f"/portal/remediation/tasks/{task_id}/evidence",
        headers=_auth(alt_api_key),
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# REM-98: Metrics increment on comment add
# ---------------------------------------------------------------------------


def test_rem_98_metrics_increment_on_comment(client, api_key, task_id):
    """REM-98  Adding a comment increments frostgate_portal_comments_total."""
    from api.observability.metrics import PORTAL_COMMENTS_TOTAL

    before = PORTAL_COMMENTS_TOTAL._value.get()
    client.post(
        f"/portal/remediation/tasks/{task_id}/comments",
        json={"body": "Metrics test comment.", "author": "metrics@example.com"},
        headers=_auth(api_key),
    )
    after = PORTAL_COMMENTS_TOTAL._value.get()
    assert after > before


# ---------------------------------------------------------------------------
# REM-99: Metrics increment on evidence upload
# ---------------------------------------------------------------------------


def test_rem_99_metrics_increment_on_evidence(client, api_key, task_id):
    """REM-99  Submitting evidence increments frostgate_portal_evidence_uploads_total."""
    from api.observability.metrics import PORTAL_EVIDENCE_UPLOADS_TOTAL

    before = PORTAL_EVIDENCE_UPLOADS_TOTAL._value.get()
    client.post(
        f"/portal/remediation/tasks/{task_id}/evidence",
        json={
            "filename": "metrics-test.zip",
            "content_type": "application/zip",
            "sha256": "e" * 64,
            "submitted_by": "metrics@example.com",
        },
        headers=_auth(api_key),
    )
    after = PORTAL_EVIDENCE_UPLOADS_TOTAL._value.get()
    assert after > before


# ---------------------------------------------------------------------------
# REM-100: Portal audit projection — only portal events returned
# ---------------------------------------------------------------------------


def test_rem_100_portal_audit_projection_only_portal_events(client, api_key, task_id):
    """REM-100  Portal audit endpoint returns only portal_* event types."""
    resp = client.get(
        f"/portal/remediation/tasks/{task_id}/audit",
        headers=_auth(api_key),
    )
    assert resp.status_code == 200
    for event in resp.json()["events"]:
        assert event["event_type"].startswith("portal_"), (
            f"Non-portal event in portal audit: {event['event_type']}"
        )
