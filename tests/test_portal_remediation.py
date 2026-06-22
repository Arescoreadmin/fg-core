# tests/test_portal_remediation.py
"""Portal Remediation Integration tests — PR 13.4 + PR 13.5.

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

import os
import pathlib
import tempfile

import pytest
from starlette.testclient import TestClient

_TENANT_A = "tenant-portal-a"
_TENANT_B = "tenant-portal-b"


# ---------------------------------------------------------------------------
# App factory — mirrors the conftest build_app pattern
# ---------------------------------------------------------------------------


def _make_app():
    from api.main import build_app
    from api.db import reset_engine_cache, init_db

    db_path = pathlib.Path(tempfile.mkdtemp()) / "fg-portal-test.db"
    os.environ["FG_SQLITE_PATH"] = str(db_path)
    os.environ.setdefault("FG_ENV", "test")
    os.environ.setdefault("FG_AUTH_ENABLED", "1")
    os.environ.setdefault("FG_KEY_PEPPER", "ci-test-pepper")
    os.environ.setdefault("FG_API_KEY", "ci-test-key-00000000000000000000000000000000")
    os.environ.setdefault("FG_DEVICE_KEY_KEK_CURRENT_VERSION", "v1")
    os.environ.setdefault(
        "FG_DEVICE_KEY_KEK_V1", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
    )
    reset_engine_cache()
    init_db(sqlite_path=str(db_path))
    return build_app()


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
def api_key():
    """Tenant-A scoped key, minted directly (no REST round-trip)."""
    from api.auth_scopes import mint_key

    return mint_key("governance:read", "governance:write", tenant_id=_TENANT_A)


@pytest.fixture(scope="module")
def alt_api_key():
    """Tenant-B scoped key for cross-tenant isolation tests."""
    from api.auth_scopes import mint_key

    return mint_key("governance:read", "governance:write", tenant_id=_TENANT_B)


def _auth(key: str) -> dict:
    return {"X-API-Key": key}


# ---------------------------------------------------------------------------
# Helpers: create a remediation task through the internal API
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def finding_and_assessment(app):
    """Seed a finding + assessment directly via ORM (no REST round-trip)."""
    import uuid
    from api.db import get_engine
    from api.db_models_field_assessment import FaEngagement, FaNormalizedFinding
    from sqlalchemy.orm import Session

    now = "2026-01-01T00:00:00+00:00"
    eid = uuid.uuid4().hex
    fid = uuid.uuid4().hex
    with Session(get_engine()) as db:
        db.add(
            FaEngagement(
                id=eid,
                tenant_id=_TENANT_A,
                client_name="Portal Test Client",
                assessor_id="assessor-portal",
                assessment_type="security",
                status="in_progress",
                engagement_metadata={},
                created_at=now,
                updated_at=now,
            )
        )
        db.add(
            FaNormalizedFinding(
                id=fid,
                tenant_id=_TENANT_A,
                engagement_id=eid,
                finding_type="vulnerability",
                findings_hash=uuid.uuid4().hex,
                severity="high",
                status="open",
                title="Portal Test Finding",
                description="A portal test finding.",
                source_attribution="scanner",
                created_at=now,
                updated_at=now,
            )
        )
        db.commit()
    return eid, fid


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


# ---------------------------------------------------------------------------
# REM-101 / REM-102: Portal session enforcement (13.4a folded in)
# ---------------------------------------------------------------------------


def test_rem_101_portal_source_without_session_returns_403(client, api_key):
    """REM-101  x-portal-source: client-portal without a session token returns 403."""
    resp = client.get(
        "/portal/remediation",
        headers={**_auth(api_key), "x-portal-source": "client-portal"},
    )
    assert resp.status_code == 403
    body = resp.json()
    assert body.get("code") == "PORTAL_SESSION_REQUIRED"


def test_rem_102_portal_source_with_invalid_session_returns_403(client, api_key):
    """REM-102  x-portal-source: client-portal with a bogus session token returns 403."""
    resp = client.get(
        "/portal/remediation",
        headers={
            **_auth(api_key),
            "x-portal-source": "client-portal",
            "x-fg-portal-session": "00000000000000000000000000000000000000000000000000000000000000ff",
        },
    )
    assert resp.status_code == 403
    body = resp.json()
    assert body.get("code") in {
        "PORTAL_SESSION_INVALID",
        "PORTAL_ACCESS_DENIED",
        "PORTAL_ACCESS_CHECK_FAILED",
    }


# ===========================================================================
# PR 13.5 — Portal Input Hardening & Operational Safety
# REM-103 through REM-120
# ===========================================================================


# ---------------------------------------------------------------------------
# REM-103: Comment edit creates PORTAL_COMMENT_EDITED audit event
# ---------------------------------------------------------------------------


def test_rem_103_comment_edit_creates_audit_event(client, api_key, task_id):
    """REM-103  Editing a comment creates a PORTAL_COMMENT_EDITED audit event."""
    add_resp = client.post(
        f"/portal/remediation/tasks/{task_id}/comments",
        json={"body": "Original body for audit test.", "author": "audit@example.com"},
        headers=_auth(api_key),
    )
    assert add_resp.status_code == 201
    comment_id = add_resp.json()["id"]

    client.patch(
        f"/portal/remediation/tasks/{task_id}/comments/{comment_id}",
        json={"body": "Edited body for audit test."},
        headers=_auth(api_key),
    )

    audit_resp = client.get(
        f"/portal/remediation/tasks/{task_id}/audit",
        headers=_auth(api_key),
    )
    assert audit_resp.status_code == 200
    event_types = [e["event_type"] for e in audit_resp.json()["events"]]
    assert "portal_comment_edited" in event_types


# ---------------------------------------------------------------------------
# REM-104 / REM-105 / REM-106: SHA256 format validation
# ---------------------------------------------------------------------------


def test_rem_104_invalid_sha256_uppercase_rejected(client, api_key, task_id):
    """REM-104  Uppercase SHA256 is rejected with 422."""
    resp = client.post(
        f"/portal/remediation/tasks/{task_id}/evidence",
        json={
            "filename": "report.pdf",
            "content_type": "application/pdf",
            "sha256": "A" * 64,  # uppercase — invalid
            "submitted_by": "user@example.com",
        },
        headers=_auth(api_key),
    )
    assert resp.status_code == 422


def test_rem_105_invalid_sha256_non_hex_rejected(client, api_key, task_id):
    """REM-105  Non-hex SHA256 (all Z's) is rejected with 422."""
    resp = client.post(
        f"/portal/remediation/tasks/{task_id}/evidence",
        json={
            "filename": "report.pdf",
            "content_type": "application/pdf",
            "sha256": "Z" * 64,  # non-hex — invalid
            "submitted_by": "user@example.com",
        },
        headers=_auth(api_key),
    )
    assert resp.status_code == 422


def test_rem_106_invalid_sha256_wrong_length_rejected(client, api_key, task_id):
    """REM-106  SHA256 with wrong length (63 chars) is rejected with 422."""
    resp = client.post(
        f"/portal/remediation/tasks/{task_id}/evidence",
        json={
            "filename": "report.pdf",
            "content_type": "application/pdf",
            "sha256": "a" * 63,  # one char short — invalid
            "submitted_by": "user@example.com",
        },
        headers=_auth(api_key),
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# REM-107 / REM-108: Evidence metadata size limits
# ---------------------------------------------------------------------------


def test_rem_107_oversized_metadata_rejected(client, api_key, task_id):
    """REM-107  evidence_metadata exceeding 8 KB is rejected with 422."""
    large_meta = {"key_" + str(i): "x" * 100 for i in range(200)}  # ~24 KB
    resp = client.post(
        f"/portal/remediation/tasks/{task_id}/evidence",
        json={
            "filename": "big.pdf",
            "content_type": "application/pdf",
            "sha256": "b" * 64,
            "submitted_by": "user@example.com",
            "evidence_metadata": large_meta,
        },
        headers=_auth(api_key),
    )
    assert resp.status_code == 422


def test_rem_108_metadata_within_limit_accepted(client, api_key, task_id):
    """REM-108  evidence_metadata within 8 KB limit is accepted."""
    small_meta = {"classification": "financial", "reviewed_by": "auditor@example.com"}
    resp = client.post(
        f"/portal/remediation/tasks/{task_id}/evidence",
        json={
            "filename": "within-limit.pdf",
            "content_type": "application/pdf",
            "sha256": "c1" + "0" * 62,
            "submitted_by": "user@example.com",
            "evidence_metadata": small_meta,
        },
        headers=_auth(api_key),
    )
    assert resp.status_code == 201


# ---------------------------------------------------------------------------
# REM-109 / REM-110 / REM-111: MIME type whitelist
# ---------------------------------------------------------------------------


def test_rem_109_invalid_mime_type_rejected(client, api_key, task_id):
    """REM-109  content_type not in approved list is rejected with 422."""
    resp = client.post(
        f"/portal/remediation/tasks/{task_id}/evidence",
        json={
            "filename": "script.exe",
            "content_type": "application/x-msdownload",
            "sha256": "d1" + "0" * 62,
            "submitted_by": "user@example.com",
        },
        headers=_auth(api_key),
    )
    assert resp.status_code == 422


def test_rem_110_valid_mime_types_accepted(client, api_key, task_id):
    """REM-110  All approved MIME types are accepted."""
    approved = [
        ("application/pdf", "f1" + "0" * 62),
        ("text/plain", "f2" + "0" * 62),
        ("text/csv", "f3" + "0" * 62),
        ("image/png", "f4" + "0" * 62),
        ("image/jpeg", "f5" + "0" * 62),
        ("application/zip", "f6" + "0" * 62),
        ("application/json", "f7" + "0" * 62),
    ]
    for mime, sha in approved:
        resp = client.post(
            f"/portal/remediation/tasks/{task_id}/evidence",
            json={
                "filename": f"file.{mime.split('/')[-1]}",
                "content_type": mime,
                "sha256": sha,
                "submitted_by": "user@example.com",
            },
            headers=_auth(api_key),
        )
        assert resp.status_code == 201, (
            f"Expected 201 for mime={mime}, got {resp.status_code}"
        )


def test_rem_111_image_family_accepted(client, api_key, task_id):
    """REM-111  image/* family MIME types (image/webp, image/tiff) are accepted."""
    for mime, sha in [("image/webp", "a1" + "0" * 62), ("image/tiff", "a2" + "0" * 62)]:
        resp = client.post(
            f"/portal/remediation/tasks/{task_id}/evidence",
            json={
                "filename": "screenshot.img",
                "content_type": mime,
                "sha256": sha,
                "submitted_by": "user@example.com",
            },
            headers=_auth(api_key),
        )
        assert resp.status_code == 201, f"Expected 201 for mime={mime}"


# ---------------------------------------------------------------------------
# REM-112 / REM-113: Comment body sanitization
# ---------------------------------------------------------------------------


def test_rem_112_whitespace_only_comment_rejected(client, api_key, task_id):
    """REM-112  Whitespace-only comment body is rejected with 422."""
    resp = client.post(
        f"/portal/remediation/tasks/{task_id}/comments",
        json={"body": "     ", "author": "user@example.com"},
        headers=_auth(api_key),
    )
    assert resp.status_code == 422


def test_rem_113_whitespace_only_edit_rejected(client, api_key, task_id):
    """REM-113  Whitespace-only body on comment edit is rejected with 422."""
    add_resp = client.post(
        f"/portal/remediation/tasks/{task_id}/comments",
        json={"body": "Valid initial body.", "author": "user@example.com"},
        headers=_auth(api_key),
    )
    assert add_resp.status_code == 201
    comment_id = add_resp.json()["id"]

    resp = client.patch(
        f"/portal/remediation/tasks/{task_id}/comments/{comment_id}",
        json={"body": "\t\n  "},
        headers=_auth(api_key),
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# REM-114 / REM-115 / REM-116: Pagination on list endpoints
# ---------------------------------------------------------------------------


def test_rem_114_comment_list_pagination_fields_present(client, api_key, task_id):
    """REM-114  Comment list response contains total, limit, offset fields."""
    resp = client.get(
        f"/portal/remediation/tasks/{task_id}/comments",
        headers=_auth(api_key),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "total" in data
    assert "limit" in data
    assert "offset" in data
    assert data["limit"] == 50
    assert data["offset"] == 0


def test_rem_115_evidence_list_pagination_fields_present(client, api_key, task_id):
    """REM-115  Evidence list response contains total, limit, offset fields."""
    resp = client.get(
        f"/portal/remediation/tasks/{task_id}/evidence",
        headers=_auth(api_key),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "total" in data
    assert "limit" in data
    assert "offset" in data


def test_rem_116_audit_list_pagination_fields_present(client, api_key, task_id):
    """REM-116  Audit list response contains total, limit, offset fields."""
    resp = client.get(
        f"/portal/remediation/tasks/{task_id}/audit",
        headers=_auth(api_key),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "total" in data
    assert "limit" in data
    assert "offset" in data


# ---------------------------------------------------------------------------
# REM-117: Pagination max limit enforcement
# ---------------------------------------------------------------------------


def test_rem_117_pagination_limit_exceeding_max_rejected(client, api_key, task_id):
    """REM-117  limit > 100 is rejected with 422."""
    resp = client.get(
        f"/portal/remediation/tasks/{task_id}/comments?limit=101",
        headers=_auth(api_key),
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# REM-118: Pagination offset returns subset
# ---------------------------------------------------------------------------


def test_rem_118_pagination_offset_returns_subset(client, api_key, task_id):
    """REM-118  offset=999 returns empty list when fewer items exist."""
    resp = client.get(
        f"/portal/remediation/tasks/{task_id}/comments?limit=50&offset=999",
        headers=_auth(api_key),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data["comments"], list)
    assert len(data["comments"]) == 0
    assert data["total"] >= 0
    assert data["offset"] == 999


# ---------------------------------------------------------------------------
# REM-119: Validation failure metric increments on bad SHA256
# ---------------------------------------------------------------------------


def test_rem_119_sha256_validation_failure_metric_increments(client, api_key, task_id):
    """REM-119  Submitting a bad SHA256 increments frostgate_portal_sha256_validation_failures_total."""
    from api.observability.metrics import (
        PORTAL_SHA256_VALIDATION_FAILURES_TOTAL,
        PORTAL_VALIDATION_FAILURES_TOTAL,
    )

    before_sha = PORTAL_SHA256_VALIDATION_FAILURES_TOTAL._value.get()
    before_total = PORTAL_VALIDATION_FAILURES_TOTAL._value.get()

    client.post(
        f"/portal/remediation/tasks/{task_id}/evidence",
        json={
            "filename": "x.pdf",
            "content_type": "application/pdf",
            "sha256": "Z" * 64,  # 64 chars but non-hex — triggers our validator
            "submitted_by": "user@example.com",
        },
        headers=_auth(api_key),
    )

    assert PORTAL_SHA256_VALIDATION_FAILURES_TOTAL._value.get() > before_sha
    assert PORTAL_VALIDATION_FAILURES_TOTAL._value.get() > before_total


# ---------------------------------------------------------------------------
# REM-121: Wrong-length SHA256 increments validation counter
# ---------------------------------------------------------------------------


def test_rem_121_wrong_length_sha256_increments_metric(client, api_key, task_id):
    """REM-121  Wrong-length SHA256 (63 chars) still increments validation counters.

    Pydantic's min_length/max_length was removed from the field so our regex
    validator always fires — no Pydantic pre-check can short-circuit the metric.
    """
    from api.observability.metrics import (
        PORTAL_SHA256_VALIDATION_FAILURES_TOTAL,
        PORTAL_VALIDATION_FAILURES_TOTAL,
    )

    before_sha = PORTAL_SHA256_VALIDATION_FAILURES_TOTAL._value.get()
    before_total = PORTAL_VALIDATION_FAILURES_TOTAL._value.get()

    resp = client.post(
        f"/portal/remediation/tasks/{task_id}/evidence",
        json={
            "filename": "x.pdf",
            "content_type": "application/pdf",
            "sha256": "a" * 63,  # one char short — wrong length
            "submitted_by": "user@example.com",
        },
        headers=_auth(api_key),
    )

    assert resp.status_code == 422
    assert PORTAL_SHA256_VALIDATION_FAILURES_TOTAL._value.get() > before_sha
    assert PORTAL_VALIDATION_FAILURES_TOTAL._value.get() > before_total


# ---------------------------------------------------------------------------
# REM-120: Cross-tenant pagination isolation
# ---------------------------------------------------------------------------


def test_rem_120_cross_tenant_comment_pagination_denied(
    client, api_key, alt_api_key, task_id
):
    """REM-120  Tenant B cannot paginate Tenant A's comments — gets 404."""
    resp = client.get(
        f"/portal/remediation/tasks/{task_id}/comments?limit=10&offset=0",
        headers=_auth(alt_api_key),
    )
    assert resp.status_code == 404


# ===========================================================================
# PR 13.6 — Portal Abuse Protection & Rate Limiting (REM-122 through REM-145)
# ===========================================================================

# ---------------------------------------------------------------------------
# Shared helpers for rate-limit tests
# ---------------------------------------------------------------------------

_RL_COMMENT_BODY = {"body": "rate limit test comment", "author": "rl-tester"}
_RL_EVIDENCE_BODY = {
    "filename": "rl-test.pdf",
    "content_type": "application/pdf",
    "sha256": "a" * 64,
    "submitted_by": "rl-tester",
}
_RL_ACK_BODY = {"acknowledged_by": "rl-tester"}


class _AlwaysThrottledLimiter:
    """Test backend that always reports the limit as exhausted."""

    def increment_and_check(self, key: str, limit: int, window_seconds: int) -> tuple:
        return False, 3600

    def reset(self, key: str) -> None:
        pass

    def backend_name(self) -> str:
        return "always_throttled"


@pytest.fixture()
def throttled_limiter():
    """Swap in an always-throttled backend; restore original after test."""
    from services.remediation_portal.rate_limit import (
        _set_portal_rate_limiter,
        get_portal_rate_limiter,
    )

    original = get_portal_rate_limiter()
    _set_portal_rate_limiter(_AlwaysThrottledLimiter())
    yield
    _set_portal_rate_limiter(original)


@pytest.fixture()
def fresh_limiter():
    """Swap in a fresh MemoryPortalRateLimiter; restore original after test."""
    from services.remediation_portal.rate_limit import (
        MemoryPortalRateLimiter,
        _set_portal_rate_limiter,
        get_portal_rate_limiter,
    )

    original = get_portal_rate_limiter()
    limiter = MemoryPortalRateLimiter()
    _set_portal_rate_limiter(limiter)
    yield limiter
    _set_portal_rate_limiter(original)


# ---------------------------------------------------------------------------
# Fixtures for Tenant B task (cross-tenant fairness tests)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def finding_and_assessment_b(app):
    """Seed a finding + assessment for Tenant B directly via ORM."""
    import uuid

    from sqlalchemy.orm import Session

    from api.db import get_engine
    from api.db_models_field_assessment import FaEngagement, FaNormalizedFinding

    now = "2026-01-02T00:00:00+00:00"
    eid = uuid.uuid4().hex
    fid = uuid.uuid4().hex
    with Session(get_engine()) as db:
        db.add(
            FaEngagement(
                id=eid,
                tenant_id=_TENANT_B,
                client_name="Portal Test Client B",
                assessor_id="assessor-portal-b",
                assessment_type="security",
                status="in_progress",
                engagement_metadata={},
                created_at=now,
                updated_at=now,
            )
        )
        db.add(
            FaNormalizedFinding(
                id=fid,
                tenant_id=_TENANT_B,
                engagement_id=eid,
                finding_type="vulnerability",
                findings_hash=uuid.uuid4().hex,
                severity="medium",
                status="open",
                title="Portal Test Finding B",
                description="A portal test finding for Tenant B.",
                source_attribution="scanner",
                created_at=now,
                updated_at=now,
            )
        )
        db.commit()
    return eid, fid


@pytest.fixture(scope="module")
def task_id_b(client, alt_api_key, finding_and_assessment_b):
    """Create a remediation task for Tenant B and return its ID."""
    assessment_id, finding_id = finding_and_assessment_b
    resp = client.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id,
            "assessment_id": assessment_id,
            "title": "Portal Test Task B",
            "description": "Test remediation for portal tenant B",
            "priority": "medium",
        },
        headers=_auth(alt_api_key),
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


@pytest.fixture(scope="module")
def api_key_b2():
    """Second API key for Tenant A — different client ID for per-client isolation tests."""
    from api.auth_scopes import mint_key

    return mint_key("governance:read", "governance:write", tenant_id=_TENANT_A)


# ---------------------------------------------------------------------------
# REM-122: Comment create throttled → 429
# ---------------------------------------------------------------------------


def test_rem_122_comment_create_throttled(client, api_key, task_id, throttled_limiter):
    """REM-122  Add-comment is rejected with 429 when rate limit is exhausted."""
    resp = client.post(
        f"/portal/remediation/tasks/{task_id}/comments",
        json=_RL_COMMENT_BODY,
        headers=_auth(api_key),
    )
    assert resp.status_code == 429


# ---------------------------------------------------------------------------
# REM-123: Comment edit throttled → 429
# ---------------------------------------------------------------------------


def test_rem_123_comment_edit_throttled(client, api_key, task_id, throttled_limiter):
    """REM-123  Edit-comment is rejected with 429 when rate limit is exhausted."""
    # Create a real comment first (using fresh limiter, not throttled)
    from services.remediation_portal.rate_limit import (
        MemoryPortalRateLimiter,
        _set_portal_rate_limiter,
    )

    _set_portal_rate_limiter(MemoryPortalRateLimiter())
    r = client.post(
        f"/portal/remediation/tasks/{task_id}/comments",
        json=_RL_COMMENT_BODY,
        headers=_auth(api_key),
    )
    assert r.status_code == 201
    cid = r.json()["id"]
    _set_portal_rate_limiter(_AlwaysThrottledLimiter())

    resp = client.patch(
        f"/portal/remediation/tasks/{task_id}/comments/{cid}",
        json={"body": "edited"},
        headers=_auth(api_key),
    )
    assert resp.status_code == 429


# ---------------------------------------------------------------------------
# REM-124: Evidence upload throttled → 429
# ---------------------------------------------------------------------------


def test_rem_124_evidence_upload_throttled(client, api_key, task_id, throttled_limiter):
    """REM-124  Submit-evidence is rejected with 429 when rate limit is exhausted."""
    resp = client.post(
        f"/portal/remediation/tasks/{task_id}/evidence",
        json=_RL_EVIDENCE_BODY,
        headers=_auth(api_key),
    )
    assert resp.status_code == 429


# ---------------------------------------------------------------------------
# REM-125: Acknowledgement throttled → 429
# ---------------------------------------------------------------------------


def test_rem_125_acknowledgement_throttled(client, api_key, task_id, throttled_limiter):
    """REM-125  Acknowledge-ownership is rejected with 429 when rate limit is exhausted."""
    resp = client.post(
        f"/portal/remediation/tasks/{task_id}/acknowledge",
        json=_RL_ACK_BODY,
        headers=_auth(api_key),
    )
    assert resp.status_code == 429


# ---------------------------------------------------------------------------
# REM-126: 429 response body format
# ---------------------------------------------------------------------------


def test_rem_126_429_body_format(client, api_key, task_id, throttled_limiter):
    """REM-126  429 body is {"error": "RATE_LIMIT_EXCEEDED", "retry_after_seconds": N}."""
    resp = client.post(
        f"/portal/remediation/tasks/{task_id}/comments",
        json=_RL_COMMENT_BODY,
        headers=_auth(api_key),
    )
    assert resp.status_code == 429
    data = resp.json()
    assert data["error"] == "RATE_LIMIT_EXCEEDED"
    assert isinstance(data["retry_after_seconds"], int)
    assert data["retry_after_seconds"] > 0


# ---------------------------------------------------------------------------
# REM-127: Retry-After header on 429
# ---------------------------------------------------------------------------


def test_rem_127_retry_after_header(client, api_key, task_id, throttled_limiter):
    """REM-127  429 response includes Retry-After header."""
    resp = client.post(
        f"/portal/remediation/tasks/{task_id}/comments",
        json=_RL_COMMENT_BODY,
        headers=_auth(api_key),
    )
    assert resp.status_code == 429
    assert "retry-after" in {k.lower() for k in resp.headers}
    assert int(resp.headers["retry-after"]) > 0


# ---------------------------------------------------------------------------
# REM-128: Cross-tenant fairness — Tenant A throttled ≠ Tenant B degraded
# ---------------------------------------------------------------------------


def test_rem_128_cross_tenant_fairness(
    client, api_key, alt_api_key, task_id, task_id_b, fresh_limiter, monkeypatch
):
    """REM-128  Exhausting Tenant A's rate limit does not affect Tenant B."""
    from services.remediation_portal import engine as _engine
    from services.remediation_portal.rate_policy import PortalRatePolicy

    monkeypatch.setattr(
        _engine,
        "resolve_portal_limits",
        lambda op, **kw: PortalRatePolicy(limit=1, window_seconds=3600),
    )

    # Tenant A: first request allowed, second throttled
    r1 = client.post(
        f"/portal/remediation/tasks/{task_id}/comments",
        json=_RL_COMMENT_BODY,
        headers=_auth(api_key),
    )
    assert r1.status_code == 201

    r2 = client.post(
        f"/portal/remediation/tasks/{task_id}/comments",
        json={**_RL_COMMENT_BODY, "body": "second comment"},
        headers=_auth(api_key),
    )
    assert r2.status_code == 429

    # Tenant B: must still be able to write (different tenant bucket)
    r3 = client.post(
        f"/portal/remediation/tasks/{task_id_b}/comments",
        json=_RL_COMMENT_BODY,
        headers=_auth(alt_api_key),
    )
    assert r3.status_code == 201


# ---------------------------------------------------------------------------
# REM-129: Per-client isolation — Client A throttled ≠ Client B throttled
# ---------------------------------------------------------------------------


def test_rem_129_per_client_isolation(
    client, api_key, api_key_b2, task_id, fresh_limiter, monkeypatch
):
    """REM-129  Client A throttled within Tenant A does not affect Client B (same tenant)."""
    from services.remediation_portal import engine as _engine
    from services.remediation_portal.rate_policy import PortalRatePolicy

    monkeypatch.setattr(
        _engine,
        "resolve_portal_limits",
        lambda op, **kw: PortalRatePolicy(limit=1, window_seconds=3600),
    )

    # Client A (api_key): exhaust
    r1 = client.post(
        f"/portal/remediation/tasks/{task_id}/comments",
        json=_RL_COMMENT_BODY,
        headers=_auth(api_key),
    )
    assert r1.status_code == 201
    r2 = client.post(
        f"/portal/remediation/tasks/{task_id}/comments",
        json={**_RL_COMMENT_BODY, "body": "second"},
        headers=_auth(api_key),
    )
    assert r2.status_code == 429

    # Client B2 (api_key_b2, different key → different client_id within Tenant A)
    r3 = client.post(
        f"/portal/remediation/tasks/{task_id}/comments",
        json=_RL_COMMENT_BODY,
        headers=_auth(api_key_b2),
    )
    assert r3.status_code == 201


# ---------------------------------------------------------------------------
# REM-130: Throttle audit event recorded
# ---------------------------------------------------------------------------


def test_rem_130_throttle_audit_event_recorded(
    client, api_key, task_id, throttled_limiter
):
    """REM-130  A PORTAL_COMMENT_THROTTLED audit event is written on throttle."""
    client.post(
        f"/portal/remediation/tasks/{task_id}/comments",
        json=_RL_COMMENT_BODY,
        headers=_auth(api_key),
    )
    # Fetch audit trail with fresh limiter so the GET is not blocked
    from services.remediation_portal.rate_limit import (
        MemoryPortalRateLimiter,
        _set_portal_rate_limiter,
    )

    _set_portal_rate_limiter(MemoryPortalRateLimiter())
    audit = client.get(
        f"/portal/remediation/tasks/{task_id}/audit",
        headers=_auth(api_key),
    )
    assert audit.status_code == 200
    events = audit.json()["events"]
    throttle_events = [e for e in events if "throttled" in e["event_type"]]
    assert len(throttle_events) >= 1
    assert throttle_events[-1]["event_type"] == "portal_comment_throttled"


# ---------------------------------------------------------------------------
# REM-131: PORTAL_RATE_LIMIT_HITS_TOTAL increments
# ---------------------------------------------------------------------------


def test_rem_131_rate_limit_hits_metric(client, api_key, task_id, throttled_limiter):
    """REM-131  PORTAL_RATE_LIMIT_HITS_TOTAL increments when any write is throttled."""
    from api.observability.metrics import PORTAL_RATE_LIMIT_HITS_TOTAL

    before = PORTAL_RATE_LIMIT_HITS_TOTAL._value.get()
    client.post(
        f"/portal/remediation/tasks/{task_id}/comments",
        json=_RL_COMMENT_BODY,
        headers=_auth(api_key),
    )
    assert PORTAL_RATE_LIMIT_HITS_TOTAL._value.get() > before


# ---------------------------------------------------------------------------
# REM-132: PORTAL_COMMENT_THROTTLES_TOTAL increments
# ---------------------------------------------------------------------------


def test_rem_132_comment_throttle_metric(client, api_key, task_id, throttled_limiter):
    """REM-132  PORTAL_COMMENT_THROTTLES_TOTAL increments on comment throttle."""
    from api.observability.metrics import PORTAL_COMMENT_THROTTLES_TOTAL

    before = PORTAL_COMMENT_THROTTLES_TOTAL._value.get()
    client.post(
        f"/portal/remediation/tasks/{task_id}/comments",
        json=_RL_COMMENT_BODY,
        headers=_auth(api_key),
    )
    assert PORTAL_COMMENT_THROTTLES_TOTAL._value.get() > before


# ---------------------------------------------------------------------------
# REM-133: PORTAL_EVIDENCE_THROTTLES_TOTAL increments
# ---------------------------------------------------------------------------


def test_rem_133_evidence_throttle_metric(client, api_key, task_id, throttled_limiter):
    """REM-133  PORTAL_EVIDENCE_THROTTLES_TOTAL increments on evidence throttle."""
    from api.observability.metrics import PORTAL_EVIDENCE_THROTTLES_TOTAL

    before = PORTAL_EVIDENCE_THROTTLES_TOTAL._value.get()
    client.post(
        f"/portal/remediation/tasks/{task_id}/evidence",
        json=_RL_EVIDENCE_BODY,
        headers=_auth(api_key),
    )
    assert PORTAL_EVIDENCE_THROTTLES_TOTAL._value.get() > before


# ---------------------------------------------------------------------------
# REM-134: PORTAL_ACKNOWLEDGEMENT_THROTTLES_TOTAL increments
# ---------------------------------------------------------------------------


def test_rem_134_acknowledgement_throttle_metric(
    client, api_key, task_id, throttled_limiter
):
    """REM-134  PORTAL_ACKNOWLEDGEMENT_THROTTLES_TOTAL increments on ack throttle."""
    from api.observability.metrics import PORTAL_ACKNOWLEDGEMENT_THROTTLES_TOTAL

    before = PORTAL_ACKNOWLEDGEMENT_THROTTLES_TOTAL._value.get()
    client.post(
        f"/portal/remediation/tasks/{task_id}/acknowledge",
        json=_RL_ACK_BODY,
        headers=_auth(api_key),
    )
    assert PORTAL_ACKNOWLEDGEMENT_THROTTLES_TOTAL._value.get() > before


# ---------------------------------------------------------------------------
# REM-135: Read endpoints are NOT rate-limited
# ---------------------------------------------------------------------------


def test_rem_135_reads_not_rate_limited(client, api_key, task_id, throttled_limiter):
    """REM-135  GET endpoints bypass rate limiting — throttled_limiter has no effect."""
    r1 = client.get("/portal/remediation", headers=_auth(api_key))
    assert r1.status_code == 200

    r2 = client.get(f"/portal/remediation/tasks/{task_id}", headers=_auth(api_key))
    assert r2.status_code == 200

    r3 = client.get(
        f"/portal/remediation/tasks/{task_id}/comments", headers=_auth(api_key)
    )
    assert r3.status_code == 200

    r4 = client.get(
        f"/portal/remediation/tasks/{task_id}/evidence", headers=_auth(api_key)
    )
    assert r4.status_code == 200

    r5 = client.get(
        f"/portal/remediation/tasks/{task_id}/audit", headers=_auth(api_key)
    )
    assert r5.status_code == 200


# ---------------------------------------------------------------------------
# REM-136: Separate rate-limit buckets per operation
# ---------------------------------------------------------------------------


def test_rem_136_separate_buckets_per_operation(
    client, api_key, task_id, fresh_limiter, monkeypatch
):
    """REM-136  Comment bucket is independent from evidence bucket."""
    from services.remediation_portal import engine as _engine
    from services.remediation_portal.rate_policy import PortalRatePolicy

    monkeypatch.setattr(
        _engine,
        "resolve_portal_limits",
        lambda op, **kw: PortalRatePolicy(limit=1, window_seconds=3600),
    )

    # Exhaust comment bucket
    client.post(
        f"/portal/remediation/tasks/{task_id}/comments",
        json=_RL_COMMENT_BODY,
        headers=_auth(api_key),
    )
    r_comment = client.post(
        f"/portal/remediation/tasks/{task_id}/comments",
        json={**_RL_COMMENT_BODY, "body": "second"},
        headers=_auth(api_key),
    )
    assert r_comment.status_code == 429

    # Evidence bucket is independent — still has capacity (unique sha256 per test)
    r_evidence = client.post(
        f"/portal/remediation/tasks/{task_id}/evidence",
        json={**_RL_EVIDENCE_BODY, "sha256": "1" * 64},
        headers=_auth(api_key),
    )
    assert r_evidence.status_code == 201


# ---------------------------------------------------------------------------
# REM-137 / REM-138: Rate-limit key composition
# ---------------------------------------------------------------------------


def test_rem_137_rate_limit_key_includes_tenant():
    """REM-137  Keys for the same operation differ across tenants."""
    from services.remediation_portal.rate_limit import make_rate_limit_key

    key_a = make_rate_limit_key("tenant-a", "client-x", "comment_create")
    key_b = make_rate_limit_key("tenant-b", "client-x", "comment_create")
    assert key_a != key_b
    assert "tenant-a" in key_a
    assert "tenant-b" in key_b


def test_rem_138_rate_limit_key_includes_client():
    """REM-138  Keys for the same tenant + operation differ across clients."""
    from services.remediation_portal.rate_limit import make_rate_limit_key

    key_1 = make_rate_limit_key("tenant-a", "client-1", "comment_create")
    key_2 = make_rate_limit_key("tenant-a", "client-2", "comment_create")
    assert key_1 != key_2
    assert "client-1" in key_1
    assert "client-2" in key_2


# ---------------------------------------------------------------------------
# REM-139: Exactly at limit is allowed; first-over is rejected
# ---------------------------------------------------------------------------


def test_rem_139_at_limit_allowed_over_limit_rejected(
    client, api_key, task_id, fresh_limiter, monkeypatch
):
    """REM-139  Request exactly at the limit is allowed; the next one is rejected."""
    from services.remediation_portal import engine as _engine
    from services.remediation_portal.rate_policy import PortalRatePolicy

    monkeypatch.setattr(
        _engine,
        "resolve_portal_limits",
        lambda op, **kw: PortalRatePolicy(limit=2, window_seconds=3600),
    )

    r1 = client.post(
        f"/portal/remediation/tasks/{task_id}/comments",
        json=_RL_COMMENT_BODY,
        headers=_auth(api_key),
    )
    assert r1.status_code == 201

    r2 = client.post(
        f"/portal/remediation/tasks/{task_id}/comments",
        json={**_RL_COMMENT_BODY, "body": "second"},
        headers=_auth(api_key),
    )
    assert r2.status_code == 201  # exactly at limit — allowed

    r3 = client.post(
        f"/portal/remediation/tasks/{task_id}/comments",
        json={**_RL_COMMENT_BODY, "body": "third"},
        headers=_auth(api_key),
    )
    assert r3.status_code == 429  # over limit — rejected


# ---------------------------------------------------------------------------
# REM-140: Throttle audit metadata
# ---------------------------------------------------------------------------


def test_rem_140_throttle_audit_metadata(client, api_key, task_id, throttled_limiter):
    """REM-140  Throttle audit event metadata contains operation, limit, retry_after_seconds."""
    client.post(
        f"/portal/remediation/tasks/{task_id}/evidence",
        json=_RL_EVIDENCE_BODY,
        headers=_auth(api_key),
    )
    from services.remediation_portal.rate_limit import (
        MemoryPortalRateLimiter,
        _set_portal_rate_limiter,
    )

    _set_portal_rate_limiter(MemoryPortalRateLimiter())
    audit = client.get(
        f"/portal/remediation/tasks/{task_id}/audit",
        headers=_auth(api_key),
    )
    events = audit.json()["events"]
    ev = next(
        (e for e in reversed(events) if e["event_type"] == "portal_evidence_throttled"),
        None,
    )
    assert ev is not None
    meta = ev["event_metadata"]
    assert "operation" in meta
    assert "limit" in meta
    assert "retry_after_seconds" in meta
    assert meta["operation"] == "evidence_upload"


# ---------------------------------------------------------------------------
# REM-141: MemoryPortalRateLimiter satisfies backend protocol
# ---------------------------------------------------------------------------


def test_rem_141_memory_backend_protocol():
    """REM-141  MemoryPortalRateLimiter implements the PortalRateLimiterBackend protocol."""
    from services.remediation_portal.rate_limit import (
        MemoryPortalRateLimiter,
        PortalRateLimiterBackend,
    )

    limiter = MemoryPortalRateLimiter()
    assert isinstance(limiter, PortalRateLimiterBackend)
    assert limiter.backend_name() == "memory"

    allowed, retry = limiter.increment_and_check("test-key", 5, 60)
    assert allowed is True
    assert retry == 0

    limiter.reset("test-key")
    allowed2, _ = limiter.increment_and_check("test-key", 5, 60)
    assert allowed2 is True  # counter reset


# ---------------------------------------------------------------------------
# REM-142: resolve_portal_limits returns correct defaults
# ---------------------------------------------------------------------------


def test_rem_142_default_policy_values():
    """REM-142  Default limits: 60/hr for comments, 30/hr for evidence and acks."""
    from services.remediation_portal.rate_policy import (
        PortalOperation,
        resolve_portal_limits,
    )

    comment = resolve_portal_limits(PortalOperation.COMMENT_CREATE)
    assert comment.limit == 60
    assert comment.window_seconds == 3600

    edit = resolve_portal_limits(PortalOperation.COMMENT_EDIT)
    assert edit.limit == 60

    evidence = resolve_portal_limits(PortalOperation.EVIDENCE_UPLOAD)
    assert evidence.limit == 30
    assert evidence.window_seconds == 3600

    ack = resolve_portal_limits(PortalOperation.ACKNOWLEDGEMENT)
    assert ack.limit == 30


# ---------------------------------------------------------------------------
# REM-143: Subscription tier multiplier
# ---------------------------------------------------------------------------


def test_rem_143_professional_tier_doubles_limit():
    """REM-143  Professional subscription tier doubles the base rate limit."""
    from services.remediation_portal.rate_policy import (
        PortalOperation,
        resolve_portal_limits,
    )

    base = resolve_portal_limits(PortalOperation.COMMENT_CREATE)
    pro = resolve_portal_limits(
        PortalOperation.COMMENT_CREATE, subscription_tier="professional"
    )
    assert pro.limit == base.limit * 2
    assert pro.window_seconds == base.window_seconds


# ---------------------------------------------------------------------------
# REM-144: Window reset allows fresh requests
# ---------------------------------------------------------------------------


def test_rem_144_window_reset_allows_fresh_requests():
    """REM-144  Moving to a new time window resets the counter (new epoch key)."""
    from services.remediation_portal.rate_limit import MemoryPortalRateLimiter

    clock_val = [0.0]
    limiter = MemoryPortalRateLimiter(clock=lambda: clock_val[0])
    window = 3600

    # Window 0: exhaust
    clock_val[0] = 0.0
    allowed, _ = limiter.increment_and_check("k", 1, window)
    assert allowed is True
    allowed, _ = limiter.increment_and_check("k", 1, window)
    assert allowed is False

    # Advance to window 1
    clock_val[0] = float(window)
    allowed, _ = limiter.increment_and_check("k", 1, window)
    assert allowed is True  # fresh window


# ---------------------------------------------------------------------------
# REM-145: Comment create and comment edit are separate buckets
# ---------------------------------------------------------------------------


def test_rem_145_comment_create_and_edit_are_separate_buckets(
    client, api_key, task_id, fresh_limiter, monkeypatch
):
    """REM-145  COMMENT_CREATE and COMMENT_EDIT use separate rate-limit buckets."""
    from services.remediation_portal import engine as _engine
    from services.remediation_portal.rate_policy import PortalRatePolicy

    monkeypatch.setattr(
        _engine,
        "resolve_portal_limits",
        lambda op, **kw: PortalRatePolicy(limit=1, window_seconds=3600),
    )

    # Create a comment (uses COMMENT_CREATE bucket)
    r_create = client.post(
        f"/portal/remediation/tasks/{task_id}/comments",
        json=_RL_COMMENT_BODY,
        headers=_auth(api_key),
    )
    assert r_create.status_code == 201
    cid = r_create.json()["id"]

    # Second create is throttled (COMMENT_CREATE exhausted)
    r_create2 = client.post(
        f"/portal/remediation/tasks/{task_id}/comments",
        json={**_RL_COMMENT_BODY, "body": "second"},
        headers=_auth(api_key),
    )
    assert r_create2.status_code == 429

    # Edit uses a DIFFERENT bucket — first edit is allowed
    r_edit = client.patch(
        f"/portal/remediation/tasks/{task_id}/comments/{cid}",
        json={"body": "edited body"},
        headers=_auth(api_key),
    )
    assert r_edit.status_code == 200


# ---------------------------------------------------------------------------
# REM-146 / REM-147: Zero / negative WINDOW env var guard (bot P2 fix)
# ---------------------------------------------------------------------------


def test_rem_146_zero_window_falls_back_to_default(monkeypatch):
    """REM-146  window_seconds=0 in env falls back to the default (not ZeroDivisionError)."""
    from services.remediation_portal.rate_policy import (
        PortalOperation,
        resolve_portal_limits,
    )

    monkeypatch.setenv("FG_PORTAL_RL_COMMENT_CREATE_WINDOW", "0")
    policy = resolve_portal_limits(PortalOperation.COMMENT_CREATE)
    assert policy.window_seconds == 3600


def test_rem_147_negative_window_falls_back_to_default(monkeypatch):
    """REM-147  Negative window_seconds in env falls back to the default."""
    from services.remediation_portal.rate_policy import (
        PortalOperation,
        resolve_portal_limits,
    )

    monkeypatch.setenv("FG_PORTAL_RL_EVIDENCE_UPLOAD_WINDOW", "-1")
    policy = resolve_portal_limits(PortalOperation.EVIDENCE_UPLOAD)
    assert policy.window_seconds == 3600


def test_rem_148_zero_window_does_not_500_write_endpoint(
    client, api_key, task_id, fresh_limiter, monkeypatch
):
    """REM-148  A zero WINDOW env var does not crash the write endpoint with 500."""
    monkeypatch.setenv("FG_PORTAL_RL_COMMENT_CREATE_WINDOW", "0")
    r = client.post(
        f"/portal/remediation/tasks/{task_id}/comments",
        json=_RL_COMMENT_BODY,
        headers=_auth(api_key),
    )
    assert r.status_code in (201, 429)
