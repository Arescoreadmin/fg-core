# tests/test_remediation_timeline.py
"""Unified Timeline & Notification Authority tests — PR 13.7.

REM-149  GET /remediation/tasks/{task_id}/timeline returns 200 with correct schema
REM-150  Timeline includes task_created event from remediation_task_audits
REM-151  Timeline events ordered chronologically (event_at ascending)
REM-152  Timeline total count matches event count
REM-153  Timeline pagination — limit=1 returns 1 event
REM-154  Timeline pagination — offset skips events
REM-155  Timeline requires governance:read scope
REM-156  Timeline for unknown task returns 404
REM-157  Cross-tenant isolation — Tenant A cannot see Tenant B timeline
REM-158  Timeline event has required fields (id, task_id, event_type, source, actor, event_at, metadata)

REM-159  Timeline includes task_updated event after PATCH
REM-160  Timeline includes task_planned after transition to PLANNED
REM-161  Timeline includes task_started after transition to IN_PROGRESS (after assign)
REM-162  Timeline includes task_closed after close
REM-163  Timeline includes task_assigned after assign_owner
REM-164  Timeline includes task_unassigned after remove_owner

REM-165  Timeline includes portal_comment_added events (source=portal)
REM-166  Timeline includes portal_evidence_uploaded events

REM-167  event_type filter returns only matching events
REM-168  source filter — source=remediation returns only remediation events
REM-169  source filter — source=portal returns only portal events
REM-170  since filter excludes events before the date
REM-171  until filter excludes events after the date

REM-172  assign_owner creates a notification record in DB
REM-173  Notification has delivery_status=sent after assignment
REM-174  Notification trigger_type is task_assigned
REM-175  remove_owner creates a notification record
REM-176  transition to CLOSED creates notification when task is assigned
REM-177  transition to ACCEPTED_RISK creates notification when task is assigned
REM-178  transition to CLOSED does NOT create notification when task is unassigned (no recipient)

REM-179  Timeline includes notification events (source=notification) after assignment
REM-180  source filter — source=notification returns only notification events

REM-181  Acknowledge endpoint marks notification as acknowledged
REM-182  NOTIFICATIONS_ACKNOWLEDGED_TOTAL increments on acknowledge

REM-183  notify_sla_approaching creates notification with trigger_type=sla_approaching
REM-184  notify_sla_breached creates notification with trigger_type=sla_breached
REM-185  SLA_ESCALATIONS_TOTAL increments on SLA notification

REM-186  NOTIFICATIONS_SENT_TOTAL increments after assignment
REM-187  NOTIFICATIONS_FAILED_TOTAL increments when channel fails
REM-188  TIMELINE_EVENTS_TOTAL increments on timeline request

REM-189  Timeline events have flat JSON structure (export compatible)
REM-190  All event sources present in merged timeline
"""

from __future__ import annotations

import os
import pathlib
import tempfile
import uuid

import pytest
from starlette.testclient import TestClient

_TENANT_A = "tenant-timeline-a"
_TENANT_B = "tenant-timeline-b"


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def _make_app():
    from api.db import init_db, reset_engine_cache
    from api.main import build_app

    db_path = pathlib.Path(tempfile.mkdtemp()) / "fg-timeline-test.db"
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
# Module-scoped fixtures
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
    from api.auth_scopes import mint_key

    return mint_key("governance:read", "governance:write", tenant_id=_TENANT_A)


@pytest.fixture(scope="module")
def alt_api_key():
    from api.auth_scopes import mint_key

    return mint_key("governance:read", "governance:write", tenant_id=_TENANT_B)


@pytest.fixture(scope="module")
def read_only_key():
    from api.auth_scopes import mint_key

    return mint_key("governance:read", tenant_id=_TENANT_A)


def _auth(key: str) -> dict:
    return {"X-API-Key": key}


# ---------------------------------------------------------------------------
# Seed data helpers
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def finding_and_assessment(app):
    """Seed a finding + assessment directly via ORM (Tenant A)."""
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
                client_name="Timeline Test Client",
                assessor_id="assessor-timeline",
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
                title="Timeline Test Finding",
                description="A timeline test finding.",
                source_attribution="scanner",
                created_at=now,
                updated_at=now,
            )
        )
        db.commit()
    return eid, fid


@pytest.fixture(scope="module")
def finding_and_assessment_b(app):
    """Seed a finding + assessment directly via ORM (Tenant B)."""
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
                tenant_id=_TENANT_B,
                client_name="Timeline Test Client B",
                assessor_id="assessor-timeline-b",
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
                severity="high",
                status="open",
                title="Timeline Test Finding B",
                description="A timeline test finding B.",
                source_attribution="scanner",
                created_at=now,
                updated_at=now,
            )
        )
        db.commit()
    return eid, fid


@pytest.fixture(scope="module")
def task_id(client, api_key, finding_and_assessment):
    """Create a remediation task and return its ID (Tenant A)."""
    assessment_id, finding_id = finding_and_assessment
    resp = client.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id,
            "assessment_id": assessment_id,
            "title": "Timeline Test Task",
            "description": "Test task for timeline",
            "priority": "high",
        },
        headers=_auth(api_key),
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


@pytest.fixture(scope="module")
def task_id_b(client, alt_api_key, finding_and_assessment_b):
    """Create a remediation task and return its ID (Tenant B)."""
    assessment_id, finding_id = finding_and_assessment_b
    resp = client.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id,
            "assessment_id": assessment_id,
            "title": "Timeline Test Task B",
            "description": "Test task for timeline B",
            "priority": "high",
        },
        headers=_auth(alt_api_key),
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


# ---------------------------------------------------------------------------
# Function-scoped channel injection fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def null_channel():
    """Inject NullNotificationChannel and restore previous after test."""
    from services.notifications.channels import (
        NullNotificationChannel,
        _set_notification_channel,
        get_notification_channel,
    )

    previous = get_notification_channel()
    _set_notification_channel(NullNotificationChannel())
    yield
    _set_notification_channel(previous)


@pytest.fixture()
def recording_channel():
    """Inject a RecordingChannel that stores sent notifications."""
    from services.notifications.channels import (
        NotificationChannelBackend,
        _set_notification_channel,
        get_notification_channel,
    )

    class RecordingChannel(NotificationChannelBackend):
        def __init__(self):
            self.sent = []

        def send(self, *, recipient, subject, body, metadata) -> bool:
            self.sent.append(
                {
                    "recipient": recipient,
                    "subject": subject,
                    "body": body,
                    "metadata": metadata,
                }
            )
            return True

        def channel_name(self) -> str:
            return "recording"

    channel = RecordingChannel()
    previous = get_notification_channel()
    _set_notification_channel(channel)
    yield channel
    _set_notification_channel(previous)


@pytest.fixture()
def failing_channel():
    """Inject a channel that always returns False (failure)."""
    from services.notifications.channels import (
        NotificationChannelBackend,
        _set_notification_channel,
        get_notification_channel,
    )

    class FailingChannel(NotificationChannelBackend):
        def send(self, *, recipient, subject, body, metadata) -> bool:
            return False

        def channel_name(self) -> str:
            return "failing"

    previous = get_notification_channel()
    _set_notification_channel(FailingChannel())
    yield
    _set_notification_channel(previous)


# ===========================================================================
# REM-149–REM-158: Timeline endpoint basics
# ===========================================================================


def test_rem_149_timeline_returns_200_with_schema(client, api_key, task_id):
    """REM-149  GET /remediation/tasks/{task_id}/timeline returns 200 with correct schema."""
    resp = client.get(
        f"/remediation/tasks/{task_id}/timeline",
        headers=_auth(api_key),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "task_id" in data
    assert "events" in data
    assert "total" in data
    assert "limit" in data
    assert "offset" in data
    assert data["task_id"] == task_id
    assert isinstance(data["events"], list)


def test_rem_150_timeline_includes_task_created(client, api_key, task_id):
    """REM-150  Timeline includes task_created event from remediation_task_audits."""
    resp = client.get(
        f"/remediation/tasks/{task_id}/timeline",
        headers=_auth(api_key),
    )
    assert resp.status_code == 200
    events = resp.json()["events"]
    event_types = [e["event_type"] for e in events]
    assert "task_created" in event_types


def test_rem_151_timeline_events_ordered_chronologically(client, api_key, task_id):
    """REM-151  Timeline events ordered chronologically (event_at ascending)."""
    resp = client.get(
        f"/remediation/tasks/{task_id}/timeline",
        headers=_auth(api_key),
    )
    assert resp.status_code == 200
    events = resp.json()["events"]
    if len(events) > 1:
        for i in range(len(events) - 1):
            assert events[i]["event_at"] <= events[i + 1]["event_at"]


def test_rem_152_timeline_total_count(client, api_key, task_id):
    """REM-152  Timeline total count matches event count (when not paginated)."""
    resp = client.get(
        f"/remediation/tasks/{task_id}/timeline?limit=100",
        headers=_auth(api_key),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == len(data["events"])


def test_rem_153_timeline_pagination_limit(client, api_key, task_id):
    """REM-153  Timeline pagination — limit=1 returns 1 event."""
    resp = client.get(
        f"/remediation/tasks/{task_id}/timeline?limit=1",
        headers=_auth(api_key),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["events"]) == 1
    assert data["total"] >= 1


def test_rem_154_timeline_pagination_offset(client, api_key, task_id):
    """REM-154  Timeline pagination — offset skips events."""
    # Get all events
    resp_all = client.get(
        f"/remediation/tasks/{task_id}/timeline?limit=100",
        headers=_auth(api_key),
    )
    all_events = resp_all.json()["events"]
    if len(all_events) < 2:
        pytest.skip("Need at least 2 events to test offset")

    resp_offset = client.get(
        f"/remediation/tasks/{task_id}/timeline?limit=100&offset=1",
        headers=_auth(api_key),
    )
    offset_events = resp_offset.json()["events"]
    assert len(offset_events) == len(all_events) - 1
    # First event of offset result should be second event of full result
    assert offset_events[0]["id"] == all_events[1]["id"]


def test_rem_155_timeline_requires_auth(client, task_id):
    """REM-155  Timeline requires governance:read scope."""
    resp = client.get(f"/remediation/tasks/{task_id}/timeline")
    assert resp.status_code in (401, 403)


def test_rem_156_timeline_unknown_task_returns_404(client, api_key):
    """REM-156  Timeline for unknown task returns 404."""
    resp = client.get(
        "/remediation/tasks/does-not-exist-xyz/timeline",
        headers=_auth(api_key),
    )
    assert resp.status_code == 404


def test_rem_157_cross_tenant_isolation(client, api_key, task_id_b):
    """REM-157  Cross-tenant isolation — Tenant A cannot see Tenant B timeline."""
    # Tenant A key cannot see Tenant B task
    resp = client.get(
        f"/remediation/tasks/{task_id_b}/timeline",
        headers=_auth(api_key),
    )
    assert resp.status_code == 404


def test_rem_158_timeline_event_has_required_fields(client, api_key, task_id):
    """REM-158  Timeline event has required fields (id, task_id, event_type, source, actor, event_at, metadata)."""
    resp = client.get(
        f"/remediation/tasks/{task_id}/timeline",
        headers=_auth(api_key),
    )
    assert resp.status_code == 200
    events = resp.json()["events"]
    assert len(events) > 0
    for event in events:
        for field in (
            "id",
            "task_id",
            "event_type",
            "source",
            "actor",
            "event_at",
            "metadata",
        ):
            assert field in event, f"Missing field {field!r} in event"


# ===========================================================================
# REM-159–REM-164: Timeline content — remediation source
# ===========================================================================


def test_rem_159_timeline_includes_task_updated(client, api_key, task_id):
    """REM-159  Timeline includes task_updated event after PATCH."""
    # Update the task
    resp = client.patch(
        f"/remediation/tasks/{task_id}",
        json={"title": "Updated Timeline Test Task"},
        headers=_auth(api_key),
    )
    assert resp.status_code == 200

    resp = client.get(
        f"/remediation/tasks/{task_id}/timeline",
        headers=_auth(api_key),
    )
    assert resp.status_code == 200
    event_types = [e["event_type"] for e in resp.json()["events"]]
    assert "task_updated" in event_types


def test_rem_160_timeline_includes_task_planned(client, api_key, task_id):
    """REM-160  Timeline includes task_planned after transition to PLANNED."""
    resp = client.post(
        f"/remediation/tasks/{task_id}/transition",
        json={"new_status": "planned"},
        headers=_auth(api_key),
    )
    assert resp.status_code == 200

    resp = client.get(
        f"/remediation/tasks/{task_id}/timeline",
        headers=_auth(api_key),
    )
    assert resp.status_code == 200
    event_types = [e["event_type"] for e in resp.json()["events"]]
    assert "task_planned" in event_types


def test_rem_161_timeline_includes_task_started(client, api_key, task_id):
    """REM-161  Timeline includes task_started after transition to IN_PROGRESS (after assign)."""
    # Assign owner first
    resp = client.post(
        f"/remediation/tasks/{task_id}/assign",
        json={
            "user_id": "user-timeline-1",
            "display_name": "Timeline User",
            "email": "timeline@example.com",
            "reason": "Test assignment",
        },
        headers=_auth(api_key),
    )
    assert resp.status_code == 200

    # Transition to IN_PROGRESS
    resp = client.post(
        f"/remediation/tasks/{task_id}/transition",
        json={"new_status": "in_progress"},
        headers=_auth(api_key),
    )
    assert resp.status_code == 200

    resp = client.get(
        f"/remediation/tasks/{task_id}/timeline",
        headers=_auth(api_key),
    )
    assert resp.status_code == 200
    event_types = [e["event_type"] for e in resp.json()["events"]]
    assert "task_started" in event_types


def test_rem_162_timeline_includes_task_closed(client, api_key, task_id):
    """REM-162  Timeline includes task_closed after close."""
    resp = client.post(
        f"/remediation/tasks/{task_id}/transition",
        json={"new_status": "closed"},
        headers=_auth(api_key),
    )
    assert resp.status_code == 200

    resp = client.get(
        f"/remediation/tasks/{task_id}/timeline",
        headers=_auth(api_key),
    )
    assert resp.status_code == 200
    event_types = [e["event_type"] for e in resp.json()["events"]]
    assert "task_closed" in event_types


def test_rem_163_timeline_includes_task_assigned(
    client, api_key, finding_and_assessment
):
    """REM-163  Timeline includes task_assigned after assign_owner."""
    # Create a fresh task for this test
    assessment_id, finding_id = finding_and_assessment
    resp = client.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id,
            "assessment_id": assessment_id,
            "title": "Task for assign test",
            "priority": "medium",
        },
        headers=_auth(api_key),
    )
    assert resp.status_code == 201
    tid = resp.json()["id"]

    resp = client.post(
        f"/remediation/tasks/{tid}/assign",
        json={
            "user_id": "user-assign-test",
            "display_name": "Assign Test User",
            "email": "assign@example.com",
        },
        headers=_auth(api_key),
    )
    assert resp.status_code == 200

    resp = client.get(f"/remediation/tasks/{tid}/timeline", headers=_auth(api_key))
    assert resp.status_code == 200
    event_types = [e["event_type"] for e in resp.json()["events"]]
    assert "task_assigned" in event_types


def test_rem_164_timeline_includes_task_unassigned(
    client, api_key, finding_and_assessment
):
    """REM-164  Timeline includes task_unassigned after remove_owner."""
    assessment_id, finding_id = finding_and_assessment
    resp = client.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id,
            "assessment_id": assessment_id,
            "title": "Task for unassign test",
            "priority": "medium",
        },
        headers=_auth(api_key),
    )
    assert resp.status_code == 201
    tid = resp.json()["id"]

    # Assign then unassign
    client.post(
        f"/remediation/tasks/{tid}/assign",
        json={
            "user_id": "user-unassign-test",
            "display_name": "Unassign Test User",
            "email": "unassign@example.com",
        },
        headers=_auth(api_key),
    )
    client.post(
        f"/remediation/tasks/{tid}/unassign",
        json={},
        headers=_auth(api_key),
    )

    resp = client.get(f"/remediation/tasks/{tid}/timeline", headers=_auth(api_key))
    assert resp.status_code == 200
    event_types = [e["event_type"] for e in resp.json()["events"]]
    assert "task_unassigned" in event_types


# ===========================================================================
# REM-165–REM-166: Timeline content — portal source
# ===========================================================================


def test_rem_165_timeline_includes_portal_comment_added(
    client, api_key, finding_and_assessment
):
    """REM-165  Timeline includes portal_comment_added events (source=portal)."""
    assessment_id, finding_id = finding_and_assessment
    resp = client.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id,
            "assessment_id": assessment_id,
            "title": "Task for portal comment test",
            "priority": "medium",
        },
        headers=_auth(api_key),
    )
    assert resp.status_code == 201
    tid = resp.json()["id"]

    # Add a comment via portal API
    resp = client.post(
        f"/portal/remediation/tasks/{tid}/comments",
        json={
            "body": "Portal comment for timeline test.",
            "author": "user@example.com",
        },
        headers=_auth(api_key),
    )
    assert resp.status_code == 201

    resp = client.get(f"/remediation/tasks/{tid}/timeline", headers=_auth(api_key))
    assert resp.status_code == 200
    events = resp.json()["events"]
    portal_events = [e for e in events if e["source"] == "portal"]
    assert len(portal_events) >= 1
    portal_event_types = [e["event_type"] for e in portal_events]
    assert any("comment" in et for et in portal_event_types)


def test_rem_166_timeline_includes_portal_evidence_uploaded(
    client, api_key, finding_and_assessment
):
    """REM-166  Timeline includes portal_evidence_uploaded events."""
    assessment_id, finding_id = finding_and_assessment
    resp = client.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id,
            "assessment_id": assessment_id,
            "title": "Task for portal evidence test",
            "priority": "medium",
        },
        headers=_auth(api_key),
    )
    assert resp.status_code == 201
    tid = resp.json()["id"]

    # Submit evidence via portal API
    sha = "a" * 64
    resp = client.post(
        f"/portal/remediation/tasks/{tid}/evidence",
        json={
            "filename": "evidence.pdf",
            "content_type": "application/pdf",
            "sha256": sha,
            "submitted_by": "user@example.com",
        },
        headers=_auth(api_key),
    )
    assert resp.status_code == 201

    resp = client.get(f"/remediation/tasks/{tid}/timeline", headers=_auth(api_key))
    assert resp.status_code == 200
    events = resp.json()["events"]
    portal_events = [e for e in events if e["source"] == "portal"]
    assert len(portal_events) >= 1


# ===========================================================================
# REM-167–REM-171: Timeline filtering
# ===========================================================================


def test_rem_167_event_type_filter(client, api_key, task_id):
    """REM-167  event_type filter returns only matching events."""
    resp = client.get(
        f"/remediation/tasks/{task_id}/timeline?event_type=task_created",
        headers=_auth(api_key),
    )
    assert resp.status_code == 200
    events = resp.json()["events"]
    # All returned events should match the filter
    for e in events:
        assert e["event_type"] == "task_created"


def test_rem_168_source_filter_remediation(client, api_key, task_id):
    """REM-168  source filter — source=remediation returns only remediation events."""
    resp = client.get(
        f"/remediation/tasks/{task_id}/timeline?source=remediation",
        headers=_auth(api_key),
    )
    assert resp.status_code == 200
    events = resp.json()["events"]
    for e in events:
        assert e["source"] == "remediation"


def test_rem_169_source_filter_portal(client, api_key, finding_and_assessment):
    """REM-169  source filter — source=portal returns only portal events."""
    assessment_id, finding_id = finding_and_assessment
    resp = client.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id,
            "assessment_id": assessment_id,
            "title": "Task for source portal filter",
            "priority": "low",
        },
        headers=_auth(api_key),
    )
    assert resp.status_code == 201
    tid = resp.json()["id"]

    # Add a portal event
    client.post(
        f"/portal/remediation/tasks/{tid}/comments",
        json={"body": "Source filter test comment.", "author": "user@example.com"},
        headers=_auth(api_key),
    )

    resp = client.get(
        f"/remediation/tasks/{tid}/timeline?source=portal",
        headers=_auth(api_key),
    )
    assert resp.status_code == 200
    events = resp.json()["events"]
    for e in events:
        assert e["source"] == "portal"


def test_rem_170_since_filter(client, api_key, task_id):
    """REM-170  since filter excludes events before the date."""
    # Use a far-future date to exclude all events
    resp = client.get(
        f"/remediation/tasks/{task_id}/timeline?since=2099-01-01T00:00:00+00:00",
        headers=_auth(api_key),
    )
    assert resp.status_code == 200
    # All events should be filtered out
    assert resp.json()["total"] == 0


def test_rem_171_until_filter(client, api_key, task_id):
    """REM-171  until filter excludes events after the date."""
    # Use a far-past date to exclude all events
    resp = client.get(
        f"/remediation/tasks/{task_id}/timeline?until=2000-01-01T00:00:00+00:00",
        headers=_auth(api_key),
    )
    assert resp.status_code == 200
    # All events should be filtered out
    assert resp.json()["total"] == 0


# ===========================================================================
# REM-172–REM-178: Notification creation
# ===========================================================================


def test_rem_172_assign_creates_notification(
    client, api_key, null_channel, finding_and_assessment
):
    """REM-172  assign_owner creates a notification record in DB."""
    from api.db import get_engine
    from api.db_models_notifications import Notification
    from sqlalchemy.orm import Session

    assessment_id, finding_id = finding_and_assessment
    resp = client.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id,
            "assessment_id": assessment_id,
            "title": "Task for notification test",
            "priority": "high",
        },
        headers=_auth(api_key),
    )
    assert resp.status_code == 201
    tid = resp.json()["id"]

    resp = client.post(
        f"/remediation/tasks/{tid}/assign",
        json={
            "user_id": "user-notif-test",
            "display_name": "Notif Test User",
            "email": "notif@example.com",
        },
        headers=_auth(api_key),
    )
    assert resp.status_code == 200

    with Session(get_engine()) as db:
        notifs = (
            db.query(Notification)
            .filter(
                Notification.tenant_id == _TENANT_A,
                Notification.task_id == tid,
            )
            .all()
        )
    assert len(notifs) >= 1


def test_rem_173_notification_delivery_status_sent(
    client, api_key, null_channel, finding_and_assessment
):
    """REM-173  Notification has delivery_status=sent after assignment."""
    from api.db import get_engine
    from api.db_models_notifications import Notification
    from sqlalchemy.orm import Session

    assessment_id, finding_id = finding_and_assessment
    resp = client.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id,
            "assessment_id": assessment_id,
            "title": "Task for status sent test",
            "priority": "high",
        },
        headers=_auth(api_key),
    )
    assert resp.status_code == 201
    tid = resp.json()["id"]

    client.post(
        f"/remediation/tasks/{tid}/assign",
        json={
            "user_id": "user-sent-test",
            "display_name": "Sent Test User",
            "email": "sent@example.com",
        },
        headers=_auth(api_key),
    )

    with Session(get_engine()) as db:
        notif = (
            db.query(Notification)
            .filter(
                Notification.tenant_id == _TENANT_A,
                Notification.task_id == tid,
                Notification.trigger_type == "task_assigned",
            )
            .first()
        )
    assert notif is not None
    assert notif.delivery_status == "sent"


def test_rem_174_notification_trigger_type_task_assigned(
    client, api_key, null_channel, finding_and_assessment
):
    """REM-174  Notification trigger_type is task_assigned."""
    from api.db import get_engine
    from api.db_models_notifications import Notification
    from sqlalchemy.orm import Session

    assessment_id, finding_id = finding_and_assessment
    resp = client.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id,
            "assessment_id": assessment_id,
            "title": "Task for trigger type test",
            "priority": "medium",
        },
        headers=_auth(api_key),
    )
    assert resp.status_code == 201
    tid = resp.json()["id"]

    client.post(
        f"/remediation/tasks/{tid}/assign",
        json={
            "user_id": "user-trigger-test",
            "display_name": "Trigger Test User",
            "email": "trigger@example.com",
        },
        headers=_auth(api_key),
    )

    with Session(get_engine()) as db:
        notif = (
            db.query(Notification)
            .filter(
                Notification.tenant_id == _TENANT_A,
                Notification.task_id == tid,
            )
            .first()
        )
    assert notif is not None
    assert notif.trigger_type == "task_assigned"


def test_rem_175_remove_owner_creates_notification(
    client, api_key, null_channel, finding_and_assessment
):
    """REM-175  remove_owner creates a notification record."""
    from api.db import get_engine
    from api.db_models_notifications import Notification
    from sqlalchemy.orm import Session

    assessment_id, finding_id = finding_and_assessment
    resp = client.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id,
            "assessment_id": assessment_id,
            "title": "Task for unassign notif test",
            "priority": "medium",
        },
        headers=_auth(api_key),
    )
    assert resp.status_code == 201
    tid = resp.json()["id"]

    client.post(
        f"/remediation/tasks/{tid}/assign",
        json={
            "user_id": "user-unassign-notif",
            "display_name": "Unassign Notif User",
            "email": "unassign-notif@example.com",
        },
        headers=_auth(api_key),
    )
    client.post(
        f"/remediation/tasks/{tid}/unassign",
        json={},
        headers=_auth(api_key),
    )

    with Session(get_engine()) as db:
        notifs = (
            db.query(Notification)
            .filter(
                Notification.tenant_id == _TENANT_A,
                Notification.task_id == tid,
                Notification.trigger_type == "task_unassigned",
            )
            .all()
        )
    assert len(notifs) >= 1


def test_rem_176_closed_creates_notification(
    client, api_key, null_channel, finding_and_assessment
):
    """REM-176  transition to CLOSED creates notification when task is assigned."""
    from api.db import get_engine
    from api.db_models_notifications import Notification
    from sqlalchemy.orm import Session

    assessment_id, finding_id = finding_and_assessment
    resp = client.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id,
            "assessment_id": assessment_id,
            "title": "Task for closed notif test",
            "priority": "medium",
        },
        headers=_auth(api_key),
    )
    assert resp.status_code == 201
    tid = resp.json()["id"]

    # Assign, plan, start, close
    client.post(
        f"/remediation/tasks/{tid}/assign",
        json={
            "user_id": "user-closed-notif",
            "display_name": "Closed Notif User",
            "email": "closed-notif@example.com",
        },
        headers=_auth(api_key),
    )
    client.post(
        f"/remediation/tasks/{tid}/transition",
        json={"new_status": "planned"},
        headers=_auth(api_key),
    )
    client.post(
        f"/remediation/tasks/{tid}/transition",
        json={"new_status": "in_progress"},
        headers=_auth(api_key),
    )
    client.post(
        f"/remediation/tasks/{tid}/transition",
        json={"new_status": "closed"},
        headers=_auth(api_key),
    )

    with Session(get_engine()) as db:
        notifs = (
            db.query(Notification)
            .filter(
                Notification.tenant_id == _TENANT_A,
                Notification.task_id == tid,
                Notification.trigger_type == "task_closed",
            )
            .all()
        )
    assert len(notifs) >= 1


def test_rem_177_accepted_risk_creates_notification(
    client, api_key, null_channel, finding_and_assessment
):
    """REM-177  transition to ACCEPTED_RISK creates notification when task is assigned."""
    from api.db import get_engine
    from api.db_models_notifications import Notification
    from sqlalchemy.orm import Session

    assessment_id, finding_id = finding_and_assessment
    resp = client.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id,
            "assessment_id": assessment_id,
            "title": "Task for risk notif test",
            "priority": "medium",
        },
        headers=_auth(api_key),
    )
    assert resp.status_code == 201
    tid = resp.json()["id"]

    client.post(
        f"/remediation/tasks/{tid}/assign",
        json={
            "user_id": "user-risk-notif",
            "display_name": "Risk Notif User",
            "email": "risk-notif@example.com",
        },
        headers=_auth(api_key),
    )
    client.post(
        f"/remediation/tasks/{tid}/transition",
        json={"new_status": "accepted_risk", "reason": "Accepted for testing"},
        headers=_auth(api_key),
    )

    with Session(get_engine()) as db:
        notifs = (
            db.query(Notification)
            .filter(
                Notification.tenant_id == _TENANT_A,
                Notification.task_id == tid,
                Notification.trigger_type == "task_accepted_risk",
            )
            .all()
        )
    assert len(notifs) >= 1


def test_rem_178_closed_no_notification_when_unassigned(
    client, api_key, null_channel, finding_and_assessment
):
    """REM-178  transition to CLOSED does NOT create notification when task is unassigned (no recipient)."""
    from api.db import get_engine
    from api.db_models_notifications import Notification
    from sqlalchemy.orm import Session

    assessment_id, finding_id = finding_and_assessment

    # Create task, assign to get in_progress, then unassign (but can't unassign in_progress)
    # So create a task, plan+assign+start, unassign is not allowed.
    # Instead: create task, plan it, assign, start, then we cannot unassign.
    # For this test: create task that is closed but was never assigned
    # We can't transition an unassigned task to in_progress, so use:
    # OPEN -> ACCEPTED_RISK (accepted_risk allowed from OPEN with reason)
    resp = client.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id,
            "assessment_id": assessment_id,
            "title": "Unassigned close no notif test",
            "priority": "low",
        },
        headers=_auth(api_key),
    )
    assert resp.status_code == 201
    tid = resp.json()["id"]

    with Session(get_engine()) as db:
        before_notifs = (
            db.query(Notification)
            .filter(
                Notification.tenant_id == _TENANT_A,
                Notification.task_id == tid,
            )
            .all()
        )
    before_count = len(before_notifs)

    # Transition to ACCEPTED_RISK (terminal) without assigning — no notification should be created
    # since task has no assigned_user_email
    client.post(
        f"/remediation/tasks/{tid}/transition",
        json={"new_status": "accepted_risk", "reason": "No owner risk acceptance"},
        headers=_auth(api_key),
    )

    with Session(get_engine()) as db:
        after_notifs = (
            db.query(Notification)
            .filter(
                Notification.tenant_id == _TENANT_A,
                Notification.task_id == tid,
            )
            .all()
        )
    after_count = len(after_notifs)

    # Should not have created any new notifications (no email to send to)
    assert after_count == before_count


# ===========================================================================
# REM-179–REM-180: Timeline — notification source
# ===========================================================================


def test_rem_179_timeline_includes_notification_events(
    client, api_key, null_channel, finding_and_assessment
):
    """REM-179  Timeline includes notification events (source=notification) after assignment."""
    assessment_id, finding_id = finding_and_assessment
    resp = client.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id,
            "assessment_id": assessment_id,
            "title": "Task for notif in timeline test",
            "priority": "medium",
        },
        headers=_auth(api_key),
    )
    assert resp.status_code == 201
    tid = resp.json()["id"]

    client.post(
        f"/remediation/tasks/{tid}/assign",
        json={
            "user_id": "user-timeline-notif",
            "display_name": "Timeline Notif User",
            "email": "timeline-notif@example.com",
        },
        headers=_auth(api_key),
    )

    resp = client.get(
        f"/remediation/tasks/{tid}/timeline",
        headers=_auth(api_key),
    )
    assert resp.status_code == 200
    events = resp.json()["events"]
    notif_events = [e for e in events if e["source"] == "notification"]
    assert len(notif_events) >= 1


def test_rem_180_source_filter_notification(
    client, api_key, null_channel, finding_and_assessment
):
    """REM-180  source filter — source=notification returns only notification events."""
    assessment_id, finding_id = finding_and_assessment
    resp = client.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id,
            "assessment_id": assessment_id,
            "title": "Task for source notif filter",
            "priority": "medium",
        },
        headers=_auth(api_key),
    )
    assert resp.status_code == 201
    tid = resp.json()["id"]

    client.post(
        f"/remediation/tasks/{tid}/assign",
        json={
            "user_id": "user-src-notif",
            "display_name": "Src Notif User",
            "email": "src-notif@example.com",
        },
        headers=_auth(api_key),
    )

    resp = client.get(
        f"/remediation/tasks/{tid}/timeline?source=notification",
        headers=_auth(api_key),
    )
    assert resp.status_code == 200
    events = resp.json()["events"]
    assert len(events) >= 1
    for e in events:
        assert e["source"] == "notification"


# ===========================================================================
# REM-181–REM-182: Notification acknowledgement
# ===========================================================================


def test_rem_181_acknowledge_marks_acknowledged(
    client, api_key, null_channel, finding_and_assessment
):
    """REM-181  Acknowledge endpoint marks notification as acknowledged."""
    from api.db import get_engine
    from api.db_models_notifications import Notification
    from sqlalchemy.orm import Session

    assessment_id, finding_id = finding_and_assessment
    resp = client.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id,
            "assessment_id": assessment_id,
            "title": "Task for ack test",
            "priority": "medium",
        },
        headers=_auth(api_key),
    )
    assert resp.status_code == 201
    tid = resp.json()["id"]

    client.post(
        f"/remediation/tasks/{tid}/assign",
        json={
            "user_id": "user-ack-test",
            "display_name": "Ack Test User",
            "email": "ack@example.com",
        },
        headers=_auth(api_key),
    )

    with Session(get_engine()) as db:
        notif = (
            db.query(Notification)
            .filter(
                Notification.tenant_id == _TENANT_A,
                Notification.task_id == tid,
            )
            .first()
        )
    assert notif is not None
    notif_id = notif.id

    resp = client.post(
        f"/remediation/tasks/{tid}/notifications/{notif_id}/acknowledge",
        json={"actor": "ack@example.com"},
        headers=_auth(api_key),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["delivery_status"] == "acknowledged"
    assert data["acknowledged_at"] is not None


def test_rem_182_acknowledge_increments_metric(
    client, api_key, null_channel, finding_and_assessment
):
    """REM-182  NOTIFICATIONS_ACKNOWLEDGED_TOTAL increments on acknowledge."""
    from api.db import get_engine
    from api.db_models_notifications import Notification
    from api.observability.metrics import NOTIFICATIONS_ACKNOWLEDGED_TOTAL
    from sqlalchemy.orm import Session

    before = NOTIFICATIONS_ACKNOWLEDGED_TOTAL._value.get()

    assessment_id, finding_id = finding_and_assessment
    resp = client.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id,
            "assessment_id": assessment_id,
            "title": "Task for ack metric test",
            "priority": "medium",
        },
        headers=_auth(api_key),
    )
    assert resp.status_code == 201
    tid = resp.json()["id"]

    client.post(
        f"/remediation/tasks/{tid}/assign",
        json={
            "user_id": "user-ack-metric",
            "display_name": "Ack Metric User",
            "email": "ack-metric@example.com",
        },
        headers=_auth(api_key),
    )

    with Session(get_engine()) as db:
        notif = (
            db.query(Notification)
            .filter(
                Notification.tenant_id == _TENANT_A,
                Notification.task_id == tid,
            )
            .first()
        )
    assert notif is not None
    notif_id = notif.id

    client.post(
        f"/remediation/tasks/{tid}/notifications/{notif_id}/acknowledge",
        json={"actor": "ack-metric@example.com"},
        headers=_auth(api_key),
    )

    after = NOTIFICATIONS_ACKNOWLEDGED_TOTAL._value.get()
    assert after > before


# ===========================================================================
# REM-183–REM-185: SLA escalation
# ===========================================================================


def test_rem_183_notify_sla_approaching(null_channel, finding_and_assessment, app):
    """REM-183  notify_sla_approaching creates notification with trigger_type=sla_approaching."""
    from api.db import get_engine
    from api.db_models_notifications import Notification
    from services.notifications.engine import NotificationEngine
    from sqlalchemy.orm import Session

    assessment_id, finding_id = finding_and_assessment
    with Session(get_engine()) as db:
        # We need a real task_id; find one for tenant A
        from api.db_models_remediation import RemediationTask

        task = (
            db.query(RemediationTask)
            .filter(RemediationTask.tenant_id == _TENANT_A)
            .first()
        )
        assert task is not None
        tid = task.id

        ne = NotificationEngine(db, tenant_id=_TENANT_A)
        ne.notify_sla_approaching(
            task_id=tid,
            recipient="sla-approaching@example.com",
            days_remaining=5,
        )
        db.commit()

    with Session(get_engine()) as db:
        notifs = (
            db.query(Notification)
            .filter(
                Notification.tenant_id == _TENANT_A,
                Notification.task_id == tid,
                Notification.trigger_type == "sla_approaching",
            )
            .all()
        )
    assert len(notifs) >= 1


def test_rem_184_notify_sla_breached(null_channel, finding_and_assessment, app):
    """REM-184  notify_sla_breached creates notification with trigger_type=sla_breached."""
    from api.db import get_engine
    from api.db_models_notifications import Notification
    from services.notifications.engine import NotificationEngine
    from sqlalchemy.orm import Session

    with Session(get_engine()) as db:
        from api.db_models_remediation import RemediationTask

        task = (
            db.query(RemediationTask)
            .filter(RemediationTask.tenant_id == _TENANT_A)
            .first()
        )
        assert task is not None
        tid = task.id

        ne = NotificationEngine(db, tenant_id=_TENANT_A)
        ne.notify_sla_breached(
            task_id=tid,
            recipient="sla-breached@example.com",
        )
        db.commit()

    with Session(get_engine()) as db:
        notifs = (
            db.query(Notification)
            .filter(
                Notification.tenant_id == _TENANT_A,
                Notification.task_id == tid,
                Notification.trigger_type == "sla_breached",
            )
            .all()
        )
    assert len(notifs) >= 1


def test_rem_185_sla_escalations_total_increments(
    null_channel, finding_and_assessment, app
):
    """REM-185  SLA_ESCALATIONS_TOTAL increments on SLA notification."""
    from api.db import get_engine
    from api.observability.metrics import SLA_ESCALATIONS_TOTAL
    from services.notifications.engine import NotificationEngine
    from sqlalchemy.orm import Session

    before = SLA_ESCALATIONS_TOTAL._value.get()

    with Session(get_engine()) as db:
        from api.db_models_remediation import RemediationTask

        task = (
            db.query(RemediationTask)
            .filter(RemediationTask.tenant_id == _TENANT_A)
            .first()
        )
        assert task is not None
        tid = task.id

        ne = NotificationEngine(db, tenant_id=_TENANT_A)
        ne.notify_sla_approaching(
            task_id=tid,
            recipient="sla-metric@example.com",
            days_remaining=3,
        )
        db.commit()

    after = SLA_ESCALATIONS_TOTAL._value.get()
    assert after > before


# ===========================================================================
# REM-186–REM-188: Metrics
# ===========================================================================


def test_rem_186_notifications_sent_total_increments(
    client, api_key, null_channel, finding_and_assessment
):
    """REM-186  NOTIFICATIONS_SENT_TOTAL increments after assignment."""
    from api.observability.metrics import NOTIFICATIONS_SENT_TOTAL

    before = NOTIFICATIONS_SENT_TOTAL._value.get()

    assessment_id, finding_id = finding_and_assessment
    resp = client.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id,
            "assessment_id": assessment_id,
            "title": "Task for sent metric",
            "priority": "medium",
        },
        headers=_auth(api_key),
    )
    assert resp.status_code == 201
    tid = resp.json()["id"]

    client.post(
        f"/remediation/tasks/{tid}/assign",
        json={
            "user_id": "user-sent-metric",
            "display_name": "Sent Metric User",
            "email": "sent-metric@example.com",
        },
        headers=_auth(api_key),
    )

    after = NOTIFICATIONS_SENT_TOTAL._value.get()
    assert after > before


def test_rem_187_notifications_failed_total_increments(
    client, api_key, failing_channel, finding_and_assessment
):
    """REM-187  NOTIFICATIONS_FAILED_TOTAL increments when channel fails."""
    from api.observability.metrics import NOTIFICATIONS_FAILED_TOTAL

    before = NOTIFICATIONS_FAILED_TOTAL._value.get()

    assessment_id, finding_id = finding_and_assessment
    resp = client.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id,
            "assessment_id": assessment_id,
            "title": "Task for failed metric",
            "priority": "medium",
        },
        headers=_auth(api_key),
    )
    assert resp.status_code == 201
    tid = resp.json()["id"]

    # Assign — this will fire a notification that will fail (FailingChannel returns False)
    client.post(
        f"/remediation/tasks/{tid}/assign",
        json={
            "user_id": "user-fail-metric",
            "display_name": "Fail Metric User",
            "email": "fail-metric@example.com",
        },
        headers=_auth(api_key),
    )

    after = NOTIFICATIONS_FAILED_TOTAL._value.get()
    assert after > before


def test_rem_188_timeline_events_total_increments(client, api_key, task_id):
    """REM-188  TIMELINE_EVENTS_TOTAL increments on timeline request."""
    from api.observability.metrics import TIMELINE_EVENTS_TOTAL

    before = TIMELINE_EVENTS_TOTAL._value.get()

    client.get(
        f"/remediation/tasks/{task_id}/timeline",
        headers=_auth(api_key),
    )

    after = TIMELINE_EVENTS_TOTAL._value.get()
    assert after > before


# ===========================================================================
# REM-189–REM-190: Governance / export readiness
# ===========================================================================


def test_rem_189_timeline_events_flat_json(client, api_key, task_id):
    """REM-189  Timeline events have flat JSON structure (export compatible)."""
    resp = client.get(
        f"/remediation/tasks/{task_id}/timeline",
        headers=_auth(api_key),
    )
    assert resp.status_code == 200
    events = resp.json()["events"]
    assert len(events) > 0
    for event in events:
        # All top-level fields should be scalars or dict (no nested lists)
        assert isinstance(event["id"], str)
        assert isinstance(event["task_id"], str)
        assert isinstance(event["event_type"], str)
        assert isinstance(event["source"], str)
        assert isinstance(event["actor"], str)
        assert isinstance(event["event_at"], str)
        assert isinstance(event["metadata"], dict)


def test_rem_190_all_event_sources_present(
    client, api_key, null_channel, finding_and_assessment
):
    """REM-190  All event sources present in merged timeline."""
    assessment_id, finding_id = finding_and_assessment

    # Create a fresh task and generate events from all three sources
    resp = client.post(
        "/remediation/tasks",
        json={
            "finding_id": finding_id,
            "assessment_id": assessment_id,
            "title": "Task for all sources test",
            "priority": "medium",
        },
        headers=_auth(api_key),
    )
    assert resp.status_code == 201
    tid = resp.json()["id"]

    # Source: remediation — already has task_created event

    # Source: portal — add a comment
    client.post(
        f"/portal/remediation/tasks/{tid}/comments",
        json={"body": "All sources comment.", "author": "all@example.com"},
        headers=_auth(api_key),
    )

    # Source: notification — assign to create a notification
    client.post(
        f"/remediation/tasks/{tid}/assign",
        json={
            "user_id": "user-all-sources",
            "display_name": "All Sources User",
            "email": "all-sources@example.com",
        },
        headers=_auth(api_key),
    )

    resp = client.get(
        f"/remediation/tasks/{tid}/timeline",
        headers=_auth(api_key),
    )
    assert resp.status_code == 200
    events = resp.json()["events"]
    sources = {e["source"] for e in events}

    # All three sources should be present
    assert "remediation" in sources, (
        f"remediation source missing. Sources found: {sources}"
    )
    assert "portal" in sources, f"portal source missing. Sources found: {sources}"
    assert "notification" in sources, (
        f"notification source missing. Sources found: {sources}"
    )
