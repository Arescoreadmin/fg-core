"""Tests for identity governance persistence repositories.

Covers:
    * InMemoryRepository CRUD for lifecycle, device, timeline, break-glass.
    * DB repository (SQLite via test infra) stores and retrieves.
    * fail-closed behavior when DB session raises.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from api.identity_governance.models import (
    BreakGlassRequest,
    BreakGlassStatus,
    DeviceRecord,
    DeviceTrustState,
    IdentityLifecycleRecord,
    IdentityLifecycleState,
    IdentityTimelineEvent,
    IdentityTimelineEventType,
)
from api.identity_governance.repositories.memory import (
    InMemoryBreakGlassRepository,
    InMemoryDeviceRepository,
    InMemoryLifecycleRepository,
    InMemoryTimelineRepository,
)


NOW = datetime(2026, 7, 9, 12, 0, 0, tzinfo=timezone.utc)


def _make_lifecycle_record(
    tenant_id: str = "tenant-a", subject: str = "user:1", record_id: str = "r1"
) -> IdentityLifecycleRecord:
    return IdentityLifecycleRecord(
        record_id=record_id,
        subject=subject,
        tenant_id=tenant_id,
        from_state=IdentityLifecycleState.INVITED,
        to_state=IdentityLifecycleState.ACTIVE,
        reason="test",
        actor="admin@example.com",
        occurred_at=NOW,
    )


def _make_device_record(
    tenant_id: str = "tenant-a",
    subject: str = "user:1",
    device_id: str = "d1",
) -> DeviceRecord:
    return DeviceRecord(
        device_id=device_id,
        tenant_id=tenant_id,
        subject=subject,
        fingerprint_hash="fpr_hash",
        user_agent_hash="ua_hash",
        ip_metadata="v4/hash",
        trust_state=DeviceTrustState.KNOWN,
        risk_score=0.1,
        registered_at=NOW,
        updated_at=NOW,
        last_reason="registered",
    )


def _make_timeline_event(
    tenant_id: str = "tenant-a",
    subject: str = "user:1",
    event_id: str = "e1",
) -> IdentityTimelineEvent:
    return IdentityTimelineEvent(
        event_id=event_id,
        event_type=IdentityTimelineEventType.LOGIN,
        subject=subject,
        tenant_id=tenant_id,
        actor=subject,
        occurred_at=NOW,
        details=(("auth_source", "api_key"),),
        correlation_id="cid-1",
        previous_hash="genesis",
        event_hash="hash-1",
    )


def _make_break_glass_request(
    tenant_id: str = "tenant-a",
    subject: str = "user:1",
    request_id: str = "bg1",
    status: BreakGlassStatus = BreakGlassStatus.PENDING,
) -> BreakGlassRequest:
    return BreakGlassRequest(
        request_id=request_id,
        tenant_id=tenant_id,
        subject=subject,
        requested_capability="platform.admin",
        reason="incident_response",
        requested_by="oncall@example.com",
        requested_at=NOW,
        duration_seconds=1800,
        status=status,
    )


# ---------------------------------------------------------------------------
# In-memory: lifecycle
# ---------------------------------------------------------------------------


def test_memory_lifecycle_create_and_get() -> None:
    repo = InMemoryLifecycleRepository()
    rec = _make_lifecycle_record()
    repo.create(rec)
    fetched = repo.get("tenant-a", "r1")
    assert fetched == rec


def test_memory_lifecycle_cross_tenant_isolation() -> None:
    repo = InMemoryLifecycleRepository()
    repo.create(_make_lifecycle_record(tenant_id="tenant-a", record_id="r1"))
    assert repo.get("tenant-b", "r1") is None


def test_memory_lifecycle_list_for_subject_returns_ordered() -> None:
    repo = InMemoryLifecycleRepository()
    repo.create(_make_lifecycle_record(record_id="r1"))
    repo.create(_make_lifecycle_record(record_id="r2"))
    listed = repo.list_for_subject("tenant-a", "user:1")
    assert [r.record_id for r in listed] == ["r1", "r2"]


def test_memory_lifecycle_requires_tenant_id() -> None:
    repo = InMemoryLifecycleRepository()
    with pytest.raises(ValueError):
        repo.create(
            IdentityLifecycleRecord(
                record_id="r1",
                subject="u",
                tenant_id="",
                from_state=IdentityLifecycleState.INVITED,
                to_state=IdentityLifecycleState.ACTIVE,
                reason="x",
                actor="x",
                occurred_at=NOW,
            )
        )


# ---------------------------------------------------------------------------
# In-memory: device
# ---------------------------------------------------------------------------


def test_memory_device_upsert_and_get() -> None:
    repo = InMemoryDeviceRepository()
    rec = _make_device_record()
    repo.upsert(rec)
    assert repo.get("tenant-a", "d1") == rec

    # Upsert replaces existing.
    updated = DeviceRecord(
        device_id="d1",
        tenant_id="tenant-a",
        subject="user:1",
        fingerprint_hash="fpr_hash",
        user_agent_hash="ua_hash",
        ip_metadata="v4/hash",
        trust_state=DeviceTrustState.REVOKED,
        risk_score=1.0,
        registered_at=NOW,
        updated_at=NOW + timedelta(minutes=5),
        last_reason="revoked",
    )
    repo.upsert(updated)
    fetched_device = repo.get("tenant-a", "d1")
    assert fetched_device is not None
    assert fetched_device.trust_state == DeviceTrustState.REVOKED


def test_memory_device_cross_tenant_isolation() -> None:
    repo = InMemoryDeviceRepository()
    repo.upsert(_make_device_record(tenant_id="tenant-a", device_id="d1"))
    assert repo.get("tenant-b", "d1") is None


def test_memory_device_list_for_subject_sorted() -> None:
    repo = InMemoryDeviceRepository()
    repo.upsert(_make_device_record(device_id="dB"))
    repo.upsert(_make_device_record(device_id="dA"))
    listed = repo.list_for_subject("tenant-a", "user:1")
    assert [d.device_id for d in listed] == ["dA", "dB"]


# ---------------------------------------------------------------------------
# In-memory: timeline
# ---------------------------------------------------------------------------


def test_memory_timeline_append_and_list() -> None:
    repo = InMemoryTimelineRepository()
    repo.append(_make_timeline_event(event_id="e1"))
    repo.append(_make_timeline_event(event_id="e2"))
    events = repo.list_events("tenant-a")
    assert [e.event_id for e in events] == ["e1", "e2"]


def test_memory_timeline_cross_tenant_isolation() -> None:
    repo = InMemoryTimelineRepository()
    repo.append(_make_timeline_event(tenant_id="tenant-a"))
    assert repo.list_events("tenant-b") == []


def test_memory_timeline_filter_by_subject() -> None:
    repo = InMemoryTimelineRepository()
    repo.append(_make_timeline_event(subject="user:1", event_id="e1"))
    repo.append(_make_timeline_event(subject="user:2", event_id="e2"))
    filtered = repo.list_events("tenant-a", subject="user:2")
    assert [e.event_id for e in filtered] == ["e2"]


# ---------------------------------------------------------------------------
# In-memory: break-glass
# ---------------------------------------------------------------------------


def test_memory_break_glass_create_and_update() -> None:
    repo = InMemoryBreakGlassRepository()
    req = _make_break_glass_request()
    repo.create(req)
    active = BreakGlassRequest(
        request_id=req.request_id,
        tenant_id=req.tenant_id,
        subject=req.subject,
        requested_capability=req.requested_capability,
        reason=req.reason,
        requested_by=req.requested_by,
        requested_at=req.requested_at,
        duration_seconds=req.duration_seconds,
        status=BreakGlassStatus.ACTIVE,
        approver="approver@example.com",
        approved_at=NOW,
        expires_at=NOW + timedelta(minutes=30),
    )
    repo.update(active)
    fetched_request = repo.get("tenant-a", req.request_id)
    assert fetched_request is not None
    assert fetched_request.status == BreakGlassStatus.ACTIVE


def test_memory_break_glass_cross_tenant_isolation() -> None:
    repo = InMemoryBreakGlassRepository()
    repo.create(_make_break_glass_request(tenant_id="tenant-a", request_id="bg1"))
    assert repo.get("tenant-b", "bg1") is None


def test_memory_break_glass_list_active_only() -> None:
    repo = InMemoryBreakGlassRepository()
    repo.create(_make_break_glass_request(request_id="bg1"))
    repo.create(
        _make_break_glass_request(request_id="bg2", status=BreakGlassStatus.ACTIVE)
    )
    active = repo.list_active_for_subject("tenant-a", "user:1")
    assert [r.request_id for r in active] == ["bg2"]


def test_memory_break_glass_update_missing_raises() -> None:
    repo = InMemoryBreakGlassRepository()
    with pytest.raises(ValueError):
        repo.update(_make_break_glass_request())


# ---------------------------------------------------------------------------
# DB repositories (SQLite in-memory) — end-to-end round trip
# ---------------------------------------------------------------------------


@pytest.fixture()
def sqlite_session_factory():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    engine = create_engine("sqlite+pysqlite:///:memory:", future=True)

    ddl = [
        """
        CREATE TABLE IF NOT EXISTS identity_lifecycle_events (
            record_id   TEXT PRIMARY KEY,
            tenant_id   TEXT NOT NULL,
            subject     TEXT NOT NULL,
            from_state  TEXT NOT NULL,
            to_state    TEXT NOT NULL,
            reason      TEXT NOT NULL,
            actor       TEXT NOT NULL,
            occurred_at TEXT NOT NULL,
            created_at  TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS identity_devices (
            device_id        TEXT PRIMARY KEY,
            tenant_id        TEXT NOT NULL,
            subject          TEXT NOT NULL,
            fingerprint_hash TEXT NOT NULL,
            user_agent_hash  TEXT NOT NULL,
            ip_metadata      TEXT,
            trust_state      TEXT NOT NULL,
            risk_score       REAL NOT NULL DEFAULT 0.0,
            last_reason      TEXT,
            registered_at    TEXT NOT NULL,
            updated_at       TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS identity_timeline_events (
            event_id       TEXT PRIMARY KEY,
            tenant_id      TEXT NOT NULL,
            subject        TEXT NOT NULL,
            actor          TEXT NOT NULL,
            event_type     TEXT NOT NULL,
            occurred_at    TEXT NOT NULL,
            correlation_id TEXT,
            details_json   TEXT,
            previous_hash  TEXT NOT NULL,
            event_hash     TEXT NOT NULL,
            created_at     TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS identity_break_glass_requests (
            request_id           TEXT PRIMARY KEY,
            tenant_id            TEXT NOT NULL,
            subject              TEXT NOT NULL,
            requested_capability TEXT NOT NULL,
            reason               TEXT NOT NULL,
            requested_by         TEXT NOT NULL,
            requested_at         TEXT NOT NULL,
            duration_seconds     INTEGER NOT NULL,
            status               TEXT NOT NULL,
            approver             TEXT,
            approved_at          TEXT,
            expires_at           TEXT,
            revoked_by           TEXT,
            revoked_at           TEXT,
            created_at           TEXT NOT NULL
        )
        """,
    ]
    from sqlalchemy import text as _text

    with engine.begin() as conn:
        for stmt in ddl:
            conn.execute(_text(stmt))

    factory = sessionmaker(bind=engine, future=True)
    yield factory
    engine.dispose()


def test_db_lifecycle_roundtrip(sqlite_session_factory) -> None:
    from api.identity_governance.repositories.db import DbLifecycleRepository

    repo = DbLifecycleRepository(sqlite_session_factory)
    rec = _make_lifecycle_record()
    repo.create(rec)
    fetched = repo.get("tenant-a", "r1")
    assert fetched is not None
    assert fetched.subject == rec.subject
    assert fetched.to_state == rec.to_state


def test_db_device_upsert_replaces(sqlite_session_factory) -> None:
    from api.identity_governance.repositories.db import DbDeviceRepository

    repo = DbDeviceRepository(sqlite_session_factory)
    rec = _make_device_record()
    repo.upsert(rec)
    updated = DeviceRecord(
        device_id="d1",
        tenant_id="tenant-a",
        subject="user:1",
        fingerprint_hash="fpr_hash",
        user_agent_hash="ua_hash",
        ip_metadata="v4/hash",
        trust_state=DeviceTrustState.REVOKED,
        risk_score=1.0,
        registered_at=NOW,
        updated_at=NOW + timedelta(minutes=5),
        last_reason="revoked",
    )
    repo.upsert(updated)
    fetched = repo.get("tenant-a", "d1")
    assert fetched is not None
    assert fetched.trust_state == DeviceTrustState.REVOKED


def test_db_timeline_roundtrip(sqlite_session_factory) -> None:
    from api.identity_governance.repositories.db import DbTimelineRepository

    repo = DbTimelineRepository(sqlite_session_factory)
    repo.append(_make_timeline_event(event_id="e1"))
    events = repo.list_events("tenant-a")
    assert len(events) == 1
    assert events[0].event_id == "e1"


def test_db_break_glass_update_missing_raises(sqlite_session_factory) -> None:
    from api.identity_governance.repositories.db import DbBreakGlassRepository

    repo = DbBreakGlassRepository(sqlite_session_factory)
    with pytest.raises(ValueError):
        repo.update(_make_break_glass_request(request_id="does-not-exist"))


def test_db_break_glass_cross_tenant(sqlite_session_factory) -> None:
    from api.identity_governance.repositories.db import DbBreakGlassRepository

    repo = DbBreakGlassRepository(sqlite_session_factory)
    repo.create(_make_break_glass_request(tenant_id="tenant-a", request_id="bg1"))
    assert repo.get("tenant-b", "bg1") is None


def test_db_repository_fails_closed_on_session_error() -> None:
    from api.identity_governance.repositories.db import DbLifecycleRepository

    def broken_factory():
        raise RuntimeError("db unavailable")

    repo = DbLifecycleRepository(broken_factory)
    with pytest.raises(RuntimeError):
        repo.create(_make_lifecycle_record())
