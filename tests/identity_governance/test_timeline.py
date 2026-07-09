"""tests/identity_governance/test_timeline.py — Timeline hash-chain tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from api.identity_governance.models import IdentityTimelineEventType
from api.identity_governance.timeline import IdentityTimeline


@pytest.fixture
def timeline() -> IdentityTimeline:
    return IdentityTimeline()


def test_emit_creates_event(timeline: IdentityTimeline) -> None:
    e = timeline.emit(
        IdentityTimelineEventType.LOGIN,
        subject="user-1",
        tenant_id="tenant-a",
        actor="user-1",
        details={"ip": "10.0.0.1"},
    )
    assert e.event_type == IdentityTimelineEventType.LOGIN
    assert e.previous_hash == "genesis"
    assert e.event_hash != ""


def test_hash_chain_forwards(timeline: IdentityTimeline) -> None:
    e1 = timeline.emit(
        IdentityTimelineEventType.LOGIN,
        subject="u",
        tenant_id="t",
        actor="a",
    )
    e2 = timeline.emit(
        IdentityTimelineEventType.LOGOUT,
        subject="u",
        tenant_id="t",
        actor="a",
    )
    assert e2.previous_hash == e1.event_hash
    assert e1.event_hash != e2.event_hash


def test_verify_chain_integrity(timeline: IdentityTimeline) -> None:
    for _ in range(5):
        timeline.emit(
            IdentityTimelineEventType.LOGIN,
            subject="u",
            tenant_id="t",
            actor="a",
        )
    assert timeline.verify_chain() is True


def test_verify_chain_detects_tampering(timeline: IdentityTimeline) -> None:
    e = timeline.emit(
        IdentityTimelineEventType.LOGIN,
        subject="u",
        tenant_id="t",
        actor="a",
    )
    # Tamper by injecting a wrong event.
    from api.identity_governance.models import IdentityTimelineEvent

    tampered = IdentityTimelineEvent(
        event_id=e.event_id,
        event_type=e.event_type,
        subject="different-user",  # tampered
        tenant_id=e.tenant_id,
        actor=e.actor,
        occurred_at=e.occurred_at,
        details=e.details,
        correlation_id=e.correlation_id,
        previous_hash=e.previous_hash,
        event_hash=e.event_hash,
    )
    timeline._events[0] = tampered
    assert timeline.verify_chain() is False


def test_query_tenant_isolation(timeline: IdentityTimeline) -> None:
    timeline.emit(
        IdentityTimelineEventType.LOGIN,
        subject="u1",
        tenant_id="tenant-a",
        actor="u1",
    )
    timeline.emit(
        IdentityTimelineEventType.LOGIN,
        subject="u2",
        tenant_id="tenant-b",
        actor="u2",
    )
    events_a = timeline.query("tenant-a")
    events_b = timeline.query("tenant-b")
    assert len(events_a) == 1
    assert len(events_b) == 1
    assert events_a[0].tenant_id == "tenant-a"
    assert events_b[0].tenant_id == "tenant-b"


def test_query_filter_by_subject(timeline: IdentityTimeline) -> None:
    timeline.emit(
        IdentityTimelineEventType.LOGIN,
        subject="alice",
        tenant_id="t",
        actor="alice",
    )
    timeline.emit(
        IdentityTimelineEventType.LOGIN,
        subject="bob",
        tenant_id="t",
        actor="bob",
    )
    r = timeline.query("t", subject="alice")
    assert len(r) == 1
    assert r[0].subject == "alice"


def test_query_filter_by_event_type(timeline: IdentityTimeline) -> None:
    timeline.emit(
        IdentityTimelineEventType.LOGIN,
        subject="u",
        tenant_id="t",
        actor="u",
    )
    timeline.emit(
        IdentityTimelineEventType.LOGOUT,
        subject="u",
        tenant_id="t",
        actor="u",
    )
    r = timeline.query("t", event_types=[IdentityTimelineEventType.LOGOUT])
    assert len(r) == 1
    assert r[0].event_type == IdentityTimelineEventType.LOGOUT


def test_details_secrets_redacted(timeline: IdentityTimeline) -> None:
    e = timeline.emit(
        IdentityTimelineEventType.LOGIN,
        subject="u",
        tenant_id="t",
        actor="u",
        details={"password": "hunter2", "ip": "10.0.0.1"},
    )
    d = dict(e.details)
    assert d["password"] == "[REDACTED]"
    assert d["ip"] == "10.0.0.1"


def test_emit_requires_subject(timeline: IdentityTimeline) -> None:
    with pytest.raises(ValueError, match="subject is required"):
        timeline.emit(
            IdentityTimelineEventType.LOGIN,
            subject="",
            tenant_id="t",
            actor="a",
        )


def test_emit_requires_tenant(timeline: IdentityTimeline) -> None:
    with pytest.raises(ValueError, match="tenant_id is required"):
        timeline.emit(
            IdentityTimelineEventType.LOGIN,
            subject="u",
            tenant_id="",
            actor="a",
        )


def test_emit_requires_actor(timeline: IdentityTimeline) -> None:
    with pytest.raises(ValueError, match="actor is required"):
        timeline.emit(
            IdentityTimelineEventType.LOGIN,
            subject="u",
            tenant_id="t",
            actor="",
        )


def test_query_since_until(timeline: IdentityTimeline) -> None:
    timeline.emit(
        IdentityTimelineEventType.LOGIN,
        subject="u",
        tenant_id="t",
        actor="u",
    )
    now = datetime.now(tz=timezone.utc)
    past = now - timedelta(days=1)
    future = now + timedelta(days=1)
    assert len(timeline.query("t", since=past, until=future)) == 1
    assert len(timeline.query("t", since=future)) == 0


def test_query_limit(timeline: IdentityTimeline) -> None:
    for _ in range(10):
        timeline.emit(
            IdentityTimelineEventType.LOGIN,
            subject="u",
            tenant_id="t",
            actor="u",
        )
    assert len(timeline.query("t", limit=3)) == 3
    assert len(timeline.query("t", limit=0)) == 0


def test_deterministic_previous_hash(timeline: IdentityTimeline) -> None:
    e1 = timeline.emit(
        IdentityTimelineEventType.LOGIN,
        subject="u",
        tenant_id="t",
        actor="u",
    )
    e2 = timeline.emit(
        IdentityTimelineEventType.LOGIN,
        subject="u",
        tenant_id="t",
        actor="u",
    )
    assert e2.previous_hash == e1.event_hash


def test_no_secrets_in_details_tuple(timeline: IdentityTimeline) -> None:
    e = timeline.emit(
        IdentityTimelineEventType.LOGIN,
        subject="u",
        tenant_id="t",
        actor="u",
        details={"authorization": "Bearer x", "token": "abc"},
    )
    d = dict(e.details)
    assert d["authorization"] == "[REDACTED]"
    assert d["token"] == "[REDACTED]"
