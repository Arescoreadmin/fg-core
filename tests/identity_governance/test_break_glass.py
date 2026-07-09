"""tests/identity_governance/test_break_glass.py — Break-glass workflow tests."""

from __future__ import annotations

import time

import pytest

from api.identity_governance.break_glass import (
    MAX_BREAK_GLASS_DURATION_SECONDS,
    BreakGlassAuthority,
)
from api.identity_governance.models import (
    BreakGlassStatus,
    IdentityTimelineEventType,
)
from api.identity_governance.timeline import IdentityTimeline


@pytest.fixture
def timeline() -> IdentityTimeline:
    return IdentityTimeline()


@pytest.fixture
def authority(timeline: IdentityTimeline) -> BreakGlassAuthority:
    return BreakGlassAuthority(timeline=timeline)


def test_request_creates_pending(authority: BreakGlassAuthority) -> None:
    r = authority.request_access(
        subject="user-1",
        tenant_id="tenant-a",
        requested_capability="platform.admin",
        reason="incident #1234",
        requested_by="oncall@fg",
        duration_seconds=600,
    )
    assert r.status == BreakGlassStatus.PENDING
    assert r.approver is None
    assert r.expires_at is None


def test_reason_required(authority: BreakGlassAuthority) -> None:
    with pytest.raises(ValueError, match="requires a non-empty reason"):
        authority.request_access(
            subject="u",
            tenant_id="t",
            requested_capability="c",
            reason="",
            requested_by="o",
            duration_seconds=60,
        )


def test_whitespace_reason_rejected(authority: BreakGlassAuthority) -> None:
    with pytest.raises(ValueError, match="non-empty reason"):
        authority.request_access(
            subject="u",
            tenant_id="t",
            requested_capability="c",
            reason="   ",
            requested_by="o",
            duration_seconds=60,
        )


def test_max_duration_enforced(authority: BreakGlassAuthority) -> None:
    with pytest.raises(ValueError, match="exceeds MAX_BREAK_GLASS_DURATION_SECONDS"):
        authority.request_access(
            subject="u",
            tenant_id="t",
            requested_capability="c",
            reason="r",
            requested_by="o",
            duration_seconds=MAX_BREAK_GLASS_DURATION_SECONDS + 1,
        )


def test_zero_duration_rejected(authority: BreakGlassAuthority) -> None:
    with pytest.raises(ValueError, match="duration_seconds must be > 0"):
        authority.request_access(
            subject="u",
            tenant_id="t",
            requested_capability="c",
            reason="r",
            requested_by="o",
            duration_seconds=0,
        )


def test_approve_activates(authority: BreakGlassAuthority) -> None:
    r = authority.request_access(
        subject="u",
        tenant_id="t",
        requested_capability="c",
        reason="r",
        requested_by="oncall",
        duration_seconds=600,
    )
    approved = authority.approve(r.request_id, approver="chief@fg", tenant_id="t")
    assert approved.status == BreakGlassStatus.ACTIVE
    assert approved.approver == "chief@fg"
    assert approved.expires_at is not None


def test_approver_cannot_be_requester(authority: BreakGlassAuthority) -> None:
    r = authority.request_access(
        subject="u",
        tenant_id="t",
        requested_capability="c",
        reason="r",
        requested_by="alice",
        duration_seconds=60,
    )
    with pytest.raises(ValueError, match="approver must differ"):
        authority.approve(r.request_id, approver="alice", tenant_id="t")


def test_cannot_approve_twice(authority: BreakGlassAuthority) -> None:
    r = authority.request_access(
        subject="u",
        tenant_id="t",
        requested_capability="c",
        reason="r",
        requested_by="a",
        duration_seconds=60,
    )
    authority.approve(r.request_id, approver="b", tenant_id="t")
    with pytest.raises(ValueError, match="cannot approve"):
        authority.approve(r.request_id, approver="b", tenant_id="t")


def test_cross_tenant_approve_denied(authority: BreakGlassAuthority) -> None:
    r = authority.request_access(
        subject="u",
        tenant_id="tenant-a",
        requested_capability="c",
        reason="r",
        requested_by="a",
        duration_seconds=60,
    )
    with pytest.raises(ValueError, match="not found for tenant"):
        authority.approve(r.request_id, approver="b", tenant_id="tenant-b")


def test_is_active_true_after_approve(authority: BreakGlassAuthority) -> None:
    r = authority.request_access(
        subject="u",
        tenant_id="t",
        requested_capability="c",
        reason="r",
        requested_by="a",
        duration_seconds=60,
    )
    authority.approve(r.request_id, approver="b", tenant_id="t")
    assert authority.is_active(r.request_id, "t") is True


def test_expiry_flips_to_expired(authority: BreakGlassAuthority) -> None:
    r = authority.request_access(
        subject="u",
        tenant_id="t",
        requested_capability="c",
        reason="r",
        requested_by="a",
        duration_seconds=1,
    )
    authority.approve(r.request_id, approver="b", tenant_id="t")
    time.sleep(1.1)
    assert authority.is_active(r.request_id, "t") is False
    fetched = authority.get_request(r.request_id, "t")
    assert fetched is not None
    assert fetched.status == BreakGlassStatus.EXPIRED


def test_revoke_ends_active(authority: BreakGlassAuthority) -> None:
    r = authority.request_access(
        subject="u",
        tenant_id="t",
        requested_capability="c",
        reason="r",
        requested_by="a",
        duration_seconds=600,
    )
    authority.approve(r.request_id, approver="b", tenant_id="t")
    revoked = authority.revoke(r.request_id, "t", revoker="admin")
    assert revoked.status == BreakGlassStatus.REVOKED
    assert revoked.revoked_by == "admin"
    assert authority.is_active(r.request_id, "t") is False


def test_get_active_requests_filters_expired(
    authority: BreakGlassAuthority,
) -> None:
    r = authority.request_access(
        subject="u",
        tenant_id="t",
        requested_capability="c",
        reason="r",
        requested_by="a",
        duration_seconds=1,
    )
    authority.approve(r.request_id, approver="b", tenant_id="t")
    time.sleep(1.1)
    assert authority.get_active_requests("u", "t") == []


def test_cross_tenant_get_active_denied(authority: BreakGlassAuthority) -> None:
    r = authority.request_access(
        subject="u",
        tenant_id="tenant-a",
        requested_capability="c",
        reason="r",
        requested_by="a",
        duration_seconds=60,
    )
    authority.approve(r.request_id, approver="b", tenant_id="tenant-a")
    assert authority.get_active_requests("u", "tenant-b") == []


def test_timeline_events_emitted(
    authority: BreakGlassAuthority, timeline: IdentityTimeline
) -> None:
    r = authority.request_access(
        subject="u",
        tenant_id="t",
        requested_capability="c",
        reason="r",
        requested_by="a",
        duration_seconds=60,
    )
    authority.approve(r.request_id, approver="b", tenant_id="t")
    events = timeline.query("t", subject="u")
    types = [e.event_type for e in events]
    assert IdentityTimelineEventType.BREAK_GLASS_REQUESTED in types
    assert IdentityTimelineEventType.BREAK_GLASS_APPROVED in types


def test_no_secrets_in_request(authority: BreakGlassAuthority) -> None:
    r = authority.request_access(
        subject="u",
        tenant_id="t",
        requested_capability="c",
        reason="incident-123",
        requested_by="oncall",
        duration_seconds=60,
    )
    dump = repr(r)
    for banned in ("password=", "token=", "PORTAL_PASSWORD", "secret_val"):
        assert banned not in dump


def test_request_immutable(authority: BreakGlassAuthority) -> None:
    r = authority.request_access(
        subject="u",
        tenant_id="t",
        requested_capability="c",
        reason="r",
        requested_by="a",
        duration_seconds=60,
    )
    with pytest.raises(Exception):
        r.status = BreakGlassStatus.APPROVED  # type: ignore[misc]


def test_expiry_before_expires_at_stays_active(
    authority: BreakGlassAuthority,
) -> None:
    r = authority.request_access(
        subject="u",
        tenant_id="t",
        requested_capability="c",
        reason="r",
        requested_by="a",
        duration_seconds=3600,
    )
    authority.approve(r.request_id, approver="b", tenant_id="t")
    fetched = authority.get_request(r.request_id, "t")
    assert fetched is not None
    assert fetched.status == BreakGlassStatus.ACTIVE


def test_double_revoke_idempotent(authority: BreakGlassAuthority) -> None:
    r = authority.request_access(
        subject="u",
        tenant_id="t",
        requested_capability="c",
        reason="r",
        requested_by="a",
        duration_seconds=60,
    )
    authority.approve(r.request_id, approver="b", tenant_id="t")
    r1 = authority.revoke(r.request_id, "t", revoker="admin")
    r2 = authority.revoke(r.request_id, "t", revoker="admin")
    assert r1.status == BreakGlassStatus.REVOKED
    assert r2.status == BreakGlassStatus.REVOKED
