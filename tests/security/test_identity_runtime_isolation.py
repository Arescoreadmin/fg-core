"""Security tests for identity runtime cross-tenant isolation.

Every identity-governance service must reject cross-tenant reads and
writes by construction. Break-glass grants cannot cross tenant boundaries
or elevate deleted identities.
"""

from __future__ import annotations

from collections.abc import Generator
from datetime import datetime, timezone

import pytest

from api.identity_governance import reset_services
from api.identity_governance.break_glass import BreakGlassAuthority
from api.identity_governance.devices import DeviceTrustRegistry
from api.identity_governance.lifecycle import IdentityLifecycleManager
from api.identity_governance.models import (
    DeviceTrustState,
    IdentityLifecycleState,
    IdentityTimelineEventType,
)
from api.identity_governance.timeline import IdentityTimeline


NOW = datetime(2026, 7, 9, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def _reset() -> Generator[None, None, None]:
    reset_services()
    yield
    reset_services()


# ---------------------------------------------------------------------------
# Timeline: cross-tenant reads must return empty
# ---------------------------------------------------------------------------


def test_timeline_cross_tenant_read_returns_empty() -> None:
    timeline = IdentityTimeline()
    timeline.emit(
        IdentityTimelineEventType.LOGIN,
        subject="user:1",
        tenant_id="tenant-a",
        actor="user:1",
        details={"auth_source": "api_key"},
    )
    # Same subject id under a different tenant returns nothing.
    events = timeline.query(tenant_id="tenant-b", subject="user:1")
    assert events == []


def test_timeline_query_requires_tenant_id() -> None:
    timeline = IdentityTimeline()
    with pytest.raises(ValueError):
        timeline.query(tenant_id="")


# ---------------------------------------------------------------------------
# Devices: cross-tenant lookups return None
# ---------------------------------------------------------------------------


def test_device_registry_cross_tenant_lookup_returns_none() -> None:
    reg = DeviceTrustRegistry()
    device = reg.register_device(
        subject="user:1",
        tenant_id="tenant-a",
        fingerprint_hash="fpr",
        user_agent_hash="ua",
        ip_metadata="",
    )
    assert reg.get_device(device.device_id, "tenant-a") == device
    assert reg.get_device(device.device_id, "tenant-b") is None


def test_device_registry_cross_tenant_update_rejected() -> None:
    reg = DeviceTrustRegistry()
    device = reg.register_device(
        subject="user:1",
        tenant_id="tenant-a",
        fingerprint_hash="fpr",
        user_agent_hash="ua",
        ip_metadata="",
    )
    with pytest.raises(ValueError):
        reg.update_trust_state(
            device.device_id,
            "tenant-b",  # foreign tenant
            DeviceTrustState.REVOKED,
            reason="revoked",
            actor="admin@example.com",
        )


# ---------------------------------------------------------------------------
# Break-glass: cannot cross tenant boundary
# ---------------------------------------------------------------------------


def test_break_glass_cannot_cross_tenant_boundary() -> None:
    authority = BreakGlassAuthority(timeline=IdentityTimeline())
    request = authority.request_access(
        subject="user:1",
        tenant_id="tenant-a",
        requested_capability="platform.admin",
        reason="incident_response",
        requested_by="oncall@example.com",
        duration_seconds=1800,
    )
    with pytest.raises(ValueError):
        authority.approve(
            request_id=request.request_id,
            approver="approver@example.com",
            tenant_id="tenant-b",  # foreign tenant
        )
    with pytest.raises(ValueError):
        authority.revoke(
            request_id=request.request_id,
            tenant_id="tenant-b",
            revoker="admin@example.com",
        )
    assert authority.get_request(request.request_id, "tenant-b") is None


def test_break_glass_requires_non_empty_reason() -> None:
    authority = BreakGlassAuthority(timeline=IdentityTimeline())
    with pytest.raises(ValueError):
        authority.request_access(
            subject="user:1",
            tenant_id="tenant-a",
            requested_capability="platform.admin",
            reason="",
            requested_by="oncall@example.com",
            duration_seconds=1800,
        )


def test_break_glass_cannot_elevate_deleted_identity() -> None:
    """A DELETED lifecycle state cannot be transitioned out of via any path.

    The lifecycle state machine has no successor for DELETED, so no
    downstream break-glass approval can 'unarchive' a subject. This is
    checked at the lifecycle manager which is the source of truth.
    """
    lifecycle = IdentityLifecycleManager()
    # Sanity: cannot transition out of DELETED to anything else.
    for successor in IdentityLifecycleState:
        with pytest.raises(ValueError):
            lifecycle.transition(
                subject="user:1",
                tenant_id="tenant-a",
                current_state=IdentityLifecycleState.DELETED,
                next_state=successor,
                reason="test",
                actor="admin@example.com",
            )
    # And a DELETED subject cannot authenticate — required break-glass gate.
    assert lifecycle.can_authenticate(IdentityLifecycleState.DELETED) is False


# ---------------------------------------------------------------------------
# Repositories: enforced tenant scoping
# ---------------------------------------------------------------------------


def test_memory_timeline_repository_cross_tenant_isolation() -> None:
    from api.identity_governance.models import IdentityTimelineEvent
    from api.identity_governance.repositories.memory import (
        InMemoryTimelineRepository,
    )

    repo = InMemoryTimelineRepository()
    event = IdentityTimelineEvent(
        event_id="e1",
        event_type=IdentityTimelineEventType.LOGIN,
        subject="user:1",
        tenant_id="tenant-a",
        actor="user:1",
        occurred_at=NOW,
        details=(),
        correlation_id=None,
        previous_hash="genesis",
        event_hash="h",
    )
    repo.append(event)
    assert repo.list_events("tenant-a") == [event]
    assert repo.list_events("tenant-b") == []


def test_memory_break_glass_repository_cross_tenant_isolation() -> None:
    from api.identity_governance.models import (
        BreakGlassRequest,
        BreakGlassStatus,
    )
    from api.identity_governance.repositories.memory import (
        InMemoryBreakGlassRepository,
    )

    repo = InMemoryBreakGlassRepository()
    req = BreakGlassRequest(
        request_id="bg1",
        tenant_id="tenant-a",
        subject="user:1",
        requested_capability="platform.admin",
        reason="incident",
        requested_by="oncall@example.com",
        requested_at=NOW,
        duration_seconds=600,
        status=BreakGlassStatus.PENDING,
    )
    repo.create(req)
    assert repo.get("tenant-a", "bg1") == req
    assert repo.get("tenant-b", "bg1") is None
    assert repo.list_active_for_subject("tenant-b", "user:1") == []
