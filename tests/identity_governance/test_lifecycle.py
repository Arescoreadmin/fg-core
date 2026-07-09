"""tests/identity_governance/test_lifecycle.py — Lifecycle state machine tests."""

from __future__ import annotations

import pytest

from api.identity_governance.lifecycle import (
    VALID_TRANSITIONS,
    IdentityLifecycleManager,
)
from api.identity_governance.models import IdentityLifecycleState


@pytest.fixture
def manager() -> IdentityLifecycleManager:
    return IdentityLifecycleManager()


def test_created_to_active_valid(manager: IdentityLifecycleManager) -> None:
    record = manager.transition(
        subject="user-1",
        tenant_id="tenant-a",
        current_state=IdentityLifecycleState.CREATED,
        next_state=IdentityLifecycleState.ACTIVE,
        reason="onboarding",
        actor="admin@fg",
    )
    assert record.from_state == IdentityLifecycleState.CREATED
    assert record.to_state == IdentityLifecycleState.ACTIVE
    assert record.reason == "onboarding"
    assert record.tenant_id == "tenant-a"


def test_invalid_direct_active_to_deleted(manager: IdentityLifecycleManager) -> None:
    with pytest.raises(ValueError, match="invalid lifecycle transition"):
        manager.transition(
            subject="u",
            tenant_id="t",
            current_state=IdentityLifecycleState.ACTIVE,
            next_state=IdentityLifecycleState.DELETED,
            reason="r",
            actor="a",
        )


def test_deleted_is_terminal(manager: IdentityLifecycleManager) -> None:
    assert VALID_TRANSITIONS[IdentityLifecycleState.DELETED] == set()
    for target in IdentityLifecycleState:
        with pytest.raises(ValueError):
            manager.transition(
                subject="u",
                tenant_id="t",
                current_state=IdentityLifecycleState.DELETED,
                next_state=target,
                reason="r",
                actor="a",
            )


def test_only_active_can_authenticate(manager: IdentityLifecycleManager) -> None:
    assert manager.can_authenticate(IdentityLifecycleState.ACTIVE) is True
    for s in IdentityLifecycleState:
        if s == IdentityLifecycleState.ACTIVE:
            continue
        assert manager.can_authenticate(s) is False


def test_reason_required(manager: IdentityLifecycleManager) -> None:
    with pytest.raises(ValueError, match="reason is required"):
        manager.transition(
            subject="u",
            tenant_id="t",
            current_state=IdentityLifecycleState.CREATED,
            next_state=IdentityLifecycleState.ACTIVE,
            reason="",
            actor="a",
        )


def test_actor_required(manager: IdentityLifecycleManager) -> None:
    with pytest.raises(ValueError, match="actor is required"):
        manager.transition(
            subject="u",
            tenant_id="t",
            current_state=IdentityLifecycleState.CREATED,
            next_state=IdentityLifecycleState.ACTIVE,
            reason="r",
            actor="",
        )


def test_subject_and_tenant_required(manager: IdentityLifecycleManager) -> None:
    with pytest.raises(ValueError, match="subject is required"):
        manager.transition(
            subject="",
            tenant_id="t",
            current_state=IdentityLifecycleState.CREATED,
            next_state=IdentityLifecycleState.ACTIVE,
            reason="r",
            actor="a",
        )
    with pytest.raises(ValueError, match="tenant_id is required"):
        manager.transition(
            subject="u",
            tenant_id="",
            current_state=IdentityLifecycleState.CREATED,
            next_state=IdentityLifecycleState.ACTIVE,
            reason="r",
            actor="a",
        )


def test_all_valid_transitions_pass(manager: IdentityLifecycleManager) -> None:
    for current, targets in VALID_TRANSITIONS.items():
        for tgt in targets:
            record = manager.transition(
                subject="u",
                tenant_id="t",
                current_state=current,
                next_state=tgt,
                reason="test",
                actor="tester",
            )
            assert record.from_state == current
            assert record.to_state == tgt


def test_suspended_to_active_allowed(manager: IdentityLifecycleManager) -> None:
    record = manager.transition(
        subject="u",
        tenant_id="t",
        current_state=IdentityLifecycleState.SUSPENDED,
        next_state=IdentityLifecycleState.ACTIVE,
        reason="reactivation approved",
        actor="admin",
    )
    assert record.to_state == IdentityLifecycleState.ACTIVE


def test_archived_only_to_deleted(manager: IdentityLifecycleManager) -> None:
    record = manager.transition(
        subject="u",
        tenant_id="t",
        current_state=IdentityLifecycleState.ARCHIVED,
        next_state=IdentityLifecycleState.DELETED,
        reason="retention purge",
        actor="scheduler",
    )
    assert record.to_state == IdentityLifecycleState.DELETED
    with pytest.raises(ValueError):
        manager.transition(
            subject="u",
            tenant_id="t",
            current_state=IdentityLifecycleState.ARCHIVED,
            next_state=IdentityLifecycleState.ACTIVE,
            reason="r",
            actor="a",
        )


def test_record_is_immutable(manager: IdentityLifecycleManager) -> None:
    record = manager.transition(
        subject="u",
        tenant_id="t",
        current_state=IdentityLifecycleState.CREATED,
        next_state=IdentityLifecycleState.ACTIVE,
        reason="r",
        actor="a",
    )
    with pytest.raises(Exception):
        record.reason = "changed"  # type: ignore[misc]


def test_record_carries_tenant(manager: IdentityLifecycleManager) -> None:
    r1 = manager.transition(
        subject="u",
        tenant_id="tenant-a",
        current_state=IdentityLifecycleState.CREATED,
        next_state=IdentityLifecycleState.ACTIVE,
        reason="r",
        actor="a",
    )
    r2 = manager.transition(
        subject="u",
        tenant_id="tenant-b",
        current_state=IdentityLifecycleState.CREATED,
        next_state=IdentityLifecycleState.ACTIVE,
        reason="r",
        actor="a",
    )
    assert r1.tenant_id == "tenant-a"
    assert r2.tenant_id == "tenant-b"


def test_no_secrets_in_reason_field(manager: IdentityLifecycleManager) -> None:
    # Lifecycle records must not accidentally serialize secrets.
    record = manager.transition(
        subject="u",
        tenant_id="t",
        current_state=IdentityLifecycleState.CREATED,
        next_state=IdentityLifecycleState.ACTIVE,
        reason="clean-reason-no-secret",
        actor="a",
    )
    dump = repr(record)
    for banned in ("password", "secret_val", "token=", "PORTAL_PASSWORD"):
        assert banned not in dump
