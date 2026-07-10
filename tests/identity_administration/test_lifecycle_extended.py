"""Tests for extended lifecycle state transitions added in PR-02.

All new transitions are tested for validity and correctness.
Invalid transitions raise ValueError.
"""

from __future__ import annotations

import os

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_ACKNOWLEDGMENT_KEY", "test-key-32-bytes-exactly-padded!!")

import pytest

from api.identity_governance.lifecycle import IdentityLifecycleManager
from api.identity_governance.models import IdentityLifecycleState


@pytest.fixture
def mgr() -> IdentityLifecycleManager:
    return IdentityLifecycleManager()


def _transition(
    mgr: IdentityLifecycleManager,
    from_state: IdentityLifecycleState,
    to_state: IdentityLifecycleState,
) -> None:
    mgr.transition(
        subject="sub-test",
        tenant_id="tenant-test",
        current_state=from_state,
        next_state=to_state,
        reason="test transition",
        actor="test-actor",
    )


class TestNewLifecycleTransitions:
    """Valid transitions introduced by PR-02."""

    def test_created_to_invited(self, mgr: IdentityLifecycleManager) -> None:
        _transition(mgr, IdentityLifecycleState.CREATED, IdentityLifecycleState.INVITED)

    def test_invited_to_invitation_sent(self, mgr: IdentityLifecycleManager) -> None:
        _transition(
            mgr, IdentityLifecycleState.INVITED, IdentityLifecycleState.INVITATION_SENT
        )

    def test_invitation_sent_to_invitation_opened(
        self, mgr: IdentityLifecycleManager
    ) -> None:
        _transition(
            mgr,
            IdentityLifecycleState.INVITATION_SENT,
            IdentityLifecycleState.INVITATION_OPENED,
        )

    def test_invitation_opened_to_accepted(self, mgr: IdentityLifecycleManager) -> None:
        _transition(
            mgr,
            IdentityLifecycleState.INVITATION_OPENED,
            IdentityLifecycleState.ACCEPTED,
        )

    def test_accepted_to_provisioned(self, mgr: IdentityLifecycleManager) -> None:
        _transition(
            mgr, IdentityLifecycleState.ACCEPTED, IdentityLifecycleState.PROVISIONED
        )

    def test_provisioned_to_active(self, mgr: IdentityLifecycleManager) -> None:
        _transition(
            mgr, IdentityLifecycleState.PROVISIONED, IdentityLifecycleState.ACTIVE
        )

    def test_active_to_locked(self, mgr: IdentityLifecycleManager) -> None:
        _transition(mgr, IdentityLifecycleState.ACTIVE, IdentityLifecycleState.LOCKED)

    def test_locked_to_active_unlock(self, mgr: IdentityLifecycleManager) -> None:
        _transition(mgr, IdentityLifecycleState.LOCKED, IdentityLifecycleState.ACTIVE)

    def test_locked_to_disabled(self, mgr: IdentityLifecycleManager) -> None:
        _transition(mgr, IdentityLifecycleState.LOCKED, IdentityLifecycleState.DISABLED)

    def test_active_to_password_reset_pending(
        self, mgr: IdentityLifecycleManager
    ) -> None:
        _transition(
            mgr,
            IdentityLifecycleState.ACTIVE,
            IdentityLifecycleState.PASSWORD_RESET_PENDING,
        )

    def test_password_reset_pending_to_active(
        self, mgr: IdentityLifecycleManager
    ) -> None:
        _transition(
            mgr,
            IdentityLifecycleState.PASSWORD_RESET_PENDING,
            IdentityLifecycleState.ACTIVE,
        )

    def test_active_to_mfa_enrollment_required(
        self, mgr: IdentityLifecycleManager
    ) -> None:
        _transition(
            mgr,
            IdentityLifecycleState.ACTIVE,
            IdentityLifecycleState.MFA_ENROLLMENT_REQUIRED,
        )

    def test_mfa_enrollment_required_to_verified(
        self, mgr: IdentityLifecycleManager
    ) -> None:
        _transition(
            mgr,
            IdentityLifecycleState.MFA_ENROLLMENT_REQUIRED,
            IdentityLifecycleState.VERIFIED,
        )

    def test_verified_to_active(self, mgr: IdentityLifecycleManager) -> None:
        _transition(mgr, IdentityLifecycleState.VERIFIED, IdentityLifecycleState.ACTIVE)

    def test_suspended_to_locked(self, mgr: IdentityLifecycleManager) -> None:
        _transition(
            mgr, IdentityLifecycleState.SUSPENDED, IdentityLifecycleState.LOCKED
        )


class TestInvalidTransitions:
    """Transitions that must raise ValueError."""

    def test_deleted_to_active_is_invalid(self, mgr: IdentityLifecycleManager) -> None:
        with pytest.raises(ValueError, match="invalid lifecycle transition"):
            _transition(
                mgr, IdentityLifecycleState.DELETED, IdentityLifecycleState.ACTIVE
            )

    def test_active_to_created_is_invalid(self, mgr: IdentityLifecycleManager) -> None:
        with pytest.raises(ValueError, match="invalid lifecycle transition"):
            _transition(
                mgr, IdentityLifecycleState.ACTIVE, IdentityLifecycleState.CREATED
            )

    def test_disabled_to_active_is_invalid(self, mgr: IdentityLifecycleManager) -> None:
        with pytest.raises(ValueError, match="invalid lifecycle transition"):
            _transition(
                mgr, IdentityLifecycleState.DISABLED, IdentityLifecycleState.ACTIVE
            )

    def test_locked_to_archived_is_invalid(self, mgr: IdentityLifecycleManager) -> None:
        with pytest.raises(ValueError, match="invalid lifecycle transition"):
            _transition(
                mgr, IdentityLifecycleState.LOCKED, IdentityLifecycleState.ARCHIVED
            )

    def test_provisioned_to_invited_is_invalid(
        self, mgr: IdentityLifecycleManager
    ) -> None:
        with pytest.raises(ValueError, match="invalid lifecycle transition"):
            _transition(
                mgr,
                IdentityLifecycleState.PROVISIONED,
                IdentityLifecycleState.INVITED,
            )


class TestExistingTransitionsUnchanged:
    """Verify original transitions still work after extension."""

    def test_disabled_to_archived(self, mgr: IdentityLifecycleManager) -> None:
        _transition(
            mgr, IdentityLifecycleState.DISABLED, IdentityLifecycleState.ARCHIVED
        )

    def test_archived_to_deleted(self, mgr: IdentityLifecycleManager) -> None:
        _transition(
            mgr, IdentityLifecycleState.ARCHIVED, IdentityLifecycleState.DELETED
        )

    def test_active_to_suspended(self, mgr: IdentityLifecycleManager) -> None:
        _transition(
            mgr, IdentityLifecycleState.ACTIVE, IdentityLifecycleState.SUSPENDED
        )
