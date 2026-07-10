"""Tests for IdentityAdministrationService."""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_ACKNOWLEDGMENT_KEY", "test-key-32-bytes-exactly-padded!!")

import pytest

from api.identity_administration.administration import IdentityAdministrationService
from api.identity_administration.invitation import InvitationService
from api.identity_administration.notification import NotificationPublisher
from api.identity_administration.repositories.memory import (
    InMemoryAuditRepository,
    InMemoryIdentityRepository,
    InMemoryInvitationRepository,
)
from api.identity_governance.models import IdentityLifecycleState
from api.identity_governance.services import reset_services

TENANT = "tenant-admin-test-001"
ACTOR = "admin-subject-001"
EMAIL = "new-user@example.com"


@pytest.fixture(autouse=True)
def _reset_gov() -> None:
    reset_services()


@pytest.fixture
def identity_repo() -> InMemoryIdentityRepository:
    return InMemoryIdentityRepository()


@pytest.fixture
def invitation_repo() -> InMemoryInvitationRepository:
    return InMemoryInvitationRepository()


@pytest.fixture
def audit_repo() -> InMemoryAuditRepository:
    return InMemoryAuditRepository()


@pytest.fixture
def admin_svc(
    identity_repo: InMemoryIdentityRepository,
    invitation_repo: InMemoryInvitationRepository,
    audit_repo: InMemoryAuditRepository,
) -> IdentityAdministrationService:
    from api.identity_governance.services import get_services

    gov = get_services()
    publisher = NotificationPublisher(timeline=gov.timeline)
    invitation_svc = InvitationService(invitation_repo=invitation_repo)
    return IdentityAdministrationService(
        identity_repo=identity_repo,
        invitation_service=invitation_svc,
        audit_repo=audit_repo,
        notification_publisher=publisher,
    )


class TestInviteUser:
    def test_invite_user_creates_identity_in_invited_state(
        self, admin_svc: IdentityAdministrationService
    ) -> None:
        identity, invitation, raw_token = admin_svc.invite_user(TENANT, EMAIL, ACTOR)
        assert identity.lifecycle_state == IdentityLifecycleState.INVITED
        assert identity.email == EMAIL
        assert identity.tenant_id == TENANT

    def test_invite_user_emits_timeline_event(
        self,
        admin_svc: IdentityAdministrationService,
        identity_repo: InMemoryIdentityRepository,
    ) -> None:
        from api.identity_governance.services import get_services

        gov = get_services()
        admin_svc.invite_user(TENANT, EMAIL, ACTOR)
        events = gov.timeline.query(tenant_id=TENANT, limit=100)
        assert len(events) >= 1
        event_types = [e.event_type.value for e in events]
        assert "ADMIN_ACTION" in event_types

    def test_invite_user_returns_raw_token(
        self, admin_svc: IdentityAdministrationService
    ) -> None:
        _, invitation, raw_token = admin_svc.invite_user(TENANT, EMAIL, ACTOR)
        assert len(raw_token) == 43  # secrets.token_urlsafe(32) → 43 chars
        assert invitation.status.value == "PENDING"

    def test_invite_user_creates_audit_record(
        self,
        admin_svc: IdentityAdministrationService,
        audit_repo: InMemoryAuditRepository,
    ) -> None:
        admin_svc.invite_user(TENANT, EMAIL, ACTOR)
        records = audit_repo.list_for_tenant(TENANT, limit=50, offset=0)
        assert len(records) >= 1
        assert records[0].action.value == "invite"


class TestTransitionLifecycle:
    def test_transition_active_to_suspended(
        self, admin_svc: IdentityAdministrationService
    ) -> None:
        identity, _, _ = admin_svc.invite_user(TENANT, EMAIL, ACTOR)
        # Manually set to ACTIVE via multiple transitions
        identity_repo = admin_svc._repo
        from dataclasses import replace
        from datetime import datetime, timezone

        active_record = replace(
            identity,
            lifecycle_state=IdentityLifecycleState.ACTIVE,
            updated_at=datetime.now(tz=timezone.utc),
        )
        identity_repo.update(active_record)

        updated = admin_svc.transition_lifecycle(
            TENANT, identity.subject, IdentityLifecycleState.SUSPENDED, ACTOR, "test"
        )
        assert updated.lifecycle_state == IdentityLifecycleState.SUSPENDED

    def test_transition_emits_suspended_notification(
        self, admin_svc: IdentityAdministrationService
    ) -> None:
        from api.identity_governance.services import get_services
        from dataclasses import replace
        from datetime import datetime, timezone

        identity, _, _ = admin_svc.invite_user(TENANT, EMAIL, ACTOR)
        identity_repo = admin_svc._repo
        active_record = replace(
            identity,
            lifecycle_state=IdentityLifecycleState.ACTIVE,
            updated_at=datetime.now(tz=timezone.utc),
        )
        identity_repo.update(active_record)

        gov = get_services()
        before_count = len(gov.timeline.query(tenant_id=TENANT, limit=200))
        admin_svc.transition_lifecycle(
            TENANT, identity.subject, IdentityLifecycleState.SUSPENDED, ACTOR, "reason"
        )
        after_count = len(gov.timeline.query(tenant_id=TENANT, limit=200))
        assert after_count > before_count

    def test_invalid_transition_raises_value_error(
        self, admin_svc: IdentityAdministrationService
    ) -> None:
        identity, _, _ = admin_svc.invite_user(TENANT, EMAIL, ACTOR)
        with pytest.raises(ValueError, match="invalid lifecycle transition"):
            # INVITED → LOCKED is not a valid transition
            admin_svc.transition_lifecycle(
                TENANT, identity.subject, IdentityLifecycleState.LOCKED, ACTOR, "test"
            )


class TestTerminateSession:
    def test_terminate_session_calls_identity_authority(
        self, admin_svc: IdentityAdministrationService
    ) -> None:
        mock_authority = MagicMock()
        with patch(
            "api.identity_authority.authority.get_identity_authority",
            return_value=mock_authority,
        ):
            admin_svc.terminate_session(
                TENANT, "sub-001", "sess-001", ACTOR, "security reason"
            )
        mock_authority.logout.assert_called_once_with(
            "sess-001", subject="sub-001", correlation_id=None
        )


class TestRevokeDevice:
    def test_revoke_device_updates_device_trust(
        self, admin_svc: IdentityAdministrationService
    ) -> None:
        from api.identity_governance.services import get_services

        gov = get_services()
        # Register a device first
        device = gov.device_registry.register_device(
            subject="sub-device-test",
            tenant_id=TENANT,
            fingerprint_hash="abc123",
            user_agent_hash="ua456",
            ip_metadata="127.0.0.1",
        )
        admin_svc.revoke_device(
            TENANT, "sub-device-test", device.device_id, ACTOR, "test revocation"
        )
        updated = gov.device_registry.get_device(device.device_id, TENANT)
        assert updated is not None
        from api.identity_governance.models import DeviceTrustState

        assert updated.trust_state == DeviceTrustState.REVOKED


class TestGetIdentity:
    def test_get_identity_returns_none_for_unknown_subject(
        self, admin_svc: IdentityAdministrationService
    ) -> None:
        result = admin_svc.get_identity(TENANT, "no-such-subject")
        assert result is None

    def test_list_identities_returns_paginated_results(
        self, admin_svc: IdentityAdministrationService
    ) -> None:
        for i in range(3):
            admin_svc.invite_user(TENANT, f"user{i}@example.com", ACTOR)
        records, total = admin_svc.list_identities(TENANT, limit=2, offset=0)
        assert len(records) == 2
        assert total == 3


class TestCompleteInvitationAcceptance:
    def test_transitions_identity_to_accepted(
        self, admin_svc: IdentityAdministrationService
    ) -> None:
        identity, _, raw_token = admin_svc.invite_user(TENANT, EMAIL, ACTOR)
        assert identity.lifecycle_state == IdentityLifecycleState.INVITED

        admin_svc.complete_invitation_acceptance(
            tenant_id=TENANT,
            email=EMAIL,
            accepted_by=identity.subject,
        )
        record = admin_svc.get_identity(TENANT, identity.subject)
        assert record is not None
        assert record.lifecycle_state == IdentityLifecycleState.ACCEPTED

    def test_noop_when_identity_already_accepted(
        self, admin_svc: IdentityAdministrationService
    ) -> None:
        identity, _, _ = admin_svc.invite_user(TENANT, EMAIL, ACTOR)
        admin_svc.complete_invitation_acceptance(TENANT, EMAIL, identity.subject)
        # Second call must not raise
        admin_svc.complete_invitation_acceptance(TENANT, EMAIL, identity.subject)
        record = admin_svc.get_identity(TENANT, identity.subject)
        assert record is not None
        assert record.lifecycle_state == IdentityLifecycleState.ACCEPTED

    def test_noop_when_email_has_no_identity(
        self, admin_svc: IdentityAdministrationService
    ) -> None:
        # Must not raise even if there's no matching identity record.
        admin_svc.complete_invitation_acceptance(
            TENANT, "ghost@example.com", "some-subject"
        )


class TestDeleteIdentity:
    def test_delete_invited_user_reaches_deleted_state(
        self, admin_svc: IdentityAdministrationService
    ) -> None:
        identity, _, _ = admin_svc.invite_user(TENANT, EMAIL, ACTOR)
        assert identity.lifecycle_state == IdentityLifecycleState.INVITED

        admin_svc.delete_identity(TENANT, identity.subject, ACTOR)

        record = admin_svc.get_identity(TENANT, identity.subject)
        assert record is not None
        assert record.lifecycle_state == IdentityLifecycleState.DELETED

    def test_delete_active_user_reaches_deleted_state(
        self, admin_svc: IdentityAdministrationService
    ) -> None:
        from dataclasses import replace
        from datetime import datetime, timezone

        identity, _, _ = admin_svc.invite_user(TENANT, EMAIL, ACTOR)
        active = replace(
            identity,
            lifecycle_state=IdentityLifecycleState.ACTIVE,
            updated_at=datetime.now(tz=timezone.utc),
        )
        admin_svc._repo.update(active)

        admin_svc.delete_identity(TENANT, identity.subject, ACTOR)

        record = admin_svc.get_identity(TENANT, identity.subject)
        assert record is not None
        assert record.lifecycle_state == IdentityLifecycleState.DELETED

    def test_delete_idempotent_when_already_deleted(
        self, admin_svc: IdentityAdministrationService
    ) -> None:
        identity, _, _ = admin_svc.invite_user(TENANT, EMAIL, ACTOR)
        admin_svc.delete_identity(TENANT, identity.subject, ACTOR)
        # Second call must not raise
        admin_svc.delete_identity(TENANT, identity.subject, ACTOR)

    def test_delete_missing_subject_raises_value_error(
        self, admin_svc: IdentityAdministrationService
    ) -> None:
        with pytest.raises(ValueError, match="not found"):
            admin_svc.delete_identity(TENANT, "no-such-subject", ACTOR)
