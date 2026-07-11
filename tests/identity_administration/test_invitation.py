"""Tests for InvitationService: token security, replay protection, expiry."""

from __future__ import annotations

import hashlib
import os
from datetime import datetime, timedelta, timezone
from dataclasses import replace

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_ACKNOWLEDGMENT_KEY", "test-key-32-bytes-exactly-padded!!")

import pytest

from api.identity_administration.invitation import (
    DuplicateInvitationError,
    InvitationAlreadyUsedError,
    InvitationError,
    InvitationExpiredError,
    InvitationRevokedError,
    InvitationService,
)
from api.identity_administration.models import InvitationStatus
from api.identity_administration.repositories.memory import InMemoryInvitationRepository

TENANT_A = "tenant-invitation-a"
TENANT_B = "tenant-invitation-b"
ACTOR = "admin-subject-001"
EMAIL = "user@example.com"


@pytest.fixture
def repo() -> InMemoryInvitationRepository:
    return InMemoryInvitationRepository()


@pytest.fixture
def svc(repo: InMemoryInvitationRepository) -> InvitationService:
    return InvitationService(invitation_repo=repo)


class TestCreateInvitation:
    def test_returns_invitation_and_raw_token(self, svc: InvitationService) -> None:
        invitation, raw_token = svc.create_invitation(TENANT_A, EMAIL, ACTOR)
        assert invitation is not None
        assert raw_token is not None
        assert len(raw_token) > 0

    def test_raw_token_is_43_chars_urlsafe_base64(self, svc: InvitationService) -> None:
        _, raw_token = svc.create_invitation(TENANT_A, EMAIL, ACTOR)
        # secrets.token_urlsafe(32) produces 43 chars of base64url
        assert len(raw_token) == 43

    def test_token_hash_is_sha256_hex_64_chars(self, svc: InvitationService) -> None:
        invitation, raw_token = svc.create_invitation(TENANT_A, EMAIL, ACTOR)
        expected_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        assert invitation.token_hash == expected_hash
        assert len(invitation.token_hash) == 64

    def test_invitation_status_is_pending(self, svc: InvitationService) -> None:
        invitation, _ = svc.create_invitation(TENANT_A, EMAIL, ACTOR)
        assert invitation.status == InvitationStatus.PENDING

    def test_duplicate_invitation_raises(self, svc: InvitationService) -> None:
        svc.create_invitation(TENANT_A, EMAIL, ACTOR)
        with pytest.raises(DuplicateInvitationError):
            svc.create_invitation(TENANT_A, EMAIL, ACTOR)

    def test_different_tenants_do_not_conflict(self, svc: InvitationService) -> None:
        svc.create_invitation(TENANT_A, EMAIL, ACTOR)
        # Should NOT raise for a different tenant
        invitation_b, _ = svc.create_invitation(TENANT_B, EMAIL, ACTOR)
        assert invitation_b.tenant_id == TENANT_B


class TestAcceptInvitation:
    def test_accept_with_correct_token_succeeds(self, svc: InvitationService) -> None:
        invitation, raw_token = svc.create_invitation(TENANT_A, EMAIL, ACTOR)
        accepted = svc.accept_invitation(raw_token, accepted_by="user-subject")
        assert accepted.status == InvitationStatus.ACCEPTED
        assert accepted.accepted_by == "user-subject"
        assert accepted.accepted_at is not None

    def test_replay_raises_already_used(self, svc: InvitationService) -> None:
        invitation, raw_token = svc.create_invitation(TENANT_A, EMAIL, ACTOR)
        svc.accept_invitation(raw_token, accepted_by="user-subject")
        with pytest.raises(InvitationAlreadyUsedError):
            svc.accept_invitation(raw_token, accepted_by="user-subject")

    def test_accept_expired_invitation_raises(
        self, repo: InMemoryInvitationRepository, svc: InvitationService
    ) -> None:
        invitation, raw_token = svc.create_invitation(TENANT_A, EMAIL, ACTOR)
        # Manually set expires_at to the past
        past = datetime.now(tz=timezone.utc) - timedelta(seconds=1)
        expired = replace(invitation, expires_at=past)
        repo.update(expired)
        with pytest.raises(InvitationExpiredError):
            svc.accept_invitation(raw_token, accepted_by="user-subject")

    def test_accept_revoked_invitation_raises(self, svc: InvitationService) -> None:
        invitation, raw_token = svc.create_invitation(TENANT_A, EMAIL, ACTOR)
        svc.revoke_invitation(TENANT_A, invitation.invitation_id, revoked_by=ACTOR)
        with pytest.raises(InvitationRevokedError):
            svc.accept_invitation(raw_token, accepted_by="user-subject")

    def test_accept_unknown_token_raises(self, svc: InvitationService) -> None:
        with pytest.raises(InvitationError):
            svc.accept_invitation("no-such-token", accepted_by="user-subject")


class TestRevokeInvitation:
    def test_revoke_marks_as_revoked(self, svc: InvitationService) -> None:
        invitation, _ = svc.create_invitation(TENANT_A, EMAIL, ACTOR)
        revoked = svc.revoke_invitation(
            TENANT_A, invitation.invitation_id, revoked_by=ACTOR
        )
        assert revoked.status == InvitationStatus.REVOKED
        assert revoked.revoked_by == ACTOR
        assert revoked.revoked_at is not None

    def test_revoke_not_found_raises(self, svc: InvitationService) -> None:
        with pytest.raises(InvitationError):
            svc.revoke_invitation(TENANT_A, "no-such-id", revoked_by=ACTOR)

    def test_revoke_already_accepted_raises(self, svc: InvitationService) -> None:
        invitation, raw_token = svc.create_invitation(TENANT_A, EMAIL, ACTOR)
        svc.accept_invitation(raw_token, accepted_by="user-sub")
        with pytest.raises(InvitationError):
            svc.revoke_invitation(TENANT_A, invitation.invitation_id, revoked_by=ACTOR)


class TestReissueInvitation:
    def test_reissue_revokes_old_creates_new(self, svc: InvitationService) -> None:
        old, old_token = svc.create_invitation(TENANT_A, EMAIL, ACTOR)
        new_inv, new_token = svc.reissue_invitation(
            TENANT_A, old.invitation_id, reissued_by=ACTOR
        )
        assert new_inv.invitation_id != old.invitation_id
        assert new_inv.email == old.email
        assert new_token != old_token
        assert new_inv.status == InvitationStatus.PENDING

    def test_old_token_no_longer_usable_after_reissue(
        self, svc: InvitationService
    ) -> None:
        old, old_token = svc.create_invitation(TENANT_A, EMAIL, ACTOR)
        svc.reissue_invitation(TENANT_A, old.invitation_id, reissued_by=ACTOR)
        # old token maps to REVOKED invitation → InvitationRevokedError
        with pytest.raises(InvitationRevokedError):
            svc.accept_invitation(old_token, accepted_by="user-sub")


class TestCrossTenantSafety:
    def test_token_from_tenant_a_accepted_carries_tenant_a(
        self, svc: InvitationService
    ) -> None:
        """Token lookup is global but returned invitation carries tenant_id."""
        _, raw_token = svc.create_invitation(TENANT_A, EMAIL, ACTOR)
        accepted = svc.accept_invitation(raw_token, accepted_by="user-sub")
        assert accepted.tenant_id == TENANT_A
