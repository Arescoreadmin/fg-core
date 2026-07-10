"""api/identity_administration/invitation.py — Invitation service.

Cryptographic token management and replay protection for user invitations.

Security invariants:
- Raw token is returned ONCE from create_invitation and never stored.
- Only the SHA-256 hex hash (token_hash) is persisted.
- Replay protection: once accepted, re-lookup by token_hash returns an
  ACCEPTED invitation which raises InvitationAlreadyUsedError.
- Expired invitations are detected on accept (not eagerly).
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Optional

from api.identity_administration.models import Invitation, InvitationStatus
from api.identity_administration.repositories.base import InvitationRepository

DEFAULT_EXPIRY_DAYS: int = 7
MAX_EXPIRY_DAYS: int = 30


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class InvitationError(Exception):
    """Base class for invitation errors."""


class InvitationExpiredError(InvitationError):
    """Raised when the invitation has passed its expiry time."""


class InvitationAlreadyUsedError(InvitationError):
    """Raised on replay: invitation was already accepted."""


class InvitationRevokedError(InvitationError):
    """Raised when the invitation has been revoked."""


class DuplicateInvitationError(InvitationError):
    """Raised when a PENDING invitation already exists for this email+tenant."""


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


class InvitationService:
    """Manages invitation lifecycle: create, accept, revoke, reissue."""

    def __init__(self, invitation_repo: InvitationRepository) -> None:
        self._repo = invitation_repo

    def create_invitation(
        self,
        tenant_id: str,
        email: str,
        invited_by: str,
        *,
        custom_message: str = "",
        assigned_roles: tuple[str, ...] = (),
        assigned_capabilities: tuple[str, ...] = (),
        expiry_days: int = DEFAULT_EXPIRY_DAYS,
        correlation_id: Optional[str] = None,
    ) -> tuple[Invitation, str]:
        """Create invitation. Returns (invitation_record, raw_token).

        Raw token is returned ONCE and never stored. Caller is responsible for
        delivering it to the invitee (email in future). If a pending invitation
        already exists for this email+tenant, raises DuplicateInvitationError.
        """
        existing = self._repo.get_pending_for_email(tenant_id, email)
        if existing is not None:
            raise DuplicateInvitationError(
                f"Pending invitation already exists for {email}"
            )

        raw_token = secrets.token_urlsafe(32)  # 256 bits entropy
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

        now = datetime.now(tz=timezone.utc)
        invitation = Invitation(
            invitation_id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            email=email,
            token_hash=token_hash,
            invited_by=invited_by,
            invited_at=now,
            expires_at=now + timedelta(days=min(expiry_days, MAX_EXPIRY_DAYS)),
            status=InvitationStatus.PENDING,
            custom_message=custom_message,
            assigned_roles=assigned_roles,
            assigned_capabilities=assigned_capabilities,
        )
        self._repo.create(invitation)
        return invitation, raw_token

    def accept_invitation(
        self,
        raw_token: str,
        *,
        accepted_by: str,
    ) -> Invitation:
        """Accept invitation using raw token.

        Validates: exists, not expired, not used, not revoked.

        Replay protection: once accepted, token_hash cannot match a new lookup
        for a PENDING invitation — any subsequent call raises
        InvitationAlreadyUsedError.
        """
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        invitation = self._repo.get_by_token_hash(token_hash)
        if invitation is None:
            raise InvitationError("Invalid invitation token")
        if invitation.status == InvitationStatus.ACCEPTED:
            raise InvitationAlreadyUsedError("Invitation has already been accepted")
        if invitation.status == InvitationStatus.REVOKED:
            raise InvitationRevokedError("Invitation has been revoked")
        now = datetime.now(tz=timezone.utc)
        if now > invitation.expires_at:
            raise InvitationExpiredError("Invitation has expired")

        accepted = replace(
            invitation,
            status=InvitationStatus.ACCEPTED,
            accepted_at=now,
            accepted_by=accepted_by,
        )
        return self._repo.update(accepted)

    def revoke_invitation(
        self,
        tenant_id: str,
        invitation_id: str,
        *,
        revoked_by: str,
    ) -> Invitation:
        """Revoke a pending invitation.

        Raises InvitationError if not found or not pending.
        """
        invitation = self._repo.get(tenant_id, invitation_id)
        if invitation is None:
            raise InvitationError(f"Invitation {invitation_id!r} not found for tenant")
        if invitation.status != InvitationStatus.PENDING:
            raise InvitationError(
                f"Invitation {invitation_id!r} is not pending (status={invitation.status.value})"
            )
        now = datetime.now(tz=timezone.utc)
        revoked = replace(
            invitation,
            status=InvitationStatus.REVOKED,
            revoked_at=now,
            revoked_by=revoked_by,
        )
        return self._repo.update(revoked)

    def reissue_invitation(
        self,
        tenant_id: str,
        invitation_id: str,
        *,
        reissued_by: str,
        expiry_days: int = DEFAULT_EXPIRY_DAYS,
    ) -> tuple[Invitation, str]:
        """Revoke existing invitation and create a new one for the same email.

        Returns (new_invitation, new_raw_token).
        """
        old = self._repo.get(tenant_id, invitation_id)
        if old is None:
            raise InvitationError(f"Invitation {invitation_id!r} not found for tenant")
        if old.status not in (InvitationStatus.PENDING, InvitationStatus.EXPIRED):
            raise InvitationError(
                f"Invitation {invitation_id!r} cannot be reissued (status={old.status.value})"
            )
        # Revoke or mark expired first so get_pending_for_email won't block
        now = datetime.now(tz=timezone.utc)
        revoked = replace(
            old,
            status=InvitationStatus.REVOKED,
            revoked_at=now,
            revoked_by=reissued_by,
        )
        self._repo.update(revoked)

        # Now create a fresh invitation for the same email
        return self.create_invitation(
            tenant_id=tenant_id,
            email=old.email,
            invited_by=reissued_by,
            custom_message=old.custom_message,
            assigned_roles=old.assigned_roles,
            assigned_capabilities=old.assigned_capabilities,
            expiry_days=expiry_days,
        )

    def expire_pending(self, tenant_id: str, invitation_id: str) -> Invitation:
        """Mark a pending invitation as expired (called by background job or on-access check)."""
        invitation = self._repo.get(tenant_id, invitation_id)
        if invitation is None:
            raise InvitationError(f"Invitation {invitation_id!r} not found for tenant")
        if invitation.status != InvitationStatus.PENDING:
            raise InvitationError(
                f"Invitation {invitation_id!r} is not pending (status={invitation.status.value})"
            )
        expired = replace(invitation, status=InvitationStatus.EXPIRED)
        return self._repo.update(expired)


__all__ = [
    "DEFAULT_EXPIRY_DAYS",
    "DuplicateInvitationError",
    "InvitationAlreadyUsedError",
    "InvitationError",
    "InvitationExpiredError",
    "InvitationRevokedError",
    "InvitationService",
    "MAX_EXPIRY_DAYS",
]
