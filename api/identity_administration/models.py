"""api/identity_administration/models.py — Administration domain models.

All models are frozen dataclasses (immutable by construction).
Tenant-scoped: every persisted record carries tenant_id.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Optional

from api.identity_governance.models import IdentityLifecycleState


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class InvitationStatus(str, Enum):
    """Lifecycle status of an invitation."""

    PENDING = "PENDING"
    ACCEPTED = "ACCEPTED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


class AdminActionType(str, Enum):
    """Types of admin actions recorded in the audit log."""

    INVITE = "invite"
    DISABLE = "disable"
    SUSPEND = "suspend"
    ARCHIVE = "archive"
    RESTORE = "restore"
    DELETE = "delete"
    UNLOCK = "unlock"
    FORCE_MFA = "force_mfa"
    FORCE_PASSWORD_RESET = "force_password_reset"
    TERMINATE_SESSION = "terminate_session"
    REVOKE_DEVICE = "revoke_device"
    TRUST_DEVICE = "trust_device"
    ASSIGN_ROLE = "assign_role"
    REMOVE_ROLE = "remove_role"


class NotificationEventType(str, Enum):
    """Types of notification events emitted to the timeline."""

    INVITATION_CREATED = "invitation.created"
    INVITATION_ACCEPTED = "invitation.accepted"
    INVITATION_EXPIRED = "invitation.expired"
    INVITATION_REVOKED = "invitation.revoked"
    USER_ACTIVATED = "user.activated"
    USER_SUSPENDED = "user.suspended"
    USER_DISABLED = "user.disabled"
    USER_LOCKED = "user.locked"
    USER_UNLOCKED = "user.unlocked"
    ROLE_ASSIGNED = "role.assigned"
    ROLE_REMOVED = "role.removed"
    SESSION_REVOKED = "session.revoked"
    PASSWORD_RESET = "password.reset"
    DEVICE_REVOKED = "device.revoked"
    DEVICE_TRUSTED = "device.trusted"
    PROFILE_UPDATED = "profile.updated"
    GROUP_MEMBER_ADDED = "group.member_added"
    GROUP_MEMBER_REMOVED = "group.member_removed"


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IdentityRecord:
    """Immutable identity record for a subject within a tenant."""

    record_id: str
    tenant_id: str
    subject: str
    email: str
    display_name: str
    lifecycle_state: IdentityLifecycleState
    created_at: datetime
    updated_at: datetime
    invited_by: Optional[str] = None
    invitation_id: Optional[str] = None


@dataclass(frozen=True)
class Invitation:
    """Immutable invitation record.

    Raw invitation token is NEVER stored — only the SHA-256 hex hash.
    """

    invitation_id: str
    tenant_id: str
    email: str
    token_hash: str  # SHA-256 hex of raw token; never store raw token
    invited_by: str  # subject of inviting admin
    invited_at: datetime
    expires_at: datetime
    status: InvitationStatus
    custom_message: str = ""
    assigned_roles: tuple[str, ...] = ()
    assigned_capabilities: tuple[str, ...] = ()
    accepted_at: Optional[datetime] = None
    accepted_by: Optional[str] = None  # subject who accepted
    revoked_at: Optional[datetime] = None
    revoked_by: Optional[str] = None


@dataclass(frozen=True)
class Group:
    """Immutable group record."""

    group_id: str
    tenant_id: str
    name: str
    description: str
    created_by: str
    created_at: datetime
    updated_at: datetime
    roles: tuple[str, ...] = ()
    capabilities: tuple[str, ...] = ()


@dataclass(frozen=True)
class GroupMember:
    """Immutable group membership record."""

    group_id: str
    tenant_id: str
    subject: str
    added_by: str
    added_at: datetime


@dataclass(frozen=True)
class NotificationEvent:
    """Immutable notification event to be published to the timeline."""

    event_type: NotificationEventType
    tenant_id: str
    subject: str
    actor: str
    occurred_at: datetime
    correlation_id: Optional[str] = None
    payload: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class AdminAuditRecord:
    """Immutable admin audit log entry."""

    audit_id: str
    tenant_id: str
    action: AdminActionType
    actor: str  # who performed the action
    subject: str  # who was acted upon
    occurred_at: datetime
    reason: str
    previous_state: str
    new_state: str
    correlation_id: Optional[str] = None
    object_id: Optional[str] = None
    object_type: Optional[str] = None


__all__ = [
    "AdminActionType",
    "AdminAuditRecord",
    "Group",
    "GroupMember",
    "IdentityRecord",
    "Invitation",
    "InvitationStatus",
    "NotificationEvent",
    "NotificationEventType",
]
