"""api/identity_administration/repositories/db.py — SQLAlchemy stubs.

Real implementation is a follow-up PR.
Use migration 0149 and add SQLAlchemy models before enabling these.
"""

from __future__ import annotations

from typing import Optional

from api.identity_administration.models import (
    AdminAuditRecord,
    Group,
    GroupMember,
    IdentityRecord,
    Invitation,
)

_MSG = (
    "DB repository not yet implemented for identity_administration"
    " — use migration 0149 and add SQLAlchemy models"
)


class DbIdentityRepository:
    """SQLAlchemy stub for IdentityRepository."""

    def __init__(self, session_factory) -> None:  # type: ignore[no-untyped-def]
        self._session_factory = session_factory

    def create(self, record: IdentityRecord) -> IdentityRecord:
        raise NotImplementedError(_MSG)

    def update(self, record: IdentityRecord) -> IdentityRecord:
        raise NotImplementedError(_MSG)

    def get(self, tenant_id: str, subject: str) -> Optional[IdentityRecord]:
        raise NotImplementedError(_MSG)

    def get_by_email(self, tenant_id: str, email: str) -> Optional[IdentityRecord]:
        raise NotImplementedError(_MSG)

    def list_for_tenant(
        self, tenant_id: str, limit: int, offset: int
    ) -> list[IdentityRecord]:
        raise NotImplementedError(_MSG)

    def count_for_tenant(self, tenant_id: str) -> int:
        raise NotImplementedError(_MSG)

    def search(
        self,
        tenant_id: str,
        query: str,
        lifecycle_states: list[str],
        limit: int,
        offset: int,
    ) -> list[IdentityRecord]:
        raise NotImplementedError(_MSG)


class DbInvitationRepository:
    """SQLAlchemy stub for InvitationRepository."""

    def __init__(self, session_factory) -> None:  # type: ignore[no-untyped-def]
        self._session_factory = session_factory

    def create(self, invitation: Invitation) -> Invitation:
        raise NotImplementedError(_MSG)

    def update(self, invitation: Invitation) -> Invitation:
        raise NotImplementedError(_MSG)

    def get(self, tenant_id: str, invitation_id: str) -> Optional[Invitation]:
        raise NotImplementedError(_MSG)

    def get_by_token_hash(self, token_hash: str) -> Optional[Invitation]:
        raise NotImplementedError(_MSG)

    def get_pending_for_email(self, tenant_id: str, email: str) -> Optional[Invitation]:
        raise NotImplementedError(_MSG)

    def list_for_tenant(
        self, tenant_id: str, limit: int, offset: int
    ) -> list[Invitation]:
        raise NotImplementedError(_MSG)


class DbGroupRepository:
    """SQLAlchemy stub for GroupRepository."""

    def __init__(self, session_factory) -> None:  # type: ignore[no-untyped-def]
        self._session_factory = session_factory

    def create(self, group: Group) -> Group:
        raise NotImplementedError(_MSG)

    def update(self, group: Group) -> Group:
        raise NotImplementedError(_MSG)

    def get(self, tenant_id: str, group_id: str) -> Optional[Group]:
        raise NotImplementedError(_MSG)

    def list_for_tenant(self, tenant_id: str, limit: int, offset: int) -> list[Group]:
        raise NotImplementedError(_MSG)

    def delete(self, tenant_id: str, group_id: str) -> None:
        raise NotImplementedError(_MSG)

    def add_member(self, member: GroupMember) -> GroupMember:
        raise NotImplementedError(_MSG)

    def remove_member(self, tenant_id: str, group_id: str, subject: str) -> None:
        raise NotImplementedError(_MSG)

    def list_members(self, tenant_id: str, group_id: str) -> list[GroupMember]:
        raise NotImplementedError(_MSG)

    def list_groups_for_subject(self, tenant_id: str, subject: str) -> list[Group]:
        raise NotImplementedError(_MSG)


class DbAuditRepository:
    """SQLAlchemy stub for AuditRepository."""

    def __init__(self, session_factory) -> None:  # type: ignore[no-untyped-def]
        self._session_factory = session_factory

    def create(self, record: AdminAuditRecord) -> AdminAuditRecord:
        raise NotImplementedError(_MSG)

    def list_for_subject(
        self, tenant_id: str, subject: str, limit: int, offset: int
    ) -> list[AdminAuditRecord]:
        raise NotImplementedError(_MSG)

    def list_for_tenant(
        self, tenant_id: str, limit: int, offset: int
    ) -> list[AdminAuditRecord]:
        raise NotImplementedError(_MSG)


__all__ = [
    "DbAuditRepository",
    "DbGroupRepository",
    "DbIdentityRepository",
    "DbInvitationRepository",
]
