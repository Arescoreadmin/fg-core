"""api/identity_administration/repositories/base.py — Repository protocols.

Thin persistence Protocols. Every repository is tenant-scoped: the
``tenant_id`` parameter is required on every read/write and cross-tenant
access is rejected by construction.

The in-memory implementation lives in ``memory.py``; the SQLAlchemy
stub implementation lives in ``db.py``.
"""

from __future__ import annotations

from typing import Optional, Protocol

from api.identity_administration.models import (
    AdminAuditRecord,
    Group,
    GroupMember,
    IdentityRecord,
    Invitation,
)


class IdentityRepository(Protocol):
    """Persistence protocol for identity records."""

    def create(self, record: IdentityRecord) -> IdentityRecord: ...

    def update(self, record: IdentityRecord) -> IdentityRecord: ...

    def get(self, tenant_id: str, subject: str) -> Optional[IdentityRecord]: ...

    def get_by_email(self, tenant_id: str, email: str) -> Optional[IdentityRecord]: ...

    def list_for_tenant(
        self, tenant_id: str, limit: int, offset: int
    ) -> list[IdentityRecord]: ...

    def count_for_tenant(self, tenant_id: str) -> int: ...

    def search(
        self,
        tenant_id: str,
        query: str,
        lifecycle_states: list[str],
        limit: int,
        offset: int,
    ) -> list[IdentityRecord]: ...


class InvitationRepository(Protocol):
    """Persistence protocol for invitation records."""

    def create(self, invitation: Invitation) -> Invitation: ...

    def update(self, invitation: Invitation) -> Invitation: ...

    def get(self, tenant_id: str, invitation_id: str) -> Optional[Invitation]: ...

    def get_by_token_hash(self, token_hash: str) -> Optional[Invitation]: ...

    def get_pending_for_email(
        self, tenant_id: str, email: str
    ) -> Optional[Invitation]: ...

    def list_for_tenant(
        self, tenant_id: str, limit: int, offset: int
    ) -> list[Invitation]: ...


class GroupRepository(Protocol):
    """Persistence protocol for group records and memberships."""

    def create(self, group: Group) -> Group: ...

    def update(self, group: Group) -> Group: ...

    def get(self, tenant_id: str, group_id: str) -> Optional[Group]: ...

    def list_for_tenant(
        self, tenant_id: str, limit: int, offset: int
    ) -> list[Group]: ...

    def delete(self, tenant_id: str, group_id: str) -> None: ...

    def add_member(self, member: GroupMember) -> GroupMember: ...

    def remove_member(self, tenant_id: str, group_id: str, subject: str) -> None: ...

    def list_members(self, tenant_id: str, group_id: str) -> list[GroupMember]: ...

    def list_groups_for_subject(self, tenant_id: str, subject: str) -> list[Group]: ...


class AuditRepository(Protocol):
    """Persistence protocol for admin audit records."""

    def create(self, record: AdminAuditRecord) -> AdminAuditRecord: ...

    def list_for_subject(
        self, tenant_id: str, subject: str, limit: int, offset: int
    ) -> list[AdminAuditRecord]: ...

    def list_for_tenant(
        self, tenant_id: str, limit: int, offset: int
    ) -> list[AdminAuditRecord]: ...


__all__ = [
    "AuditRepository",
    "GroupRepository",
    "IdentityRepository",
    "InvitationRepository",
]
