"""api/identity_administration/repositories/memory.py — In-memory repositories.

Default repository backend for identity administration. Data lives in
per-instance dicts guarded by a threading.Lock so tests (or an
unconfigured deployment) can use administration services without a database.

Every repository is tenant-scoped by construction: keys are
``(tenant_id, id)`` tuples so cross-tenant lookups return ``None`` even
when the id collides between tenants.
"""

from __future__ import annotations

import threading
from typing import Optional

from api.identity_administration.models import (
    AdminAuditRecord,
    Group,
    GroupMember,
    IdentityRecord,
    Invitation,
    InvitationStatus,
)


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------


class InMemoryIdentityRepository:
    """In-memory repository for identity records."""

    def __init__(self) -> None:
        # keyed by (tenant_id, subject)
        self._records: dict[tuple[str, str], IdentityRecord] = {}
        self._lock = threading.Lock()

    def create(self, record: IdentityRecord) -> IdentityRecord:
        if not record.tenant_id:
            raise ValueError("tenant_id is required")
        key = (record.tenant_id, record.subject)
        with self._lock:
            self._records[key] = record
        return record

    def update(self, record: IdentityRecord) -> IdentityRecord:
        if not record.tenant_id:
            raise ValueError("tenant_id is required")
        key = (record.tenant_id, record.subject)
        with self._lock:
            if key not in self._records:
                raise ValueError(
                    f"identity record for subject {record.subject!r} not found in tenant"
                )
            self._records[key] = record
        return record

    def get(self, tenant_id: str, subject: str) -> Optional[IdentityRecord]:
        with self._lock:
            return self._records.get((tenant_id, subject))

    def get_by_email(self, tenant_id: str, email: str) -> Optional[IdentityRecord]:
        with self._lock:
            for (tid, _), record in self._records.items():
                if tid == tenant_id and record.email == email:
                    return record
        return None

    def list_for_tenant(
        self, tenant_id: str, limit: int, offset: int
    ) -> list[IdentityRecord]:
        with self._lock:
            records = [r for (tid, _), r in self._records.items() if tid == tenant_id]
        records.sort(key=lambda r: r.created_at)
        return records[offset : offset + limit]

    def count_for_tenant(self, tenant_id: str) -> int:
        with self._lock:
            return sum(1 for (tid, _) in self._records if tid == tenant_id)

    def search(
        self,
        tenant_id: str,
        query: str,
        lifecycle_states: list[str],
        limit: int,
        offset: int,
    ) -> list[IdentityRecord]:
        q = query.lower()
        with self._lock:
            candidates = [
                r for (tid, _), r in self._records.items() if tid == tenant_id
            ]
        if q:
            candidates = [
                r
                for r in candidates
                if q in r.email.lower() or q in r.display_name.lower()
            ]
        if lifecycle_states:
            state_set = set(lifecycle_states)
            candidates = [r for r in candidates if r.lifecycle_state.value in state_set]
        candidates.sort(key=lambda r: r.created_at)
        return candidates[offset : offset + limit]


# ---------------------------------------------------------------------------
# Invitation
# ---------------------------------------------------------------------------


class InMemoryInvitationRepository:
    """In-memory repository for invitation records."""

    def __init__(self) -> None:
        # keyed by (tenant_id, invitation_id)
        self._invitations: dict[tuple[str, str], Invitation] = {}
        self._lock = threading.Lock()

    def create(self, invitation: Invitation) -> Invitation:
        if not invitation.tenant_id:
            raise ValueError("tenant_id is required")
        key = (invitation.tenant_id, invitation.invitation_id)
        with self._lock:
            self._invitations[key] = invitation
        return invitation

    def update(self, invitation: Invitation) -> Invitation:
        if not invitation.tenant_id:
            raise ValueError("tenant_id is required")
        key = (invitation.tenant_id, invitation.invitation_id)
        with self._lock:
            if key not in self._invitations:
                raise ValueError(
                    f"invitation {invitation.invitation_id!r} not found for tenant"
                )
            self._invitations[key] = invitation
        return invitation

    def get(self, tenant_id: str, invitation_id: str) -> Optional[Invitation]:
        with self._lock:
            return self._invitations.get((tenant_id, invitation_id))

    def get_by_token_hash(self, token_hash: str) -> Optional[Invitation]:
        """Search all records for matching token_hash (cross-tenant by design — tokens are global)."""
        with self._lock:
            for invitation in self._invitations.values():
                if invitation.token_hash == token_hash:
                    return invitation
        return None

    def get_pending_for_email(self, tenant_id: str, email: str) -> Optional[Invitation]:
        """Return PENDING invitation for email in tenant, or None."""
        with self._lock:
            for (tid, _), invitation in self._invitations.items():
                if (
                    tid == tenant_id
                    and invitation.email == email
                    and invitation.status == InvitationStatus.PENDING
                ):
                    return invitation
        return None

    def list_for_tenant(
        self, tenant_id: str, limit: int, offset: int
    ) -> list[Invitation]:
        with self._lock:
            invitations = [
                inv for (tid, _), inv in self._invitations.items() if tid == tenant_id
            ]
        invitations.sort(key=lambda i: i.invited_at)
        return invitations[offset : offset + limit]


# ---------------------------------------------------------------------------
# Group
# ---------------------------------------------------------------------------


class InMemoryGroupRepository:
    """In-memory repository for group records and memberships."""

    def __init__(self) -> None:
        # keyed by (tenant_id, group_id)
        self._groups: dict[tuple[str, str], Group] = {}
        # keyed by (tenant_id, group_id, subject)
        self._members: dict[tuple[str, str, str], GroupMember] = {}
        self._lock = threading.Lock()

    def create(self, group: Group) -> Group:
        if not group.tenant_id:
            raise ValueError("tenant_id is required")
        key = (group.tenant_id, group.group_id)
        with self._lock:
            self._groups[key] = group
        return group

    def update(self, group: Group) -> Group:
        if not group.tenant_id:
            raise ValueError("tenant_id is required")
        key = (group.tenant_id, group.group_id)
        with self._lock:
            if key not in self._groups:
                raise ValueError(f"group {group.group_id!r} not found for tenant")
            self._groups[key] = group
        return group

    def get(self, tenant_id: str, group_id: str) -> Optional[Group]:
        with self._lock:
            return self._groups.get((tenant_id, group_id))

    def list_for_tenant(self, tenant_id: str, limit: int, offset: int) -> list[Group]:
        with self._lock:
            groups = [g for (tid, _), g in self._groups.items() if tid == tenant_id]
        groups.sort(key=lambda g: g.created_at)
        return groups[offset : offset + limit]

    def delete(self, tenant_id: str, group_id: str) -> None:
        key = (tenant_id, group_id)
        with self._lock:
            self._groups.pop(key, None)
            # Also remove all memberships for this group
            to_remove = [
                k for k in self._members if k[0] == tenant_id and k[1] == group_id
            ]
            for k in to_remove:
                del self._members[k]

    def add_member(self, member: GroupMember) -> GroupMember:
        if not member.tenant_id:
            raise ValueError("tenant_id is required")
        key = (member.tenant_id, member.group_id, member.subject)
        with self._lock:
            self._members[key] = member
        return member

    def remove_member(self, tenant_id: str, group_id: str, subject: str) -> None:
        key = (tenant_id, group_id, subject)
        with self._lock:
            self._members.pop(key, None)

    def list_members(self, tenant_id: str, group_id: str) -> list[GroupMember]:
        with self._lock:
            members = [
                m
                for (tid, gid, _), m in self._members.items()
                if tid == tenant_id and gid == group_id
            ]
        return sorted(members, key=lambda m: m.added_at)

    def list_groups_for_subject(self, tenant_id: str, subject: str) -> list[Group]:
        with self._lock:
            group_ids = {
                gid
                for (tid, gid, sub) in self._members
                if tid == tenant_id and sub == subject
            }
            groups = [
                self._groups[(tenant_id, gid)]
                for gid in group_ids
                if (tenant_id, gid) in self._groups
            ]
        return sorted(groups, key=lambda g: g.created_at)


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


class InMemoryAuditRepository:
    """In-memory repository for admin audit records."""

    def __init__(self) -> None:
        # keyed by (tenant_id, audit_id)
        self._records: dict[tuple[str, str], AdminAuditRecord] = {}
        self._lock = threading.Lock()

    def create(self, record: AdminAuditRecord) -> AdminAuditRecord:
        if not record.tenant_id:
            raise ValueError("tenant_id is required")
        key = (record.tenant_id, record.audit_id)
        with self._lock:
            self._records[key] = record
        return record

    def list_for_subject(
        self, tenant_id: str, subject: str, limit: int, offset: int
    ) -> list[AdminAuditRecord]:
        with self._lock:
            records = [
                r
                for (tid, _), r in self._records.items()
                if tid == tenant_id and r.subject == subject
            ]
        records.sort(key=lambda r: r.occurred_at)
        return records[offset : offset + limit]

    def list_for_tenant(
        self, tenant_id: str, limit: int, offset: int
    ) -> list[AdminAuditRecord]:
        with self._lock:
            records = [r for (tid, _), r in self._records.items() if tid == tenant_id]
        records.sort(key=lambda r: r.occurred_at)
        return records[offset : offset + limit]


__all__ = [
    "InMemoryAuditRepository",
    "InMemoryGroupRepository",
    "InMemoryIdentityRepository",
    "InMemoryInvitationRepository",
]
