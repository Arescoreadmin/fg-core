"""api/identity_administration/groups.py — Group management service."""

from __future__ import annotations

import uuid
from dataclasses import replace
from datetime import datetime, timezone
from typing import Optional

from api.identity_administration.models import Group, GroupMember
from api.identity_administration.repositories.base import GroupRepository


class GroupService:
    """Manages group lifecycle: create, delete, member management, role assignment."""

    def __init__(self, group_repo: GroupRepository) -> None:
        self._repo = group_repo

    def create_group(
        self,
        tenant_id: str,
        name: str,
        description: str,
        actor: str,
        *,
        roles: tuple[str, ...] = (),
        capabilities: tuple[str, ...] = (),
    ) -> Group:
        """Create a new group within a tenant."""
        if not tenant_id:
            raise ValueError("tenant_id is required")
        if not name:
            raise ValueError("name is required")
        if not actor:
            raise ValueError("actor is required")
        now = datetime.now(tz=timezone.utc)
        group = Group(
            group_id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            name=name,
            description=description,
            created_by=actor,
            created_at=now,
            updated_at=now,
            roles=roles,
            capabilities=capabilities,
        )
        return self._repo.create(group)

    def get_group(self, tenant_id: str, group_id: str) -> Optional[Group]:
        """Return a group record, or None if not found."""
        return self._repo.get(tenant_id, group_id)

    def list_groups(
        self, tenant_id: str, limit: int, offset: int
    ) -> tuple[list[Group], int]:
        """List groups for a tenant. Returns (groups, total_count)."""
        groups = self._repo.list_for_tenant(tenant_id, limit=limit + offset, offset=0)
        total = len(groups)
        return groups[offset : offset + limit], total

    def delete_group(self, tenant_id: str, group_id: str, actor: str) -> None:
        """Delete a group and all its memberships."""
        self._repo.delete(tenant_id, group_id)

    def add_member(
        self, tenant_id: str, group_id: str, subject: str, actor: str
    ) -> GroupMember:
        """Add a member to a group (idempotent)."""
        if not tenant_id:
            raise ValueError("tenant_id is required")
        if not group_id:
            raise ValueError("group_id is required")
        if not subject:
            raise ValueError("subject is required")
        member = GroupMember(
            group_id=group_id,
            tenant_id=tenant_id,
            subject=subject,
            added_by=actor,
            added_at=datetime.now(tz=timezone.utc),
        )
        return self._repo.add_member(member)

    def remove_member(
        self, tenant_id: str, group_id: str, subject: str, actor: str
    ) -> None:
        """Remove a member from a group."""
        self._repo.remove_member(tenant_id, group_id, subject)

    def list_members(self, tenant_id: str, group_id: str) -> list[GroupMember]:
        """List all members of a group."""
        return self._repo.list_members(tenant_id, group_id)

    def assign_role_to_group(
        self, tenant_id: str, group_id: str, role: str, actor: str
    ) -> Group:
        """Add a role to a group."""
        group = self._repo.get(tenant_id, group_id)
        if group is None:
            raise ValueError(f"Group {group_id!r} not found for tenant")
        if role in group.roles:
            return group
        updated = replace(
            group,
            roles=tuple(sorted(set(group.roles) | {role})),
            updated_at=datetime.now(tz=timezone.utc),
        )
        return self._repo.update(updated)

    def remove_role_from_group(
        self, tenant_id: str, group_id: str, role: str, actor: str
    ) -> Group:
        """Remove a role from a group."""
        group = self._repo.get(tenant_id, group_id)
        if group is None:
            raise ValueError(f"Group {group_id!r} not found for tenant")
        updated = replace(
            group,
            roles=tuple(r for r in group.roles if r != role),
            updated_at=datetime.now(tz=timezone.utc),
        )
        return self._repo.update(updated)


__all__ = ["GroupService"]
