"""api/identity_administration/routes/groups.py — Read-only group endpoints.

Admin group CRUD is on /identity/admin/groups/.
These endpoints provide read-only access for authenticated users.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict

from api.actor_context import ActorContext
from api.auth_dispatch import require_permission
from api.identity_administration.services import get_admin_services

router = APIRouter(prefix="/groups")


class GroupResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    group_id: str
    tenant_id: str
    name: str
    description: str
    created_by: str
    created_at: str
    updated_at: str
    roles: list[str]
    capabilities: list[str]


class GroupMemberResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    group_id: str
    tenant_id: str
    subject: str
    added_by: str
    added_at: str


def _require_tenant(actor: ActorContext) -> str:
    from fastapi import HTTPException

    if actor.tenant_id is None:
        raise HTTPException(status_code=403, detail="No tenant bound to actor")
    return actor.tenant_id


@router.get("")
def list_groups(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    actor: ActorContext = Depends(require_permission("governance.read")),
) -> list[GroupResponse]:
    """List groups for the actor's tenant."""
    tenant_id = _require_tenant(actor)
    svc = get_admin_services()
    groups, _ = svc.group_service.list_groups(tenant_id, limit=limit, offset=offset)
    return [
        GroupResponse(
            group_id=g.group_id,
            tenant_id=g.tenant_id,
            name=g.name,
            description=g.description,
            created_by=g.created_by,
            created_at=g.created_at.isoformat(),
            updated_at=g.updated_at.isoformat(),
            roles=list(g.roles),
            capabilities=list(g.capabilities),
        )
        for g in groups
    ]


@router.get("/{group_id}", response_model=GroupResponse)
def get_group(
    group_id: str,
    actor: ActorContext = Depends(require_permission("governance.read")),
) -> GroupResponse:
    """Return a single group."""
    tenant_id = _require_tenant(actor)
    svc = get_admin_services()
    group = svc.group_service.get_group(tenant_id, group_id)
    if group is None:
        raise HTTPException(status_code=404, detail="Group not found")
    return GroupResponse(
        group_id=group.group_id,
        tenant_id=group.tenant_id,
        name=group.name,
        description=group.description,
        created_by=group.created_by,
        created_at=group.created_at.isoformat(),
        updated_at=group.updated_at.isoformat(),
        roles=list(group.roles),
        capabilities=list(group.capabilities),
    )


@router.get("/{group_id}/members")
def list_group_members(
    group_id: str,
    actor: ActorContext = Depends(require_permission("governance.read")),
) -> list[GroupMemberResponse]:
    """List members of a group."""
    tenant_id = _require_tenant(actor)
    svc = get_admin_services()
    members = svc.group_service.list_members(tenant_id, group_id)
    return [
        GroupMemberResponse(
            group_id=m.group_id,
            tenant_id=m.tenant_id,
            subject=m.subject,
            added_by=m.added_by,
            added_at=m.added_at.isoformat(),
        )
        for m in members
    ]
