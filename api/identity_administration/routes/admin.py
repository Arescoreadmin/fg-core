"""api/identity_administration/routes/admin.py — Admin identity management endpoints.

All mutation endpoints require tenant.configure or user.invite.
All read endpoints require governance.read.
Tenant isolation: actor.tenant_id must be non-None and match resource tenant.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict

from api.actor_context import ActorContext
from api.auth_dispatch import require_permission
from api.identity_administration.services import get_admin_services
from api.identity_governance.models import IdentityLifecycleState as LifecycleState

router = APIRouter(prefix="/identity/admin")


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------


class InviteUserRequest(BaseModel):
    model_config = ConfigDict(frozen=True)

    email: str
    display_name: str = ""
    custom_message: str = ""
    assigned_roles: list[str] = []
    assigned_capabilities: list[str] = []
    expiry_days: int = 7


class InviteUserResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    subject: str
    email: str
    lifecycle_state: str
    invitation_id: str
    invitation_token: str
    invited_at: str


class IdentityRecordResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    record_id: str
    tenant_id: str
    subject: str
    email: str
    display_name: str
    lifecycle_state: str
    created_at: str
    updated_at: str
    invited_by: Optional[str] = None
    invitation_id: Optional[str] = None


class IdentityListResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    items: list[IdentityRecordResponse]
    total: int
    limit: int
    offset: int


class LifecycleTransitionRequest(BaseModel):
    model_config = ConfigDict(frozen=True)

    target_state: str
    reason: str


class InvitationResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    invitation_id: str
    tenant_id: str
    email: str
    invited_by: str
    invited_at: str
    expires_at: str
    status: str
    custom_message: str
    assigned_roles: list[str]


class TimelineEventResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    event_id: str
    event_type: str
    subject: str
    actor: str
    occurred_at: str
    details: dict[str, str]


class DeviceResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    device_id: str
    subject: str
    trust_state: str
    risk_score: float
    registered_at: str
    updated_at: str


class DeviceActionRequest(BaseModel):
    model_config = ConfigDict(frozen=True)

    action: str  # "trust" | "revoke"
    reason: str = ""


class AuditRecordResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    audit_id: str
    tenant_id: str
    action: str
    actor: str
    subject: str
    occurred_at: str
    reason: str
    previous_state: str
    new_state: str
    correlation_id: Optional[str] = None
    object_id: Optional[str] = None
    object_type: Optional[str] = None


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


class CreateGroupRequest(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    description: str = ""
    roles: list[str] = []
    capabilities: list[str] = []


class GroupMemberResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    group_id: str
    tenant_id: str
    subject: str
    added_by: str
    added_at: str


class AddMemberRequest(BaseModel):
    model_config = ConfigDict(frozen=True)

    subject: str


class ReissueInvitationRequest(BaseModel):
    model_config = ConfigDict(frozen=True)

    expiry_days: int = 7


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _require_tenant(actor: ActorContext) -> str:
    if actor.tenant_id is None:
        raise HTTPException(status_code=403, detail="No tenant bound to actor")
    return actor.tenant_id


# ---------------------------------------------------------------------------
# User administration endpoints
# ---------------------------------------------------------------------------


@router.post("/users/invite", status_code=201)
def invite_user(
    body: InviteUserRequest,
    actor: ActorContext = Depends(require_permission("user.invite")),
) -> InviteUserResponse:
    tenant_id = _require_tenant(actor)
    svc = get_admin_services()
    identity, invitation, raw_token = svc.administration_service.invite_user(
        tenant_id=tenant_id,
        email=body.email,
        actor=actor.subject,
        display_name=body.display_name,
        custom_message=body.custom_message,
        assigned_roles=tuple(body.assigned_roles),
        assigned_capabilities=tuple(body.assigned_capabilities),
        expiry_days=body.expiry_days,
    )
    return InviteUserResponse(
        subject=identity.subject,
        email=identity.email,
        lifecycle_state=identity.lifecycle_state.value,
        invitation_id=invitation.invitation_id,
        invitation_token=raw_token,
        invited_at=invitation.invited_at.isoformat(),
    )


@router.get("/users", response_model=IdentityListResponse)
def list_users(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    actor: ActorContext = Depends(require_permission("governance.read")),
) -> IdentityListResponse:
    tenant_id = _require_tenant(actor)
    svc = get_admin_services()
    records, total = svc.administration_service.list_identities(
        tenant_id, limit=limit, offset=offset
    )
    return IdentityListResponse(
        items=[
            IdentityRecordResponse(
                record_id=r.record_id,
                tenant_id=r.tenant_id,
                subject=r.subject,
                email=r.email,
                display_name=r.display_name,
                lifecycle_state=r.lifecycle_state.value,
                created_at=r.created_at.isoformat(),
                updated_at=r.updated_at.isoformat(),
                invited_by=r.invited_by,
                invitation_id=r.invitation_id,
            )
            for r in records
        ],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/users/{subject}", response_model=IdentityRecordResponse)
def get_user(
    subject: str,
    actor: ActorContext = Depends(require_permission("governance.read")),
) -> IdentityRecordResponse:
    tenant_id = _require_tenant(actor)
    svc = get_admin_services()
    record = svc.administration_service.get_identity(tenant_id, subject)
    if record is None:
        raise HTTPException(status_code=404, detail="Identity not found")
    return IdentityRecordResponse(
        record_id=record.record_id,
        tenant_id=record.tenant_id,
        subject=record.subject,
        email=record.email,
        display_name=record.display_name,
        lifecycle_state=record.lifecycle_state.value,
        created_at=record.created_at.isoformat(),
        updated_at=record.updated_at.isoformat(),
        invited_by=record.invited_by,
        invitation_id=record.invitation_id,
    )


@router.patch("/users/{subject}/lifecycle", response_model=IdentityRecordResponse)
def transition_lifecycle(
    subject: str,
    body: LifecycleTransitionRequest,
    actor: ActorContext = Depends(require_permission("tenant.configure")),
) -> IdentityRecordResponse:
    tenant_id = _require_tenant(actor)
    svc = get_admin_services()
    try:
        target_state = LifecycleState(body.target_state)
    except ValueError:
        raise HTTPException(
            status_code=422, detail=f"Unknown lifecycle state: {body.target_state!r}"
        )
    try:
        record = svc.administration_service.transition_lifecycle(
            tenant_id=tenant_id,
            subject=subject,
            target_state=target_state,
            actor=actor.subject,
            reason=body.reason,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return IdentityRecordResponse(
        record_id=record.record_id,
        tenant_id=record.tenant_id,
        subject=record.subject,
        email=record.email,
        display_name=record.display_name,
        lifecycle_state=record.lifecycle_state.value,
        created_at=record.created_at.isoformat(),
        updated_at=record.updated_at.isoformat(),
        invited_by=record.invited_by,
        invitation_id=record.invitation_id,
    )


@router.delete("/users/{subject}", status_code=204)
def delete_user(
    subject: str,
    actor: ActorContext = Depends(require_permission("tenant.configure")),
) -> None:
    tenant_id = _require_tenant(actor)
    svc = get_admin_services()
    try:
        svc.administration_service.delete_identity(
            tenant_id=tenant_id,
            subject=subject,
            actor=actor.subject,
            reason="admin soft-delete",
        )
    except ValueError as exc:
        status = 404 if "not found" in str(exc).lower() else 400
        raise HTTPException(status_code=status, detail=str(exc))


@router.get("/users/{subject}/timeline")
def get_user_timeline(
    subject: str,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    actor: ActorContext = Depends(require_permission("governance.read")),
) -> list[TimelineEventResponse]:
    tenant_id = _require_tenant(actor)
    gov = get_admin_services().administration_service._gov()
    events = gov.timeline.query(tenant_id=tenant_id, subject=subject, limit=limit)
    return [
        TimelineEventResponse(
            event_id=e.event_id,
            event_type=e.event_type.value,
            subject=e.subject,
            actor=e.actor,
            occurred_at=e.occurred_at.isoformat(),
            details=dict(e.details),
        )
        for e in events
    ]


@router.get("/users/{subject}/devices")
def get_user_devices(
    subject: str,
    actor: ActorContext = Depends(require_permission("governance.read")),
) -> list[DeviceResponse]:
    tenant_id = _require_tenant(actor)
    gov = get_admin_services().administration_service._gov()
    devices = gov.device_registry.list_devices_for_subject(
        subject=subject, tenant_id=tenant_id
    )
    return [
        DeviceResponse(
            device_id=d.device_id,
            subject=d.subject,
            trust_state=d.trust_state.value,
            risk_score=d.risk_score,
            registered_at=d.registered_at.isoformat(),
            updated_at=d.updated_at.isoformat(),
        )
        for d in devices
    ]


@router.patch("/users/{subject}/devices/{device_id}", response_model=DeviceResponse)
def update_device_trust(
    subject: str,
    device_id: str,
    body: DeviceActionRequest,
    actor: ActorContext = Depends(require_permission("tenant.configure")),
) -> DeviceResponse:
    tenant_id = _require_tenant(actor)
    svc = get_admin_services()
    gov = svc.administration_service._gov()

    # Verify device exists and belongs to subject before mutating.
    pre_device = gov.device_registry.get_device(device_id, tenant_id)
    if pre_device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    if pre_device.subject != subject:
        raise HTTPException(
            status_code=403, detail="Device does not belong to this user"
        )

    if body.action == "revoke":
        svc.administration_service.revoke_device(
            tenant_id=tenant_id,
            subject=subject,
            device_id=device_id,
            actor=actor.subject,
            reason=body.reason or "admin revocation",
        )
    elif body.action == "trust":
        svc.administration_service.trust_device(
            tenant_id=tenant_id,
            subject=subject,
            device_id=device_id,
            actor=actor.subject,
        )
    else:
        raise HTTPException(
            status_code=422, detail=f"Unknown device action: {body.action!r}"
        )
    device = gov.device_registry.get_device(device_id, tenant_id)
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    return DeviceResponse(
        device_id=device.device_id,
        subject=device.subject,
        trust_state=device.trust_state.value,
        risk_score=device.risk_score,
        registered_at=device.registered_at.isoformat(),
        updated_at=device.updated_at.isoformat(),
    )


# ---------------------------------------------------------------------------
# Invitation management
# ---------------------------------------------------------------------------


@router.get("/invitations")
def list_invitations(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    actor: ActorContext = Depends(require_permission("governance.read")),
) -> list[InvitationResponse]:
    tenant_id = _require_tenant(actor)
    svc = get_admin_services()
    invitations = svc.invitation_repo.list_for_tenant(
        tenant_id, limit=limit, offset=offset
    )
    return [
        InvitationResponse(
            invitation_id=inv.invitation_id,
            tenant_id=inv.tenant_id,
            email=inv.email,
            invited_by=inv.invited_by,
            invited_at=inv.invited_at.isoformat(),
            expires_at=inv.expires_at.isoformat(),
            status=inv.status.value,
            custom_message=inv.custom_message,
            assigned_roles=list(inv.assigned_roles),
        )
        for inv in invitations
    ]


@router.delete("/invitations/{invitation_id}", status_code=204)
def revoke_invitation(
    invitation_id: str,
    actor: ActorContext = Depends(require_permission("tenant.configure")),
) -> None:
    tenant_id = _require_tenant(actor)
    svc = get_admin_services()
    try:
        svc.invitation_service.revoke_invitation(
            tenant_id=tenant_id,
            invitation_id=invitation_id,
            revoked_by=actor.subject,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/invitations/{invitation_id}/reissue", status_code=201)
def reissue_invitation(
    invitation_id: str,
    body: ReissueInvitationRequest,
    actor: ActorContext = Depends(require_permission("user.invite")),
) -> InviteUserResponse:
    tenant_id = _require_tenant(actor)
    svc = get_admin_services()
    try:
        new_invitation, raw_token = svc.invitation_service.reissue_invitation(
            tenant_id=tenant_id,
            invitation_id=invitation_id,
            reissued_by=actor.subject,
            expiry_days=body.expiry_days,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return InviteUserResponse(
        subject="",
        email=new_invitation.email,
        lifecycle_state="INVITED",
        invitation_id=new_invitation.invitation_id,
        invitation_token=raw_token,
        invited_at=new_invitation.invited_at.isoformat(),
    )


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


@router.get("/audit")
def list_audit(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    actor: ActorContext = Depends(require_permission("governance.read")),
) -> list[AuditRecordResponse]:
    tenant_id = _require_tenant(actor)
    svc = get_admin_services()
    records = svc.audit_repo.list_for_tenant(tenant_id, limit=limit, offset=offset)
    return [
        AuditRecordResponse(
            audit_id=r.audit_id,
            tenant_id=r.tenant_id,
            action=r.action.value,
            actor=r.actor,
            subject=r.subject,
            occurred_at=r.occurred_at.isoformat(),
            reason=r.reason,
            previous_state=r.previous_state,
            new_state=r.new_state,
            correlation_id=r.correlation_id,
            object_id=r.object_id,
            object_type=r.object_type,
        )
        for r in records
    ]


# ---------------------------------------------------------------------------
# Group administration (CRUD is here; read-only is in /identity/groups)
# ---------------------------------------------------------------------------


@router.get("/groups")
def list_admin_groups(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    actor: ActorContext = Depends(require_permission("governance.read")),
) -> list[GroupResponse]:
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


@router.post("/groups", status_code=201)
def create_group(
    body: CreateGroupRequest,
    actor: ActorContext = Depends(require_permission("tenant.configure")),
) -> GroupResponse:
    tenant_id = _require_tenant(actor)
    svc = get_admin_services()
    group = svc.group_service.create_group(
        tenant_id=tenant_id,
        name=body.name,
        description=body.description,
        actor=actor.subject,
        roles=tuple(body.roles),
        capabilities=tuple(body.capabilities),
    )
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


@router.get("/groups/{group_id}", response_model=GroupResponse)
def get_admin_group(
    group_id: str,
    actor: ActorContext = Depends(require_permission("governance.read")),
) -> GroupResponse:
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


@router.delete("/groups/{group_id}", status_code=204)
def delete_group(
    group_id: str,
    actor: ActorContext = Depends(require_permission("tenant.configure")),
) -> None:
    tenant_id = _require_tenant(actor)
    svc = get_admin_services()
    svc.group_service.delete_group(
        tenant_id=tenant_id,
        group_id=group_id,
        actor=actor.subject,
    )


@router.post("/groups/{group_id}/members", status_code=201)
def add_group_member(
    group_id: str,
    body: AddMemberRequest,
    actor: ActorContext = Depends(require_permission("tenant.configure")),
) -> GroupMemberResponse:
    tenant_id = _require_tenant(actor)
    svc = get_admin_services()
    member = svc.group_service.add_member(
        tenant_id=tenant_id,
        group_id=group_id,
        subject=body.subject,
        actor=actor.subject,
    )
    return GroupMemberResponse(
        group_id=member.group_id,
        tenant_id=member.tenant_id,
        subject=member.subject,
        added_by=member.added_by,
        added_at=member.added_at.isoformat(),
    )


@router.delete("/groups/{group_id}/members/{subject}", status_code=204)
def remove_group_member(
    group_id: str,
    subject: str,
    actor: ActorContext = Depends(require_permission("tenant.configure")),
) -> None:
    tenant_id = _require_tenant(actor)
    svc = get_admin_services()
    svc.group_service.remove_member(
        tenant_id=tenant_id,
        group_id=group_id,
        subject=subject,
        actor=actor.subject,
    )
