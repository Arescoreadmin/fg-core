"""api/identity_administration/routes/self_service.py — Self-service identity endpoints.

All endpoints are authenticated (assessment.read = all authenticated roles).
Subject ownership check: actor.subject must equal the path subject for mutations.
"""

from __future__ import annotations


from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict

from api.actor_context import ActorContext
from api.auth_dispatch import require_permission
from api.identity_administration.self_service import SelfServiceError
from api.identity_administration.services import get_admin_services

router = APIRouter(prefix="/me")


class ProfileResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    record_id: str
    tenant_id: str
    subject: str
    email: str
    display_name: str
    lifecycle_state: str
    created_at: str
    updated_at: str


class UpdateProfileRequest(BaseModel):
    model_config = ConfigDict(frozen=True)

    display_name: str


class DeviceResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    device_id: str
    subject: str
    trust_state: str
    risk_score: float
    registered_at: str
    updated_at: str


class TimelineEventResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    event_id: str
    event_type: str
    subject: str
    actor: str
    occurred_at: str
    details: dict[str, str]


def _require_tenant(actor: ActorContext) -> str:
    if actor.tenant_id is None:
        raise HTTPException(status_code=403, detail="No tenant bound to actor")
    return actor.tenant_id


@router.get("")
def get_own_profile(
    actor: ActorContext = Depends(require_permission("assessment.read")),
) -> ProfileResponse:
    """Return own identity profile."""
    tenant_id = _require_tenant(actor)
    svc = get_admin_services()
    record = svc.self_service.get_profile(tenant_id, actor.subject)
    if record is None:
        raise HTTPException(status_code=404, detail="Identity profile not found")
    return ProfileResponse(
        record_id=record.record_id,
        tenant_id=record.tenant_id,
        subject=record.subject,
        email=record.email,
        display_name=record.display_name,
        lifecycle_state=record.lifecycle_state.value,
        created_at=record.created_at.isoformat(),
        updated_at=record.updated_at.isoformat(),
    )


@router.patch("")
def update_own_profile(
    body: UpdateProfileRequest,
    actor: ActorContext = Depends(require_permission("assessment.read")),
) -> ProfileResponse:
    """Update own display name."""
    tenant_id = _require_tenant(actor)
    svc = get_admin_services()
    try:
        record = svc.self_service.update_profile(
            tenant_id=tenant_id,
            subject=actor.subject,
            display_name=body.display_name,
            actor=actor.subject,
        )
    except SelfServiceError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return ProfileResponse(
        record_id=record.record_id,
        tenant_id=record.tenant_id,
        subject=record.subject,
        email=record.email,
        display_name=record.display_name,
        lifecycle_state=record.lifecycle_state.value,
        created_at=record.created_at.isoformat(),
        updated_at=record.updated_at.isoformat(),
    )


@router.get("/devices")
def get_own_devices(
    actor: ActorContext = Depends(require_permission("assessment.read")),
) -> list[DeviceResponse]:
    """Return own registered devices."""
    tenant_id = _require_tenant(actor)
    svc = get_admin_services()
    devices = svc.self_service.get_own_devices(tenant_id, actor.subject)
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


@router.delete("/devices/{device_id}", status_code=204)
def revoke_own_device(
    device_id: str,
    actor: ActorContext = Depends(require_permission("assessment.read")),
) -> None:
    """Revoke own device."""
    tenant_id = _require_tenant(actor)
    svc = get_admin_services()
    try:
        svc.self_service.revoke_own_device(
            tenant_id=tenant_id,
            subject=actor.subject,
            device_id=device_id,
        )
    except SelfServiceError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/timeline")
def get_own_timeline(
    limit: int = Query(default=50, ge=1, le=500),
    actor: ActorContext = Depends(require_permission("assessment.read")),
) -> list[TimelineEventResponse]:
    """Return own timeline events."""
    tenant_id = _require_tenant(actor)
    svc = get_admin_services()
    events = svc.self_service.get_own_timeline(tenant_id, actor.subject, limit=limit)
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
