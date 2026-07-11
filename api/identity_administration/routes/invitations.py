"""api/identity_administration/routes/invitations.py — Public invitation acceptance.

This endpoint is public (no require_permission) — anyone with a valid token
can accept an invitation. The token is validated cryptographically.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict

from api.identity_administration.invitation import (
    InvitationAlreadyUsedError,
    InvitationError,
    InvitationExpiredError,
    InvitationRevokedError,
)
from api.identity_administration.services import get_admin_services

router = APIRouter(prefix="/identity/invitations")


class AcceptInvitationRequest(BaseModel):
    model_config = ConfigDict(frozen=True)

    token: str
    accepted_by: str  # subject of the user accepting


class AcceptInvitationResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    invitation_id: str
    tenant_id: str
    email: str
    status: str
    accepted_at: str
    accepted_by: str
    assigned_roles: list[str]
    assigned_capabilities: list[str]


@router.post("/accept")
def accept_invitation(body: AcceptInvitationRequest) -> AcceptInvitationResponse:
    """Accept an invitation using the raw token. Public endpoint — no auth required.

    Token is validated cryptographically (SHA-256 hash comparison).
    Replay protection: once accepted, the token cannot be reused.
    """
    svc = get_admin_services()
    try:
        invitation = svc.invitation_service.accept_invitation(
            body.token,
            accepted_by=body.accepted_by,
        )
    except InvitationAlreadyUsedError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except InvitationExpiredError as exc:
        raise HTTPException(status_code=410, detail=str(exc))
    except InvitationRevokedError as exc:
        raise HTTPException(status_code=410, detail=str(exc))
    except InvitationError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    # Transition the linked IdentityRecord to ACCEPTED (best-effort — the
    # invitation token is already persisted as accepted regardless).
    svc.administration_service.complete_invitation_acceptance(
        tenant_id=invitation.tenant_id,
        email=invitation.email,
        accepted_by=body.accepted_by,
    )

    return AcceptInvitationResponse(
        invitation_id=invitation.invitation_id,
        tenant_id=invitation.tenant_id,
        email=invitation.email,
        status=invitation.status.value,
        accepted_at=invitation.accepted_at.isoformat()
        if invitation.accepted_at
        else "",
        accepted_by=invitation.accepted_by or "",
        assigned_roles=list(invitation.assigned_roles),
        assigned_capabilities=list(invitation.assigned_capabilities),
    )
