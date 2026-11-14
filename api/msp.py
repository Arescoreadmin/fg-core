"""api/msp.py — MSP-001 MSP service relationship routes.

Route table (all fail-closed; authority from api/msp_authority.py):

    PUT  /admin/msp/organizations/{tenant_id}             platform: internal gateway + platform.admin
    GET  /admin/msp/relationships                         tenant_admin of the caller's tenant (either party)
    POST /admin/msp/relationships                         MSP tenant_admin (+ msp.multi_tenant entitlement)
    POST /admin/msp/relationships/{id}/approve            customer tenant_admin, not an MSP member
    POST /admin/msp/relationships/{id}/suspend            customer tenant_admin
    POST /admin/msp/relationships/{id}/resume             customer tenant_admin
    POST /admin/msp/relationships/{id}/revoke             customer or MSP tenant_admin
    GET  /admin/msp/customers                             MSP member (+ msp.multi_tenant)
    POST /admin/msp/customers/{customer_tenant_id}/context MSP member (+ msp.multi_tenant)

The caller's tenant always comes from the bound credential
(``resolve_authoritative_tenant``); no route accepts a tenant header or body
field as the caller's identity. MSP-001 exposes no customer data through MSP
authority: the context route only reports and audits what the actor may do.

Non-goals: no second RBAC, tenant registry or audit ledger; no MSP write
access to customer data; no billing. See docs/msp/MSP_001_ARCHITECTURE.md.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from api.actor_context import ActorContext
from api.admin import require_internal_admin_gateway
from api.auth_dispatch import get_actor_context, require_permission
from api.auth_scopes import require_scopes, resolve_authoritative_tenant
from api.db import set_tenant_context
from api.db_models_msp import MspOrganization, MspServiceRelationship
from api.deps import auth_ctx_db_session
from api.entitlements import require_capability
from api.msp_authority import (
    MAX_RELATIONSHIP_DAYS,
    MSP_APPROVAL_REQUIRES_CUSTOMER,
    MSP_APPROVAL_WINDOW_INVALID,
    MSP_CAPABILITY_NOT_DELEGABLE,
    MSP_CUSTOMER_NOT_FOUND,
    MSP_ORGANIZATION_INACTIVE,
    MSP_RELATIONSHIP_EXISTS,
    MSP_RELATIONSHIP_INVALID_TRANSITION,
    MSP_RELATIONSHIP_NOT_FOUND,
    MSP_SELF_APPROVAL_DENIED,
    MSP_TENANT_NOT_ELIGIBLE,
    MSP_ACCESS_DENIED,
    as_utc,
    canonical_capabilities,
    correlation_id,
    decode_capabilities,
    emit_msp_audit,
    encode_capabilities,
    list_actor_customers,
    load_open_relationship,
    load_relationship,
    msp_error,
    msp_organization_active,
    principal_is_member_of,
    relationship_view,
    resolve_actor_access,
    resolve_msp_membership,
    tenant_kind_and_name,
    utcnow,
)
from api.tenant_admin_authority import (
    TenantAdminAuthority,
    check_tenant_admin_authority,
)

router = APIRouter(prefix="/admin/msp", tags=["msp-001"])

_CLOCK_SKEW = timedelta(seconds=60)


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class OrganizationStatusBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["active", "suspended"]


class ProposeRelationshipBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    customer_tenant_id: str = Field(..., min_length=1, max_length=128)
    requested_capabilities: list[str] = Field(..., min_length=1, max_length=32)


class ApproveRelationshipBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    authorized_capabilities: list[str] = Field(..., min_length=1, max_length=32)
    effective_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _caller_tenant(request: Request, actor_ctx: ActorContext) -> str:
    """The caller's own tenant, from the bound credential only."""
    tenant = str(actor_ctx.tenant_id or "").strip()
    if not tenant:
        raise msp_error(403, MSP_ACCESS_DENIED)
    return resolve_authoritative_tenant(request, actor_ctx, tenant)


def _party_relationship(db: Session, relationship_id: str, caller: str) -> Any:
    """Load a relationship only for one of its two parties; otherwise 404."""
    row = load_relationship(db, relationship_id)
    if row is None or caller not in (str(row.tenant_id), str(row.msp_tenant_id)):
        raise msp_error(404, MSP_RELATIONSHIP_NOT_FOUND)
    return row


def _transition(
    db: Session, row: Any, *, expected: tuple[str, ...], values: dict[Any, Any]
) -> None:
    """Compare-and-set on (id, status, version). A concurrent change loses."""
    if str(row.status) not in expected:
        raise msp_error(409, MSP_RELATIONSHIP_INVALID_TRANSITION)
    values = {**values, "version": int(row.version) + 1, "updated_at": utcnow()}
    changed = (
        db.query(MspServiceRelationship)
        .filter(
            MspServiceRelationship.id == row.id,
            MspServiceRelationship.status == row.status,
            MspServiceRelationship.version == row.version,
        )
        .update(values, synchronize_session=False)
    )
    if changed != 1:
        db.rollback()
        raise msp_error(409, MSP_RELATIONSHIP_INVALID_TRANSITION)
    db.flush()
    db.expire_all()


def _audit_relationship(
    db: Session,
    request: Request,
    *,
    caller: str,
    row: Any,
    event_type: str,
    reason_code: str,
    actor_subject: str,
    membership_id: Optional[str],
    operation: str,
) -> None:
    emit_msp_audit(
        db,
        chains=(str(row.tenant_id), str(row.msp_tenant_id)),
        restore_tenant=caller,
        event_type=event_type,
        actor_subject=actor_subject,
        membership_id=membership_id,
        reason_code=reason_code,
        msp_tenant_id=str(row.msp_tenant_id),
        customer_tenant_id=str(row.tenant_id),
        relationship_id=str(row.id),
        operation=operation,
        capabilities=decode_capabilities(row.authorized_capabilities)
        or decode_capabilities(row.requested_capabilities),
        correlation=correlation_id(request),
    )


def _customer_admin(
    db: Session, request: Request, actor_ctx: ActorContext, row: Any, caller: str
) -> TenantAdminAuthority:
    """The caller must be the customer party's canonical tenant_admin."""
    if caller != str(row.tenant_id):
        raise msp_error(403, MSP_APPROVAL_REQUIRES_CUSTOMER)
    return check_tenant_admin_authority(db, actor_ctx=actor_ctx, tenant_id=caller)


# ---------------------------------------------------------------------------
# Platform: MSP organization designation
# ---------------------------------------------------------------------------


@router.put(
    "/organizations/{tenant_id}",
    dependencies=[
        Depends(require_internal_admin_gateway),
        Depends(require_scopes("admin:write")),
    ],
)
def set_msp_organization_status(
    tenant_id: str,
    body: OrganizationStatusBody,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("platform.admin")),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """Designate (``active``) or suspend an existing customer tenant as an MSP.

    Platform-only and idempotent. Suspension is the platform kill switch: it
    denies every relationship of that MSP on the next check. It never grants
    access to any customer and never approves a relationship.
    """
    info = tenant_kind_and_name(db, tenant_id)
    if info is None or info[0] != "customer":
        raise msp_error(404, MSP_TENANT_NOT_ELIGIBLE)
    set_tenant_context(db, tenant_id)
    now = utcnow()
    subject = actor_ctx.subject or "platform"
    row = db.get(MspOrganization, tenant_id)
    if row is not None and str(row.status) == body.status:
        return {"tenant_id": tenant_id, "status": body.status, "changed": False}
    if row is None:
        db.add(
            MspOrganization(
                tenant_id=tenant_id,
                status=body.status,
                designated_by_subject=subject,
                designated_at=now,
                status_changed_by_subject=subject,
                status_changed_at=now,
            )
        )
    else:
        row.status = body.status
        row.status_changed_by_subject = subject
        row.status_changed_at = now
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise msp_error(409, MSP_RELATIONSHIP_INVALID_TRANSITION)
    emit_msp_audit(
        db,
        chains=(tenant_id,),
        restore_tenant=tenant_id,
        event_type=(
            "tenant.msp.organization_designated"
            if body.status == "active"
            else "tenant.msp.organization_suspended"
        ),
        actor_subject=subject,
        membership_id=None,
        reason_code=(
            "MSP_ORGANIZATION_DESIGNATED"
            if body.status == "active"
            else "MSP_ORGANIZATION_SUSPENDED"
        ),
        msp_tenant_id=tenant_id,
        customer_tenant_id="",
        relationship_id=None,
        operation=f"organization.{body.status}",
        correlation=correlation_id(request),
    )
    db.commit()
    return {"tenant_id": tenant_id, "status": body.status, "changed": True}


# ---------------------------------------------------------------------------
# Relationship lifecycle
# ---------------------------------------------------------------------------


@router.get(
    "/relationships",
    dependencies=[Depends(require_scopes("admin:read"))],
)
def list_relationships(
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("tenant.configure")),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """Relationships in which the caller's tenant is a party (MSP or customer).

    Customers see every MSP that has asked for or holds access to them.
    """
    caller = _caller_tenant(request, actor_ctx)
    check_tenant_admin_authority(db, actor_ctx=actor_ctx, tenant_id=caller)
    rows = (
        db.query(MspServiceRelationship)
        .filter(
            (MspServiceRelationship.tenant_id == caller)
            | (MspServiceRelationship.msp_tenant_id == caller)
        )
        .order_by(MspServiceRelationship.created_at.desc())
        .all()
    )
    now = utcnow()
    items = [
        {
            **relationship_view(r, now=now),
            "party": "customer" if str(r.tenant_id) == caller else "msp",
        }
        for r in rows
    ]
    return {"tenant_id": caller, "items": items, "total": len(items)}


@router.post(
    "/relationships",
    dependencies=[
        Depends(require_scopes("admin:write")),
        Depends(require_capability("msp.multi_tenant")),
    ],
)
def propose_relationship(
    body: ProposeRelationshipBody,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("tenant.configure")),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """An MSP tenant_admin asks a customer for delegated access.

    Grants nothing. Idempotent: re-proposing the same capabilities while the
    proposal is pending returns it with ``created: false``; any other open
    relationship for the pair is a 409.
    """
    caller = _caller_tenant(request, actor_ctx)
    authority = check_tenant_admin_authority(db, actor_ctx=actor_ctx, tenant_id=caller)
    if not msp_organization_active(db, caller):
        raise msp_error(403, MSP_ORGANIZATION_INACTIVE)
    caps = canonical_capabilities(body.requested_capabilities)
    customer = body.customer_tenant_id.strip()
    info = tenant_kind_and_name(db, customer) if customer != caller else None
    if info is None or info[0] != "customer":
        raise msp_error(404, MSP_CUSTOMER_NOT_FOUND)

    def _existing_response(existing: Any) -> dict[str, Any]:
        if str(existing.status) == "proposed" and decode_capabilities(
            existing.requested_capabilities
        ) == frozenset(caps):
            return {**relationship_view(existing), "created": False}
        raise msp_error(409, MSP_RELATIONSHIP_EXISTS)

    existing = load_open_relationship(db, msp_tenant_id=caller, customer_id=customer)
    if existing is not None:
        return _existing_response(existing)

    now = utcnow()
    row = MspServiceRelationship(
        id=str(uuid.uuid4()),
        msp_tenant_id=caller,
        tenant_id=customer,
        status="proposed",
        requested_capabilities=encode_capabilities(caps),
        proposed_by_subject=authority.subject,
        proposed_at=now,
        version=1,
        created_at=now,
        updated_at=now,
    )
    db.add(row)
    try:
        db.flush()
    except IntegrityError:
        # A concurrent proposal for the same pair won the unique index.
        db.rollback()
        set_tenant_context(db, caller)
        existing = load_open_relationship(
            db, msp_tenant_id=caller, customer_id=customer
        )
        if existing is None:
            raise msp_error(409, MSP_RELATIONSHIP_EXISTS)
        return _existing_response(existing)
    _audit_relationship(
        db,
        request,
        caller=caller,
        row=row,
        event_type="tenant.msp.relationship_proposed",
        reason_code="MSP_RELATIONSHIP_PROPOSED",
        actor_subject=authority.subject,
        membership_id=authority.membership_id,
        operation="relationship.propose",
    )
    db.commit()
    return {**relationship_view(row), "created": True}


@router.post(
    "/relationships/{relationship_id}/approve",
    dependencies=[Depends(require_scopes("admin:write"))],
)
def approve_relationship(
    relationship_id: str,
    body: ApproveRelationshipBody,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("tenant.configure")),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """The customer's own tenant_admin approves a bounded, expiring delegation.

    The approver may narrow but never widen the requested capabilities, and
    may not hold any active membership in the MSP organization.
    """
    caller = _caller_tenant(request, actor_ctx)
    row = _party_relationship(db, relationship_id, caller)
    authority = _customer_admin(db, request, actor_ctx, row, caller)
    if authority.subject == str(row.proposed_by_subject) or principal_is_member_of(
        db, principal_id=authority.principal_id, tenant_id=str(row.msp_tenant_id)
    ):
        set_tenant_context(db, caller)
        raise msp_error(403, MSP_SELF_APPROVAL_DENIED)
    set_tenant_context(db, caller)

    caps = canonical_capabilities(body.authorized_capabilities)
    if not frozenset(caps) <= decode_capabilities(row.requested_capabilities):
        raise msp_error(422, MSP_CAPABILITY_NOT_DELEGABLE)

    now = utcnow()
    effective_at = as_utc(body.effective_at) or now
    expires_at = as_utc(body.expires_at) or effective_at + timedelta(
        days=MAX_RELATIONSHIP_DAYS
    )
    if (
        effective_at < now - _CLOCK_SKEW
        or expires_at <= effective_at
        or expires_at > effective_at + timedelta(days=MAX_RELATIONSHIP_DAYS)
    ):
        raise msp_error(422, MSP_APPROVAL_WINDOW_INVALID)

    _transition(
        db,
        row,
        expected=("proposed",),
        values={
            "status": "approved",
            "authorized_capabilities": encode_capabilities(caps),
            "approved_by_subject": authority.subject,
            "approved_by_membership_id": authority.membership_id,
            "approved_at": now,
            "effective_at": effective_at,
            "expires_at": expires_at,
        },
    )
    row = load_relationship(db, relationship_id)
    _audit_relationship(
        db,
        request,
        caller=caller,
        row=row,
        event_type="tenant.msp.relationship_approved",
        reason_code="MSP_RELATIONSHIP_APPROVED",
        actor_subject=authority.subject,
        membership_id=authority.membership_id,
        operation="relationship.approve",
    )
    db.commit()
    return relationship_view(row)


def _customer_status_change(
    *,
    relationship_id: str,
    request: Request,
    actor_ctx: ActorContext,
    db: Session,
    expected: tuple[str, ...],
    values: dict[str, Any],
    event_type: str,
    reason_code: str,
    operation: str,
) -> dict[str, Any]:
    caller = _caller_tenant(request, actor_ctx)
    row = _party_relationship(db, relationship_id, caller)
    authority = _customer_admin(db, request, actor_ctx, row, caller)
    _transition(db, row, expected=expected, values=values)
    row = load_relationship(db, relationship_id)
    _audit_relationship(
        db,
        request,
        caller=caller,
        row=row,
        event_type=event_type,
        reason_code=reason_code,
        actor_subject=authority.subject,
        membership_id=authority.membership_id,
        operation=operation,
    )
    db.commit()
    return relationship_view(row)


@router.post(
    "/relationships/{relationship_id}/suspend",
    dependencies=[Depends(require_scopes("admin:write"))],
)
def suspend_relationship(
    relationship_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("tenant.configure")),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """The customer pauses MSP access. Effective on the next check."""
    return _customer_status_change(
        relationship_id=relationship_id,
        request=request,
        actor_ctx=actor_ctx,
        db=db,
        expected=("approved",),
        values={"status": "suspended", "suspended_at": utcnow()},
        event_type="tenant.msp.relationship_suspended",
        reason_code="MSP_RELATIONSHIP_SUSPENDED",
        operation="relationship.suspend",
    )


@router.post(
    "/relationships/{relationship_id}/resume",
    dependencies=[Depends(require_scopes("admin:write"))],
)
def resume_relationship(
    relationship_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("tenant.configure")),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """The customer resumes a suspended relationship. The original approval
    window still applies; an expired approval stays expired."""
    return _customer_status_change(
        relationship_id=relationship_id,
        request=request,
        actor_ctx=actor_ctx,
        db=db,
        expected=("suspended",),
        values={"status": "approved", "suspended_at": None},
        event_type="tenant.msp.relationship_resumed",
        reason_code="MSP_RELATIONSHIP_RESUMED",
        operation="relationship.resume",
    )


@router.post(
    "/relationships/{relationship_id}/revoke",
    dependencies=[Depends(require_scopes("admin:write"))],
)
def revoke_relationship(
    relationship_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("tenant.configure")),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """Either party's tenant_admin ends the relationship permanently.

    Customer data, evidence and audit history are untouched. Idempotent: an
    already revoked relationship returns ``changed: false``.
    """
    caller = _caller_tenant(request, actor_ctx)
    row = _party_relationship(db, relationship_id, caller)
    authority = check_tenant_admin_authority(db, actor_ctx=actor_ctx, tenant_id=caller)
    if str(row.status) == "revoked":
        return {**relationship_view(row), "changed": False}
    party = "customer" if caller == str(row.tenant_id) else "msp"
    _transition(
        db,
        row,
        expected=("proposed", "approved", "suspended"),
        values={
            "status": "revoked",
            "revoked_at": utcnow(),
            "revoked_by_subject": authority.subject,
            "revoked_by_party": party,
        },
    )
    row = load_relationship(db, relationship_id)
    _audit_relationship(
        db,
        request,
        caller=caller,
        row=row,
        event_type="tenant.msp.relationship_revoked",
        reason_code="MSP_RELATIONSHIP_REVOKED",
        actor_subject=authority.subject,
        membership_id=authority.membership_id,
        operation=f"relationship.revoke.{party}",
    )
    db.commit()
    return {**relationship_view(row), "changed": True}


# ---------------------------------------------------------------------------
# Multi-client operating context (MSP staff)
# ---------------------------------------------------------------------------


@router.get(
    "/customers",
    dependencies=[
        Depends(require_scopes("admin:read")),
        Depends(require_capability("msp.multi_tenant")),
    ],
)
def list_authorized_customers(
    request: Request,
    actor_ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """Customers this MSP member can act for right now, with the permissions
    they can use for each. Nothing else is listed."""
    caller = _caller_tenant(request, actor_ctx)
    membership = resolve_msp_membership(db, actor_ctx=actor_ctx, msp_tenant_id=caller)
    items = []
    for row, effective in list_actor_customers(db, membership=membership):
        info = tenant_kind_and_name(db, str(row.tenant_id))
        if info is None:
            continue
        expires_at = as_utc(row.expires_at)
        items.append(
            {
                "customer_tenant_id": str(row.tenant_id),
                "display_name": info[1],
                "relationship_id": str(row.id),
                "effective_permissions": sorted(effective),
                "expires_at": expires_at.isoformat() if expires_at else None,
            }
        )
    return {"msp_tenant_id": caller, "items": items, "total": len(items)}


@router.post(
    "/customers/{customer_tenant_id}/context",
    dependencies=[
        Depends(require_scopes("admin:read")),
        Depends(require_capability("msp.multi_tenant")),
    ],
)
def resolve_customer_context(
    customer_tenant_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """Select a customer: validate and audit, grant nothing.

    The response is informational. It is not a token; every protected request
    re-runs the same check, so suspension, revocation, expiry and membership
    removal apply to the very next request.
    """
    caller = _caller_tenant(request, actor_ctx)
    membership, access = resolve_actor_access(
        db,
        actor_ctx=actor_ctx,
        msp_tenant_id=caller,
        customer_tenant_id=customer_tenant_id,
    )
    emit_msp_audit(
        db,
        chains=(access.customer_tenant_id, caller),
        restore_tenant=caller,
        event_type="tenant.msp.context_resolved",
        actor_subject=membership.subject,
        membership_id=membership.membership_id,
        reason_code="MSP_CONTEXT_RESOLVED",
        msp_tenant_id=caller,
        customer_tenant_id=access.customer_tenant_id,
        relationship_id=access.relationship_id,
        operation="context.resolve",
        capabilities=access.effective_permissions,
        correlation=correlation_id(request),
    )
    db.commit()
    return {
        "msp_tenant_id": caller,
        "customer_tenant_id": access.customer_tenant_id,
        "relationship_id": access.relationship_id,
        "effective_permissions": sorted(access.effective_permissions),
        "valid_until": access.expires_at.isoformat() if access.expires_at else None,
        "revalidation": "every_request",
    }
