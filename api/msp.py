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

MSP-002 (read-only, same authority):

    GET  /admin/msp/portfolio                             MSP member (+ msp.multi_tenant)
    GET  /admin/msp/relationships/{id}/events             tenant_admin of either party (own chain)

The caller's tenant always comes from the bound credential
(``resolve_authoritative_tenant``); no route accepts a tenant header or body
field as the caller's identity. MSP-001 exposes no customer data through MSP
authority: the context route only reports and audits what the actor may do.

Non-goals: no second RBAC, tenant registry or audit ledger; no MSP write
access to customer data; no billing. See docs/msp/MSP_001_ARCHITECTURE.md
and docs/msp/MSP_002_ARCHITECTURE.md.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from api.actor_context import ActorContext
from api.admin import require_internal_admin_gateway
from api.auth_dispatch import get_actor_context, require_permission
from api.auth_scopes import require_scopes, resolve_authoritative_tenant
from api.db import set_tenant_context
from api.db_models_identity import TenantIdentityAuditEvent
from api.db_models_msp import MspOrganization, MspServiceRelationship
from api.deps import auth_ctx_db_session
from api.entitlements import (
    _ensure_admin_gateway_tenant_bound,
    require_capability,
)
from api.identity.store import verify_identity_audit_chain
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
from api.msp_portfolio import (
    PORTFOLIO_DEFAULT_PAGE,
    PORTFOLIO_MAX_PAGE,
    PortfolioEntry,
    build_portfolio_items,
)
from api.tenant_admin_authority import (
    TenantAdminAuthority,
    check_tenant_admin_authority,
)

router = APIRouter(prefix="/admin/msp", tags=["msp-001"])

_CLOCK_SKEW = timedelta(seconds=60)


def _bind_console_gateway_tenant(request: Request) -> None:
    """MSP-002 console transport: verify before the actor is resolved.

    For the admin-gateway credential (the console BFF), Core's delegation
    proof check, the tenant-human authority check and tenant lifecycle check
    all run inside ``bind_tenant_id``. Running it first means the actor is
    then built from the verified named human and its DB roles. For tenant-bound
    credentials it is a no-op. Reuses the entitlement module's binder so there
    is one implementation of this order.
    """
    _ensure_admin_gateway_tenant_bound(request)


_CONSOLE_BIND = Depends(_bind_console_gateway_tenant)


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


def _caller_tenant_from_auth(request: Request, actor_ctx: ActorContext) -> str:
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
    dependencies=[_CONSOLE_BIND, Depends(require_scopes("admin:read"))],
)
def list_relationships(
    request: Request,
    limit: int = Query(100, ge=1, le=200),
    offset: int = Query(0, ge=0),
    actor_ctx: ActorContext = Depends(require_permission("tenant.configure")),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """Relationships in which the caller's tenant is a party (MSP or customer).

    Customers see every MSP that has asked for or holds access to them, with
    the MSP's display name. An MSP sees a customer's display name only once
    that customer has approved (MSP-002): a proposal never reveals more about
    a tenant than the id the MSP already typed.
    """
    caller = _caller_tenant_from_auth(request, actor_ctx)
    check_tenant_admin_authority(db, actor_ctx=actor_ctx, tenant_id=caller)
    base = db.query(MspServiceRelationship).filter(
        (MspServiceRelationship.tenant_id == caller)
        | (MspServiceRelationship.msp_tenant_id == caller)
    )
    total = base.count()
    rows = (
        base.order_by(
            MspServiceRelationship.created_at.desc(), MspServiceRelationship.id
        )
        .offset(offset)
        .limit(limit)
        .all()
    )
    now = utcnow()
    names: dict[str, Optional[str]] = {}

    def _name(tenant_id: str) -> Optional[str]:
        if tenant_id not in names:
            info = tenant_kind_and_name(db, tenant_id)
            names[tenant_id] = info[1] if info else None
        return names[tenant_id]

    items = []
    for r in rows:
        party = "customer" if str(r.tenant_id) == caller else "msp"
        if party == "customer":
            counterparty: Optional[str] = _name(str(r.msp_tenant_id))
        else:
            counterparty = _name(str(r.tenant_id)) if r.approved_at else None
        items.append(
            {
                **relationship_view(r, now=now),
                "party": party,
                "counterparty_display_name": counterparty,
            }
        )
    end = offset + len(items)
    return {
        "tenant_id": caller,
        "items": items,
        "total": total,
        "limit": limit,
        "offset": offset,
        "next_offset": end if end < total else None,
    }


_CUSTOMER_OPERATIONS = frozenset(
    {
        "relationship.approve",
        "relationship.suspend",
        "relationship.resume",
        # MSP-003 assessment grants (api/msp_orchestration.py)
        "assessment_grant.approve",
        "assessment_grant.reject",
        "assessment_grant.revoke",
        # MSP-007 report sharing (api/msp_reporting.py)
        "report_share.approve",
        "report_share.reject",
        "report_share.revoke",
    }
)
_MSP_OPERATIONS = frozenset(
    {
        "relationship.propose",
        "context.resolve",
        "portfolio.summary",
        "assessment_grant.request",
        "assessment_grant.withdraw",
        "assessment.initiate",
        "report_share.request",
        "report_share.withdraw",
        "report.verify",
        "report.download",
    }
)
_HISTORY_DEFAULT_PAGE = 100
_HISTORY_MAX_PAGE = 200


def relationship_events_query(db: Session, chain_tenant: str, relationship_id: str):
    """MSP events for one relationship on one tenant's chain.

    The relationship predicate runs in the database, before any paging, so
    unrelated MSP activity on the chain can never push this relationship's
    events out of a page.
    """
    return db.query(TenantIdentityAuditEvent).filter(
        TenantIdentityAuditEvent.tenant_id == chain_tenant,
        TenantIdentityAuditEvent.event_type.like("tenant.msp.%"),
        TenantIdentityAuditEvent.details_json["relationship_id"].as_string()
        == relationship_id,
    )


def _actor_party(operation: str) -> str:
    if operation.startswith("relationship.revoke."):
        return operation.rsplit(".", 1)[1]
    if operation in _CUSTOMER_OPERATIONS:
        return "customer"
    if operation in _MSP_OPERATIONS:
        return "msp"
    return "platform"


@router.get(
    "/relationships/{relationship_id}/events",
    dependencies=[_CONSOLE_BIND, Depends(require_scopes("admin:read"))],
)
def list_relationship_events(
    relationship_id: str,
    request: Request,
    limit: int = Query(_HISTORY_DEFAULT_PAGE, ge=1, le=_HISTORY_MAX_PAGE),
    offset: int = Query(0, ge=0),
    actor_ctx: ActorContext = Depends(require_permission("tenant.configure")),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """This relationship's events from the caller's own audit chain.

    Read-only; it never reads the other party's chain. Each event names the
    party that acted. The acting subject is shown only when that party is the
    caller's own organization, so neither side learns the other's people.
    ``chain_verified`` is the result of verifying the caller's whole chain.
    """
    caller = _caller_tenant_from_auth(request, actor_ctx)
    check_tenant_admin_authority(db, actor_ctx=actor_ctx, tenant_id=caller)
    row = _party_relationship(db, relationship_id, caller)
    caller_party = "customer" if caller == str(row.tenant_id) else "msp"
    base = relationship_events_query(db, caller, relationship_id)
    total = base.count()
    events = (
        base.order_by(
            TenantIdentityAuditEvent.created_at.desc(),
            TenantIdentityAuditEvent.id.desc(),
        )
        .offset(offset)
        .limit(limit)
        .all()
    )
    items: list[dict[str, Any]] = []
    for ev in events:
        details = ev.details_json if isinstance(ev.details_json, dict) else {}
        operation = str(details.get("operation") or "")
        party = _actor_party(operation)
        created = as_utc(ev.created_at)
        items.append(
            {
                "event_type": ev.event_type,
                "occurred_at": created.isoformat() if created else None,
                "operation": operation,
                "capabilities": list(details.get("capabilities") or []),
                "result": details.get("result"),
                "actor_party": party,
                "actor_subject": ev.actor_user_id if party == caller_party else None,
                "correlation_id": ev.correlation_id,
                "event_hash": ev.event_hash,
            }
        )
    next_offset = offset + len(items) if offset + len(items) < total else None
    return {
        "tenant_id": caller,
        "relationship_id": relationship_id,
        "party": caller_party,
        "chain_verified": bool(verify_identity_audit_chain(db, caller)),
        "items": items,
        "total": total,
        "limit": limit,
        "offset": offset,
        "next_offset": next_offset,
    }


@router.post(
    "/relationships",
    dependencies=[
        _CONSOLE_BIND,
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
    caller = _caller_tenant_from_auth(request, actor_ctx)
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
    view = {**relationship_view(row), "created": True}
    db.commit()
    return view


@router.post(
    "/relationships/{relationship_id}/approve",
    dependencies=[_CONSOLE_BIND, Depends(require_scopes("admin:write"))],
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
    caller = _caller_tenant_from_auth(request, actor_ctx)
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
    view = relationship_view(row)
    db.commit()
    return view


def _customer_status_change(
    *,
    caller: str,
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
    view = relationship_view(row)
    db.commit()
    return view


@router.post(
    "/relationships/{relationship_id}/suspend",
    dependencies=[_CONSOLE_BIND, Depends(require_scopes("admin:write"))],
)
def suspend_relationship(
    relationship_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("tenant.configure")),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """The customer pauses MSP access. Effective on the next check."""
    return _customer_status_change(
        caller=_caller_tenant_from_auth(request, actor_ctx),
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
    dependencies=[_CONSOLE_BIND, Depends(require_scopes("admin:write"))],
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
        caller=_caller_tenant_from_auth(request, actor_ctx),
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
    dependencies=[_CONSOLE_BIND, Depends(require_scopes("admin:write"))],
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
    caller = _caller_tenant_from_auth(request, actor_ctx)
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
    view = {**relationship_view(row), "changed": True}
    db.commit()
    return view


# ---------------------------------------------------------------------------
# Multi-client operating context (MSP staff)
# ---------------------------------------------------------------------------


@router.get(
    "/customers",
    dependencies=[
        _CONSOLE_BIND,
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
    caller = _caller_tenant_from_auth(request, actor_ctx)
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


@router.get(
    "/portfolio",
    dependencies=[
        _CONSOLE_BIND,
        Depends(require_scopes("admin:read")),
        Depends(require_capability("msp.multi_tenant")),
    ],
)
def get_portfolio(
    request: Request,
    limit: int = Query(PORTFOLIO_DEFAULT_PAGE, ge=1, le=PORTFOLIO_MAX_PAGE),
    offset: int = Query(0, ge=0),
    actor_ctx: ActorContext = Depends(get_actor_context),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """MSP-002 read-only portfolio: one page of authorized customers.

    The customer set and each customer's permissions come only from
    ``list_actor_customers`` (re-evaluated on every request, no cache). Each
    summary section is read only when its capability is delegated, under that
    customer's tenant context; every customer whose data was read gets a
    ``tenant.msp.portfolio_summary_accessed`` event on its own chain.
    Stable order: customer tenant id.
    """
    caller = _caller_tenant_from_auth(request, actor_ctx)
    membership = resolve_msp_membership(db, actor_ctx=actor_ctx, msp_tenant_id=caller)
    entries: list[PortfolioEntry] = []
    for row, effective in list_actor_customers(db, membership=membership):
        info = tenant_kind_and_name(db, str(row.tenant_id))
        if info is None:
            continue
        expires_at = as_utc(row.expires_at)
        entries.append(
            PortfolioEntry(
                customer_tenant_id=str(row.tenant_id),
                display_name=info[1],
                relationship_id=str(row.id),
                expires_at=expires_at.isoformat() if expires_at else None,
                effective_permissions=effective,
            )
        )
    total = len(entries)
    page = entries[offset : offset + limit]
    items, reads = build_portfolio_items(db, entries=page, restore_tenant=caller)
    for entry, used in reads:
        emit_msp_audit(
            db,
            chains=(entry.customer_tenant_id,),
            restore_tenant=caller,
            event_type="tenant.msp.portfolio_summary_accessed",
            actor_subject=membership.subject,
            membership_id=membership.membership_id,
            reason_code="MSP_PORTFOLIO_SUMMARY_ACCESSED",
            msp_tenant_id=caller,
            customer_tenant_id=entry.customer_tenant_id,
            relationship_id=entry.relationship_id,
            operation="portfolio.summary",
            capabilities=used,
            correlation=correlation_id(request),
        )
    end = offset + len(items)
    view = {
        "msp_tenant_id": caller,
        "items": items,
        "total": total,
        "limit": limit,
        "offset": offset,
        "next_offset": end if end < total else None,
        "generated_at": utcnow().isoformat(),
        "revalidation": "every_request",
    }
    db.commit()
    return view


@router.post(
    "/customers/{customer_tenant_id}/context",
    dependencies=[
        _CONSOLE_BIND,
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
    caller = _caller_tenant_from_auth(request, actor_ctx)
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
