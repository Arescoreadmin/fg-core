"""api/msp_orchestration.py — MSP-003 partner-guided onboarding and assessment
orchestration.

Not a standalone authority. It coordinates existing ones and adds only two
records (migration 0208):

  * ``msp_assessment_grants``   — one customer-approved, expiring, single-use
    grant to initiate exactly one Field Assessment engagement.
  * ``msp_onboarding_requests`` — an MSP's referral of an organization that is
    not yet a tenant; a platform review queue, never a provisioning path.

Reused, unchanged:

  * Relationship and read delegation — MSP-001 ``msp_service_relationships``
    and ``resolve_actor_access``. The read-only ceiling
    ``MSP_DELEGABLE_PERMISSIONS`` is NOT widened: write authority exists only
    in a grant.
  * Administrators — TENANT-ADMIN-001 ``check_tenant_admin_authority`` for the
    MSP and the customer side.
  * Engagement creation — ``create_engagement_with_audit``, the same function
    the Field Assessment create route uses. Every later step (scans, evidence,
    readiness, QA, report qualification, governed delivery) stays with Field
    Assessment under the customer tenant's own authority; this module has no
    engagement status mutation.
  * Commercial authority — MSP-006 ``resolve_payer``. Charges still come only
    from the canonical delivery producer; initiation records no usage.
  * Customer readiness — CLIENT-LIFECYCLE ``evaluate_client_lifecycle``.
  * Audit — ``emit_msp_audit`` (per-tenant identity hash chains).

An MSP-initiated engagement requires, at the moment of the call:

    MSP designation active  ∩  actor is the MSP's canonical tenant_admin
    ∩ relationship active  ∩  grant approved, unexpired, unused
    ∩ customer tenant active  ∩  payer resolves (MSP-006)

Scope (assessment type, assessor) comes only from the grant. Nothing is
cached; revocation, suspension, expiry and membership removal apply on the
next call. See docs/msp/MSP_003_ARCHITECTURE.md.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Optional, TypeVar

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from api.actor_context import ActorContext
from api.admin import require_internal_admin_gateway
from api.auth_dispatch import require_permission
from api.auth_scopes import require_scopes, resolve_authoritative_tenant
from api.db import set_tenant_context
from api.db_models_field_assessment import FaEngagement
from api.db_models_msp import MspAssessmentGrant, MspOnboardingRequest
from api.deps import auth_ctx_db_session
from api.entitlements import _ensure_admin_gateway_tenant_bound
from api.msp_authority import (
    MSP_ACCESS_DENIED,
    MSP_APPROVAL_REQUIRES_CUSTOMER,
    MSP_APPROVAL_WINDOW_INVALID,
    MSP_CUSTOMER_NOT_FOUND,
    MSP_ORGANIZATION_INACTIVE,
    MSP_SELF_APPROVAL_DENIED,
    as_utc,
    canonical_capabilities,
    correlation_id,
    decode_capabilities,
    effective_status,
    emit_msp_audit,
    encode_capabilities,
    load_open_relationship,
    load_relationship,
    msp_error,
    msp_organization_active,
    principal_is_member_of,
    resolve_actor_access,
    tenant_kind_and_name,
    utcnow,
)
from api.tenant_admin_authority import (
    TenantAdminAuthority,
    check_tenant_admin_authority,
)
from services.field_assessment.models import AssessmentType

router = APIRouter(prefix="/admin/msp", tags=["msp-003"])

# ---------------------------------------------------------------------------
# Limits and contract
# ---------------------------------------------------------------------------

# The only capability a grant carries: the canonical engagement-creation
# permission, for one engagement. Widening it is a reviewed code change.
GRANT_CAPABILITIES: frozenset[str] = frozenset({"assessment.create"})
MAX_GRANT_DAYS = 90
ONBOARDING_REQUEST_DAYS = 30
BILLED_PRODUCT = "assessment.delivered"
_DEFAULT_PAGE = 50
_MAX_PAGE = 200
_KEY_PATTERN = r"^[A-Za-z0-9._:-]{1,128}$"
_ASSESSOR_PATTERN = r"^[A-Za-z0-9._@|:-]{1,128}$"
_EMAIL_PATTERN = r"^[^@\s]{1,64}@[^@\s]{1,189}\.[^@\s]{1,63}$"

MSP_ASSESSMENT_GRANT_NOT_FOUND = "MSP_ASSESSMENT_GRANT_NOT_FOUND"
MSP_ASSESSMENT_GRANT_CONFLICT = "MSP_ASSESSMENT_GRANT_CONFLICT"
MSP_ASSESSMENT_GRANT_INVALID_TRANSITION = "MSP_ASSESSMENT_GRANT_INVALID_TRANSITION"
MSP_ASSESSMENT_GRANT_EXPIRED = "MSP_ASSESSMENT_GRANT_EXPIRED"
MSP_ASSESSMENT_NOT_ENTITLED = "MSP_ASSESSMENT_NOT_ENTITLED"
MSP_RELATIONSHIP_INACTIVE = "MSP_RELATIONSHIP_INACTIVE"
MSP_CUSTOMER_TENANT_INACTIVE = "MSP_CUSTOMER_TENANT_INACTIVE"
MSP_ONBOARDING_REQUEST_NOT_FOUND = "MSP_ONBOARDING_REQUEST_NOT_FOUND"
MSP_ONBOARDING_REQUEST_CONFLICT = "MSP_ONBOARDING_REQUEST_CONFLICT"
MSP_ONBOARDING_INVALID_TRANSITION = "MSP_ONBOARDING_INVALID_TRANSITION"

# Why initiation is unavailable, in precedence order. Shown to the parties as
# blockers; the initiate route raises the first one.
BLOCKER_ERRORS: dict[str, tuple[int, str]] = {
    "CUSTOMER_APPROVAL_PENDING": (409, MSP_ASSESSMENT_GRANT_INVALID_TRANSITION),
    "GRANT_REJECTED": (409, MSP_ASSESSMENT_GRANT_INVALID_TRANSITION),
    "GRANT_WITHDRAWN": (409, MSP_ASSESSMENT_GRANT_INVALID_TRANSITION),
    "GRANT_REVOKED": (409, MSP_ASSESSMENT_GRANT_INVALID_TRANSITION),
    "GRANT_EXPIRED": (409, MSP_ASSESSMENT_GRANT_EXPIRED),
    "MSP_ORGANIZATION_INACTIVE": (403, MSP_ORGANIZATION_INACTIVE),
    "RELATIONSHIP_INACTIVE": (409, MSP_RELATIONSHIP_INACTIVE),
    "CUSTOMER_TENANT_INACTIVE": (409, MSP_CUSTOMER_TENANT_INACTIVE),
    "NOT_ENTITLED": (409, MSP_ASSESSMENT_NOT_ENTITLED),
}
_STATUS_BLOCKERS = {
    "requested": "CUSTOMER_APPROVAL_PENDING",
    "rejected": "GRANT_REJECTED",
    "withdrawn": "GRANT_WITHDRAWN",
    "revoked": "GRANT_REVOKED",
}


def grant_capabilities(raw: Any) -> frozenset[str]:
    """A grant's stored capabilities, bounded by ``GRANT_CAPABILITIES``.

    The MSP-001 decoder intersects with the read-only relationship ceiling,
    so a grant uses its own ceiling instead; neither can widen the other."""
    if not raw:
        return frozenset()
    try:
        values = json.loads(raw) if isinstance(raw, str) else list(raw)
    except (TypeError, ValueError):
        return frozenset()
    return frozenset(str(v) for v in values) & GRANT_CAPABILITIES


def _grant_not_found() -> HTTPException:
    """Unknown, foreign and invisible grants are indistinguishable."""
    return msp_error(404, MSP_ASSESSMENT_GRANT_NOT_FOUND)


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class RequestGrantBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    customer_tenant_id: str = Field(..., min_length=1, max_length=128)
    request_key: str = Field(..., pattern=_KEY_PATTERN)
    assessment_type: AssessmentType
    assessor_id: str = Field(..., pattern=_ASSESSOR_PATTERN)
    expires_at: datetime


class DecisionBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_version: int = Field(..., ge=1)


class ApproveGrantBody(DecisionBody):
    expires_at: Optional[datetime] = None


class InitiateBody(BaseModel):
    """Initiation takes no input: scope comes from the approved grant."""

    model_config = ConfigDict(extra="forbid")


class OnboardingRequestBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_key: str = Field(..., pattern=_KEY_PATTERN)
    organization_name: str = Field(..., min_length=1, max_length=200)
    contact_email: str = Field(..., pattern=_EMAIL_PATTERN, max_length=254)
    requested_capabilities: list[str] = Field(..., min_length=1, max_length=32)


class PlatformOnboardingBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    msp_tenant_id: str = Field(..., min_length=1, max_length=128)
    customer_tenant_id: Optional[str] = Field(None, min_length=1, max_length=128)


# ---------------------------------------------------------------------------
# Authority helpers
# ---------------------------------------------------------------------------


def _bind_console_gateway_tenant(request: Request) -> None:
    """MSP-002 console transport: verify the delegation proof before the actor
    is resolved (same binder as api/msp.py)."""
    _ensure_admin_gateway_tenant_bound(request)


_CONSOLE_BIND = Depends(_bind_console_gateway_tenant)


def _caller_tenant_from_auth(request: Request, actor_ctx: ActorContext) -> str:
    """The caller's own tenant, from the bound credential only."""
    tenant = str(actor_ctx.tenant_id or "").strip()
    if not tenant:
        raise msp_error(403, MSP_ACCESS_DENIED)
    return resolve_authoritative_tenant(request, actor_ctx, tenant)


def _msp_admin(
    db: Session, actor_ctx: ActorContext, caller: str
) -> TenantAdminAuthority:
    """The caller must be the canonical tenant_admin of an active MSP."""
    authority = check_tenant_admin_authority(db, actor_ctx=actor_ctx, tenant_id=caller)
    if not msp_organization_active(db, caller):
        raise msp_error(403, MSP_ORGANIZATION_INACTIVE)
    set_tenant_context(db, caller)
    return authority


_RowT = TypeVar("_RowT", MspAssessmentGrant, MspOnboardingRequest)


def _reload(db: Session, model: type[_RowT], row_id: str) -> _RowT:
    """Re-read a row this request just changed. It is visible under the
    bound context, so absence is a server fault, not a caller error."""
    row = db.get(model, row_id)
    if row is None:
        raise HTTPException(status_code=500, detail={"code": "MSP_STATE_UNAVAILABLE"})
    return row


def _load_grant(db: Session, grant_id: str, caller: str) -> MspAssessmentGrant:
    """A grant, only for one of its two parties; otherwise 404."""
    set_tenant_context(db, caller)
    row = db.get(MspAssessmentGrant, str(grant_id)[:64])
    if row is None or caller not in (str(row.tenant_id), str(row.msp_tenant_id)):
        raise _grant_not_found()
    return row


def _transition_grant(
    db: Session,
    row: MspAssessmentGrant,
    *,
    expected_status: tuple[str, ...],
    expected_version: Optional[int],
    values: dict[str, Any],
) -> None:
    """Compare-and-set on (id, status, version). A concurrent change loses."""
    if str(row.status) not in expected_status or (
        expected_version is not None and int(row.version) != int(expected_version)
    ):
        raise msp_error(409, MSP_ASSESSMENT_GRANT_INVALID_TRANSITION)
    update: dict[Any, Any] = {
        **values,
        "version": int(row.version) + 1,
        "updated_at": utcnow(),
    }
    changed = (
        db.query(MspAssessmentGrant)
        .filter(
            MspAssessmentGrant.id == row.id,
            MspAssessmentGrant.status == row.status,
            MspAssessmentGrant.version == row.version,
        )
        .update(update, synchronize_session=False)
    )
    if changed != 1:
        db.rollback()
        raise msp_error(409, MSP_ASSESSMENT_GRANT_INVALID_TRANSITION)
    db.flush()
    db.expire_all()


def _audit_grant(
    db: Session,
    *,
    caller: str,
    row: MspAssessmentGrant,
    event_type: str,
    reason_code: str,
    actor_subject: str,
    membership_id: Optional[str],
    operation: str,
    previous_state: Optional[str],
    new_state: str,
    correlation: Optional[str],
    engagement_id: Optional[str] = None,
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
        relationship_id=str(row.relationship_id),
        operation=operation,
        capabilities=grant_capabilities(row.capabilities),
        correlation=correlation,
        extra={
            "grant_id": str(row.id),
            "engagement_id": engagement_id or row.engagement_id,
            "assessment_type": str(row.assessment_type),
            "assessor_id": str(row.assessor_id),
            "previous_state": previous_state,
            "new_state": new_state,
        },
    )


# ---------------------------------------------------------------------------
# Derived state
# ---------------------------------------------------------------------------


def initiation_blockers(
    db: Session, row: MspAssessmentGrant, *, now: datetime, restore_tenant: str
) -> list[str]:
    """Every reason initiation is unavailable now, in precedence order, from
    canonical state only. An initiated grant has none (re-initiation returns
    the existing engagement)."""
    status = str(row.status)
    if status == "initiated":
        return []
    out: list[str] = []
    if status in _STATUS_BLOCKERS:
        out.append(_STATUS_BLOCKERS[status])
    expires_at = as_utc(row.expires_at)
    if expires_at is None or now >= expires_at:
        out.append("GRANT_EXPIRED")
    msp = str(row.msp_tenant_id)
    customer = str(row.tenant_id)
    try:
        set_tenant_context(db, msp)
        if not msp_organization_active(db, msp):
            out.append("MSP_ORGANIZATION_INACTIVE")
        rel = load_relationship(db, str(row.relationship_id))
        if rel is None or effective_status(rel, now) != "active":
            out.append("RELATIONSHIP_INACTIVE")
        info = tenant_kind_and_name(db, customer)
        if info is None or info[0] != "customer":
            out.append("CUSTOMER_TENANT_INACTIVE")
        from api.msp_billing import resolve_payer

        if not resolve_payer(
            db, customer_tenant_id=customer, product_code=BILLED_PRODUCT, at=now
        ).billable:
            out.append("NOT_ENTITLED")
    finally:
        set_tenant_context(db, restore_tenant)
    return out


def _progress(
    db: Session,
    row: MspAssessmentGrant,
    *,
    caller_party: str,
    actor_ctx: ActorContext,
    caller: str,
) -> dict[str, Any]:
    """Canonical engagement status, never a copy. The MSP sees it only while
    the grant is not revoked and the relationship delegates assessment.read."""
    if not row.engagement_id:
        return {"state": "not_started"}
    customer = str(row.tenant_id)
    if caller_party == "msp":
        if str(row.status) == "revoked":
            return {"state": "not_authorized"}
        try:
            resolve_actor_access(
                db,
                actor_ctx=actor_ctx,
                msp_tenant_id=caller,
                customer_tenant_id=customer,
                required="assessment.read",
            )
        except HTTPException:
            set_tenant_context(db, caller)
            return {"state": "not_authorized"}
    try:
        set_tenant_context(db, customer)
        eng = (
            db.query(FaEngagement)
            .filter(
                FaEngagement.id == str(row.engagement_id),
                FaEngagement.tenant_id == customer,
            )
            .first()
        )
        if eng is None:
            return {"state": "unavailable"}
        return {
            "state": "available",
            "engagement_status": str(eng.status),
            "updated_at": eng.updated_at,
        }
    finally:
        set_tenant_context(db, caller)


def _next_actions(
    row: MspAssessmentGrant, blockers: list[str], progress: dict[str, Any]
) -> list[dict[str, str]]:
    status = str(row.status)
    if status == "requested" and "GRANT_EXPIRED" not in blockers:
        return [{"owner": "customer", "code": "REVIEW_ASSESSMENT_REQUEST"}]
    if status == "approved":
        if not blockers:
            return [{"owner": "msp", "code": "INITIATE_ASSESSMENT"}]
        if blockers == ["NOT_ENTITLED"]:
            return [{"owner": "platform", "code": "ASSIGN_PAYER"}]
        return []
    if status == "initiated" and progress.get("engagement_status") == "in_progress":
        return [{"owner": "assessor", "code": "CONDUCT_ASSESSMENT"}]
    return []


def grant_view(
    db: Session,
    row: MspAssessmentGrant,
    *,
    caller: str,
    actor_ctx: ActorContext,
    now: Optional[datetime] = None,
) -> dict[str, Any]:
    now = now or utcnow()
    caller_party = "customer" if caller == str(row.tenant_id) else "msp"
    blockers = initiation_blockers(db, row, now=now, restore_tenant=caller)
    progress = _progress(
        db, row, caller_party=caller_party, actor_ctx=actor_ctx, caller=caller
    )
    expires_at = as_utc(row.expires_at)

    def _iso(value: Any) -> Optional[str]:
        dt = as_utc(value)
        return dt.isoformat() if dt else None

    effective = str(row.status)
    if effective in ("requested", "approved") and expires_at and now >= expires_at:
        effective = "expired"
    return {
        "grant_id": str(row.id),
        "relationship_id": str(row.relationship_id),
        "msp_tenant_id": str(row.msp_tenant_id),
        "customer_tenant_id": str(row.tenant_id),
        "party": caller_party,
        "request_key": str(row.request_key) if caller_party == "msp" else None,
        "status": str(row.status),
        "effective_status": effective,
        "capabilities": sorted(grant_capabilities(row.capabilities)),
        "scope": {
            "assessment_type": str(row.assessment_type),
            "assessor_id": str(row.assessor_id),
        },
        "requested_at": _iso(row.requested_at),
        "expires_at": _iso(row.expires_at),
        "decided_at": _iso(row.decided_at),
        "initiated_at": _iso(row.initiated_at),
        "revoked_at": _iso(row.revoked_at),
        "engagement_id": row.engagement_id,
        "version": int(row.version),
        "blockers": blockers,
        "progress": progress,
        "next_actions": _next_actions(row, blockers, progress),
    }


# ---------------------------------------------------------------------------
# Initiation (the only MSP write into a customer tenant)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class InitiationOutcome:
    engagement_id: str
    created: bool


def initiate_grant(
    db: Session,
    *,
    grant_id: str,
    msp_tenant_id: str,
    actor_subject: str,
    membership_id: Optional[str],
    correlation: Optional[str],
    preloaded: Optional[MspAssessmentGrant] = None,
    now: Optional[datetime] = None,
) -> InitiationOutcome:
    """Create the grant's one engagement through the canonical creation path.

    The caller has already proven the actor is the MSP's tenant_admin.
    Idempotent: an initiated grant returns its engagement. Concurrency: the
    grant moves ``approved`` → ``initiated`` by compare-and-set inside a
    savepoint that also holds the new engagement, so the loser of a race
    rolls back its engagement and returns the winner's. ``preloaded`` is a
    grant row the caller already read (it may be stale).
    """
    from api.field_assessment import create_engagement_with_audit

    now = now or utcnow()
    set_tenant_context(db, msp_tenant_id)
    row = (
        preloaded
        if preloaded is not None
        else db.get(MspAssessmentGrant, str(grant_id)[:64])
    )
    if row is None or str(row.msp_tenant_id) != msp_tenant_id:
        raise _grant_not_found()
    if str(row.status) == "initiated" and row.engagement_id:
        return InitiationOutcome(str(row.engagement_id), False)
    blockers = initiation_blockers(db, row, now=now, restore_tenant=msp_tenant_id)
    if blockers:
        status_code, code = BLOCKER_ERRORS[blockers[0]]
        raise msp_error(status_code, code)

    customer = str(row.tenant_id)
    info = tenant_kind_and_name(db, customer)
    client_name = info[1] if info else customer
    grant_key = (str(row.id), int(row.version))
    set_tenant_context(db, customer)
    savepoint = db.begin_nested()
    eng = create_engagement_with_audit(
        db,
        tenant_id=customer,
        client_name=client_name,
        client_domain=None,
        assessor_id=str(row.assessor_id),
        assessment_type=str(row.assessment_type),
        scheduled_date=None,
        engagement_metadata={},
        actor=actor_subject,
        audit_extra={
            "msp": {
                "msp_tenant_id": msp_tenant_id,
                "relationship_id": str(row.relationship_id),
                "grant_id": str(row.id),
            }
        },
    )
    engagement_id = str(eng.id)
    changed = (
        db.query(MspAssessmentGrant)
        .filter(
            MspAssessmentGrant.id == grant_key[0],
            MspAssessmentGrant.status == "approved",
            MspAssessmentGrant.version == grant_key[1],
            MspAssessmentGrant.engagement_id.is_(None),
        )
        .update(
            {
                "status": "initiated",
                "engagement_id": engagement_id,
                "initiated_by_subject": actor_subject,
                "initiated_at": now,
                "version": grant_key[1] + 1,
                "updated_at": now,
            },
            synchronize_session=False,
        )
    )
    if changed != 1:
        savepoint.rollback()
        set_tenant_context(db, msp_tenant_id)
        db.expire_all()
        current = db.get(MspAssessmentGrant, grant_key[0])
        if current is not None and str(current.status) == "initiated":
            return InitiationOutcome(str(current.engagement_id), False)
        raise msp_error(409, MSP_ASSESSMENT_GRANT_INVALID_TRANSITION)
    savepoint.commit()
    db.expire_all()
    row = _reload(db, MspAssessmentGrant, grant_key[0])
    _audit_grant(
        db,
        caller=msp_tenant_id,
        row=row,
        event_type="tenant.msp.assessment_initiated",
        reason_code="MSP_ASSESSMENT_INITIATED",
        actor_subject=actor_subject,
        membership_id=membership_id,
        operation="assessment.initiate",
        previous_state="approved",
        new_state="initiated",
        correlation=correlation,
        engagement_id=engagement_id,
    )
    return InitiationOutcome(engagement_id, True)


# ---------------------------------------------------------------------------
# Assessment grant routes
# ---------------------------------------------------------------------------


@router.get(
    "/assessments/grants",
    dependencies=[_CONSOLE_BIND, Depends(require_scopes("admin:read"))],
)
def list_assessment_grants(
    request: Request,
    customer_tenant_id: Optional[str] = Query(None, max_length=128),
    limit: int = Query(_DEFAULT_PAGE, ge=1, le=_MAX_PAGE),
    offset: int = Query(0, ge=0),
    actor_ctx: ActorContext = Depends(require_permission("tenant.configure")),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """Grants where the caller is a party. The MSP may filter by customer."""
    caller = _caller_tenant_from_auth(request, actor_ctx)
    check_tenant_admin_authority(db, actor_ctx=actor_ctx, tenant_id=caller)
    set_tenant_context(db, caller)
    q = db.query(MspAssessmentGrant).filter(
        or_(
            MspAssessmentGrant.tenant_id == caller,
            MspAssessmentGrant.msp_tenant_id == caller,
        )
    )
    if customer_tenant_id:
        q = q.filter(MspAssessmentGrant.tenant_id == customer_tenant_id)
    total = q.count()
    rows = (
        q.order_by(MspAssessmentGrant.requested_at.desc(), MspAssessmentGrant.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    now = utcnow()
    items = [
        grant_view(db, r, caller=caller, actor_ctx=actor_ctx, now=now) for r in rows
    ]
    next_offset = offset + len(items) if offset + len(items) < total else None
    return {
        "tenant_id": caller,
        "items": items,
        "total": total,
        "limit": limit,
        "offset": offset,
        "next_offset": next_offset,
    }


@router.post(
    "/assessments/grants",
    dependencies=[_CONSOLE_BIND, Depends(require_scopes("admin:write"))],
)
def request_assessment_grant(
    body: RequestGrantBody,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("tenant.configure")),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """An MSP tenant_admin asks a customer for one assessment. Grants nothing.

    Requires an active relationship. Idempotent on (customer, request_key):
    a replay with the same scope returns the grant with ``created: false``;
    a different scope under the same key is a 409.
    """
    caller = _caller_tenant_from_auth(request, actor_ctx)
    authority = _msp_admin(db, actor_ctx, caller)
    now = utcnow()
    expires_at = as_utc(body.expires_at)
    if (
        expires_at is None
        or expires_at <= now
        or expires_at > now + timedelta(days=MAX_GRANT_DAYS)
    ):
        raise msp_error(422, MSP_APPROVAL_WINDOW_INVALID)
    customer = body.customer_tenant_id.strip()
    rel = None
    if customer and customer != caller:
        info = tenant_kind_and_name(db, customer)
        if info is not None and info[0] == "customer":
            rel = load_open_relationship(db, msp_tenant_id=caller, customer_id=customer)
    if rel is None or effective_status(rel, now) != "active":
        raise msp_error(404, MSP_CUSTOMER_NOT_FOUND)
    scope = (body.assessment_type.value, body.assessor_id)

    def _replay(existing: MspAssessmentGrant) -> dict[str, Any]:
        if (str(existing.assessment_type), str(existing.assessor_id)) != scope:
            raise msp_error(409, MSP_ASSESSMENT_GRANT_CONFLICT)
        return {
            **grant_view(db, existing, caller=caller, actor_ctx=actor_ctx),
            "created": False,
        }

    def _find() -> Optional[MspAssessmentGrant]:
        return (
            db.query(MspAssessmentGrant)
            .filter(
                MspAssessmentGrant.msp_tenant_id == caller,
                MspAssessmentGrant.tenant_id == customer,
                MspAssessmentGrant.request_key == body.request_key,
            )
            .first()
        )

    existing = _find()
    if existing is not None:
        return _replay(existing)
    row = MspAssessmentGrant(
        id=str(uuid.uuid4()),
        tenant_id=customer,
        msp_tenant_id=caller,
        relationship_id=str(rel.id),
        request_key=body.request_key,
        capabilities=encode_capabilities(GRANT_CAPABILITIES),
        assessment_type=scope[0],
        assessor_id=scope[1],
        status="requested",
        requested_by_subject=authority.subject,
        requested_at=now,
        expires_at=expires_at,
        version=1,
        created_at=now,
        updated_at=now,
    )
    db.add(row)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        set_tenant_context(db, caller)
        existing = _find()
        if existing is None:
            raise msp_error(409, MSP_ASSESSMENT_GRANT_CONFLICT)
        return _replay(existing)
    _audit_grant(
        db,
        caller=caller,
        row=row,
        event_type="tenant.msp.assessment_grant_requested",
        reason_code="MSP_ASSESSMENT_GRANT_REQUESTED",
        actor_subject=authority.subject,
        membership_id=authority.membership_id,
        operation="assessment_grant.request",
        previous_state=None,
        new_state="requested",
        correlation=correlation_id(request),
    )
    view = {**grant_view(db, row, caller=caller, actor_ctx=actor_ctx), "created": True}
    db.commit()
    return view


def _customer_decision(
    *,
    caller: str,
    grant_id: str,
    request: Request,
    actor_ctx: ActorContext,
    db: Session,
    expected_version: int,
    action: str,
    expected_status: tuple[str, ...],
    new_status: str,
    values_for: Any,
    independent: bool,
) -> dict[str, Any]:
    row = _load_grant(db, grant_id, caller)
    if caller != str(row.tenant_id):
        raise msp_error(403, MSP_APPROVAL_REQUIRES_CUSTOMER)
    authority = check_tenant_admin_authority(db, actor_ctx=actor_ctx, tenant_id=caller)
    if independent and (
        authority.subject == str(row.requested_by_subject)
        or principal_is_member_of(
            db, principal_id=authority.principal_id, tenant_id=str(row.msp_tenant_id)
        )
    ):
        set_tenant_context(db, caller)
        raise msp_error(403, MSP_SELF_APPROVAL_DENIED)
    set_tenant_context(db, caller)
    now = utcnow()
    previous = str(row.status)
    _transition_grant(
        db,
        row,
        expected_status=expected_status,
        expected_version=expected_version,
        values={"status": new_status, **values_for(row, authority, now)},
    )
    row = _load_grant(db, grant_id, caller)
    _audit_grant(
        db,
        caller=caller,
        row=row,
        event_type=f"tenant.msp.assessment_grant_{new_status}",
        reason_code=f"MSP_ASSESSMENT_GRANT_{new_status.upper()}",
        actor_subject=authority.subject,
        membership_id=authority.membership_id,
        operation=f"assessment_grant.{action}",
        previous_state=previous,
        new_state=new_status,
        correlation=correlation_id(request),
    )
    view = grant_view(db, row, caller=caller, actor_ctx=actor_ctx)
    db.commit()
    return view


@router.post(
    "/assessments/grants/{grant_id}/approve",
    dependencies=[_CONSOLE_BIND, Depends(require_scopes("admin:write"))],
)
def approve_assessment_grant(
    grant_id: str,
    body: ApproveGrantBody,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("tenant.configure")),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """The customer's own tenant_admin approves the exact requested scope.

    The approver may shorten but never extend the expiry, may not be the
    requester or hold any membership in the MSP, and approves only while the
    relationship is active. The grant never outlives the relationship.
    """

    def _values(
        row: MspAssessmentGrant, authority: TenantAdminAuthority, now: datetime
    ) -> dict[str, Any]:
        requested_expiry = as_utc(row.expires_at)
        if requested_expiry is None or now >= requested_expiry:
            raise msp_error(409, MSP_ASSESSMENT_GRANT_EXPIRED)
        expiry = as_utc(body.expires_at) or requested_expiry
        if expiry <= now or expiry > requested_expiry:
            raise msp_error(422, MSP_APPROVAL_WINDOW_INVALID)
        rel = load_relationship(db, str(row.relationship_id))
        if rel is None or effective_status(rel, now) != "active":
            raise msp_error(409, MSP_RELATIONSHIP_INACTIVE)
        rel_expiry = as_utc(rel.expires_at)
        if rel_expiry is not None and rel_expiry < expiry:
            expiry = rel_expiry
        return {
            "decided_by_subject": authority.subject,
            "decided_by_membership_id": authority.membership_id,
            "decided_at": now,
            "expires_at": expiry,
        }

    return _customer_decision(
        caller=_caller_tenant_from_auth(request, actor_ctx),
        grant_id=grant_id,
        request=request,
        actor_ctx=actor_ctx,
        db=db,
        expected_version=body.expected_version,
        action="approve",
        expected_status=("requested",),
        new_status="approved",
        values_for=_values,
        independent=True,
    )


@router.post(
    "/assessments/grants/{grant_id}/reject",
    dependencies=[_CONSOLE_BIND, Depends(require_scopes("admin:write"))],
)
def reject_assessment_grant(
    grant_id: str,
    body: DecisionBody,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("tenant.configure")),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """The customer's tenant_admin declines a pending request."""

    def _values(row: Any, authority: TenantAdminAuthority, now: datetime) -> dict:
        return {
            "decided_by_subject": authority.subject,
            "decided_by_membership_id": authority.membership_id,
            "decided_at": now,
        }

    return _customer_decision(
        caller=_caller_tenant_from_auth(request, actor_ctx),
        grant_id=grant_id,
        request=request,
        actor_ctx=actor_ctx,
        db=db,
        expected_version=body.expected_version,
        action="reject",
        expected_status=("requested",),
        new_status="rejected",
        values_for=_values,
        independent=False,
    )


@router.post(
    "/assessments/grants/{grant_id}/revoke",
    dependencies=[_CONSOLE_BIND, Depends(require_scopes("admin:write"))],
)
def revoke_assessment_grant(
    grant_id: str,
    body: DecisionBody,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("tenant.configure")),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """The customer's tenant_admin revokes an approved or used grant.

    Revocation blocks initiation and the MSP's progress view. An engagement
    already initiated is NOT cancelled: it stays the customer's, under Field
    Assessment's own lifecycle.
    """

    def _values(row: Any, authority: TenantAdminAuthority, now: datetime) -> dict:
        return {"revoked_by_subject": authority.subject, "revoked_at": now}

    return _customer_decision(
        caller=_caller_tenant_from_auth(request, actor_ctx),
        grant_id=grant_id,
        request=request,
        actor_ctx=actor_ctx,
        db=db,
        expected_version=body.expected_version,
        action="revoke",
        expected_status=("approved", "initiated"),
        new_status="revoked",
        values_for=_values,
        independent=False,
    )


@router.post(
    "/assessments/grants/{grant_id}/withdraw",
    dependencies=[_CONSOLE_BIND, Depends(require_scopes("admin:write"))],
)
def withdraw_assessment_grant(
    grant_id: str,
    body: DecisionBody,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("tenant.configure")),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """The MSP withdraws its own pending request. Nothing else."""
    caller = _caller_tenant_from_auth(request, actor_ctx)
    row = _load_grant(db, grant_id, caller)
    if caller != str(row.msp_tenant_id):
        raise msp_error(403, MSP_ACCESS_DENIED)
    authority = _msp_admin(db, actor_ctx, caller)
    _transition_grant(
        db,
        row,
        expected_status=("requested",),
        expected_version=body.expected_version,
        values={"status": "withdrawn"},
    )
    row = _load_grant(db, grant_id, caller)
    _audit_grant(
        db,
        caller=caller,
        row=row,
        event_type="tenant.msp.assessment_grant_withdrawn",
        reason_code="MSP_ASSESSMENT_GRANT_WITHDRAWN",
        actor_subject=authority.subject,
        membership_id=authority.membership_id,
        operation="assessment_grant.withdraw",
        previous_state="requested",
        new_state="withdrawn",
        correlation=correlation_id(request),
    )
    view = grant_view(db, row, caller=caller, actor_ctx=actor_ctx)
    db.commit()
    return view


@router.post(
    "/assessments/grants/{grant_id}/initiate",
    dependencies=[_CONSOLE_BIND, Depends(require_scopes("admin:write"))],
)
def initiate_assessment(
    grant_id: str,
    body: InitiateBody,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("tenant.configure")),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """The MSP's tenant_admin initiates the grant's one engagement."""
    caller = _caller_tenant_from_auth(request, actor_ctx)
    authority = _msp_admin(db, actor_ctx, caller)
    outcome = initiate_grant(
        db,
        grant_id=grant_id,
        msp_tenant_id=caller,
        actor_subject=authority.subject,
        membership_id=authority.membership_id,
        correlation=correlation_id(request),
    )
    row = _load_grant(db, grant_id, caller)
    view = grant_view(db, row, caller=caller, actor_ctx=actor_ctx)
    db.commit()
    return {**view, "engagement_id": outcome.engagement_id, "created": outcome.created}


# ---------------------------------------------------------------------------
# Onboarding requests (new organizations)
# ---------------------------------------------------------------------------


def _onboarding_stage(
    db: Session, row: MspOnboardingRequest, *, now: datetime, msp: str
) -> tuple[str, list[dict[str, str]]]:
    """Stored status plus canonical state. After linking, the stage is derived
    from the tenant's client lifecycle and the MSP-001 relationship; nothing
    from the customer tenant is copied here."""
    status = str(row.status)
    if status == "requested":
        expires_at = as_utc(row.expires_at)
        if expires_at is not None and now >= expires_at:
            return "expired", []
        return "requested", [{"owner": "platform", "code": "REVIEW_ONBOARDING_REQUEST"}]
    if status != "linked":
        return status, []
    from api.client_lifecycle import evaluate_client_lifecycle

    customer = str(row.customer_tenant_id)
    try:
        set_tenant_context(db, customer)
        lifecycle = evaluate_client_lifecycle(db, customer).lifecycle_state
        set_tenant_context(db, msp)
        if lifecycle == "admin_unset":
            return "provisioning", [
                {"owner": "platform", "code": "INVITE_INITIAL_ADMIN"}
            ]
        if lifecycle == "admin_unbound":
            return "invited", [{"owner": "customer", "code": "ACCEPT_INVITATION"}]
        if lifecycle != "operational":
            return "customer_inactive", []
        rel = load_open_relationship(db, msp_tenant_id=msp, customer_id=customer)
        if rel is None:
            return "customer_accepted", [
                {"owner": "msp", "code": "PROPOSE_RELATIONSHIP"}
            ]
        rel_status = effective_status(rel, now)
        if rel_status == "proposed":
            return "awaiting_customer_approval", [
                {"owner": "customer", "code": "REVIEW_RELATIONSHIP"}
            ]
        if rel_status == "active":
            return "active", []
        return "relationship_inactive", []
    finally:
        set_tenant_context(db, msp)


def onboarding_view(
    db: Session, row: MspOnboardingRequest, *, msp: str, now: Optional[datetime] = None
) -> dict[str, Any]:
    now = now or utcnow()
    stage, actions = _onboarding_stage(db, row, now=now, msp=msp)

    def _iso(value: Any) -> Optional[str]:
        dt = as_utc(value)
        return dt.isoformat() if dt else None

    return {
        "onboarding_request_id": str(row.id),
        "msp_tenant_id": str(row.tenant_id),
        "request_key": str(row.request_key),
        "organization_name": str(row.organization_name),
        "contact_email": str(row.contact_email),
        "requested_capabilities": sorted(
            decode_capabilities(row.requested_capabilities)
        ),
        "status": str(row.status),
        "stage": stage,
        "next_actions": actions,
        "requested_at": _iso(row.requested_at),
        "expires_at": _iso(row.expires_at),
        "reviewed_at": _iso(row.reviewed_at),
        "customer_tenant_id": row.customer_tenant_id,
        "version": int(row.version),
    }


def _audit_onboarding(
    db: Session,
    *,
    row: MspOnboardingRequest,
    event_type: str,
    reason_code: str,
    actor_subject: str,
    membership_id: Optional[str],
    operation: str,
    previous_state: Optional[str],
    new_state: str,
    correlation: Optional[str],
    restore_tenant: str,
) -> None:
    msp = str(row.tenant_id)
    customer = str(row.customer_tenant_id or "")
    emit_msp_audit(
        db,
        chains=(msp, customer) if customer else (msp,),
        restore_tenant=restore_tenant,
        event_type=event_type,
        actor_subject=actor_subject,
        membership_id=membership_id,
        reason_code=reason_code,
        msp_tenant_id=msp,
        customer_tenant_id=customer,
        relationship_id=None,
        operation=operation,
        capabilities=decode_capabilities(row.requested_capabilities),
        correlation=correlation,
        extra={
            "onboarding_request_id": str(row.id),
            "previous_state": previous_state,
            "new_state": new_state,
        },
    )


def _transition_onboarding(
    db: Session,
    row: MspOnboardingRequest,
    *,
    expected_version: Optional[int],
    values: dict[str, Any],
    now: datetime,
) -> None:
    """Only a live (unexpired) ``requested`` row moves, by compare-and-set."""
    expires_at = as_utc(row.expires_at)
    if (
        str(row.status) != "requested"
        or (expires_at is not None and now >= expires_at)
        or (expected_version is not None and int(row.version) != expected_version)
    ):
        raise msp_error(409, MSP_ONBOARDING_INVALID_TRANSITION)
    update: dict[Any, Any] = {
        **values,
        "version": int(row.version) + 1,
        "updated_at": now,
    }
    changed = (
        db.query(MspOnboardingRequest)
        .filter(
            MspOnboardingRequest.id == row.id,
            MspOnboardingRequest.status == "requested",
            MspOnboardingRequest.version == row.version,
        )
        .update(
            update,
            synchronize_session=False,
        )
    )
    if changed != 1:
        db.rollback()
        raise msp_error(409, MSP_ONBOARDING_INVALID_TRANSITION)
    db.flush()
    db.expire_all()


@router.get(
    "/onboarding/requests",
    dependencies=[_CONSOLE_BIND, Depends(require_scopes("admin:read"))],
)
def list_onboarding_requests(
    request: Request,
    limit: int = Query(_DEFAULT_PAGE, ge=1, le=_MAX_PAGE),
    offset: int = Query(0, ge=0),
    actor_ctx: ActorContext = Depends(require_permission("tenant.configure")),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """The caller MSP's own referrals. Any other tenant sees an empty list."""
    caller = _caller_tenant_from_auth(request, actor_ctx)
    check_tenant_admin_authority(db, actor_ctx=actor_ctx, tenant_id=caller)
    set_tenant_context(db, caller)
    return _onboarding_page(db, caller, limit=limit, offset=offset)


def _onboarding_page(db: Session, msp: str, *, limit: int, offset: int) -> dict:
    q = db.query(MspOnboardingRequest).filter(MspOnboardingRequest.tenant_id == msp)
    total = q.count()
    rows = (
        q.order_by(
            MspOnboardingRequest.requested_at.desc(), MspOnboardingRequest.id.desc()
        )
        .offset(offset)
        .limit(limit)
        .all()
    )
    now = utcnow()
    items = [onboarding_view(db, r, msp=msp, now=now) for r in rows]
    next_offset = offset + len(items) if offset + len(items) < total else None
    return {
        "msp_tenant_id": msp,
        "items": items,
        "total": total,
        "limit": limit,
        "offset": offset,
        "next_offset": next_offset,
    }


@router.post(
    "/onboarding/requests",
    dependencies=[_CONSOLE_BIND, Depends(require_scopes("admin:write"))],
)
def request_onboarding(
    body: OnboardingRequestBody,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("tenant.configure")),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """An MSP refers a new organization for platform review.

    Creates no tenant, user, invitation or relationship, and never searches
    existing tenants. Idempotent on request_key.
    """
    caller = _caller_tenant_from_auth(request, actor_ctx)
    authority = _msp_admin(db, actor_ctx, caller)
    caps = canonical_capabilities(body.requested_capabilities)
    name = body.organization_name.strip()
    email = body.contact_email.strip().lower()
    if not name:
        raise msp_error(422, MSP_ONBOARDING_REQUEST_CONFLICT)

    def _find() -> Optional[MspOnboardingRequest]:
        return (
            db.query(MspOnboardingRequest)
            .filter(
                MspOnboardingRequest.tenant_id == caller,
                MspOnboardingRequest.request_key == body.request_key,
            )
            .first()
        )

    def _replay(existing: MspOnboardingRequest) -> dict[str, Any]:
        same = (
            str(existing.organization_name) == name
            and str(existing.contact_email) == email
            and decode_capabilities(existing.requested_capabilities) == frozenset(caps)
        )
        if not same:
            raise msp_error(409, MSP_ONBOARDING_REQUEST_CONFLICT)
        return {**onboarding_view(db, existing, msp=caller), "created": False}

    existing = _find()
    if existing is not None:
        return _replay(existing)
    now = utcnow()
    row = MspOnboardingRequest(
        id=str(uuid.uuid4()),
        tenant_id=caller,
        request_key=body.request_key,
        organization_name=name,
        contact_email=email,
        requested_capabilities=encode_capabilities(caps),
        status="requested",
        requested_by_subject=authority.subject,
        requested_at=now,
        expires_at=now + timedelta(days=ONBOARDING_REQUEST_DAYS),
        version=1,
        created_at=now,
        updated_at=now,
    )
    db.add(row)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        set_tenant_context(db, caller)
        existing = _find()
        if existing is None:
            raise msp_error(409, MSP_ONBOARDING_REQUEST_CONFLICT)
        return _replay(existing)
    _audit_onboarding(
        db,
        row=row,
        event_type="tenant.msp.onboarding_requested",
        reason_code="MSP_ONBOARDING_REQUESTED",
        actor_subject=authority.subject,
        membership_id=authority.membership_id,
        operation="onboarding.request",
        previous_state=None,
        new_state="requested",
        correlation=correlation_id(request),
        restore_tenant=caller,
    )
    view = {**onboarding_view(db, row, msp=caller, now=now), "created": True}
    db.commit()
    return view


@router.post(
    "/onboarding/requests/{request_id}/cancel",
    dependencies=[_CONSOLE_BIND, Depends(require_scopes("admin:write"))],
)
def cancel_onboarding(
    request_id: str,
    body: DecisionBody,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("tenant.configure")),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    caller = _caller_tenant_from_auth(request, actor_ctx)
    authority = check_tenant_admin_authority(db, actor_ctx=actor_ctx, tenant_id=caller)
    set_tenant_context(db, caller)
    row = db.get(MspOnboardingRequest, str(request_id)[:64])
    if row is None or str(row.tenant_id) != caller:
        raise msp_error(404, MSP_ONBOARDING_REQUEST_NOT_FOUND)
    now = utcnow()
    _transition_onboarding(
        db,
        row,
        expected_version=body.expected_version,
        values={"status": "canceled"},
        now=now,
    )
    row = _reload(db, MspOnboardingRequest, str(request_id)[:64])
    _audit_onboarding(
        db,
        row=row,
        event_type="tenant.msp.onboarding_canceled",
        reason_code="MSP_ONBOARDING_CANCELED",
        actor_subject=authority.subject,
        membership_id=authority.membership_id,
        operation="onboarding.cancel",
        previous_state="requested",
        new_state="canceled",
        correlation=correlation_id(request),
        restore_tenant=caller,
    )
    view = onboarding_view(db, row, msp=caller, now=now)
    db.commit()
    return view


# -- Platform review (internal admin gateway only; never proxied by the console)


@router.get(
    "/platform/onboarding",
    dependencies=[
        Depends(require_internal_admin_gateway),
        Depends(require_scopes("admin:read")),
    ],
)
def platform_list_onboarding(
    msp_tenant_id: str = Query(..., min_length=1, max_length=128),
    limit: int = Query(_DEFAULT_PAGE, ge=1, le=_MAX_PAGE),
    offset: int = Query(0, ge=0),
    actor_ctx: ActorContext = Depends(require_permission("platform.admin")),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """One MSP's referral queue, for platform review."""
    set_tenant_context(db, msp_tenant_id)
    return _onboarding_page(db, msp_tenant_id, limit=limit, offset=offset)


def _platform_review(
    *,
    request_id: str,
    body: PlatformOnboardingBody,
    request: Request,
    actor_ctx: ActorContext,
    db: Session,
    link: bool,
) -> dict[str, Any]:
    msp = body.msp_tenant_id
    set_tenant_context(db, msp)
    row = db.get(MspOnboardingRequest, str(request_id)[:64])
    if row is None or str(row.tenant_id) != msp:
        raise msp_error(404, MSP_ONBOARDING_REQUEST_NOT_FOUND)
    now = utcnow()
    subject = actor_ctx.subject or "platform"
    values: dict[str, Any] = {"reviewed_by_subject": subject, "reviewed_at": now}
    if link:
        customer = (body.customer_tenant_id or "").strip()
        info = (
            tenant_kind_and_name(db, customer) if customer and customer != msp else None
        )
        if info is None or info[0] != "customer":
            raise msp_error(404, MSP_CUSTOMER_NOT_FOUND)
        values.update({"status": "linked", "customer_tenant_id": customer})
    else:
        values["status"] = "rejected"
    _transition_onboarding(db, row, expected_version=None, values=values, now=now)
    set_tenant_context(db, msp)
    row = _reload(db, MspOnboardingRequest, str(request_id)[:64])
    new_state = str(row.status)
    _audit_onboarding(
        db,
        row=row,
        event_type=f"tenant.msp.onboarding_{new_state}",
        reason_code=f"MSP_ONBOARDING_{new_state.upper()}",
        actor_subject=subject,
        membership_id=None,
        operation=f"onboarding.{'link' if link else 'reject'}",
        previous_state="requested",
        new_state=new_state,
        correlation=correlation_id(request),
        restore_tenant=msp,
    )
    view = onboarding_view(db, row, msp=msp, now=now)
    db.commit()
    return view


@router.post(
    "/platform/onboarding/{request_id}/link",
    dependencies=[
        Depends(require_internal_admin_gateway),
        Depends(require_scopes("admin:write")),
    ],
)
def platform_link_onboarding(
    request_id: str,
    body: PlatformOnboardingBody,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("platform.admin")),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """After provisioning the tenant through the canonical platform routes,
    record which tenant the referral became. Grants nothing: the MSP still
    proposes a relationship and the customer still approves it."""
    return _platform_review(
        request_id=request_id,
        body=body,
        request=request,
        actor_ctx=actor_ctx,
        db=db,
        link=True,
    )


@router.post(
    "/platform/onboarding/{request_id}/reject",
    dependencies=[
        Depends(require_internal_admin_gateway),
        Depends(require_scopes("admin:write")),
    ],
)
def platform_reject_onboarding(
    request_id: str,
    body: PlatformOnboardingBody,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("platform.admin")),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    return _platform_review(
        request_id=request_id,
        body=body,
        request=request,
        actor_ctx=actor_ctx,
        db=db,
        link=False,
    )


__all__ = [
    "GRANT_CAPABILITIES",
    "InitiationOutcome",
    "initiate_grant",
    "initiation_blockers",
    "router",
]
