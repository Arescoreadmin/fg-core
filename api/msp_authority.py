"""api/msp_authority.py — MSP-001 canonical MSP delegated-authority check.

Answers one question, fail-closed, from the database on every call:

    "May actor P, acting for MSP organization M, use permission X on
     customer tenant C right now?"

It is the ONLY MSP authority. It composes existing authorities and adds no
new identity, role, tenant or audit system:

  * Tenants      — canonical ``tenants`` registry (TenantRepository).
  * Membership   — canonical ``tenant_users`` rows bound to ``fg_principals``
                   (the same row semantics as TENANT-ADMIN-001).
  * Permissions  — existing permission names and ``ROLE_PERMISSIONS``.
  * MSP admin    — ``check_tenant_admin_authority`` on the MSP tenant.
  * Customer     — ``check_tenant_admin_authority`` on the customer tenant.
  * Audit        — ``emit_identity_audit_event`` (per-tenant hash chain).

Effective permissions are an INTERSECTION, never a union:

    ROLE_PERMISSIONS[actor's DB role in M]
      ∩ relationship.authorized_capabilities   (what the customer approved)
      ∩ MSP_DELEGABLE_PERMISSIONS              (static delegation ceiling)

and are empty unless all of the following hold at the moment of the check:

  1. M is a platform-designated MSP organization with status ``active``.
  2. The actor has an active, bound ``tenant_users`` row in M with a principal.
  3. A relationship (M, C) exists, was approved by C, is not suspended or
     revoked, and ``effective_at <= now < expires_at``.

Nothing is cached. Suspension, revocation, expiry and membership removal take
effect on the next check. Customer selection grants nothing by itself: every
protected request must call this module again.

The legacy control-plane v2 MSP scope (``control-plane:msp:*``) and the
inert ``control_plane_msp_delegations`` records are NOT authorities; the
control-plane cross-tenant path is gated by ``resolve_credential_access``.

See docs/msp/MSP_001_ARCHITECTURE.md.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

from fastapi import HTTPException, Request
from sqlalchemy import text
from sqlalchemy.orm import Session

from api.actor_context import ActorContext, ROLE_PERMISSIONS
from api.db import set_tenant_context
from api.db_models_msp import (
    OPEN_RELATIONSHIP_STATUSES,
    MspOrganization,
    MspServiceRelationship,
)
from api.identity.store import emit_identity_audit_event

log = logging.getLogger("frostgate.msp_authority")

# ---------------------------------------------------------------------------
# Delegation ceiling
# ---------------------------------------------------------------------------
#
# The only permissions a customer may delegate to an MSP in MSP-001. Read-only
# by design: no MSP write path exists yet, and approvals, consent, key, user,
# tenant, risk and platform permissions are never delegable. Widening this set
# is a reviewed code change, never a data change.
MSP_DELEGABLE_PERMISSIONS: frozenset[str] = frozenset(
    {
        "assessment.read",
        "finding.read",
        "evidence.read",
        "scan.read",
        "report.read",
        "bundle.read",
        "governance.read",
    }
)

# Delegation applies to customer tenants only; internal, validation and demo
# tenants cannot be served by an MSP.
_SERVICEABLE_TENANT_KINDS = frozenset({"customer"})

# Maximum lifetime of one approval. Longer engagements re-approve.
MAX_RELATIONSHIP_DAYS = 366

# ---------------------------------------------------------------------------
# Error contract
# ---------------------------------------------------------------------------

MSP_ACCESS_DENIED = "MSP_ACCESS_DENIED"
MSP_CUSTOMER_NOT_FOUND = "MSP_CUSTOMER_NOT_FOUND"
MSP_RELATIONSHIP_NOT_FOUND = "MSP_RELATIONSHIP_NOT_FOUND"
MSP_RELATIONSHIP_EXISTS = "MSP_RELATIONSHIP_EXISTS"
MSP_RELATIONSHIP_INVALID_TRANSITION = "MSP_RELATIONSHIP_INVALID_TRANSITION"
MSP_APPROVAL_REQUIRES_CUSTOMER = "MSP_APPROVAL_REQUIRES_CUSTOMER"
MSP_SELF_APPROVAL_DENIED = "MSP_SELF_APPROVAL_DENIED"
MSP_CAPABILITY_NOT_DELEGABLE = "MSP_CAPABILITY_NOT_DELEGABLE"
MSP_APPROVAL_WINDOW_INVALID = "MSP_APPROVAL_WINDOW_INVALID"
MSP_ORGANIZATION_INACTIVE = "MSP_ORGANIZATION_INACTIVE"
MSP_TENANT_NOT_ELIGIBLE = "MSP_TENANT_NOT_ELIGIBLE"


def msp_error(status_code: int, code: str) -> HTTPException:
    """Fixed-shape error. Never echoes tenant ids, subjects or capabilities."""
    return HTTPException(status_code=status_code, detail={"code": code})


def _denied() -> HTTPException:
    return msp_error(403, MSP_ACCESS_DENIED)


def _customer_not_found() -> HTTPException:
    """One response for every reason an actor may not act for a customer:
    no relationship, not yet approved, suspended, revoked, expired, capability
    not delegated, or no such tenant. No oracle."""
    return msp_error(404, MSP_CUSTOMER_NOT_FOUND)


# ---------------------------------------------------------------------------
# Time and capability helpers
# ---------------------------------------------------------------------------


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def as_utc(value: Any) -> Optional[datetime]:
    """Normalise DB timestamps (aware, naive or ISO text on SQLite) to UTC."""
    if value is None:
        return None
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def canonical_capabilities(values: Iterable[str]) -> list[str]:
    """Validate against the delegation ceiling; return sorted, de-duplicated."""
    caps = sorted({str(v).strip() for v in values if str(v).strip()})
    if not caps or any(c not in MSP_DELEGABLE_PERMISSIONS for c in caps):
        raise msp_error(422, MSP_CAPABILITY_NOT_DELEGABLE)
    return caps


def decode_capabilities(raw: Any) -> frozenset[str]:
    if not raw:
        return frozenset()
    try:
        values = json.loads(raw) if isinstance(raw, str) else list(raw)
    except (TypeError, ValueError):
        return frozenset()
    return frozenset(str(v) for v in values) & MSP_DELEGABLE_PERMISSIONS


def encode_capabilities(caps: Iterable[str]) -> str:
    return json.dumps(sorted(set(caps)), separators=(",", ":"))


def effective_status(row: Any, now: Optional[datetime] = None) -> str:
    """Derived lifecycle: proposed | approved | active | expired | suspended | revoked.

    ``approved`` means approved but not yet effective. ``active`` and
    ``expired`` are never stored.
    """
    status = str(row.status)
    if status != "approved":
        return status
    now = now or utcnow()
    effective_at = as_utc(row.effective_at)
    expires_at = as_utc(row.expires_at)
    if expires_at is not None and now >= expires_at:
        return "expired"
    if effective_at is not None and now < effective_at:
        return "approved"
    return "active"


# ---------------------------------------------------------------------------
# Tenant and membership lookups (canonical tables, no copies)
# ---------------------------------------------------------------------------


def tenant_kind_and_name(db: Session, tenant_id: str) -> Optional[tuple[str, str]]:
    """Read the canonical tenant registry. None if the tenant does not exist
    or is not in an operable lifecycle state."""
    row = db.execute(
        text(
            "SELECT tenant_kind, display_name, lifecycle_state "
            "FROM tenants WHERE tenant_id = :tid"
        ),
        {"tid": tenant_id},
    ).fetchone()
    if row is None or str(row.lifecycle_state) != "active":
        return None
    return str(row.tenant_kind or "customer"), str(row.display_name or "")


def msp_organization_active(db: Session, msp_tenant_id: str) -> bool:
    row = db.get(MspOrganization, msp_tenant_id)
    return row is not None and str(row.status) == "active"


@dataclass(frozen=True)
class MspMembership:
    """Proof of a canonical, bound membership in an active MSP organization."""

    msp_tenant_id: str
    membership_id: str
    principal_id: str
    subject: str
    role: str


def resolve_msp_membership(
    db: Session, *, actor_ctx: ActorContext, msp_tenant_id: str
) -> MspMembership:
    """DB-canonical MSP membership. JWT/API-key role claims are ignored.

    Same row semantics as TENANT-ADMIN-001 ``check_tenant_admin_authority``
    (pre-bound membership_id, else bound subject), but any role: the role only
    bounds which delegated permissions the member can use.
    """
    if not msp_tenant_id or not actor_ctx or not actor_ctx.subject:
        raise _denied()
    if not msp_organization_active(db, msp_tenant_id):
        raise _denied()
    row = None
    if actor_ctx.membership_id:
        row = db.execute(
            text(
                "SELECT id, role, active, principal_id, identity_binding_status "
                "FROM tenant_users WHERE id = :mid AND tenant_id = :tid"
            ),
            {"mid": actor_ctx.membership_id, "tid": msp_tenant_id},
        ).fetchone()
    if row is None:
        row = db.execute(
            text(
                "SELECT id, role, active, principal_id, identity_binding_status "
                "FROM tenant_users WHERE tenant_id = :tid "
                "AND identity_subject = :subject "
                "AND identity_binding_status = 'bound' LIMIT 1"
            ),
            {"tid": msp_tenant_id, "subject": actor_ctx.subject},
        ).fetchone()
    if (
        row is None
        or not row.active
        or str(row.identity_binding_status) != "bound"
        or row.principal_id is None
    ):
        log.info("msp.membership_denied", extra={"msp_tenant_id": msp_tenant_id})
        raise _denied()
    return MspMembership(
        msp_tenant_id=msp_tenant_id,
        membership_id=str(row.id),
        principal_id=str(row.principal_id),
        subject=actor_ctx.subject,
        role=str(row.role),
    )


def principal_is_member_of(db: Session, *, principal_id: str, tenant_id: str) -> bool:
    """True when the principal holds an active membership in ``tenant_id``.

    Reads under ``tenant_id``'s RLS context; the caller restores its own.
    """
    set_tenant_context(db, tenant_id)
    row = db.execute(
        text(
            "SELECT 1 FROM tenant_users WHERE tenant_id = :tid "
            "AND principal_id = :pid AND active = :active LIMIT 1"
        ),
        {"tid": tenant_id, "pid": principal_id, "active": True},
    ).fetchone()
    return row is not None


# ---------------------------------------------------------------------------
# Relationship lookups
# ---------------------------------------------------------------------------


def load_relationship(db: Session, relationship_id: str) -> Any:
    return db.get(MspServiceRelationship, relationship_id)


def load_open_relationship(db: Session, *, msp_tenant_id: str, customer_id: str) -> Any:
    return (
        db.query(MspServiceRelationship)
        .filter(
            MspServiceRelationship.msp_tenant_id == msp_tenant_id,
            MspServiceRelationship.tenant_id == customer_id,
            MspServiceRelationship.status.in_(OPEN_RELATIONSHIP_STATUSES),
        )
        .one_or_none()
    )


def relationship_view(row: Any, *, now: Optional[datetime] = None) -> dict[str, Any]:
    """Safe projection shared by both parties. No subjects or membership ids."""

    def _iso(v: Any) -> Optional[str]:
        ts = as_utc(v)
        return ts.isoformat() if ts else None

    return {
        "relationship_id": str(row.id),
        "msp_tenant_id": str(row.msp_tenant_id),
        "customer_tenant_id": str(row.tenant_id),
        "status": effective_status(row, now),
        "requested_capabilities": sorted(
            decode_capabilities(row.requested_capabilities)
        ),
        "authorized_capabilities": sorted(
            decode_capabilities(row.authorized_capabilities)
        ),
        "proposed_at": _iso(row.proposed_at),
        "approved_at": _iso(row.approved_at),
        "effective_at": _iso(row.effective_at),
        "expires_at": _iso(row.expires_at),
        "suspended_at": _iso(row.suspended_at),
        "revoked_at": _iso(row.revoked_at),
        "revoked_by_party": row.revoked_by_party,
        "version": int(row.version),
    }


# ---------------------------------------------------------------------------
# The delegated-access decision
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DelegatedAccess:
    """Proof that delegated access was valid at ``checked_at``. Not reusable:
    every protected request must obtain a fresh one."""

    relationship_id: str
    msp_tenant_id: str
    customer_tenant_id: str
    effective_permissions: frozenset[str]
    expires_at: Optional[datetime]
    checked_at: datetime


def _delegated_access(
    db: Session,
    *,
    msp_tenant_id: str,
    customer_tenant_id: str,
    actor_permissions: frozenset[str],
    required: Optional[str],
    now: datetime,
) -> DelegatedAccess:
    if not customer_tenant_id or customer_tenant_id == msp_tenant_id:
        raise _customer_not_found()
    row = load_open_relationship(
        db, msp_tenant_id=msp_tenant_id, customer_id=customer_tenant_id
    )
    if row is None or effective_status(row, now) != "active":
        raise _customer_not_found()
    effective = (
        decode_capabilities(row.authorized_capabilities)
        & actor_permissions
        & MSP_DELEGABLE_PERMISSIONS
    )
    if not effective or (required is not None and required not in effective):
        raise _customer_not_found()
    return DelegatedAccess(
        relationship_id=str(row.id),
        msp_tenant_id=msp_tenant_id,
        customer_tenant_id=customer_tenant_id,
        effective_permissions=frozenset(effective),
        expires_at=as_utc(row.expires_at),
        checked_at=now,
    )


def resolve_actor_access(
    db: Session,
    *,
    actor_ctx: ActorContext,
    msp_tenant_id: str,
    customer_tenant_id: str,
    required: Optional[str] = None,
    now: Optional[datetime] = None,
) -> tuple[MspMembership, DelegatedAccess]:
    """Human MSP staff: membership role ∩ customer approval ∩ ceiling."""
    membership = resolve_msp_membership(
        db, actor_ctx=actor_ctx, msp_tenant_id=msp_tenant_id
    )
    access = _delegated_access(
        db,
        msp_tenant_id=msp_tenant_id,
        customer_tenant_id=customer_tenant_id,
        actor_permissions=ROLE_PERMISSIONS.get(membership.role, frozenset()),
        required=required,
        now=now or utcnow(),
    )
    return membership, access


def resolve_credential_access(
    db: Session,
    *,
    msp_tenant_id: str,
    customer_tenant_id: str,
    required: str,
    now: Optional[datetime] = None,
) -> DelegatedAccess:
    """Platform-issued MSP service credentials (control-plane ``msp`` scope).

    The credential's own scope is the caller's gate; this adds the parts the
    scope can never prove: an active MSP organization and a customer-approved,
    active relationship that delegates ``required``.
    """
    if not msp_tenant_id or not msp_organization_active(db, msp_tenant_id):
        raise _customer_not_found()
    return _delegated_access(
        db,
        msp_tenant_id=msp_tenant_id,
        customer_tenant_id=customer_tenant_id,
        actor_permissions=MSP_DELEGABLE_PERMISSIONS,
        required=required,
        now=now or utcnow(),
    )


def list_actor_customers(
    db: Session,
    *,
    membership: MspMembership,
    now: Optional[datetime] = None,
) -> list[tuple[Any, frozenset[str]]]:
    """Relationships through which this member currently has any permission."""
    now = now or utcnow()
    role_perms = ROLE_PERMISSIONS.get(membership.role, frozenset())
    rows = (
        db.query(MspServiceRelationship)
        .filter(
            MspServiceRelationship.msp_tenant_id == membership.msp_tenant_id,
            MspServiceRelationship.status == "approved",
        )
        .order_by(MspServiceRelationship.tenant_id)
        .all()
    )
    out: list[tuple[Any, frozenset[str]]] = []
    for row in rows:
        if effective_status(row, now) != "active":
            continue
        effective = (
            decode_capabilities(row.authorized_capabilities)
            & role_perms
            & MSP_DELEGABLE_PERMISSIONS
        )
        if effective:
            out.append((row, frozenset(effective)))
    return out


# ---------------------------------------------------------------------------
# Audit (existing per-tenant identity audit chain — no second ledger)
# ---------------------------------------------------------------------------


def correlation_id(request: Request) -> Optional[str]:
    rid = getattr(getattr(request, "state", None), "request_id", None)
    return str(rid)[:128] if rid else None


def emit_msp_audit(
    db: Session,
    *,
    chains: Iterable[str],
    restore_tenant: str,
    event_type: str,
    actor_subject: str,
    membership_id: Optional[str],
    reason_code: str,
    msp_tenant_id: str,
    customer_tenant_id: str,
    relationship_id: Optional[str],
    operation: str,
    capabilities: Iterable[str] = (),
    correlation: Optional[str] = None,
) -> None:
    """Append one event to each party's identity audit chain.

    Each write runs under that tenant's RLS context, then the caller's context
    is restored. The event binds actor, MSP, customer, relationship, effective
    authority, operation and correlation id; ``created_at`` is the timestamp.
    """
    details = {
        "msp_tenant_id": msp_tenant_id,
        "customer_tenant_id": customer_tenant_id,
        "relationship_id": relationship_id,
        "operation": operation,
        "capabilities": sorted(set(capabilities)),
        "result": "success",
    }
    for chain_tenant in dict.fromkeys(chains):
        set_tenant_context(db, chain_tenant)
        emit_identity_audit_event(
            db,
            tenant_id=chain_tenant,
            event_type=event_type,
            actor_user_id=actor_subject,
            membership_id=membership_id,
            reason_code=reason_code,
            correlation_id=correlation,
            details=details,
        )
    set_tenant_context(db, restore_tenant)
