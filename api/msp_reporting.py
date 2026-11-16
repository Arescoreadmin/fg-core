"""api/msp_reporting.py — MSP-007 customer-controlled report sharing and
partner managed reporting.

Not a standalone authority. It adds one record (migration 0209,
``msp_report_shares``): a customer's decision to let one MSP read one exact,
released Field Assessment report version — report id, version number and
manifest fingerprint — until an expiry. Everything else is reused, unchanged:

  * Report store — ``governance_reports`` (``GovernanceReportRecord``). No copy
    of a report or of evidence is ever made for the MSP.
  * Release decision — ``api.field_assessment._authoritative_report_state``:
    the single DRAFT / FINAL decision (independent human QA, no QA rejection,
    QUALIFIED production-qualification decision, clean signed proof, verified
    provenance). Only FINAL reports can be shared or read.
  * Integrity — ``api.field_assessment.report_integrity``: the same checks as
    POST /field-assessment/engagements/{id}/reports/{version}/verify
    (re-derived manifest fingerprint; Vault Transit or legacy Ed25519
    signature). A hash is reported as a hash, never as a signature.
  * Trust gate — ``enforce_report_export`` (the export route's gate).
  * Delivery state — GOV-DELIVERY-001 authorization and transport-attempt
    records, read only.
  * Relationship and read delegation — MSP-001 ``resolve_actor_access`` with
    ``report.read``: membership role ∩ customer-approved capabilities ∩ the
    read-only ceiling ``MSP_DELEGABLE_PERMISSIONS`` (unchanged, not widened).
  * Administrators — TENANT-ADMIN-001 ``check_tenant_admin_authority``.
  * MSP-003 — an MSP may ask for a report only for an engagement it initiated
    under one of its own grants; the grant itself grants no report access.
  * Audit — ``emit_msp_audit`` (both parties' identity hash chains) and, for
    content reads, the customer's engagement audit trail.

An MSP read of shared report content requires, at the moment of the call:

    MSP designation active  ∩  bound MSP membership whose role holds
    report.read  ∩  msp.multi_tenant entitlement  ∩  relationship active and
    delegating report.read  ∩  share active and unexpired  ∩  customer tenant
    active  ∩  the stored report still has the shared id, version and
    fingerprint  ∩  the report is FINAL now  ∩  integrity verifies

Nothing is cached. Revocation, expiry, suspension, membership or entitlement
removal and a superseded or re-qualified report apply on the next call. No
billing record is written: MSP-006 delivery remains the only charge.
See docs/msp/MSP_007_ARCHITECTURE.md.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from api.actor_context import ActorContext
from api.auth_dispatch import require_permission
from api.auth_scopes import require_scopes, resolve_authoritative_tenant
from api.db import set_tenant_context
from api.db_models_governance_report import GovernanceReportRecord
from api.db_models_identity import TenantIdentityAuditEvent
from api.db_models_msp import MspAssessmentGrant, MspReportShare
from api.deps import auth_ctx_db_session
from api.entitlements import _ensure_admin_gateway_tenant_bound, require_capability
from api.identity.store import verify_identity_audit_chain
from api.msp_authority import (
    MSP_ACCESS_DENIED,
    MSP_ORGANIZATION_INACTIVE,
    MSP_APPROVAL_REQUIRES_CUSTOMER,
    MSP_APPROVAL_WINDOW_INVALID,
    MSP_SELF_APPROVAL_DENIED,
    as_utc,
    correlation_id,
    effective_status,
    emit_msp_audit,
    load_relationship,
    msp_error,
    MspMembership,
    msp_organization_active,
    principal_is_member_of,
    resolve_actor_access,
    resolve_msp_membership,
    tenant_kind_and_name,
    utcnow,
)
from api.tenant_admin_authority import (
    TenantAdminAuthority,
    check_tenant_admin_authority,
)

router = APIRouter(prefix="/admin/msp", tags=["msp-007"])

# ---------------------------------------------------------------------------
# Limits and contract
# ---------------------------------------------------------------------------

# The delegated MSP-001 capability a shared report is read under. Sharing
# adds an exact per-report decision on top of it; it never replaces it.
SHARE_READ_CAPABILITY = "report.read"
MAX_SHARE_DAYS = 90
# Bound on one downloaded report document (the canonical report_json).
MAX_DOWNLOAD_BYTES = 10 * 1024 * 1024
_DEFAULT_PAGE = 50
_MAX_PAGE = 200
_KEY_PATTERN = r"^[A-Za-z0-9._:-]{1,128}$"
_ID_PATTERN = r"^[A-Za-z0-9._:-]{1,255}$"
_FINGERPRINT_PATTERN = r"^[0-9a-f]{64}$"

MSP_REPORT_SHARE_NOT_FOUND = "MSP_REPORT_SHARE_NOT_FOUND"
MSP_REPORT_SHARE_CONFLICT = "MSP_REPORT_SHARE_CONFLICT"
MSP_REPORT_SHARE_INVALID_TRANSITION = "MSP_REPORT_SHARE_INVALID_TRANSITION"
MSP_REPORT_SHARE_UNAVAILABLE = "MSP_REPORT_SHARE_UNAVAILABLE"
MSP_REPORT_NOT_FOUND = "MSP_REPORT_NOT_FOUND"
MSP_REPORT_NOT_SHAREABLE = "MSP_REPORT_NOT_SHAREABLE"
MSP_REPORT_FINGERPRINT_MISMATCH = "MSP_REPORT_FINGERPRINT_MISMATCH"
MSP_REPORT_INTEGRITY_FAILED = "MSP_REPORT_INTEGRITY_FAILED"
MSP_REPORT_READ_NOT_DELEGATED = "MSP_REPORT_READ_NOT_DELEGATED"
MSP_REPORT_TOO_LARGE = "MSP_REPORT_TOO_LARGE"
MSP_RELATIONSHIP_INACTIVE = "MSP_RELATIONSHIP_INACTIVE"
MSP_ASSESSMENT_GRANT_NOT_FOUND = "MSP_ASSESSMENT_GRANT_NOT_FOUND"

# Integrity vocabulary (only what canonical verification actually returns).
HASH_VERIFIED = "HASH_VERIFIED"
SIGNATURE_VERIFIED = "SIGNATURE_VERIFIED"
AUDIT_CHAIN_VERIFIED = "AUDIT_CHAIN_VERIFIED"
VERIFICATION_UNAVAILABLE = "VERIFICATION_UNAVAILABLE"
VERIFICATION_FAILED = "VERIFICATION_FAILED"

# Why a share cannot be read now, in precedence order.
_STATUS_BLOCKERS = {
    "requested": "SHARE_PENDING_CUSTOMER",
    "rejected": "SHARE_REJECTED",
    "withdrawn": "SHARE_WITHDRAWN",
    "revoked": "SHARE_REVOKED",
}
_INTEGRITY_BLOCKERS = frozenset(
    {"REPORT_INTEGRITY_FAILED", "SIGNATURE_FAILED", "EVIDENCE_CHAIN_FAILED"}
)


def _share_not_found() -> HTTPException:
    """Unknown, foreign and invisible shares are indistinguishable."""
    return msp_error(404, MSP_REPORT_SHARE_NOT_FOUND)


def _report_not_found() -> HTTPException:
    """Unknown and foreign reports are indistinguishable."""
    return msp_error(404, MSP_REPORT_NOT_FOUND)


def _unavailable(blockers: list[str]) -> HTTPException:
    return HTTPException(
        status_code=409,
        detail={"code": MSP_REPORT_SHARE_UNAVAILABLE, "blockers": blockers},
        headers={"Cache-Control": "no-store"},
    )


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class ShareReportBody(BaseModel):
    """A customer shares one exact report version with one of its MSPs."""

    model_config = ConfigDict(extra="forbid")

    relationship_id: str = Field(..., min_length=1, max_length=36)
    report_id: str = Field(..., pattern=_ID_PATTERN)
    manifest_hash: str = Field(..., pattern=_FINGERPRINT_PATTERN)
    expires_at: datetime
    request_key: str = Field(..., pattern=_KEY_PATTERN)


class RequestShareBody(BaseModel):
    """An MSP asks for the report of an engagement it initiated (MSP-003)."""

    model_config = ConfigDict(extra="forbid")

    grant_id: str = Field(..., min_length=1, max_length=36)
    request_key: str = Field(..., pattern=_KEY_PATTERN)


class DecisionBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_version: int = Field(..., ge=1)


class ApproveShareBody(DecisionBody):
    report_id: str = Field(..., pattern=_ID_PATTERN)
    manifest_hash: str = Field(..., pattern=_FINGERPRINT_PATTERN)
    expires_at: datetime


# ---------------------------------------------------------------------------
# Authority helpers
# ---------------------------------------------------------------------------


def _bind_console_gateway_tenant(request: Request) -> None:
    """MSP-002 console transport: verify the delegation proof before the actor
    is resolved (same binder as api/msp.py and api/msp_orchestration.py)."""
    _ensure_admin_gateway_tenant_bound(request)


_CONSOLE_BIND = Depends(_bind_console_gateway_tenant)
# The MSP-001 entitlement gate, on every MSP-side request and read.
_MSP_ENTITLED = Depends(require_capability("msp.multi_tenant"))


def _caller_tenant_from_auth(request: Request, actor_ctx: ActorContext) -> str:
    """The caller's own tenant, from the bound credential only."""
    tenant = str(actor_ctx.tenant_id or "").strip()
    if not tenant:
        raise msp_error(403, MSP_ACCESS_DENIED)
    return resolve_authoritative_tenant(request, actor_ctx, tenant)


def _customer_admin(
    db: Session, actor_ctx: ActorContext, caller: str
) -> TenantAdminAuthority:
    authority = check_tenant_admin_authority(db, actor_ctx=actor_ctx, tenant_id=caller)
    set_tenant_context(db, caller)
    return authority


def _load_share(db: Session, share_id: str, caller: str) -> MspReportShare:
    """A share, only for one of its two parties; otherwise 404."""
    set_tenant_context(db, caller)
    row = db.get(MspReportShare, str(share_id)[:64])
    if row is None or caller not in (str(row.tenant_id), str(row.msp_tenant_id)):
        raise _share_not_found()
    return row


def _transition_share(
    db: Session,
    row: MspReportShare,
    *,
    expected_status: tuple[str, ...],
    expected_version: Optional[int],
    values: dict[str, Any],
) -> None:
    """Compare-and-set on (id, status, version). A concurrent change loses."""
    if str(row.status) not in expected_status or (
        expected_version is not None and int(row.version) != int(expected_version)
    ):
        raise msp_error(409, MSP_REPORT_SHARE_INVALID_TRANSITION)
    update: dict[Any, Any] = {
        **values,
        "version": int(row.version) + 1,
        "updated_at": utcnow(),
    }
    try:
        changed = (
            db.query(MspReportShare)
            .filter(
                MspReportShare.id == row.id,
                MspReportShare.status == row.status,
                MspReportShare.version == row.version,
            )
            .update(update, synchronize_session=False)
        )
        db.flush()
    except IntegrityError:
        # The partial unique index: another active share of this report for
        # this MSP already exists.
        db.rollback()
        raise msp_error(409, MSP_REPORT_SHARE_CONFLICT)
    if changed != 1:
        db.rollback()
        raise msp_error(409, MSP_REPORT_SHARE_INVALID_TRANSITION)
    db.expire_all()


def _iso(value: Any) -> Optional[str]:
    dt = as_utc(value)
    return dt.isoformat() if dt else None


def _audit_share(
    db: Session,
    *,
    caller: str,
    row: MspReportShare,
    event_type: str,
    reason_code: str,
    actor_subject: str,
    membership_id: Optional[str],
    operation: str,
    previous_state: Optional[str],
    new_state: str,
    correlation: Optional[str],
    decision: Optional[str] = None,
    blockers: Optional[list[str]] = None,
    integrity: Optional[dict[str, Any]] = None,
) -> None:
    extra: dict[str, Any] = {
        "share_id": str(row.id),
        "engagement_id": str(row.engagement_id),
        "grant_id": row.source_grant_id,
        "report_id": row.report_id,
        "report_version": row.report_version,
        "manifest_hash": row.manifest_hash,
        "expires_at": _iso(row.expires_at),
        "previous_state": previous_state,
        "new_state": new_state,
    }
    if decision is not None:
        extra["decision"] = decision
    if blockers is not None:
        extra["blockers"] = list(blockers)
    if integrity is not None:
        extra["content_integrity"] = integrity.get("content")
        extra["signature_integrity"] = integrity.get("signature")
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
        capabilities=(SHARE_READ_CAPABILITY,),
        correlation=correlation,
        extra=extra,
    )


# ---------------------------------------------------------------------------
# Canonical report state (read only)
# ---------------------------------------------------------------------------


def _load_report(
    db: Session, customer: str, report_id: str
) -> Optional[GovernanceReportRecord]:
    """An engagement report of ``customer``, read under its RLS context."""
    set_tenant_context(db, customer)
    row = db.get(GovernanceReportRecord, str(report_id)[:255])
    if row is None or str(row.tenant_id) != customer or not row.engagement_id:
        return None
    return row


def _delivery_state(db: Session, customer: str, record: Any) -> dict[str, bool]:
    """GOV-DELIVERY-001 records for this report version, read only."""
    from api.db_models_field_assessment import (  # noqa: PLC0415
        FaGovernedDeliveryAttempt,
        FaGovernedDeliveryAuthorization,
    )

    authorized = (
        db.query(FaGovernedDeliveryAuthorization.id)
        .filter(
            FaGovernedDeliveryAuthorization.tenant_id == customer,
            FaGovernedDeliveryAuthorization.report_id == str(record.id),
            FaGovernedDeliveryAuthorization.report_fingerprint
            == str(record.manifest_hash),
            FaGovernedDeliveryAuthorization.outcome == "AUTHORIZED",
        )
        .first()
        is not None
    )
    delivered = (
        db.query(FaGovernedDeliveryAttempt.id)
        .filter(
            FaGovernedDeliveryAttempt.tenant_id == customer,
            FaGovernedDeliveryAttempt.report_id == str(record.id),
            FaGovernedDeliveryAttempt.report_fingerprint == str(record.manifest_hash),
            FaGovernedDeliveryAttempt.outcome == "SUCCEEDED",
        )
        .first()
        is not None
    )
    return {"delivery_authorized": authorized, "delivered": delivered}


def report_release_view(
    db: Session, customer: str, record: Any, *, restore_tenant: str
) -> dict[str, Any]:
    """Every distinct lifecycle fact for one report version, from canonical
    authorities only, plus whether it may be shared. Never a score."""
    return _release_facts(db, customer, record, restore_tenant=restore_tenant)[0]


def _release_facts(
    db: Session, customer: str, record: Any, *, restore_tenant: str
) -> tuple[dict[str, Any], Any]:
    """``report_release_view`` plus the trust-gate inputs (internal only)."""
    from api.field_assessment import (  # noqa: PLC0415
        _authoritative_report_state,
        _customer_report_status,
        report_integrity,
    )

    try:
        set_tenant_context(db, customer)
        engagement_id = str(record.engagement_id)
        state, provenance = _authoritative_report_state(
            db, tenant_id=customer, engagement_id=engagement_id, record=record
        )
        integrity = report_integrity(record, engagement_id=engagement_id)
        trust = provenance.to_trust_inputs()
        chain_valid = getattr(trust, "chain_valid", None)
        delivery = _delivery_state(db, customer, record)
    finally:
        set_tenant_context(db, restore_tenant)
    state_name = str(state.get("state") or "UNKNOWN")
    audit_chain = (
        VERIFICATION_UNAVAILABLE
        if chain_valid is None
        else (AUDIT_CHAIN_VERIFIED if chain_valid else VERIFICATION_FAILED)
    )
    integrity_view = {
        "content": integrity.content,
        "signature": integrity.signature,
        "signature_kind": integrity.signature_kind,
        "evidence_chain": audit_chain,
    }
    blockers: list[str] = []
    if state_name != "FINAL":
        blockers.append("REPORT_NOT_RELEASED")
    if integrity.content != HASH_VERIFIED:
        blockers.append("REPORT_INTEGRITY_FAILED")
    if integrity.signature == VERIFICATION_FAILED:
        blockers.append("SIGNATURE_FAILED")
    if audit_chain == VERIFICATION_FAILED:
        blockers.append("EVIDENCE_CHAIN_FAILED")
    provenance_summary = state.get("provenance") or {}
    view = {
        "report_id": str(record.id),
        "engagement_id": engagement_id,
        "version": int(record.version),
        "report_type": record.report_type,
        "generated_at": record.generated_at,
        "schema_version": record.schema_version,
        "manifest_hash": str(record.manifest_hash),
        "lifecycle": {
            "exists": True,
            "state": state_name,
            "status": _customer_report_status(state),
            "qa_approved": record.qa_approved_by is not None,
            "independent_qa": bool(state.get("independent_qa")),
            "production_qualified": bool(state.get("production_qualified")),
            "released": state_name == "FINAL",
            "limited_coverage": bool(state.get("limited_coverage")),
            "release_blockers": list(state.get("release_blockers") or []),
            **delivery,
        },
        "integrity": integrity_view,
        "provenance": {
            "decision": provenance_summary.get("decision"),
            "snapshot_fingerprint": provenance_summary.get("snapshot_fingerprint"),
            "evidence_count": provenance_summary.get("evidence_count"),
            "source_authenticated": provenance_summary.get("source_authenticated"),
            "verified_at": provenance_summary.get("verified_at"),
        },
        "share_eligible": not blockers,
        "share_blockers": blockers,
    }
    return view, trust


def _share_status(row: MspReportShare, now: datetime) -> str:
    status = str(row.status)
    expires_at = as_utc(row.expires_at)
    if status == "active" and expires_at is not None and now >= expires_at:
        return "expired"
    return status


class MspShareAccess:
    """The outcome of one MSP access evaluation."""

    def __init__(
        self,
        membership: MspMembership,
        blockers: list[str],
        record: Optional[GovernanceReportRecord] = None,
        view: Optional[dict[str, Any]] = None,
        trust: Any = None,
    ) -> None:
        self.membership = membership
        self.blockers = blockers
        self.record = record
        self.view = view
        self.trust = trust


def evaluate_msp_access(
    db: Session,
    row: MspReportShare,
    *,
    actor_ctx: ActorContext,
    caller: str,
    now: datetime,
) -> MspShareAccess:
    """Why the MSP cannot read this share now (no blockers: it can), in
    precedence order, re-derived from canonical state on every call.

    The caller must first be a bound member of an active MSP (403 otherwise,
    before anything about the share is disclosed). Everything else about the
    share is reported as blockers.
    """
    membership = resolve_msp_membership(db, actor_ctx=actor_ctx, msp_tenant_id=caller)
    set_tenant_context(db, caller)
    status = _share_status(row, now)
    if status in _STATUS_BLOCKERS:
        return MspShareAccess(membership, [_STATUS_BLOCKERS[status]])
    if status == "expired":
        return MspShareAccess(membership, ["SHARE_EXPIRED"])
    customer = str(row.tenant_id)
    try:
        _, access = resolve_actor_access(
            db,
            actor_ctx=actor_ctx,
            msp_tenant_id=caller,
            customer_tenant_id=customer,
            required=SHARE_READ_CAPABILITY,
            now=now,
        )
    except HTTPException as exc:
        set_tenant_context(db, caller)
        if exc.status_code == 403:
            raise
        return MspShareAccess(membership, ["RELATIONSHIP_NOT_DELEGATING_REPORT_READ"])
    set_tenant_context(db, caller)
    if access.relationship_id != str(row.relationship_id):
        return MspShareAccess(membership, ["RELATIONSHIP_INACTIVE"])
    info = tenant_kind_and_name(db, customer)
    if info is None or info[0] != "customer":
        return MspShareAccess(membership, ["CUSTOMER_TENANT_INACTIVE"])
    record = _load_report(db, customer, str(row.report_id))
    set_tenant_context(db, caller)
    if record is None:
        return MspShareAccess(membership, ["REPORT_UNAVAILABLE"])
    if int(record.version) != int(row.report_version) or str(
        record.manifest_hash
    ) != str(row.manifest_hash):
        return MspShareAccess(membership, ["REPORT_VERSION_CHANGED"], record)
    view, trust = _release_facts(db, customer, record, restore_tenant=caller)
    return MspShareAccess(membership, list(view["share_blockers"]), record, view, trust)


def _next_actions(row: MspReportShare, status: str, blockers: list[str]) -> list:
    if status == "requested":
        return [{"owner": "customer", "code": "REVIEW_REPORT_SHARE_REQUEST"}]
    if status == "expired":
        return [{"owner": "customer", "code": "RENEW_REPORT_SHARE"}]
    if status == "active" and (
        "REPORT_NOT_RELEASED" in blockers or "REPORT_VERSION_CHANGED" in blockers
    ):
        return [{"owner": "customer", "code": "SHARE_CURRENT_RELEASED_VERSION"}]
    if status == "active" and "RELATIONSHIP_NOT_DELEGATING_REPORT_READ" in blockers:
        return [{"owner": "customer", "code": "DELEGATE_REPORT_READ"}]
    return []


def share_view(
    db: Session,
    row: MspReportShare,
    *,
    caller: str,
    actor_ctx: ActorContext,
    now: Optional[datetime] = None,
) -> dict[str, Any]:
    """One share as its caller may see it. The MSP never sees the customer's
    deciding people; the customer never sees the MSP's requesting people."""
    now = now or utcnow()
    party = "customer" if caller == str(row.tenant_id) else "msp"
    status = _share_status(row, now)
    blockers: list[str] = []
    if party == "msp":
        try:
            blockers = evaluate_msp_access(
                db, row, actor_ctx=actor_ctx, caller=caller, now=now
            ).blockers
        except HTTPException:
            set_tenant_context(db, caller)
            blockers = ["MSP_ACCESS_DENIED"]
    info = tenant_kind_and_name(db, str(row.tenant_id))
    view: dict[str, Any] = {
        "share_id": str(row.id),
        "party": party,
        "customer_tenant_id": str(row.tenant_id),
        "customer_name": info[1] if info else None,
        "msp_tenant_id": str(row.msp_tenant_id),
        "relationship_id": str(row.relationship_id),
        "origin": str(row.origin),
        "engagement_id": str(row.engagement_id),
        "grant_id": row.source_grant_id,
        "report_id": row.report_id,
        "report_version": row.report_version,
        "manifest_hash": row.manifest_hash,
        "status": status,
        "requested_at": _iso(row.requested_at),
        "decided_at": _iso(row.decided_at),
        "expires_at": _iso(row.expires_at),
        "revoked_at": _iso(row.revoked_at),
        "version": int(row.version),
        "next_actions": _next_actions(row, status, blockers),
    }
    if party == "msp":
        view["access"] = {
            "state": "available" if status == "active" and not blockers else "blocked",
            "blockers": blockers,
        }
    else:
        view["decided_by_subject"] = row.decided_by_subject
        view["revoked_by_subject"] = row.revoked_by_subject
    return view


def _validated_expiry(value: datetime, now: datetime, rel: Any) -> datetime:
    expires_at = as_utc(value)
    if (
        expires_at is None
        or expires_at <= now
        or expires_at > now + timedelta(days=MAX_SHARE_DAYS)
    ):
        raise msp_error(422, MSP_APPROVAL_WINDOW_INVALID)
    rel_expiry = as_utc(rel.expires_at)
    if rel_expiry is not None and rel_expiry < expires_at:
        expires_at = rel_expiry
    return expires_at


def _shareable_report(
    db: Session,
    *,
    caller: str,
    report_id: str,
    manifest_hash: str,
    engagement_id: Optional[str] = None,
) -> tuple[GovernanceReportRecord, dict[str, Any]]:
    """The customer's own FINAL, verified report, exactly as it saw it."""
    record = _load_report(db, caller, report_id)
    if record is None or (
        engagement_id is not None and str(record.engagement_id) != engagement_id
    ):
        set_tenant_context(db, caller)
        raise _report_not_found()
    if str(record.manifest_hash) != manifest_hash:
        raise msp_error(409, MSP_REPORT_FINGERPRINT_MISMATCH)
    view = report_release_view(db, caller, record, restore_tenant=caller)
    if not view["share_eligible"]:
        raise HTTPException(
            status_code=409,
            detail={
                "code": MSP_REPORT_NOT_SHAREABLE,
                "blockers": view["share_blockers"],
            },
        )
    return record, view


def _customer_relationship(db: Session, *, caller: str, relationship_id: str) -> Any:
    """An active relationship of this customer that delegates report.read."""
    from api.msp_authority import decode_capabilities  # noqa: PLC0415

    rel = load_relationship(db, str(relationship_id)[:36])
    if rel is None or str(rel.tenant_id) != caller:
        raise msp_error(404, "MSP_RELATIONSHIP_NOT_FOUND")
    if effective_status(rel, utcnow()) != "active":
        raise msp_error(409, MSP_RELATIONSHIP_INACTIVE)
    if SHARE_READ_CAPABILITY not in decode_capabilities(rel.authorized_capabilities):
        raise msp_error(409, MSP_REPORT_READ_NOT_DELEGATED)
    return rel


def _refuse_msp_member(
    db: Session, authority: TenantAdminAuthority, *, caller: str, msp_tenant_id: str
) -> None:
    """No MSP staff member can approve the MSP's own evidence access."""
    if principal_is_member_of(
        db, principal_id=authority.principal_id, tenant_id=msp_tenant_id
    ):
        set_tenant_context(db, caller)
        raise msp_error(403, MSP_SELF_APPROVAL_DENIED)
    set_tenant_context(db, caller)


def _retire_expired_share(
    db: Session,
    *,
    caller: str,
    msp_tenant_id: str,
    report_id: str,
    authority: TenantAdminAuthority,
    correlation: Optional[str],
) -> None:
    """Retire an active-but-expired share of this report for this MSP, so it
    can be shared again. Same transaction as the new share; the old row and
    its history stay (status ``expired``). An unexpired active share is left
    alone, so the one-active-share invariant still refuses a duplicate."""
    now = utcnow()
    rows = (
        db.query(MspReportShare)
        .filter(
            MspReportShare.tenant_id == caller,
            MspReportShare.msp_tenant_id == msp_tenant_id,
            MspReportShare.report_id == report_id,
            MspReportShare.status == "active",
        )
        .all()
    )
    for old in rows:
        if _share_status(old, now) != "expired":
            continue
        share_id = str(old.id)
        _transition_share(
            db,
            old,
            expected_status=("active",),
            expected_version=int(old.version),
            values={"status": "expired"},
        )
        retired = _load_share(db, share_id, caller)
        _audit_share(
            db,
            caller=caller,
            row=retired,
            event_type="tenant.msp.report_share_expired",
            reason_code="MSP_REPORT_SHARE_EXPIRED",
            actor_subject=authority.subject,
            membership_id=authority.membership_id,
            operation="report_share.expire",
            previous_state="active",
            new_state="expired",
            correlation=correlation,
            decision="expired",
        )


# ---------------------------------------------------------------------------
# Customer: shareable reports
# ---------------------------------------------------------------------------


@router.get(
    "/reports/shareable",
    dependencies=[_CONSOLE_BIND, Depends(require_scopes("admin:read"))],
)
def list_shareable_reports(
    request: Request,
    engagement_id: Optional[str] = Query(None, max_length=64),
    limit: int = Query(_DEFAULT_PAGE, ge=1, le=_MAX_PAGE),
    offset: int = Query(0, ge=0),
    actor_ctx: ActorContext = Depends(require_permission("tenant.configure")),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """The customer's own report versions with every lifecycle fact and
    whether each may be shared. Only the customer's tenant_admin; only the
    caller's own tenant (never a query parameter)."""
    caller = _caller_tenant_from_auth(request, actor_ctx)
    _customer_admin(db, actor_ctx, caller)
    q = db.query(GovernanceReportRecord).filter(
        GovernanceReportRecord.tenant_id == caller,
        GovernanceReportRecord.engagement_id.isnot(None),
    )
    if engagement_id:
        q = q.filter(GovernanceReportRecord.engagement_id == engagement_id)
    total = q.count()
    rows = (
        q.order_by(
            GovernanceReportRecord.generated_at.desc(),
            GovernanceReportRecord.id.desc(),
        )
        .offset(offset)
        .limit(limit)
        .all()
    )
    items = [report_release_view(db, caller, r, restore_tenant=caller) for r in rows]
    next_offset = offset + len(items) if offset + len(items) < total else None
    return {
        "tenant_id": caller,
        "items": items,
        "total": total,
        "limit": limit,
        "offset": offset,
        "next_offset": next_offset,
    }


# ---------------------------------------------------------------------------
# Shares: list and history (either party)
# ---------------------------------------------------------------------------


def _party_authority(
    db: Session, actor_ctx: ActorContext, caller: str, party: str
) -> tuple[str, Optional[str]]:
    """(subject, membership_id) of a caller acting as ``party``.

    The customer side is its canonical tenant_admin; the MSP side is any bound
    member of an active MSP (its role still bounds what it can read)."""
    if party == "customer":
        authority = _customer_admin(db, actor_ctx, caller)
        return authority.subject, authority.membership_id
    membership = resolve_msp_membership(db, actor_ctx=actor_ctx, msp_tenant_id=caller)
    set_tenant_context(db, caller)
    return membership.subject, membership.membership_id


@router.get(
    "/report-shares",
    dependencies=[_CONSOLE_BIND, Depends(require_scopes("admin:read"))],
)
def list_report_shares(
    request: Request,
    party: str = Query(..., pattern="^(customer|msp)$"),
    customer_tenant_id: Optional[str] = Query(None, max_length=128),
    status: Optional[str] = Query(
        None, pattern="^(requested|active|rejected|withdrawn|revoked|expired)$"
    ),
    limit: int = Query(_DEFAULT_PAGE, ge=1, le=_MAX_PAGE),
    offset: int = Query(0, ge=0),
    actor_ctx: ActorContext = Depends(require_permission("report.read")),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """Shares where the caller is ``party``. The MSP may filter by customer;
    each MSP row carries its live access state and blockers."""
    caller = _caller_tenant_from_auth(request, actor_ctx)
    _party_authority(db, actor_ctx, caller, party)
    column = (
        MspReportShare.tenant_id
        if party == "customer"
        else MspReportShare.msp_tenant_id
    )
    q = db.query(MspReportShare).filter(column == caller)
    if customer_tenant_id and party == "msp":
        q = q.filter(MspReportShare.tenant_id == customer_tenant_id)
    if status:
        q = q.filter(MspReportShare.status == status)
    total = q.count()
    rows = (
        q.order_by(MspReportShare.requested_at.desc(), MspReportShare.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    now = utcnow()
    items = [
        share_view(db, r, caller=caller, actor_ctx=actor_ctx, now=now) for r in rows
    ]
    next_offset = offset + len(items) if offset + len(items) < total else None
    return {
        "tenant_id": caller,
        "party": party,
        "items": items,
        "total": total,
        "limit": limit,
        "offset": offset,
        "next_offset": next_offset,
    }


# Events whose acting person the data owner may always see: reads of its
# shared evidence (chain of custody). Other events follow the MSP-002 rule:
# a party sees only its own people.
_ACCESS_OPERATIONS = frozenset({"report.verify", "report.download"})
_CUSTOMER_SHARE_OPERATIONS = frozenset(
    {
        "report_share.approve",
        "report_share.reject",
        "report_share.revoke",
        "report_share.expire",
    }
)


@router.get(
    "/report-shares/{share_id}/events",
    dependencies=[_CONSOLE_BIND, Depends(require_scopes("admin:read"))],
)
def list_report_share_events(
    share_id: str,
    request: Request,
    limit: int = Query(100, ge=1, le=_MAX_PAGE),
    offset: int = Query(0, ge=0),
    actor_ctx: ActorContext = Depends(require_permission("report.read")),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """This share's history, including every read and refused read, from the
    caller's own verified identity audit chain. It never reads the other
    party's chain and survives revocation."""
    caller = _caller_tenant_from_auth(request, actor_ctx)
    row = _load_share(db, share_id, caller)
    party = "customer" if caller == str(row.tenant_id) else "msp"
    _party_authority(db, actor_ctx, caller, party)
    base = db.query(TenantIdentityAuditEvent).filter(
        TenantIdentityAuditEvent.tenant_id == caller,
        TenantIdentityAuditEvent.event_type.like("tenant.msp.report%"),
        TenantIdentityAuditEvent.details_json["share_id"].as_string() == str(row.id),
    )
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
        actor_party = "customer" if operation in _CUSTOMER_SHARE_OPERATIONS else "msp"
        visible = actor_party == party or (
            party == "customer" and operation in _ACCESS_OPERATIONS
        )
        created = as_utc(ev.created_at)
        items.append(
            {
                "event_type": ev.event_type,
                "occurred_at": created.isoformat() if created else None,
                "operation": operation,
                "decision": details.get("decision"),
                "blockers": list(details.get("blockers") or []),
                "report_id": details.get("report_id"),
                "report_version": details.get("report_version"),
                "manifest_hash": details.get("manifest_hash"),
                "actor_party": actor_party,
                "actor_subject": ev.actor_user_id if visible else None,
                "correlation_id": ev.correlation_id,
                "event_hash": ev.event_hash,
            }
        )
    next_offset = offset + len(items) if offset + len(items) < total else None
    return {
        "tenant_id": caller,
        "share_id": str(row.id),
        "party": party,
        "chain_verified": bool(verify_identity_audit_chain(db, caller)),
        "items": items,
        "total": total,
        "limit": limit,
        "offset": offset,
        "next_offset": next_offset,
    }


# ---------------------------------------------------------------------------
# Customer: share, approve, reject, revoke
# ---------------------------------------------------------------------------


@router.post(
    "/report-shares",
    dependencies=[_CONSOLE_BIND, Depends(require_scopes("admin:write"))],
)
def share_report(
    body: ShareReportBody,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("tenant.configure")),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """The customer's tenant_admin shares one exact, FINAL report version with
    one of its MSPs, until ``expires_at`` (at most 90 days, never past the
    relationship). ``manifest_hash`` must be the fingerprint the customer
    reviewed, so a report that changed in between is never shared.

    Idempotent on ``request_key``: a replay for the same report returns the
    share with ``created: false``; a different report under the same key, or
    a second active share of the same report, is a 409.
    """
    caller = _caller_tenant_from_auth(request, actor_ctx)
    authority = _customer_admin(db, actor_ctx, caller)
    rel = _customer_relationship(
        db, caller=caller, relationship_id=body.relationship_id
    )
    msp = str(rel.msp_tenant_id)

    def _find() -> Optional[MspReportShare]:
        return (
            db.query(MspReportShare)
            .filter(
                MspReportShare.tenant_id == caller,
                MspReportShare.msp_tenant_id == msp,
                MspReportShare.origin == "customer",
                MspReportShare.request_key == body.request_key,
            )
            .first()
        )

    def _replay(existing: MspReportShare) -> dict[str, Any]:
        if (str(existing.report_id), str(existing.manifest_hash)) != (
            body.report_id,
            body.manifest_hash,
        ):
            raise msp_error(409, MSP_REPORT_SHARE_CONFLICT)
        return {
            **share_view(db, existing, caller=caller, actor_ctx=actor_ctx),
            "created": False,
        }

    existing = _find()
    if existing is not None:
        return _replay(existing)
    _refuse_msp_member(db, authority, caller=caller, msp_tenant_id=msp)
    if not msp_organization_active(db, msp):
        raise msp_error(409, MSP_ORGANIZATION_INACTIVE)
    now = utcnow()
    expires_at = _validated_expiry(body.expires_at, now, rel)
    record, _ = _shareable_report(
        db, caller=caller, report_id=body.report_id, manifest_hash=body.manifest_hash
    )
    _retire_expired_share(
        db,
        caller=caller,
        msp_tenant_id=msp,
        report_id=str(record.id),
        authority=authority,
        correlation=correlation_id(request),
    )
    row = MspReportShare(
        id=str(uuid.uuid4()),
        tenant_id=caller,
        msp_tenant_id=msp,
        relationship_id=str(rel.id),
        origin="customer",
        request_key=body.request_key,
        engagement_id=str(record.engagement_id),
        source_grant_id=None,
        report_id=str(record.id),
        report_version=int(record.version),
        manifest_hash=str(record.manifest_hash),
        status="active",
        requested_by_subject=authority.subject,
        requested_at=now,
        decided_by_subject=authority.subject,
        decided_by_membership_id=authority.membership_id,
        decided_at=now,
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
            raise msp_error(409, MSP_REPORT_SHARE_CONFLICT)
        return _replay(existing)
    _audit_share(
        db,
        caller=caller,
        row=row,
        event_type="tenant.msp.report_share_approved",
        reason_code="MSP_REPORT_SHARE_APPROVED",
        actor_subject=authority.subject,
        membership_id=authority.membership_id,
        operation="report_share.approve",
        previous_state=None,
        new_state="active",
        correlation=correlation_id(request),
        decision="approved",
    )
    view = {**share_view(db, row, caller=caller, actor_ctx=actor_ctx), "created": True}
    db.commit()
    return view


def _customer_share(
    db: Session, actor_ctx: ActorContext, caller: str, share_id: str
) -> tuple[MspReportShare, TenantAdminAuthority]:
    row = _load_share(db, share_id, caller)
    if caller != str(row.tenant_id):
        raise msp_error(403, MSP_APPROVAL_REQUIRES_CUSTOMER)
    return row, _customer_admin(db, actor_ctx, caller)


@router.post(
    "/report-shares/{share_id}/approve",
    dependencies=[_CONSOLE_BIND, Depends(require_scopes("admin:write"))],
)
def approve_report_share(
    share_id: str,
    body: ApproveShareBody,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("tenant.configure")),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """The customer answers an MSP request with one exact FINAL version of the
    requested engagement's report. Never the requester, never an MSP member."""
    caller = _caller_tenant_from_auth(request, actor_ctx)
    row, authority = _customer_share(db, actor_ctx, caller, share_id)
    if authority.subject == str(row.requested_by_subject):
        raise msp_error(403, MSP_SELF_APPROVAL_DENIED)
    _refuse_msp_member(
        db, authority, caller=caller, msp_tenant_id=str(row.msp_tenant_id)
    )
    if str(row.status) != "requested" or int(row.version) != body.expected_version:
        raise msp_error(409, MSP_REPORT_SHARE_INVALID_TRANSITION)
    rel = _customer_relationship(
        db, caller=caller, relationship_id=str(row.relationship_id)
    )
    now = utcnow()
    expires_at = _validated_expiry(body.expires_at, now, rel)
    record, _ = _shareable_report(
        db,
        caller=caller,
        report_id=body.report_id,
        manifest_hash=body.manifest_hash,
        engagement_id=str(row.engagement_id),
    )
    _retire_expired_share(
        db,
        caller=caller,
        msp_tenant_id=str(row.msp_tenant_id),
        report_id=str(record.id),
        authority=authority,
        correlation=correlation_id(request),
    )
    _transition_share(
        db,
        row,
        expected_status=("requested",),
        expected_version=body.expected_version,
        values={
            "status": "active",
            "report_id": str(record.id),
            "report_version": int(record.version),
            "manifest_hash": str(record.manifest_hash),
            "decided_by_subject": authority.subject,
            "decided_by_membership_id": authority.membership_id,
            "decided_at": now,
            "expires_at": expires_at,
        },
    )
    row = _load_share(db, share_id, caller)
    _audit_share(
        db,
        caller=caller,
        row=row,
        event_type="tenant.msp.report_share_approved",
        reason_code="MSP_REPORT_SHARE_APPROVED",
        actor_subject=authority.subject,
        membership_id=authority.membership_id,
        operation="report_share.approve",
        previous_state="requested",
        new_state="active",
        correlation=correlation_id(request),
        decision="approved",
    )
    view = share_view(db, row, caller=caller, actor_ctx=actor_ctx)
    db.commit()
    return view


@router.post(
    "/report-shares/{share_id}/reject",
    dependencies=[_CONSOLE_BIND, Depends(require_scopes("admin:write"))],
)
def reject_report_share(
    share_id: str,
    body: DecisionBody,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("tenant.configure")),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """The customer's tenant_admin declines an MSP request."""
    caller = _caller_tenant_from_auth(request, actor_ctx)
    row, authority = _customer_share(db, actor_ctx, caller, share_id)
    _transition_share(
        db,
        row,
        expected_status=("requested",),
        expected_version=body.expected_version,
        values={
            "status": "rejected",
            "decided_by_subject": authority.subject,
            "decided_by_membership_id": authority.membership_id,
            "decided_at": utcnow(),
        },
    )
    row = _load_share(db, share_id, caller)
    _audit_share(
        db,
        caller=caller,
        row=row,
        event_type="tenant.msp.report_share_rejected",
        reason_code="MSP_REPORT_SHARE_REJECTED",
        actor_subject=authority.subject,
        membership_id=authority.membership_id,
        operation="report_share.reject",
        previous_state="requested",
        new_state="rejected",
        correlation=correlation_id(request),
        decision="rejected",
    )
    view = share_view(db, row, caller=caller, actor_ctx=actor_ctx)
    db.commit()
    return view


@router.post(
    "/report-shares/{share_id}/revoke",
    dependencies=[_CONSOLE_BIND, Depends(require_scopes("admin:write"))],
)
def revoke_report_share(
    share_id: str,
    body: DecisionBody,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("tenant.configure")),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """The customer's tenant_admin ends an active (or expired) share.

    Every later MSP read is refused. A copy the MSP already downloaded cannot
    be recalled; revocation governs future access only. The share row and its
    history are kept.
    """
    caller = _caller_tenant_from_auth(request, actor_ctx)
    row, authority = _customer_share(db, actor_ctx, caller, share_id)
    _transition_share(
        db,
        row,
        expected_status=("active",),
        expected_version=body.expected_version,
        values={
            "status": "revoked",
            "revoked_by_subject": authority.subject,
            "revoked_at": utcnow(),
        },
    )
    row = _load_share(db, share_id, caller)
    _audit_share(
        db,
        caller=caller,
        row=row,
        event_type="tenant.msp.report_share_revoked",
        reason_code="MSP_REPORT_SHARE_REVOKED",
        actor_subject=authority.subject,
        membership_id=authority.membership_id,
        operation="report_share.revoke",
        previous_state="active",
        new_state="revoked",
        correlation=correlation_id(request),
        decision="revoked",
    )
    view = share_view(db, row, caller=caller, actor_ctx=actor_ctx)
    db.commit()
    return view


# ---------------------------------------------------------------------------
# MSP: request, withdraw
# ---------------------------------------------------------------------------


@router.post(
    "/report-shares/requests",
    dependencies=[_CONSOLE_BIND, Depends(require_scopes("admin:write")), _MSP_ENTITLED],
)
def request_report_share(
    body: RequestShareBody,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("report.read")),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """An MSP asks the customer to share the report of an engagement the MSP
    initiated under one of its own MSP-003 grants. Grants nothing: the
    customer chooses whether, which version and for how long."""
    caller = _caller_tenant_from_auth(request, actor_ctx)
    membership = resolve_msp_membership(db, actor_ctx=actor_ctx, msp_tenant_id=caller)
    set_tenant_context(db, caller)
    grant = db.get(MspAssessmentGrant, str(body.grant_id)[:36])
    if grant is None or str(grant.msp_tenant_id) != caller or not grant.engagement_id:
        raise msp_error(404, MSP_ASSESSMENT_GRANT_NOT_FOUND)
    if str(grant.status) != "initiated":
        raise msp_error(409, MSP_REPORT_SHARE_INVALID_TRANSITION)
    customer = str(grant.tenant_id)
    _, access = resolve_actor_access(
        db,
        actor_ctx=actor_ctx,
        msp_tenant_id=caller,
        customer_tenant_id=customer,
        required=SHARE_READ_CAPABILITY,
    )
    set_tenant_context(db, caller)

    def _find() -> Optional[MspReportShare]:
        return (
            db.query(MspReportShare)
            .filter(
                MspReportShare.tenant_id == customer,
                MspReportShare.msp_tenant_id == caller,
                MspReportShare.origin == "msp",
                MspReportShare.request_key == body.request_key,
            )
            .first()
        )

    def _replay(existing: MspReportShare) -> dict[str, Any]:
        if str(existing.source_grant_id) != str(grant.id):
            raise msp_error(409, MSP_REPORT_SHARE_CONFLICT)
        return {
            **share_view(db, existing, caller=caller, actor_ctx=actor_ctx),
            "created": False,
        }

    existing = _find()
    if existing is not None:
        return _replay(existing)
    now = utcnow()
    row = MspReportShare(
        id=str(uuid.uuid4()),
        tenant_id=customer,
        msp_tenant_id=caller,
        relationship_id=access.relationship_id,
        origin="msp",
        request_key=body.request_key,
        engagement_id=str(grant.engagement_id),
        source_grant_id=str(grant.id),
        status="requested",
        requested_by_subject=membership.subject,
        requested_at=now,
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
            raise msp_error(409, MSP_REPORT_SHARE_CONFLICT)
        return _replay(existing)
    _audit_share(
        db,
        caller=caller,
        row=row,
        event_type="tenant.msp.report_share_requested",
        reason_code="MSP_REPORT_SHARE_REQUESTED",
        actor_subject=membership.subject,
        membership_id=membership.membership_id,
        operation="report_share.request",
        previous_state=None,
        new_state="requested",
        correlation=correlation_id(request),
    )
    view = {**share_view(db, row, caller=caller, actor_ctx=actor_ctx), "created": True}
    db.commit()
    return view


@router.post(
    "/report-shares/{share_id}/withdraw",
    dependencies=[_CONSOLE_BIND, Depends(require_scopes("admin:write"))],
)
def withdraw_report_share(
    share_id: str,
    body: DecisionBody,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("report.read")),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """The MSP withdraws its own pending request. Nothing else."""
    caller = _caller_tenant_from_auth(request, actor_ctx)
    row = _load_share(db, share_id, caller)
    if caller != str(row.msp_tenant_id):
        raise msp_error(403, MSP_ACCESS_DENIED)
    membership = resolve_msp_membership(db, actor_ctx=actor_ctx, msp_tenant_id=caller)
    set_tenant_context(db, caller)
    _transition_share(
        db,
        row,
        expected_status=("requested",),
        expected_version=body.expected_version,
        values={"status": "withdrawn"},
    )
    row = _load_share(db, share_id, caller)
    _audit_share(
        db,
        caller=caller,
        row=row,
        event_type="tenant.msp.report_share_withdrawn",
        reason_code="MSP_REPORT_SHARE_WITHDRAWN",
        actor_subject=membership.subject,
        membership_id=membership.membership_id,
        operation="report_share.withdraw",
        previous_state="requested",
        new_state="withdrawn",
        correlation=correlation_id(request),
    )
    view = share_view(db, row, caller=caller, actor_ctx=actor_ctx)
    db.commit()
    return view


# ---------------------------------------------------------------------------
# MSP: verify and download a shared report
# ---------------------------------------------------------------------------


def _msp_share_access(
    db: Session, actor_ctx: ActorContext, caller: str, share_id: str
) -> tuple[MspReportShare, MspShareAccess]:
    row = _load_share(db, share_id, caller)
    if caller != str(row.msp_tenant_id):
        # The customer verifies through the canonical Field Assessment route.
        raise _share_not_found()
    return row, evaluate_msp_access(
        db, row, actor_ctx=actor_ctx, caller=caller, now=utcnow()
    )


def _refuse_access(
    db: Session,
    *,
    request: Request,
    caller: str,
    row: MspReportShare,
    access: MspShareAccess,
    operation: str,
    blockers: list[str],
) -> HTTPException:
    """Record a refused read on both chains (and, for an integrity failure,
    in the customer's engagement trail), commit it, and return the error.
    The response names only blockers, never report content."""
    from services.field_assessment.audit import (  # noqa: PLC0415
        emit_engagement_audit_event,
    )

    integrity_failure = any(b in _INTEGRITY_BLOCKERS for b in blockers) or (
        "TRUST_ENFORCEMENT_BLOCKED" in blockers
    )
    event = (
        "tenant.msp.report_integrity_failed"
        if integrity_failure
        else "tenant.msp.report_access_denied"
    )
    _audit_share(
        db,
        caller=caller,
        row=row,
        event_type=event,
        reason_code=(
            MSP_REPORT_INTEGRITY_FAILED
            if integrity_failure
            else MSP_REPORT_SHARE_UNAVAILABLE
        ),
        actor_subject=access.membership.subject,
        membership_id=access.membership.membership_id,
        operation=operation,
        previous_state=str(row.status),
        new_state=str(row.status),
        correlation=correlation_id(request),
        decision="denied",
        blockers=blockers,
        integrity=(access.view or {}).get("integrity"),
    )
    if integrity_failure and access.record is not None:
        set_tenant_context(db, str(row.tenant_id))
        emit_engagement_audit_event(
            db,
            tenant_id=str(row.tenant_id),
            engagement_id=str(row.engagement_id),
            event_type="report.access_denied",
            actor=access.membership.subject[:128],
            reason_code=MSP_REPORT_INTEGRITY_FAILED,
            payload={
                "report_id": str(row.report_id),
                "version": row.report_version,
                "channel": f"msp_share:{operation}",
                "msp_tenant_id": caller,
                "share_id": str(row.id),
                "relationship_id": str(row.relationship_id),
                "blockers": blockers,
                "correlation_id": correlation_id(request),
            },
            entity_type="report",
            entity_id=str(row.report_id),
            actor_type="human",
        )
        set_tenant_context(db, caller)
    db.commit()
    return _unavailable(blockers)


def _report_summary(row: MspReportShare, access: MspShareAccess) -> dict[str, Any]:
    from api.field_assessment import _collect_report_evidence_ids  # noqa: PLC0415

    view = access.view or {}
    record = access.record
    report_json = record.report_json if record is not None else None
    evidence_ids = (
        sorted(_collect_report_evidence_ids(report_json))
        if isinstance(report_json, dict)
        else []
    )
    return {
        "share_id": str(row.id),
        "customer_tenant_id": str(row.tenant_id),
        "report_id": view.get("report_id"),
        "engagement_id": view.get("engagement_id"),
        "version": view.get("version"),
        "report_type": view.get("report_type"),
        "generated_at": view.get("generated_at"),
        "manifest_hash": view.get("manifest_hash"),
        "lifecycle": view.get("lifecycle"),
        "integrity": view.get("integrity"),
        "provenance": view.get("provenance"),
        "evidence_references": {
            "count": len(evidence_ids),
            "ids": evidence_ids[:500],
            "truncated": len(evidence_ids) > 500,
        },
        "expires_at": _iso(row.expires_at),
    }


@router.get(
    "/report-shares/{share_id}/verify",
    dependencies=[_CONSOLE_BIND, Depends(require_scopes("admin:read")), _MSP_ENTITLED],
)
def verify_shared_report(
    share_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("report.read")),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """The MSP's view of one shared report: lifecycle, integrity (re-verified
    now through the canonical verification path), provenance and evidence
    references — never evidence content. Every call is audited."""
    caller = _caller_tenant_from_auth(request, actor_ctx)
    row, access = _msp_share_access(db, actor_ctx, caller, share_id)
    if access.blockers:
        raise _refuse_access(
            db,
            request=request,
            caller=caller,
            row=row,
            access=access,
            operation="report.verify",
            blockers=access.blockers,
        )
    summary = _report_summary(row, access)
    _audit_share(
        db,
        caller=caller,
        row=row,
        event_type="tenant.msp.report_verified",
        reason_code="MSP_REPORT_VERIFIED",
        actor_subject=access.membership.subject,
        membership_id=access.membership.membership_id,
        operation="report.verify",
        previous_state="active",
        new_state="active",
        correlation=correlation_id(request),
        decision="granted",
        integrity=summary["integrity"],
    )
    db.commit()
    return {**summary, "verified_at": utcnow().isoformat()}


@router.get(
    "/report-shares/{share_id}/download",
    dependencies=[_CONSOLE_BIND, Depends(require_scopes("admin:read")), _MSP_ENTITLED],
)
def download_shared_report(
    share_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("report.read")),
    db: Session = Depends(auth_ctx_db_session),
) -> Response:
    """The canonical report document of the shared version, served directly
    from the customer's report store under its RLS context. No URL, token or
    storage credential is issued, so nothing outlives this authorized call.
    Fails closed on any integrity or trust-gate failure; every call is
    audited on both chains and in the customer's engagement trail."""
    from services.field_assessment.audit import (  # noqa: PLC0415
        emit_engagement_audit_event,
    )
    from services.field_assessment.trust_enforcement import (  # noqa: PLC0415
        TrustEnforcementError,
    )
    from services.field_assessment.trust_enforcement_adapter import (  # noqa: PLC0415
        enforce_report_export,
    )

    caller = _caller_tenant_from_auth(request, actor_ctx)
    row, access = _msp_share_access(db, actor_ctx, caller, share_id)
    if access.blockers or access.record is None or access.view is None:
        raise _refuse_access(
            db,
            request=request,
            caller=caller,
            row=row,
            access=access,
            operation="report.download",
            blockers=access.blockers or ["REPORT_UNAVAILABLE"],
        )
    record = access.record
    customer = str(row.tenant_id)
    integrity = access.view["integrity"]
    signature_valid: Optional[bool] = (
        True
        if integrity["signature"] == SIGNATURE_VERIFIED
        else (None if integrity["signature"] == VERIFICATION_UNAVAILABLE else False)
    )
    trust = access.trust
    try:
        set_tenant_context(db, customer)
        enforce_report_export(
            db,
            tenant_id=customer,
            engagement_id=str(record.engagement_id),
            chain_valid=bool(trust.chain_valid),
            signature_valid=signature_valid,
            link_valid=bool(trust.link_valid),
            replay_valid=bool(trust.replay_valid),
            is_legacy=bool(getattr(trust, "is_legacy", False))
            or signature_valid is None,
        )
    except TrustEnforcementError:
        set_tenant_context(db, caller)
        raise _refuse_access(
            db,
            request=request,
            caller=caller,
            row=row,
            access=access,
            operation="report.download",
            blockers=["TRUST_ENFORCEMENT_BLOCKED"],
        )
    set_tenant_context(db, caller)
    document = {
        "share_id": str(row.id),
        "customer_tenant_id": customer,
        "report_id": str(record.id),
        "engagement_id": str(record.engagement_id),
        "version": int(record.version),
        "report_type": record.report_type,
        "schema_version": record.schema_version,
        "manifest_hash": str(record.manifest_hash),
        "signature": record.trust_signature or record.signature,
        "signature_kind": integrity["signature_kind"],
        "integrity": integrity,
        "lifecycle": access.view["lifecycle"],
        "report": record.report_json,
    }
    payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    if len(payload) > MAX_DOWNLOAD_BYTES:
        raise _refuse_access(
            db,
            request=request,
            caller=caller,
            row=row,
            access=access,
            operation="report.download",
            blockers=["REPORT_TOO_LARGE"],
        )
    set_tenant_context(db, customer)
    emit_engagement_audit_event(
        db,
        tenant_id=customer,
        engagement_id=str(record.engagement_id),
        event_type="report.content_accessed",
        actor=access.membership.subject[:128],
        reason_code="MSP_REPORT_SHARE",
        payload={
            "report_id": str(record.id),
            "version": int(record.version),
            "channel": "msp_share:download",
            "report_state": access.view["lifecycle"]["state"],
            "msp_tenant_id": caller,
            "share_id": str(row.id),
            "relationship_id": str(row.relationship_id),
            "manifest_hash": str(record.manifest_hash),
            "correlation_id": correlation_id(request),
        },
        entity_type="report",
        entity_id=str(record.id),
        actor_type="human",
    )
    set_tenant_context(db, caller)
    _audit_share(
        db,
        caller=caller,
        row=row,
        event_type="tenant.msp.report_downloaded",
        reason_code="MSP_REPORT_DOWNLOADED",
        actor_subject=access.membership.subject,
        membership_id=access.membership.membership_id,
        operation="report.download",
        previous_state="active",
        new_state="active",
        correlation=correlation_id(request),
        decision="granted",
        integrity=integrity,
    )
    # Read every header value before commit: commit expires ``record`` and
    # clears the transaction-local tenant binding, so a later attribute access
    # would reload the row under no RLS context and fail (forced RLS on
    # governance_reports).
    headers = {
        "Content-Disposition": (
            f'attachment; filename="report-{record.engagement_id}'
            f'-v{int(record.version)}.json"'
        ),
        "Cache-Control": "no-store, private",
        "X-Manifest-Hash": str(record.manifest_hash),
        "X-Report-Version": str(int(record.version)),
        "X-Report-State": "FINAL",
    }
    db.commit()
    return Response(content=payload, media_type="application/json", headers=headers)
