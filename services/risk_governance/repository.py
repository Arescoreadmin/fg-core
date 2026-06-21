# services/risk_governance/repository.py
"""Data access layer for the Risk Governance bounded context (PR 14.2).

All functions are tenant-scoped. Caller owns db.commit().
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from api.db_models_risk_acceptance import RiskAcceptance
from api.db_models_risk_governance import (
    RiskAcceptanceApproval,
    RiskAcceptanceApprovalAudit,
    RiskApprovalPolicy,
    RiskGovernanceEscalation,
    RiskReview,
)
from services.risk_governance.schemas import GovernanceTenantViolation


# ---------------------------------------------------------------------------
# Reference validation
# ---------------------------------------------------------------------------


def assert_risk_acceptance_owned(
    db: Session,
    *,
    tenant_id: str,
    risk_acceptance_id: str,
) -> RiskAcceptance:
    """Return the RiskAcceptance or raise GovernanceTenantViolation."""
    row = (
        db.query(RiskAcceptance)
        .filter(
            RiskAcceptance.id == risk_acceptance_id,
            RiskAcceptance.tenant_id == tenant_id,
        )
        .first()
    )
    if row is None:
        raise GovernanceTenantViolation(
            f"risk_acceptance_id={risk_acceptance_id!r} not found for tenant."
        )
    return row


# ---------------------------------------------------------------------------
# Approval CRUD
# ---------------------------------------------------------------------------


def insert_approval(db: Session, *, approval: RiskAcceptanceApproval) -> None:
    db.add(approval)
    db.flush()


def fetch_approval(
    db: Session, *, tenant_id: str, approval_id: str
) -> RiskAcceptanceApproval | None:
    return (
        db.query(RiskAcceptanceApproval)
        .filter(
            RiskAcceptanceApproval.id == approval_id,
            RiskAcceptanceApproval.tenant_id == tenant_id,
        )
        .first()
    )


def fetch_approvals(
    db: Session,
    *,
    tenant_id: str,
    risk_acceptance_id: str,
    status: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[RiskAcceptanceApproval]:
    q = db.query(RiskAcceptanceApproval).filter(
        RiskAcceptanceApproval.tenant_id == tenant_id,
        RiskAcceptanceApproval.risk_acceptance_id == risk_acceptance_id,
    )
    if status is not None:
        q = q.filter(RiskAcceptanceApproval.status == status)
    return q.order_by(RiskAcceptanceApproval.created_at.asc()).limit(limit).offset(offset).all()


def count_approvals(
    db: Session,
    *,
    tenant_id: str,
    risk_acceptance_id: str,
    status: str | None = None,
) -> int:
    q = db.query(RiskAcceptanceApproval).filter(
        RiskAcceptanceApproval.tenant_id == tenant_id,
        RiskAcceptanceApproval.risk_acceptance_id == risk_acceptance_id,
    )
    if status is not None:
        q = q.filter(RiskAcceptanceApproval.status == status)
    return q.count()


def count_pending_approvals(db: Session, *, tenant_id: str) -> int:
    return (
        db.query(RiskAcceptanceApproval)
        .filter(
            RiskAcceptanceApproval.tenant_id == tenant_id,
            RiskAcceptanceApproval.status == "pending",
        )
        .count()
    )


def fetch_expired_pending_approvals(
    db: Session, *, tenant_id: str, now_iso: str
) -> list[RiskAcceptanceApproval]:
    """Return PENDING approvals whose expires_at has passed (Python UTC comparison)."""
    now_dt = datetime.fromisoformat(now_iso)
    if now_dt.tzinfo is None:
        now_dt = now_dt.replace(tzinfo=timezone.utc)

    candidates = (
        db.query(RiskAcceptanceApproval)
        .filter(
            RiskAcceptanceApproval.tenant_id == tenant_id,
            RiskAcceptanceApproval.status == "pending",
            RiskAcceptanceApproval.expires_at.isnot(None),
        )
        .all()
    )

    result = []
    for approval in candidates:
        try:
            exp_dt = datetime.fromisoformat(approval.expires_at)
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            if exp_dt <= now_dt:
                result.append(approval)
        except (ValueError, TypeError):
            pass
    return result


def snapshot_approval(approval: RiskAcceptanceApproval) -> dict[str, Any]:
    return {
        "id": approval.id,
        "status": approval.status,
        "approver_name": approval.approver_name,
        "approver_role": approval.approver_role,
        "approval_type": approval.approval_type,
        "comments": approval.comments,
        "approved_at": approval.approved_at,
        "expires_at": approval.expires_at,
        "updated_at": approval.updated_at,
    }


# ---------------------------------------------------------------------------
# Approval audit
# ---------------------------------------------------------------------------


def insert_approval_audit(db: Session, *, audit: RiskAcceptanceApprovalAudit) -> None:
    db.add(audit)
    db.flush()


def fetch_approval_audits(
    db: Session,
    *,
    tenant_id: str,
    approval_id: str,
    limit: int = 100,
    offset: int = 0,
) -> list[RiskAcceptanceApprovalAudit]:
    return (
        db.query(RiskAcceptanceApprovalAudit)
        .filter(
            RiskAcceptanceApprovalAudit.tenant_id == tenant_id,
            RiskAcceptanceApprovalAudit.approval_id == approval_id,
        )
        .order_by(RiskAcceptanceApprovalAudit.event_at.asc())
        .limit(limit)
        .offset(offset)
        .all()
    )


def count_approval_audits(
    db: Session, *, tenant_id: str, approval_id: str
) -> int:
    return (
        db.query(RiskAcceptanceApprovalAudit)
        .filter(
            RiskAcceptanceApprovalAudit.tenant_id == tenant_id,
            RiskAcceptanceApprovalAudit.approval_id == approval_id,
        )
        .count()
    )


# ---------------------------------------------------------------------------
# Policy CRUD
# ---------------------------------------------------------------------------


def insert_policy(db: Session, *, policy: RiskApprovalPolicy) -> None:
    db.add(policy)
    db.flush()


def fetch_policy(
    db: Session, *, tenant_id: str, policy_id: str
) -> RiskApprovalPolicy | None:
    return (
        db.query(RiskApprovalPolicy)
        .filter(
            RiskApprovalPolicy.id == policy_id,
            RiskApprovalPolicy.tenant_id == tenant_id,
        )
        .first()
    )


def fetch_policies(
    db: Session,
    *,
    tenant_id: str,
    active_only: bool = False,
    limit: int = 50,
    offset: int = 0,
) -> list[RiskApprovalPolicy]:
    q = db.query(RiskApprovalPolicy).filter(RiskApprovalPolicy.tenant_id == tenant_id)
    if active_only:
        q = q.filter(RiskApprovalPolicy.active.is_(True))
    return q.order_by(RiskApprovalPolicy.created_at.desc()).limit(limit).offset(offset).all()


def count_policies(
    db: Session, *, tenant_id: str, active_only: bool = False
) -> int:
    q = db.query(RiskApprovalPolicy).filter(RiskApprovalPolicy.tenant_id == tenant_id)
    if active_only:
        q = q.filter(RiskApprovalPolicy.active.is_(True))
    return q.count()


# ---------------------------------------------------------------------------
# Review CRUD
# ---------------------------------------------------------------------------


def insert_review(db: Session, *, review: RiskReview) -> None:
    db.add(review)
    db.flush()


def fetch_review(
    db: Session, *, tenant_id: str, review_id: str
) -> RiskReview | None:
    return (
        db.query(RiskReview)
        .filter(
            RiskReview.id == review_id,
            RiskReview.tenant_id == tenant_id,
        )
        .first()
    )


def fetch_reviews(
    db: Session,
    *,
    tenant_id: str,
    risk_acceptance_id: str,
    status: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[RiskReview]:
    q = db.query(RiskReview).filter(
        RiskReview.tenant_id == tenant_id,
        RiskReview.risk_acceptance_id == risk_acceptance_id,
    )
    if status is not None:
        q = q.filter(RiskReview.status == status)
    return q.order_by(RiskReview.review_due_at.asc()).limit(limit).offset(offset).all()


def count_reviews(
    db: Session,
    *,
    tenant_id: str,
    risk_acceptance_id: str,
    status: str | None = None,
) -> int:
    q = db.query(RiskReview).filter(
        RiskReview.tenant_id == tenant_id,
        RiskReview.risk_acceptance_id == risk_acceptance_id,
    )
    if status is not None:
        q = q.filter(RiskReview.status == status)
    return q.count()


def count_overdue_reviews(db: Session, *, tenant_id: str) -> int:
    return (
        db.query(RiskReview)
        .filter(
            RiskReview.tenant_id == tenant_id,
            RiskReview.status == "overdue",
        )
        .count()
    )


def fetch_overdue_pending_reviews(
    db: Session, *, tenant_id: str, now_iso: str
) -> list[RiskReview]:
    """Return PENDING reviews whose review_due_at has passed."""
    now_dt = datetime.fromisoformat(now_iso)
    if now_dt.tzinfo is None:
        now_dt = now_dt.replace(tzinfo=timezone.utc)

    candidates = (
        db.query(RiskReview)
        .filter(
            RiskReview.tenant_id == tenant_id,
            RiskReview.status == "pending",
        )
        .all()
    )

    result = []
    for review in candidates:
        try:
            due_dt = datetime.fromisoformat(review.review_due_at)
            if due_dt.tzinfo is None:
                due_dt = due_dt.replace(tzinfo=timezone.utc)
            if due_dt <= now_dt:
                result.append(review)
        except (ValueError, TypeError):
            pass
    return result


# ---------------------------------------------------------------------------
# Escalation
# ---------------------------------------------------------------------------


def insert_escalation(db: Session, *, escalation: RiskGovernanceEscalation) -> None:
    db.add(escalation)
    db.flush()


def fetch_escalation(
    db: Session, *, tenant_id: str, escalation_id: str
) -> RiskGovernanceEscalation | None:
    return (
        db.query(RiskGovernanceEscalation)
        .filter(
            RiskGovernanceEscalation.id == escalation_id,
            RiskGovernanceEscalation.tenant_id == tenant_id,
        )
        .first()
    )


def fetch_escalations(
    db: Session,
    *,
    tenant_id: str,
    risk_acceptance_id: str,
    resolved: bool | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[RiskGovernanceEscalation]:
    q = db.query(RiskGovernanceEscalation).filter(
        RiskGovernanceEscalation.tenant_id == tenant_id,
        RiskGovernanceEscalation.risk_acceptance_id == risk_acceptance_id,
    )
    if resolved is not None:
        q = q.filter(RiskGovernanceEscalation.resolved == resolved)
    return q.order_by(RiskGovernanceEscalation.created_at.desc()).limit(limit).offset(offset).all()


def count_escalations(
    db: Session,
    *,
    tenant_id: str,
    risk_acceptance_id: str,
    resolved: bool | None = None,
) -> int:
    q = db.query(RiskGovernanceEscalation).filter(
        RiskGovernanceEscalation.tenant_id == tenant_id,
        RiskGovernanceEscalation.risk_acceptance_id == risk_acceptance_id,
    )
    if resolved is not None:
        q = q.filter(RiskGovernanceEscalation.resolved == resolved)
    return q.count()


def count_unresolved_escalations(db: Session, *, tenant_id: str) -> int:
    return (
        db.query(RiskGovernanceEscalation)
        .filter(
            RiskGovernanceEscalation.tenant_id == tenant_id,
            RiskGovernanceEscalation.resolved.is_(False),
        )
        .count()
    )
