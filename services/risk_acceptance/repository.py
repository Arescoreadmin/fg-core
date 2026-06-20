# services/risk_acceptance/repository.py
"""Data access layer for the Risk Acceptance bounded context (PR 14.1).

All functions are tenant-scoped.  Caller owns db.commit().
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from api.db_models_risk_acceptance import RiskAcceptance, RiskAcceptanceAudit


# ---------------------------------------------------------------------------
# Insertion helpers
# ---------------------------------------------------------------------------


def insert_risk_acceptance(db: Session, *, ra: RiskAcceptance) -> None:
    db.add(ra)
    db.flush()


def insert_audit_event(db: Session, *, audit: RiskAcceptanceAudit) -> None:
    db.add(audit)
    db.flush()


# ---------------------------------------------------------------------------
# Fetch helpers
# ---------------------------------------------------------------------------


def fetch_risk_acceptance(
    db: Session, *, tenant_id: str, ra_id: str
) -> RiskAcceptance | None:
    return (
        db.query(RiskAcceptance)
        .filter(
            RiskAcceptance.id == ra_id,
            RiskAcceptance.tenant_id == tenant_id,
        )
        .first()
    )


def fetch_risk_acceptances(
    db: Session,
    *,
    tenant_id: str,
    status: str | None = None,
    finding_id: str | None = None,
    assessment_id: str | None = None,
    remediation_task_id: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[RiskAcceptance]:
    q = db.query(RiskAcceptance).filter(RiskAcceptance.tenant_id == tenant_id)
    if status is not None:
        q = q.filter(RiskAcceptance.status == status)
    if finding_id is not None:
        q = q.filter(RiskAcceptance.finding_id == finding_id)
    if assessment_id is not None:
        q = q.filter(RiskAcceptance.assessment_id == assessment_id)
    if remediation_task_id is not None:
        q = q.filter(RiskAcceptance.remediation_task_id == remediation_task_id)
    return (
        q.order_by(RiskAcceptance.created_at.desc()).limit(limit).offset(offset).all()
    )


def count_risk_acceptances(
    db: Session,
    *,
    tenant_id: str,
    status: str | None = None,
    finding_id: str | None = None,
    assessment_id: str | None = None,
) -> int:
    q = db.query(RiskAcceptance).filter(RiskAcceptance.tenant_id == tenant_id)
    if status is not None:
        q = q.filter(RiskAcceptance.status == status)
    if finding_id is not None:
        q = q.filter(RiskAcceptance.finding_id == finding_id)
    if assessment_id is not None:
        q = q.filter(RiskAcceptance.assessment_id == assessment_id)
    return q.count()


def fetch_audit_events(
    db: Session,
    *,
    tenant_id: str,
    ra_id: str,
    limit: int = 100,
    offset: int = 0,
) -> list[RiskAcceptanceAudit]:
    return (
        db.query(RiskAcceptanceAudit)
        .filter(
            RiskAcceptanceAudit.tenant_id == tenant_id,
            RiskAcceptanceAudit.risk_acceptance_id == ra_id,
        )
        .order_by(RiskAcceptanceAudit.event_at.asc())
        .limit(limit)
        .offset(offset)
        .all()
    )


def count_audit_events(
    db: Session,
    *,
    tenant_id: str,
    ra_id: str,
) -> int:
    return (
        db.query(RiskAcceptanceAudit)
        .filter(
            RiskAcceptanceAudit.tenant_id == tenant_id,
            RiskAcceptanceAudit.risk_acceptance_id == ra_id,
        )
        .count()
    )


def fetch_expired_active(
    db: Session, *, tenant_id: str, now_iso: str
) -> list[RiskAcceptance]:
    """Return ACTIVE records whose expires_at is in the past."""
    return (
        db.query(RiskAcceptance)
        .filter(
            RiskAcceptance.tenant_id == tenant_id,
            RiskAcceptance.status == "active",
            RiskAcceptance.expires_at.isnot(None),
            RiskAcceptance.expires_at <= now_iso,
        )
        .all()
    )


def snapshot_risk_acceptance(ra: RiskAcceptance) -> dict[str, Any]:
    """Return a dict snapshot of the record for audit old_state / new_state."""
    return {
        "id": ra.id,
        "status": ra.status,
        "title": ra.title,
        "business_justification": ra.business_justification,
        "risk_rationale": ra.risk_rationale,
        "accepted_by": ra.accepted_by,
        "accepted_at": ra.accepted_at,
        "approver_name": ra.approver_name,
        "approver_role": ra.approver_role,
        "approval_authority": ra.approval_authority,
        "approval_source": ra.approval_source,
        "expires_at": ra.expires_at,
        "inherent_risk": ra.inherent_risk,
        "residual_risk": ra.residual_risk,
        "compensating_controls": ra.compensating_controls,
        "review_required": ra.review_required,
        "review_frequency_days": ra.review_frequency_days,
        "next_review_at": ra.next_review_at,
        "remediation_task_id": ra.remediation_task_id,
        "finding_id": ra.finding_id,
        "assessment_id": ra.assessment_id,
        "updated_at": ra.updated_at,
    }
