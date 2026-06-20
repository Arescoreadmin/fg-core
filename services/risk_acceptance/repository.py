# services/risk_acceptance/repository.py
"""Data access layer for the Risk Acceptance bounded context (PR 14.1).

All functions are tenant-scoped.  Caller owns db.commit().
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from api.db_models_field_assessment import FaEngagement, FaNormalizedFinding
from api.db_models_risk_acceptance import RiskAcceptance, RiskAcceptanceAudit
from services.risk_acceptance.schemas import RiskAcceptanceTenantViolation


# ---------------------------------------------------------------------------
# Reference validation (tenant-scoped)
# ---------------------------------------------------------------------------


def assert_assessment_exists(
    db: Session,
    *,
    tenant_id: str,
    assessment_id: str,
) -> None:
    """Raise RiskAcceptanceTenantViolation if the engagement does not exist for this tenant."""
    row = (
        db.query(FaEngagement)
        .filter(
            FaEngagement.id == assessment_id,
            FaEngagement.tenant_id == tenant_id,
        )
        .first()
    )
    if row is None:
        raise RiskAcceptanceTenantViolation(
            f"assessment_id={assessment_id!r} not found for tenant."
        )


def assert_finding_belongs_to_tenant(
    db: Session,
    *,
    tenant_id: str,
    finding_id: str,
    assessment_id: str,
) -> None:
    """Raise RiskAcceptanceTenantViolation if finding does not belong to tenant/assessment."""
    row = (
        db.query(FaNormalizedFinding)
        .filter(
            FaNormalizedFinding.id == finding_id,
            FaNormalizedFinding.tenant_id == tenant_id,
            FaNormalizedFinding.engagement_id == assessment_id,
        )
        .first()
    )
    if row is None:
        raise RiskAcceptanceTenantViolation(
            f"finding_id={finding_id!r} not found in assessment {assessment_id!r} for tenant."
        )


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
    remediation_task_id: str | None = None,
) -> int:
    q = db.query(RiskAcceptance).filter(RiskAcceptance.tenant_id == tenant_id)
    if status is not None:
        q = q.filter(RiskAcceptance.status == status)
    if finding_id is not None:
        q = q.filter(RiskAcceptance.finding_id == finding_id)
    if assessment_id is not None:
        q = q.filter(RiskAcceptance.assessment_id == assessment_id)
    if remediation_task_id is not None:
        q = q.filter(RiskAcceptance.remediation_task_id == remediation_task_id)
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
    """Return ACTIVE records whose expires_at is in the past.

    Comparison is done in Python with parsed datetimes so timezone-offset
    values (e.g. -05:00) are normalized to UTC before being compared —
    a lexicographic SQL string comparison would give wrong results for
    non-UTC offsets.
    """
    now_dt = datetime.fromisoformat(now_iso)
    if now_dt.tzinfo is None:
        now_dt = now_dt.replace(tzinfo=timezone.utc)

    candidates = (
        db.query(RiskAcceptance)
        .filter(
            RiskAcceptance.tenant_id == tenant_id,
            RiskAcceptance.status == "active",
            RiskAcceptance.expires_at.isnot(None),
        )
        .all()
    )

    result = []
    for ra in candidates:
        expires_at = ra.expires_at
        if expires_at is None:
            continue
        try:
            exp_dt = datetime.fromisoformat(expires_at)
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            if exp_dt <= now_dt:
                result.append(ra)
        except (ValueError, TypeError):
            pass
    return result


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
