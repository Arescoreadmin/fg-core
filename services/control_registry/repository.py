# services/control_registry/repository.py
"""Data access layer for the Control Registry bounded context (PR 14.3).

All functions are tenant-scoped. Caller owns db.commit().
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from api.db_models_control_registry import (
    ControlAudit,
    ControlEvidenceLink,
    ControlRegistry,
    ControlReview,
    RiskAcceptanceControlLink,
)
from services.control_registry.schemas import ControlNotFound, ControlTenantViolation


# ---------------------------------------------------------------------------
# Reference validation
# ---------------------------------------------------------------------------


def fetch_control_owned(
    db: Session,
    *,
    tenant_id: str,
    ctl_id: str,
) -> ControlRegistry:
    """Return ControlRegistry or raise ControlNotFound."""
    row = (
        db.query(ControlRegistry)
        .filter(
            ControlRegistry.id == ctl_id,
            ControlRegistry.tenant_id == tenant_id,
        )
        .first()
    )
    if row is None:
        raise ControlNotFound(f"control id={ctl_id!r} not found for tenant.")
    return row


# ---------------------------------------------------------------------------
# Control CRUD
# ---------------------------------------------------------------------------


def insert_control(db: Session, *, control: ControlRegistry) -> None:
    db.add(control)
    db.flush()


def fetch_control(
    db: Session, *, tenant_id: str, ctl_id: str
) -> ControlRegistry | None:
    return (
        db.query(ControlRegistry)
        .filter(
            ControlRegistry.id == ctl_id,
            ControlRegistry.tenant_id == tenant_id,
        )
        .first()
    )


def fetch_controls(
    db: Session,
    *,
    tenant_id: str,
    control_status: str | None = None,
    control_type: str | None = None,
    verification_status: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[ControlRegistry]:
    q = db.query(ControlRegistry).filter(ControlRegistry.tenant_id == tenant_id)
    if control_status is not None:
        q = q.filter(ControlRegistry.control_status == control_status)
    if control_type is not None:
        q = q.filter(ControlRegistry.control_type == control_type)
    if verification_status is not None:
        q = q.filter(ControlRegistry.verification_status == verification_status)
    return (
        q.order_by(ControlRegistry.created_at.desc()).limit(limit).offset(offset).all()
    )


def count_controls(
    db: Session,
    *,
    tenant_id: str,
    control_status: str | None = None,
    control_type: str | None = None,
    verification_status: str | None = None,
) -> int:
    q = db.query(ControlRegistry).filter(ControlRegistry.tenant_id == tenant_id)
    if control_status is not None:
        q = q.filter(ControlRegistry.control_status == control_status)
    if control_type is not None:
        q = q.filter(ControlRegistry.control_type == control_type)
    if verification_status is not None:
        q = q.filter(ControlRegistry.verification_status == verification_status)
    return q.count()


def count_controls_without_evidence(db: Session, *, tenant_id: str) -> int:
    """Count controls that have no linked evidence."""
    all_ids = [
        row.id
        for row in db.query(ControlRegistry.id).filter(
            ControlRegistry.tenant_id == tenant_id
        )
    ]
    if not all_ids:
        return 0
    linked_ids = {
        row.control_id
        for row in db.query(ControlEvidenceLink.control_id).filter(
            ControlEvidenceLink.tenant_id == tenant_id
        )
    }
    return sum(1 for cid in all_ids if cid not in linked_ids)


def count_controls_without_owner(db: Session, *, tenant_id: str) -> int:
    return (
        db.query(ControlRegistry)
        .filter(
            ControlRegistry.tenant_id == tenant_id,
            ControlRegistry.owner.is_(None),
        )
        .count()
    )


def count_controls_due_for_review(db: Session, *, tenant_id: str, now_iso: str) -> int:
    """Count ACTIVE controls where next_review_at <= now."""
    now_dt = datetime.fromisoformat(now_iso)
    if now_dt.tzinfo is None:
        now_dt = now_dt.replace(tzinfo=timezone.utc)

    candidates = (
        db.query(ControlRegistry)
        .filter(
            ControlRegistry.tenant_id == tenant_id,
            ControlRegistry.control_status == "active",
            ControlRegistry.next_review_at.isnot(None),
        )
        .all()
    )
    count = 0
    for c in candidates:
        try:
            due_dt = datetime.fromisoformat(c.next_review_at)
            if due_dt.tzinfo is None:
                due_dt = due_dt.replace(tzinfo=timezone.utc)
            if due_dt <= now_dt:
                count += 1
        except (ValueError, TypeError):
            pass
    return count


def snapshot_control(control: ControlRegistry) -> dict[str, Any]:
    return {
        "id": control.id,
        "control_id": control.control_id,
        "title": control.title,
        "control_type": control.control_type,
        "control_status": control.control_status,
        "effectiveness_rating": control.effectiveness_rating,
        "verification_status": control.verification_status,
        "criticality": control.criticality,
        "owner": control.owner,
        "last_verified_at": control.last_verified_at,
        "updated_at": control.updated_at,
    }


# ---------------------------------------------------------------------------
# Control Audit (append-only)
# ---------------------------------------------------------------------------


def insert_control_audit(db: Session, *, audit: ControlAudit) -> None:
    db.add(audit)
    db.flush()


def fetch_control_audits(
    db: Session,
    *,
    tenant_id: str,
    control_id: str,
    limit: int = 100,
    offset: int = 0,
) -> list[ControlAudit]:
    return (
        db.query(ControlAudit)
        .filter(
            ControlAudit.tenant_id == tenant_id,
            ControlAudit.control_id == control_id,
        )
        .order_by(ControlAudit.event_at.asc())
        .limit(limit)
        .offset(offset)
        .all()
    )


def count_control_audits(db: Session, *, tenant_id: str, control_id: str) -> int:
    return (
        db.query(ControlAudit)
        .filter(
            ControlAudit.tenant_id == tenant_id,
            ControlAudit.control_id == control_id,
        )
        .count()
    )


# ---------------------------------------------------------------------------
# Evidence links (append-only)
# ---------------------------------------------------------------------------


def insert_evidence_link(db: Session, *, link: ControlEvidenceLink) -> None:
    db.add(link)
    db.flush()


def fetch_evidence_links(
    db: Session,
    *,
    tenant_id: str,
    control_id: str,
    limit: int = 50,
    offset: int = 0,
) -> list[ControlEvidenceLink]:
    return (
        db.query(ControlEvidenceLink)
        .filter(
            ControlEvidenceLink.tenant_id == tenant_id,
            ControlEvidenceLink.control_id == control_id,
        )
        .order_by(ControlEvidenceLink.linked_at.asc())
        .limit(limit)
        .offset(offset)
        .all()
    )


def count_evidence_links(db: Session, *, tenant_id: str, control_id: str) -> int:
    return (
        db.query(ControlEvidenceLink)
        .filter(
            ControlEvidenceLink.tenant_id == tenant_id,
            ControlEvidenceLink.control_id == control_id,
        )
        .count()
    )


# ---------------------------------------------------------------------------
# Risk acceptance links
# ---------------------------------------------------------------------------


def insert_risk_link(db: Session, *, link: RiskAcceptanceControlLink) -> None:
    db.add(link)
    db.flush()


def fetch_risk_links(
    db: Session,
    *,
    tenant_id: str,
    control_id: str,
    limit: int = 50,
    offset: int = 0,
) -> list[RiskAcceptanceControlLink]:
    return (
        db.query(RiskAcceptanceControlLink)
        .filter(
            RiskAcceptanceControlLink.tenant_id == tenant_id,
            RiskAcceptanceControlLink.control_id == control_id,
        )
        .order_by(RiskAcceptanceControlLink.created_at.asc())
        .limit(limit)
        .offset(offset)
        .all()
    )


def count_risk_links(db: Session, *, tenant_id: str, control_id: str) -> int:
    return (
        db.query(RiskAcceptanceControlLink)
        .filter(
            RiskAcceptanceControlLink.tenant_id == tenant_id,
            RiskAcceptanceControlLink.control_id == control_id,
        )
        .count()
    )


# ---------------------------------------------------------------------------
# Reviews
# ---------------------------------------------------------------------------


def insert_review(db: Session, *, review: ControlReview) -> None:
    db.add(review)
    db.flush()


def fetch_review(
    db: Session, *, tenant_id: str, review_id: str
) -> ControlReview | None:
    return (
        db.query(ControlReview)
        .filter(
            ControlReview.id == review_id,
            ControlReview.tenant_id == tenant_id,
        )
        .first()
    )


def fetch_reviews(
    db: Session,
    *,
    tenant_id: str,
    control_id: str,
    limit: int = 50,
    offset: int = 0,
) -> list[ControlReview]:
    return (
        db.query(ControlReview)
        .filter(
            ControlReview.tenant_id == tenant_id,
            ControlReview.control_id == control_id,
        )
        .order_by(ControlReview.review_date.asc())
        .limit(limit)
        .offset(offset)
        .all()
    )


def count_reviews(db: Session, *, tenant_id: str, control_id: str) -> int:
    return (
        db.query(ControlReview)
        .filter(
            ControlReview.tenant_id == tenant_id,
            ControlReview.control_id == control_id,
        )
        .count()
    )


def fetch_overdue_pending_reviews(
    db: Session, *, tenant_id: str, now_iso: str
) -> list[ControlReview]:
    """Return PENDING reviews whose review_date has passed."""
    now_dt = datetime.fromisoformat(now_iso)
    if now_dt.tzinfo is None:
        now_dt = now_dt.replace(tzinfo=timezone.utc)

    candidates = (
        db.query(ControlReview)
        .filter(
            ControlReview.tenant_id == tenant_id,
            ControlReview.status == "pending",
        )
        .all()
    )
    result = []
    for review in candidates:
        try:
            due_dt = datetime.fromisoformat(review.review_date)
            if due_dt.tzinfo is None:
                due_dt = due_dt.replace(tzinfo=timezone.utc)
            if due_dt <= now_dt:
                result.append(review)
        except (ValueError, TypeError):
            pass
    return result


# ---------------------------------------------------------------------------
# Freshness sweep
# ---------------------------------------------------------------------------


def fetch_verified_controls_for_freshness(
    db: Session, *, tenant_id: str, now_iso: str
) -> list[ControlRegistry]:
    """Return ACTIVE VERIFIED controls whose last_verified_at is stale."""
    now_dt = datetime.fromisoformat(now_iso)
    if now_dt.tzinfo is None:
        now_dt = now_dt.replace(tzinfo=timezone.utc)

    candidates = (
        db.query(ControlRegistry)
        .filter(
            ControlRegistry.tenant_id == tenant_id,
            ControlRegistry.control_status == "active",
            ControlRegistry.verification_status == "verified",
            ControlRegistry.last_verified_at.isnot(None),
        )
        .all()
    )
    result = []
    for control in candidates:
        try:
            verified_dt = datetime.fromisoformat(control.last_verified_at)
            if verified_dt.tzinfo is None:
                verified_dt = verified_dt.replace(tzinfo=timezone.utc)
            elapsed_days = (now_dt - verified_dt).days
            freq = control.review_frequency_days or 90
            if elapsed_days >= freq:
                result.append(control)
        except (ValueError, TypeError):
            pass
    return result
