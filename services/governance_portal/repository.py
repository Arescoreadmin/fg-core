# services/governance_portal/repository.py
"""Data access layer for the Governance Portal bounded context (PR 14.4).

Read-only access to risk_acceptance, risk_governance, control_registry tables.
Write access to portal_acknowledgements and governance_portal_audits (append-only).

All functions are tenant-scoped. Caller owns db.commit().
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from api.db_models_control_registry import ControlEvidenceLink, ControlRegistry
from api.db_models_governance_portal import GovernancePortalAudit, PortalAcknowledgement
from api.db_models_risk_acceptance import RiskAcceptance
from api.db_models_risk_governance import RiskAcceptanceApproval
from services.governance_portal.schemas import (
    EvidenceFreshnessState,
    PortalAcknowledgementNotFound,
    PortalEntityNotFound,
)

_EXPIRING_SOON_DAYS = 30


# ---------------------------------------------------------------------------
# Evidence freshness helpers
# ---------------------------------------------------------------------------


def _compute_evidence_freshness(
    last_verified_at: str | None,
    review_frequency_days: int | None,
    now_dt: datetime,
) -> EvidenceFreshnessState:
    if last_verified_at is None:
        return EvidenceFreshnessState.EXPIRED
    try:
        verified_dt = datetime.fromisoformat(last_verified_at)
        if verified_dt.tzinfo is None:
            verified_dt = verified_dt.replace(tzinfo=timezone.utc)
        elapsed_days = (now_dt - verified_dt).days
        freq = review_frequency_days or 90
        remaining_days = freq - elapsed_days
        # AGING threshold: past 50% of cycle but more than 30 days remaining
        aging_threshold = freq // 2
        if remaining_days <= 0:
            return EvidenceFreshnessState.EXPIRED
        if remaining_days <= _EXPIRING_SOON_DAYS:
            return EvidenceFreshnessState.EXPIRING_SOON
        if elapsed_days >= aging_threshold:
            return EvidenceFreshnessState.AGING
        return EvidenceFreshnessState.FRESH
    except (ValueError, TypeError):
        return EvidenceFreshnessState.EXPIRED


# ---------------------------------------------------------------------------
# Risk reads (from risk_acceptance bounded context)
# ---------------------------------------------------------------------------


def fetch_risks(
    db: Session,
    *,
    tenant_id: str,
    limit: int = 50,
    offset: int = 0,
) -> list[RiskAcceptance]:
    return (
        db.query(RiskAcceptance)
        .filter(RiskAcceptance.tenant_id == tenant_id)
        .order_by(RiskAcceptance.created_at.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )


def count_risks(db: Session, *, tenant_id: str) -> int:
    return (
        db.query(RiskAcceptance)
        .filter(RiskAcceptance.tenant_id == tenant_id)
        .count()
    )


def fetch_risk_by_id(
    db: Session, *, tenant_id: str, risk_id: str
) -> RiskAcceptance:
    row = (
        db.query(RiskAcceptance)
        .filter(
            RiskAcceptance.id == risk_id,
            RiskAcceptance.tenant_id == tenant_id,
        )
        .first()
    )
    if row is None:
        raise PortalEntityNotFound(f"risk id={risk_id!r} not found for tenant.")
    return row


def fetch_approvals_for_risk(
    db: Session, *, tenant_id: str, risk_id: str
) -> list[RiskAcceptanceApproval]:
    return (
        db.query(RiskAcceptanceApproval)
        .filter(
            RiskAcceptanceApproval.tenant_id == tenant_id,
            RiskAcceptanceApproval.risk_acceptance_id == risk_id,
        )
        .order_by(RiskAcceptanceApproval.created_at.asc())
        .all()
    )


def count_risks_by_status(db: Session, *, tenant_id: str, status: str) -> int:
    return (
        db.query(RiskAcceptance)
        .filter(
            RiskAcceptance.tenant_id == tenant_id,
            RiskAcceptance.status == status,
        )
        .count()
    )


def count_expiring_risks(db: Session, *, tenant_id: str, now_iso: str) -> int:
    """Count risks expiring within _EXPIRING_SOON_DAYS days."""
    now_dt = datetime.fromisoformat(now_iso)
    if now_dt.tzinfo is None:
        now_dt = now_dt.replace(tzinfo=timezone.utc)

    candidates = (
        db.query(RiskAcceptance)
        .filter(
            RiskAcceptance.tenant_id == tenant_id,
            RiskAcceptance.expires_at.isnot(None),
        )
        .all()
    )
    count = 0
    for r in candidates:
        try:
            exp_dt = datetime.fromisoformat(r.expires_at or "")
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            days_until = (exp_dt - now_dt).days
            if 0 <= days_until <= _EXPIRING_SOON_DAYS:
                count += 1
        except (ValueError, TypeError):
            pass
    return count


def count_expired_risks(db: Session, *, tenant_id: str, now_iso: str) -> int:
    """Count risks whose expires_at is in the past."""
    now_dt = datetime.fromisoformat(now_iso)
    if now_dt.tzinfo is None:
        now_dt = now_dt.replace(tzinfo=timezone.utc)

    candidates = (
        db.query(RiskAcceptance)
        .filter(
            RiskAcceptance.tenant_id == tenant_id,
            RiskAcceptance.expires_at.isnot(None),
        )
        .all()
    )
    count = 0
    for r in candidates:
        try:
            exp_dt = datetime.fromisoformat(r.expires_at or "")
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            if exp_dt < now_dt:
                count += 1
        except (ValueError, TypeError):
            pass
    return count


# ---------------------------------------------------------------------------
# Control reads (from control_registry bounded context)
# ---------------------------------------------------------------------------


def fetch_portal_controls(
    db: Session,
    *,
    tenant_id: str,
    control_status: str | None = None,
    verification_status: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[ControlRegistry]:
    q = db.query(ControlRegistry).filter(ControlRegistry.tenant_id == tenant_id)
    if control_status is not None:
        q = q.filter(ControlRegistry.control_status == control_status)
    if verification_status is not None:
        q = q.filter(ControlRegistry.verification_status == verification_status)
    return q.order_by(ControlRegistry.created_at.desc()).limit(limit).offset(offset).all()


def count_portal_controls(
    db: Session,
    *,
    tenant_id: str,
    control_status: str | None = None,
    verification_status: str | None = None,
) -> int:
    q = db.query(ControlRegistry).filter(ControlRegistry.tenant_id == tenant_id)
    if control_status is not None:
        q = q.filter(ControlRegistry.control_status == control_status)
    if verification_status is not None:
        q = q.filter(ControlRegistry.verification_status == verification_status)
    return q.count()


def fetch_portal_control_by_id(
    db: Session, *, tenant_id: str, ctl_id: str
) -> ControlRegistry:
    row = (
        db.query(ControlRegistry)
        .filter(
            ControlRegistry.id == ctl_id,
            ControlRegistry.tenant_id == tenant_id,
        )
        .first()
    )
    if row is None:
        raise PortalEntityNotFound(f"control id={ctl_id!r} not found for tenant.")
    return row


def count_evidence_for_control(
    db: Session, *, tenant_id: str, control_id: str
) -> int:
    return (
        db.query(ControlEvidenceLink)
        .filter(
            ControlEvidenceLink.tenant_id == tenant_id,
            ControlEvidenceLink.control_id == control_id,
        )
        .count()
    )


# ---------------------------------------------------------------------------
# Evidence reads (from control_registry bounded context)
# ---------------------------------------------------------------------------


def fetch_portal_evidence(
    db: Session,
    *,
    tenant_id: str,
    control_id: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[ControlEvidenceLink]:
    q = db.query(ControlEvidenceLink).filter(
        ControlEvidenceLink.tenant_id == tenant_id
    )
    if control_id is not None:
        q = q.filter(ControlEvidenceLink.control_id == control_id)
    return q.order_by(ControlEvidenceLink.linked_at.desc()).limit(limit).offset(offset).all()


def count_portal_evidence(
    db: Session,
    *,
    tenant_id: str,
    control_id: str | None = None,
) -> int:
    q = db.query(ControlEvidenceLink).filter(
        ControlEvidenceLink.tenant_id == tenant_id
    )
    if control_id is not None:
        q = q.filter(ControlEvidenceLink.control_id == control_id)
    return q.count()


def fetch_portal_evidence_by_id(
    db: Session, *, tenant_id: str, evidence_id: str
) -> ControlEvidenceLink:
    row = (
        db.query(ControlEvidenceLink)
        .filter(
            ControlEvidenceLink.id == evidence_id,
            ControlEvidenceLink.tenant_id == tenant_id,
        )
        .first()
    )
    if row is None:
        raise PortalEntityNotFound(f"evidence id={evidence_id!r} not found for tenant.")
    return row


def count_evidence_with_freshness(
    db: Session,
    *,
    tenant_id: str,
    now_iso: str,
    target_states: set[EvidenceFreshnessState],
) -> int:
    now_dt = datetime.fromisoformat(now_iso)
    if now_dt.tzinfo is None:
        now_dt = now_dt.replace(tzinfo=timezone.utc)

    evidence_links = (
        db.query(ControlEvidenceLink)
        .filter(ControlEvidenceLink.tenant_id == tenant_id)
        .all()
    )

    control_map: dict[str, ControlRegistry] = {}
    control_ids = {e.control_id for e in evidence_links}
    for ctrl in (
        db.query(ControlRegistry)
        .filter(
            ControlRegistry.tenant_id == tenant_id,
            ControlRegistry.id.in_(control_ids),
        )
        .all()
    ):
        control_map[ctrl.id] = ctrl

    count = 0
    for ev in evidence_links:
        ctrl = control_map.get(ev.control_id)
        freshness = _compute_evidence_freshness(
            ctrl.last_verified_at if ctrl else None,
            ctrl.review_frequency_days if ctrl else None,
            now_dt,
        )
        if freshness in target_states:
            count += 1
    return count


# ---------------------------------------------------------------------------
# Acknowledgement writes (portal-owned, append-only)
# ---------------------------------------------------------------------------


def insert_acknowledgement(db: Session, *, ack: PortalAcknowledgement) -> None:
    db.add(ack)
    db.flush()


def fetch_acknowledgements(
    db: Session,
    *,
    tenant_id: str,
    entity_type: str | None = None,
    entity_id: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[PortalAcknowledgement]:
    q = db.query(PortalAcknowledgement).filter(
        PortalAcknowledgement.tenant_id == tenant_id
    )
    if entity_type is not None:
        q = q.filter(PortalAcknowledgement.entity_type == entity_type)
    if entity_id is not None:
        q = q.filter(PortalAcknowledgement.entity_id == entity_id)
    return (
        q.order_by(PortalAcknowledgement.acknowledged_at.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )


def count_acknowledgements(
    db: Session,
    *,
    tenant_id: str,
    entity_type: str | None = None,
    entity_id: str | None = None,
) -> int:
    q = db.query(PortalAcknowledgement).filter(
        PortalAcknowledgement.tenant_id == tenant_id
    )
    if entity_type is not None:
        q = q.filter(PortalAcknowledgement.entity_type == entity_type)
    if entity_id is not None:
        q = q.filter(PortalAcknowledgement.entity_id == entity_id)
    return q.count()


def fetch_acknowledgement_by_id(
    db: Session, *, tenant_id: str, ack_id: str
) -> PortalAcknowledgement:
    row = (
        db.query(PortalAcknowledgement)
        .filter(
            PortalAcknowledgement.id == ack_id,
            PortalAcknowledgement.tenant_id == tenant_id,
        )
        .first()
    )
    if row is None:
        raise PortalAcknowledgementNotFound(
            f"acknowledgement id={ack_id!r} not found for tenant."
        )
    return row


def count_acknowledgements_since(
    db: Session, *, tenant_id: str, since_iso: str
) -> int:
    """Count acknowledgements created on or after since_iso."""
    return (
        db.query(PortalAcknowledgement)
        .filter(
            PortalAcknowledgement.tenant_id == tenant_id,
            PortalAcknowledgement.acknowledged_at >= since_iso,
        )
        .count()
    )


# ---------------------------------------------------------------------------
# Portal audit writes (append-only)
# ---------------------------------------------------------------------------


def insert_portal_audit(db: Session, *, audit: GovernancePortalAudit) -> None:
    db.add(audit)
    db.flush()


def fetch_portal_audits(
    db: Session,
    *,
    tenant_id: str,
    limit: int = 100,
    offset: int = 0,
) -> list[GovernancePortalAudit]:
    return (
        db.query(GovernancePortalAudit)
        .filter(GovernancePortalAudit.tenant_id == tenant_id)
        .order_by(GovernancePortalAudit.event_at.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )


def count_portal_audits(db: Session, *, tenant_id: str) -> int:
    return (
        db.query(GovernancePortalAudit)
        .filter(GovernancePortalAudit.tenant_id == tenant_id)
        .count()
    )
