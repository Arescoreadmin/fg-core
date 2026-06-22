# services/governance_reporting/repository.py
"""Data access layer for PR 14.5 — Governance Reporting & Attestation Engine.

All read operations are tenant-scoped.
All write operations go through the engine; the repository only does DB I/O.
"""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.db_models_control_registry import (
    ControlRegistry,
    ControlEvidenceLink,
    RiskAcceptanceControlLink,
)
from api.db_models_governance_portal import PortalAcknowledgement
from api.db_models_governance_reporting import (
    GovernanceAttestation,
    GovernanceReport,
    GovernanceReportAudit,
    GovernanceReportManifest,
)
from api.db_models_risk_acceptance import RiskAcceptance, RiskAcceptanceAudit
from api.db_models_risk_governance import (
    RiskAcceptanceApproval,
    RiskAcceptanceApprovalAudit,
    RiskReview,
)
from services.governance_reporting.schemas import ReportNotFound, ReportStatus


# ---------------------------------------------------------------------------
# Read from source tables
# ---------------------------------------------------------------------------


def fetch_risk_acceptance(db: Session, tenant_id: str, risk_id: str) -> RiskAcceptance:
    """Fetch a risk acceptance by id, tenant-scoped. Raises ReportNotFound if absent."""
    stmt = select(RiskAcceptance).where(
        RiskAcceptance.tenant_id == tenant_id,
        RiskAcceptance.id == risk_id,
    )
    row = db.execute(stmt).scalar_one_or_none()
    if row is None:
        raise ReportNotFound(
            f"RiskAcceptance {risk_id} not found for tenant {tenant_id}"
        )
    return row


def fetch_approvals_for_risk(
    db: Session, tenant_id: str, risk_id: str
) -> list[RiskAcceptanceApproval]:
    """Fetch approvals for a risk acceptance, ordered by created_at ASC."""
    stmt = (
        select(RiskAcceptanceApproval)
        .where(
            RiskAcceptanceApproval.tenant_id == tenant_id,
            RiskAcceptanceApproval.risk_acceptance_id == risk_id,
        )
        .order_by(RiskAcceptanceApproval.created_at.asc())
    )
    return list(db.execute(stmt).scalars().all())


def fetch_reviews_for_risk(
    db: Session, tenant_id: str, risk_id: str
) -> list[RiskReview]:
    """Fetch reviews for a risk acceptance, ordered by review_due_at ASC."""
    stmt = (
        select(RiskReview)
        .where(
            RiskReview.tenant_id == tenant_id,
            RiskReview.risk_acceptance_id == risk_id,
        )
        .order_by(RiskReview.review_due_at.asc())
    )
    return list(db.execute(stmt).scalars().all())


def fetch_control_links_for_risk(
    db: Session, tenant_id: str, risk_id: str
) -> list[RiskAcceptanceControlLink]:
    """Fetch control links for a risk acceptance."""
    stmt = select(RiskAcceptanceControlLink).where(
        RiskAcceptanceControlLink.tenant_id == tenant_id,
        RiskAcceptanceControlLink.risk_acceptance_id == risk_id,
    )
    return list(db.execute(stmt).scalars().all())


def fetch_controls_by_ids(
    db: Session, tenant_id: str, control_ids: list[str]
) -> list[ControlRegistry]:
    """Fetch controls by their DB primary key ids."""
    if not control_ids:
        return []
    stmt = select(ControlRegistry).where(
        ControlRegistry.tenant_id == tenant_id,
        ControlRegistry.id.in_(control_ids),
    )
    return list(db.execute(stmt).scalars().all())


def fetch_evidence_for_control(
    db: Session, tenant_id: str, control_id: str
) -> list[ControlEvidenceLink]:
    """Fetch evidence links for a control."""
    stmt = select(ControlEvidenceLink).where(
        ControlEvidenceLink.tenant_id == tenant_id,
        ControlEvidenceLink.control_id == control_id,
    )
    return list(db.execute(stmt).scalars().all())


def fetch_portal_acks_for_risk(
    db: Session, tenant_id: str, risk_id: str
) -> list[PortalAcknowledgement]:
    """Fetch portal acknowledgements for a risk (entity_type=accepted_risk)."""
    stmt = select(PortalAcknowledgement).where(
        PortalAcknowledgement.tenant_id == tenant_id,
        PortalAcknowledgement.entity_id == risk_id,
        PortalAcknowledgement.entity_type == "accepted_risk",
    )
    return list(db.execute(stmt).scalars().all())


def fetch_risk_audit_trail(
    db: Session, tenant_id: str, risk_id: str
) -> list[RiskAcceptanceAudit]:
    """Fetch audit trail for a risk acceptance, ordered by event_at ASC."""
    stmt = (
        select(RiskAcceptanceAudit)
        .where(
            RiskAcceptanceAudit.tenant_id == tenant_id,
            RiskAcceptanceAudit.risk_acceptance_id == risk_id,
        )
        .order_by(RiskAcceptanceAudit.event_at.asc())
    )
    return list(db.execute(stmt).scalars().all())


def fetch_approval_audit_trail(
    db: Session, tenant_id: str, risk_id: str
) -> list[RiskAcceptanceApprovalAudit]:
    """Fetch approval audit trail for a risk acceptance, ordered by event_at ASC."""
    stmt = (
        select(RiskAcceptanceApprovalAudit)
        .where(
            RiskAcceptanceApprovalAudit.tenant_id == tenant_id,
            RiskAcceptanceApprovalAudit.risk_acceptance_id == risk_id,
        )
        .order_by(RiskAcceptanceApprovalAudit.event_at.asc())
    )
    return list(db.execute(stmt).scalars().all())


# ---------------------------------------------------------------------------
# Write own tables
# ---------------------------------------------------------------------------


def insert_report(db: Session, report: GovernanceReport) -> None:
    """Insert a governance report record."""
    db.add(report)
    db.flush()


def insert_manifest(db: Session, manifest: GovernanceReportManifest) -> None:
    """Insert a governance report manifest."""
    db.add(manifest)
    db.flush()


def insert_attestation(db: Session, attestation: GovernanceAttestation) -> None:
    """Insert a governance attestation."""
    db.add(attestation)
    db.flush()


def insert_report_audit(db: Session, audit: GovernanceReportAudit) -> None:
    """Insert a governance report audit event."""
    db.add(audit)
    db.flush()


def fetch_report_by_id(db: Session, tenant_id: str, report_id: str) -> GovernanceReport:
    """Fetch a report by id, tenant-scoped. Raises ReportNotFound if absent."""
    stmt = select(GovernanceReport).where(
        GovernanceReport.tenant_id == tenant_id,
        GovernanceReport.id == report_id,
    )
    row = db.execute(stmt).scalar_one_or_none()
    if row is None:
        raise ReportNotFound(
            f"GovernanceReport {report_id} not found for tenant {tenant_id}"
        )
    return row


def fetch_manifest_for_report(
    db: Session, report_id: str
) -> GovernanceReportManifest | None:
    """Fetch the manifest for a report. Returns None if not found."""
    stmt = select(GovernanceReportManifest).where(
        GovernanceReportManifest.report_id == report_id,
    )
    return db.execute(stmt).scalar_one_or_none()


def fetch_reports(
    db: Session,
    tenant_id: str,
    risk_acceptance_id: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[GovernanceReport]:
    """Fetch paginated list of reports for a tenant."""
    stmt = select(GovernanceReport).where(GovernanceReport.tenant_id == tenant_id)
    if risk_acceptance_id is not None:
        stmt = stmt.where(GovernanceReport.risk_acceptance_id == risk_acceptance_id)
    stmt = (
        stmt.order_by(GovernanceReport.generated_at.desc()).limit(limit).offset(offset)
    )
    return list(db.execute(stmt).scalars().all())


def count_reports(
    db: Session,
    tenant_id: str,
    risk_acceptance_id: str | None = None,
) -> int:
    """Count reports for a tenant."""
    stmt = (
        select(func.count())
        .select_from(GovernanceReport)
        .where(GovernanceReport.tenant_id == tenant_id)
    )
    if risk_acceptance_id is not None:
        stmt = stmt.where(GovernanceReport.risk_acceptance_id == risk_acceptance_id)
    result = db.execute(stmt).scalar()
    return result or 0


def fetch_attestations(
    db: Session,
    tenant_id: str,
    report_id: str,
    limit: int = 50,
    offset: int = 0,
) -> list[GovernanceAttestation]:
    """Fetch paginated attestations for a report."""
    stmt = (
        select(GovernanceAttestation)
        .where(
            GovernanceAttestation.tenant_id == tenant_id,
            GovernanceAttestation.report_id == report_id,
        )
        .order_by(GovernanceAttestation.attested_at.desc())
        .limit(limit)
        .offset(offset)
    )
    return list(db.execute(stmt).scalars().all())


def count_attestations(db: Session, tenant_id: str, report_id: str) -> int:
    """Count attestations for a report."""
    stmt = (
        select(func.count())
        .select_from(GovernanceAttestation)
        .where(
            GovernanceAttestation.tenant_id == tenant_id,
            GovernanceAttestation.report_id == report_id,
        )
    )
    result = db.execute(stmt).scalar()
    return result or 0


def fetch_report_audits(
    db: Session, report_id: str, tenant_id: str
) -> list[GovernanceReportAudit]:
    """Fetch audit trail for a report, ordered by event_at DESC."""
    stmt = (
        select(GovernanceReportAudit)
        .where(
            GovernanceReportAudit.tenant_id == tenant_id,
            GovernanceReportAudit.report_id == report_id,
        )
        .order_by(GovernanceReportAudit.event_at.desc())
    )
    return list(db.execute(stmt).scalars().all())


def supersede_previous_reports(
    db: Session,
    tenant_id: str,
    risk_acceptance_id: str,
    current_report_id: str,
) -> None:
    """Set status=SUPERSEDED for all COMPLETED reports for this risk (except current)."""
    stmt = select(GovernanceReport).where(
        GovernanceReport.tenant_id == tenant_id,
        GovernanceReport.risk_acceptance_id == risk_acceptance_id,
        GovernanceReport.id != current_report_id,
        GovernanceReport.status == ReportStatus.COMPLETED.value,
    )
    rows = db.execute(stmt).scalars().all()
    for row in rows:
        row.status = ReportStatus.SUPERSEDED.value
    db.flush()


def get_max_report_version(db: Session, tenant_id: str, risk_acceptance_id: str) -> int:
    """Get the maximum report_version for this risk (returns 0 if none)."""
    stmt = select(func.max(GovernanceReport.report_version)).where(
        GovernanceReport.tenant_id == tenant_id,
        GovernanceReport.risk_acceptance_id == risk_acceptance_id,
    )
    result = db.execute(stmt).scalar()
    return result or 0
