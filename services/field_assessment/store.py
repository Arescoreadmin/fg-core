"""Field assessment store — all DB access for engagement substrate."""

from __future__ import annotations

import hashlib
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from api.db_models_field_assessment import (
    FaDocumentAnalysis,
    FaEngagement,
    FaEngagementAuditEvent,
    FaEvidenceLink,
    FaFieldObservation,
    FaNormalizedFinding,
    FaScanResult,
)
from services.canonical import canonical_json_bytes, utc_iso8601_z_now
from services.field_assessment.models import (
    VALID_ENGAGEMENT_TRANSITIONS,
    EngagementNotFound,
    EvidenceLinkDuplicate,
    FindingNotFound,
    InvalidEngagementTransition,
    ScanResultNotFound,
)

MAX_PAGE_SIZE = 100


def _new_id() -> str:
    return (
        str(uuid.uuid4()).replace("-", "")[:16]
        + hashlib.sha256(uuid.uuid4().bytes).hexdigest()[:16]
    )


def derive_finding_id(finding_type: str, engagement_id: str, source_ref: str) -> str:
    """Deterministic finding ID: SHA-256(finding_type|engagement_id|source_ref)[:16]."""
    canonical = f"{finding_type}|{engagement_id}|{source_ref}"
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def derive_findings_hash(finding_type: str, engagement_id: str, source_ref: str) -> str:
    """Full SHA-256 for uniqueness enforcement."""
    canonical = f"{finding_type}|{engagement_id}|{source_ref}"
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def compute_evidence_hash(payload: dict[str, Any]) -> str:
    """SHA-256 over canonical JSON payload."""
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


# ---------------------------------------------------------------------------
# Engagement
# ---------------------------------------------------------------------------


def create_engagement(
    db: Session,
    *,
    tenant_id: str,
    client_name: str,
    client_domain: str | None,
    assessor_id: str,
    assessment_type: str,
    scheduled_date: str | None,
    engagement_metadata: dict[str, Any],
    actor: str,
) -> FaEngagement:
    now = utc_iso8601_z_now()
    engagement = FaEngagement(
        id=_new_id(),
        tenant_id=tenant_id,
        client_name=client_name,
        client_domain=client_domain,
        assessor_id=assessor_id,
        assessment_type=assessment_type,
        status="scheduled",
        scheduled_date=scheduled_date,
        engagement_metadata=engagement_metadata,
        schema_version="1.0",
        created_at=now,
        updated_at=now,
    )
    db.add(engagement)
    db.flush()
    return engagement


def get_engagement(
    db: Session,
    *,
    engagement_id: str,
    tenant_id: str,
) -> FaEngagement:
    stmt = select(FaEngagement).where(
        FaEngagement.id == engagement_id,
        FaEngagement.tenant_id == tenant_id,
    )
    row = db.execute(stmt).scalar_one_or_none()
    if row is None:
        raise EngagementNotFound(f"engagement {engagement_id!r} not found")
    return row


def list_engagements(
    db: Session,
    *,
    tenant_id: str,
    status_filter: str | None,
    limit: int,
    cursor: str | None,
) -> list[FaEngagement]:
    limit = min(limit, MAX_PAGE_SIZE)
    stmt = select(FaEngagement).where(FaEngagement.tenant_id == tenant_id)
    if status_filter:
        stmt = stmt.where(FaEngagement.status == status_filter)
    if cursor:
        stmt = stmt.where(FaEngagement.created_at < cursor)
    stmt = stmt.order_by(FaEngagement.created_at.desc()).limit(limit)
    return list(db.execute(stmt).scalars().all())


def transition_engagement(
    db: Session,
    *,
    engagement_id: str,
    tenant_id: str,
    new_status: str,
    actor: str,
) -> FaEngagement:
    engagement = get_engagement(db, engagement_id=engagement_id, tenant_id=tenant_id)
    current = engagement.status
    allowed = VALID_ENGAGEMENT_TRANSITIONS.get(current, set())
    if new_status not in allowed:
        raise InvalidEngagementTransition(
            f"cannot transition engagement from {current!r} to {new_status!r}"
        )
    engagement.status = new_status
    engagement.updated_at = utc_iso8601_z_now()
    db.flush()
    return engagement


# ---------------------------------------------------------------------------
# Scan results
# ---------------------------------------------------------------------------


def create_scan_result(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
    source_type: str,
    schema_version: str,
    collected_at: str,
    raw_payload: dict[str, Any],
    normalized_payload: dict[str, Any] | None,
    object_count: int,
) -> FaScanResult:
    """Idempotent via uq_fa_scan_evidence — returns existing record on duplicate payload."""
    evidence_hash = compute_evidence_hash(raw_payload)

    existing_stmt = select(FaScanResult).where(
        FaScanResult.engagement_id == engagement_id,
        FaScanResult.tenant_id == tenant_id,
        FaScanResult.evidence_hash == evidence_hash,
    )
    existing = db.execute(existing_stmt).scalar_one_or_none()
    if existing is not None:
        return existing

    now = utc_iso8601_z_now()
    result = FaScanResult(
        id=_new_id(),
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        source_type=source_type,
        schema_version=schema_version,
        collected_at=collected_at,
        evidence_hash=evidence_hash,
        raw_payload=raw_payload,
        normalized_payload=normalized_payload,
        object_count=object_count,
        created_at=now,
    )
    db.add(result)
    db.flush()
    return result


def get_scan_result(
    db: Session,
    *,
    scan_result_id: str,
    engagement_id: str,
    tenant_id: str,
) -> FaScanResult:
    stmt = select(FaScanResult).where(
        FaScanResult.id == scan_result_id,
        FaScanResult.engagement_id == engagement_id,
        FaScanResult.tenant_id == tenant_id,
    )
    row = db.execute(stmt).scalar_one_or_none()
    if row is None:
        raise ScanResultNotFound(f"scan result {scan_result_id!r} not found")
    return row


def list_scan_results(
    db: Session,
    *,
    engagement_id: str,
    tenant_id: str,
    limit: int,
) -> list[FaScanResult]:
    limit = min(limit, MAX_PAGE_SIZE)
    stmt = (
        select(FaScanResult)
        .where(
            FaScanResult.engagement_id == engagement_id,
            FaScanResult.tenant_id == tenant_id,
        )
        .order_by(FaScanResult.created_at.desc())
        .limit(limit)
    )
    return list(db.execute(stmt).scalars().all())


# ---------------------------------------------------------------------------
# Document analyses
# ---------------------------------------------------------------------------


def create_document_analysis(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
    document_name: str,
    document_classification: str,
    document_hash: str | None,
    version_label: str | None,
    approved_by: str | None,
    approval_date: str | None,
    freshness_date: str | None,
    analysis_findings: list[Any],
    gaps_identified: list[Any],
) -> FaDocumentAnalysis:
    now = utc_iso8601_z_now()
    analysis = FaDocumentAnalysis(
        id=_new_id(),
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        document_name=document_name,
        document_classification=document_classification,
        document_hash=document_hash,
        version_label=version_label,
        approved_by=approved_by,
        approval_date=approval_date,
        freshness_date=freshness_date,
        analysis_findings=analysis_findings,
        gaps_identified=gaps_identified,
        schema_version="1.0",
        created_at=now,
        updated_at=now,
    )
    db.add(analysis)
    db.flush()
    return analysis


def list_document_analyses(
    db: Session,
    *,
    engagement_id: str,
    tenant_id: str,
    limit: int,
) -> list[FaDocumentAnalysis]:
    limit = min(limit, MAX_PAGE_SIZE)
    stmt = (
        select(FaDocumentAnalysis)
        .where(
            FaDocumentAnalysis.engagement_id == engagement_id,
            FaDocumentAnalysis.tenant_id == tenant_id,
        )
        .order_by(FaDocumentAnalysis.created_at.desc())
        .limit(limit)
    )
    return list(db.execute(stmt).scalars().all())


# ---------------------------------------------------------------------------
# Field observations
# ---------------------------------------------------------------------------


def create_observation(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
    domain: str,
    observation_type: str,
    severity: str,
    title: str,
    description: str,
    interview_role: str | None,
    structured_evidence: dict[str, Any],
    linked_finding_ids: list[Any],
    assessor_id: str,
) -> FaFieldObservation:
    now = utc_iso8601_z_now()
    observation = FaFieldObservation(
        id=_new_id(),
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        domain=domain,
        observation_type=observation_type,
        severity=severity,
        title=title,
        description=description,
        interview_role=interview_role,
        structured_evidence=structured_evidence,
        linked_finding_ids=linked_finding_ids,
        assessor_id=assessor_id,
        schema_version="1.0",
        created_at=now,
    )
    db.add(observation)
    db.flush()
    return observation


def list_observations(
    db: Session,
    *,
    engagement_id: str,
    tenant_id: str,
    limit: int,
    observation_type: str | None = None,
) -> list[FaFieldObservation]:
    limit = min(limit, MAX_PAGE_SIZE)
    stmt = (
        select(FaFieldObservation)
        .where(
            FaFieldObservation.engagement_id == engagement_id,
            FaFieldObservation.tenant_id == tenant_id,
        )
        .order_by(FaFieldObservation.created_at.desc())
        .limit(limit)
    )
    if observation_type is not None:
        stmt = stmt.where(FaFieldObservation.observation_type == observation_type)
    return list(db.execute(stmt).scalars().all())


def list_audit_events(
    db: Session,
    *,
    engagement_id: str,
    tenant_id: str,
    limit: int = 100,
) -> list[FaEngagementAuditEvent]:
    limit = min(limit, MAX_PAGE_SIZE)
    stmt = (
        select(FaEngagementAuditEvent)
        .where(
            FaEngagementAuditEvent.engagement_id == engagement_id,
            FaEngagementAuditEvent.tenant_id == tenant_id,
        )
        .order_by(FaEngagementAuditEvent.created_at.desc())
        .limit(limit)
    )
    return list(db.execute(stmt).scalars().all())


# ---------------------------------------------------------------------------
# Normalized findings
# ---------------------------------------------------------------------------


def create_finding(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
    finding_type: str,
    source_ref: str,
    severity: str,
    title: str,
    description: str,
    source_attribution: str,
    confidence_score: int,
    framework_mappings: list[Any],
    nist_ai_rmf_mappings: list[Any],
    evidence_ref_ids: list[Any],
    remediation_hint: str | None,
) -> FaNormalizedFinding:
    """Idempotent via findings_hash UniqueConstraint — returns existing if duplicate."""
    findings_hash = derive_findings_hash(finding_type, engagement_id, source_ref)
    finding_id = derive_finding_id(finding_type, engagement_id, source_ref)
    now = utc_iso8601_z_now()

    # Check for existing finding (idempotent)
    stmt = select(FaNormalizedFinding).where(
        FaNormalizedFinding.tenant_id == tenant_id,
        FaNormalizedFinding.findings_hash == findings_hash,
    )
    existing = db.execute(stmt).scalar_one_or_none()
    if existing is not None:
        return existing

    finding = FaNormalizedFinding(
        id=finding_id,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        finding_type=finding_type,
        findings_hash=findings_hash,
        severity=severity,
        status="open",
        title=title,
        description=description,
        source_attribution=source_attribution,
        confidence_score=confidence_score,
        framework_mappings=framework_mappings,
        nist_ai_rmf_mappings=nist_ai_rmf_mappings,
        evidence_ref_ids=evidence_ref_ids,
        remediation_hint=remediation_hint,
        schema_version="1.0",
        created_at=now,
        updated_at=now,
    )
    db.add(finding)
    db.flush()
    return finding


def get_finding(
    db: Session,
    *,
    finding_id: str,
    engagement_id: str,
    tenant_id: str,
) -> FaNormalizedFinding:
    stmt = select(FaNormalizedFinding).where(
        FaNormalizedFinding.id == finding_id,
        FaNormalizedFinding.engagement_id == engagement_id,
        FaNormalizedFinding.tenant_id == tenant_id,
    )
    row = db.execute(stmt).scalar_one_or_none()
    if row is None:
        raise FindingNotFound(f"finding {finding_id!r} not found")
    return row


def list_findings(
    db: Session,
    *,
    engagement_id: str,
    tenant_id: str,
    severity_filter: str | None,
    status_filter: str | None,
    limit: int,
) -> list[FaNormalizedFinding]:
    limit = min(limit, MAX_PAGE_SIZE)
    stmt = select(FaNormalizedFinding).where(
        FaNormalizedFinding.engagement_id == engagement_id,
        FaNormalizedFinding.tenant_id == tenant_id,
    )
    if severity_filter:
        stmt = stmt.where(FaNormalizedFinding.severity == severity_filter)
    if status_filter:
        stmt = stmt.where(FaNormalizedFinding.status == status_filter)
    stmt = stmt.order_by(FaNormalizedFinding.created_at.desc()).limit(limit)
    return list(db.execute(stmt).scalars().all())


# ---------------------------------------------------------------------------
# Evidence links
# ---------------------------------------------------------------------------


def create_evidence_link(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
    source_entity_type: str,
    source_entity_id: str,
    evidence_entity_type: str,
    evidence_entity_id: str,
    link_metadata: dict[str, Any],
) -> FaEvidenceLink:
    """Idempotent via UniqueConstraint — raises EvidenceLinkDuplicate on duplicate."""
    now = utc_iso8601_z_now()
    link = FaEvidenceLink(
        id=_new_id(),
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        source_entity_type=source_entity_type,
        source_entity_id=source_entity_id,
        evidence_entity_type=evidence_entity_type,
        evidence_entity_id=evidence_entity_id,
        link_metadata=link_metadata,
        created_at=now,
        schema_version="1.0",
    )
    try:
        db.add(link)
        db.flush()
    except IntegrityError:
        db.rollback()
        raise EvidenceLinkDuplicate("evidence link already exists")
    return link


def list_evidence_links(
    db: Session,
    *,
    engagement_id: str,
    tenant_id: str,
    source_entity_id: str | None,
    limit: int,
) -> list[FaEvidenceLink]:
    limit = min(limit, MAX_PAGE_SIZE)
    stmt = select(FaEvidenceLink).where(
        FaEvidenceLink.engagement_id == engagement_id,
        FaEvidenceLink.tenant_id == tenant_id,
    )
    if source_entity_id:
        stmt = stmt.where(FaEvidenceLink.source_entity_id == source_entity_id)
    stmt = stmt.order_by(FaEvidenceLink.created_at.desc()).limit(limit)
    return list(db.execute(stmt).scalars().all())
