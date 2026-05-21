"""Workflow evidence attachment — thin wrapper over FaEvidenceLink.

This subsystem is NOT standalone.
It is a tenant-scoped component of the Field Assessment Engagement Substrate.

Evidence is stored in fa_evidence_links with source_entity_type="workflow".
This means workflow completion evidence is part of the same evidence graph
that the drift engine traverses — closing the lineage loop structurally.

evidence_entity_type: "link" | "text" | "scan_result_ref" | "finding_ref"
evidence_entity_id:   URL, text excerpt, FaScanResult.id, or FaNormalizedFinding.id
"""

from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db_models_field_assessment import FaEvidenceLink
from services.field_assessment.store import EvidenceLinkDuplicate, create_evidence_link

log = logging.getLogger("frostgate.governance_workflows.evidence")

VALID_EVIDENCE_TYPES = frozenset(
    {"link", "text", "scan_result_ref", "finding_ref"}
)


class WorkflowEvidenceDuplicate(ValueError):
    pass


class InvalidEvidenceType(ValueError):
    pass


def attach_workflow_evidence(
    db: Session,
    *,
    workflow_id: str,
    tenant_id: str,
    engagement_id: str,
    evidence_type: str,
    reference: str,
    submitted_by: str,
) -> FaEvidenceLink:
    """Attach evidence to a workflow via FaEvidenceLink.

    Raises InvalidEvidenceType for unknown types.
    Raises WorkflowEvidenceDuplicate when the same type+reference already exists.
    """
    if evidence_type not in VALID_EVIDENCE_TYPES:
        raise InvalidEvidenceType(
            f"evidence_type must be one of {sorted(VALID_EVIDENCE_TYPES)}, "
            f"got {evidence_type!r}"
        )
    try:
        return create_evidence_link(
            db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            source_entity_type="workflow",
            source_entity_id=workflow_id,
            evidence_entity_type=evidence_type,
            evidence_entity_id=reference,
            link_metadata={"submitted_by": submitted_by},
        )
    except EvidenceLinkDuplicate:
        raise WorkflowEvidenceDuplicate(
            f"evidence ({evidence_type}, {reference!r}) already attached to workflow "
            f"{workflow_id!r}"
        )


def workflow_evidence_complete(
    db: Session,
    *,
    workflow_id: str,
    tenant_id: str,
    engagement_id: str,
    required_types: tuple[str, ...],
) -> bool:
    """Return True only if at least one evidence row exists for every required type.

    Fail-closed: returns False on any ambiguity or empty required_types.
    """
    if not required_types:
        return False

    rows = (
        db.execute(
            select(FaEvidenceLink.evidence_entity_type).where(
                FaEvidenceLink.tenant_id == tenant_id,
                FaEvidenceLink.engagement_id == engagement_id,
                FaEvidenceLink.source_entity_type == "workflow",
                FaEvidenceLink.source_entity_id == workflow_id,
            )
        )
        .scalars()
        .all()
    )
    present = set(rows)
    return all(t in present for t in required_types)


def get_evidence_for_workflow(
    db: Session,
    *,
    workflow_id: str,
    tenant_id: str,
    engagement_id: str,
) -> list[FaEvidenceLink]:
    return (
        db.execute(
            select(FaEvidenceLink)
            .where(
                FaEvidenceLink.tenant_id == tenant_id,
                FaEvidenceLink.engagement_id == engagement_id,
                FaEvidenceLink.source_entity_type == "workflow",
                FaEvidenceLink.source_entity_id == workflow_id,
            )
            .order_by(FaEvidenceLink.created_at.asc())
        )
        .scalars()
        .all()
    )
