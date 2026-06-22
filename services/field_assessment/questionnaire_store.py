"""Store layer for NIST AI RMF questionnaire — CRUD and evidence linking.

Security invariants:
  - All queries scope by (questionnaire_id, tenant_id, engagement_id) or
    (engagement_id, tenant_id).
  - Status transitions are one-way: draft → submitted → finalized.
  - On submit: FaEvidenceLink records created for each assessed response that
    matches a finding's nist_ai_rmf_mappings. Duplicate links are silently ignored.
  - get_questionnaire() enforces engagement_id, preventing cross-engagement access.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from api.db_models_questionnaire import FaQuestionnaire, FaQuestionnaireResponse
from services.canonical import utc_iso8601_z_now
from services.field_assessment.questionnaire_framework import (
    CONTROLS,
    FRAMEWORK_ID,
    FRAMEWORK_VERSION,
)


# ---------------------------------------------------------------------------
# Domain exceptions
# ---------------------------------------------------------------------------


class QuestionnaireNotFound(Exception):
    def __init__(self, msg: str = "Questionnaire not found") -> None:
        super().__init__(msg)
        self.message = msg


class QuestionnaireAlreadyExists(Exception):
    def __init__(self, questionnaire_id: str) -> None:
        super().__init__(f"Questionnaire already exists: {questionnaire_id}")
        self.questionnaire_id = questionnaire_id


class QuestionnaireAlreadySubmitted(Exception):
    def __init__(self) -> None:
        super().__init__(
            "Questionnaire has already been submitted and cannot be modified"
        )
        self.message = "Questionnaire has already been submitted and cannot be modified"


class ControlNotFound(Exception):
    def __init__(self, control_id: str) -> None:
        super().__init__(f"Control not found in framework: {control_id}")
        self.message = f"Control not found in framework: {control_id}"


# ---------------------------------------------------------------------------
# Valid response statuses
# ---------------------------------------------------------------------------

VALID_RESPONSE_STATUSES: frozenset[str] = frozenset(
    {"not_assessed", "implemented", "partial", "not_implemented", "not_applicable"}
)

ASSESSED_STATUSES: frozenset[str] = frozenset(
    {"implemented", "partial", "not_implemented"}
)

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _new_id() -> str:
    return uuid.uuid4().hex


# ---------------------------------------------------------------------------
# NIST mapping normalization
# ---------------------------------------------------------------------------

_NIST_PREFIX = "NIST-AI-RMF-"


def normalize_nist_control(mapping: Any) -> str | None:
    """Normalize a NIST AI RMF mapping to its short canonical control_id.

    Supported input forms:
      - String:  "NIST-AI-RMF-GOVERN-1.2"  →  "GOVERN-1.2"
      - String:  "GOVERN-1.2"               →  "GOVERN-1.2"
      - Dict:    {"control_id": "NIST-AI-RMF-GOVERN-1.2"}  →  "GOVERN-1.2"
      - Dict:    {"control_id": "GOVERN-1.2"}               →  "GOVERN-1.2"
      - Dict:    {"function": "GOVERN", "category": "GOVERN-1.2", ...}  →  "GOVERN-1.2"

    Returns None for unrecognized shapes so callers can skip without crashing.
    """
    if isinstance(mapping, str):
        raw = mapping.strip()
        if raw.startswith(_NIST_PREFIX):
            return raw[len(_NIST_PREFIX) :]
        return raw or None

    if isinstance(mapping, dict):
        # {"function": "GOVERN", "category": "GOVERN-1.2", ...}
        if "category" in mapping:
            cat = mapping["category"]
            if isinstance(cat, str) and cat.strip():
                return cat.strip()

        # {"control_id": "NIST-AI-RMF-GOVERN-1.2"} or {"control_id": "GOVERN-1.2"}
        if "control_id" in mapping:
            raw = mapping["control_id"]
            if isinstance(raw, str) and raw.strip():
                s = raw.strip()
                return s[len(_NIST_PREFIX) :] if s.startswith(_NIST_PREFIX) else s

    return None


# ---------------------------------------------------------------------------
# Questionnaire creation
# ---------------------------------------------------------------------------


def create_questionnaire(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
    assessor_id: str,
    framework: str = FRAMEWORK_ID,
) -> FaQuestionnaire:
    """Create a questionnaire with all controls pre-seeded as not_assessed.

    Raises QuestionnaireAlreadyExists if one exists for (tenant, engagement, framework).
    """
    now = utc_iso8601_z_now()
    q = FaQuestionnaire(
        id=_new_id(),
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        framework=framework,
        framework_version=FRAMEWORK_VERSION,
        status="draft",
        submitted_at=None,
        submitted_by=None,
        schema_version="1.0",
        created_at=now,
        updated_at=now,
    )
    try:
        db.add(q)
        db.flush()
    except IntegrityError:
        db.rollback()
        existing = _get_questionnaire_by_framework(
            db, tenant_id=tenant_id, engagement_id=engagement_id, framework=framework
        )
        if existing is None:
            raise
        raise QuestionnaireAlreadyExists(existing.id)

    # Pre-seed all control responses
    for ctrl in CONTROLS:
        r = FaQuestionnaireResponse(
            id=_new_id(),
            questionnaire_id=q.id,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            control_id=ctrl["control_id"],
            category=ctrl["category"],
            control_name=ctrl["control_name"],
            response_status="not_assessed",
            evidence_text=None,
            confidence_score=None,
            assessor_id=assessor_id,
            schema_version="1.0",
            created_at=now,
            updated_at=now,
        )
        db.add(r)

    db.flush()
    return q


def get_or_create_questionnaire(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
    assessor_id: str,
    framework: str = FRAMEWORK_ID,
) -> tuple[FaQuestionnaire, bool]:
    """Return (questionnaire, created). Creates if no questionnaire exists."""
    existing = _get_questionnaire_by_framework(
        db, tenant_id=tenant_id, engagement_id=engagement_id, framework=framework
    )
    if existing is not None:
        return existing, False
    q = create_questionnaire(
        db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        assessor_id=assessor_id,
        framework=framework,
    )
    return q, True


# ---------------------------------------------------------------------------
# Questionnaire retrieval
# ---------------------------------------------------------------------------


def _get_questionnaire_by_framework(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
    framework: str,
) -> FaQuestionnaire | None:
    stmt = select(FaQuestionnaire).where(
        FaQuestionnaire.tenant_id == tenant_id,
        FaQuestionnaire.engagement_id == engagement_id,
        FaQuestionnaire.framework == framework,
    )
    return db.scalar(stmt)


def get_questionnaire(
    db: Session,
    *,
    questionnaire_id: str,
    tenant_id: str,
    engagement_id: str,
) -> FaQuestionnaire:
    """Load questionnaire scoped to (questionnaire_id, tenant_id, engagement_id).

    Enforces engagement isolation: a questionnaire from a different engagement
    within the same tenant is indistinguishable from a missing questionnaire —
    both raise QuestionnaireNotFound (404).
    """
    q = db.scalar(
        select(FaQuestionnaire).where(
            FaQuestionnaire.id == questionnaire_id,
            FaQuestionnaire.tenant_id == tenant_id,
            FaQuestionnaire.engagement_id == engagement_id,
        )
    )
    if q is None:
        raise QuestionnaireNotFound()
    return q


def list_responses(
    db: Session,
    *,
    questionnaire_id: str,
    tenant_id: str,
) -> list[FaQuestionnaireResponse]:
    return list(
        db.scalars(
            select(FaQuestionnaireResponse).where(
                FaQuestionnaireResponse.questionnaire_id == questionnaire_id,
                FaQuestionnaireResponse.tenant_id == tenant_id,
            )
        )
    )


def list_questionnaires(
    db: Session,
    *,
    engagement_id: str,
    tenant_id: str,
) -> list[FaQuestionnaire]:
    return list(
        db.scalars(
            select(FaQuestionnaire)
            .where(
                FaQuestionnaire.engagement_id == engagement_id,
                FaQuestionnaire.tenant_id == tenant_id,
            )
            .order_by(FaQuestionnaire.created_at)
        )
    )


# ---------------------------------------------------------------------------
# Response update
# ---------------------------------------------------------------------------


def update_response(
    db: Session,
    *,
    questionnaire_id: str,
    control_id: str,
    tenant_id: str,
    engagement_id: str,
    response_status: str,
    evidence_text: str | None,
    confidence_score: float | None,
    assessor_id: str | None,
) -> FaQuestionnaireResponse:
    """Update a single control response. Raises QuestionnaireAlreadySubmitted if finalized."""
    q = get_questionnaire(
        db,
        questionnaire_id=questionnaire_id,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
    )
    if q.status in ("submitted", "finalized"):
        raise QuestionnaireAlreadySubmitted()

    r = db.scalar(
        select(FaQuestionnaireResponse).where(
            FaQuestionnaireResponse.questionnaire_id == questionnaire_id,
            FaQuestionnaireResponse.control_id == control_id,
            FaQuestionnaireResponse.tenant_id == tenant_id,
        )
    )
    if r is None:
        raise ControlNotFound(control_id)

    r.response_status = response_status
    r.evidence_text = evidence_text
    r.confidence_score = confidence_score
    if assessor_id is not None:
        r.assessor_id = assessor_id
    r.updated_at = utc_iso8601_z_now()
    q.updated_at = r.updated_at
    db.flush()
    return r


# ---------------------------------------------------------------------------
# Submit
# ---------------------------------------------------------------------------


def submit_questionnaire(
    db: Session,
    *,
    questionnaire_id: str,
    tenant_id: str,
    engagement_id: str,
    actor: str,
) -> FaQuestionnaire:
    """Transition questionnaire to 'submitted' and create evidence links.

    Idempotent: if already submitted, returns the existing questionnaire.
    Links each assessed response to findings sharing the same nist_ai_rmf control ID.
    Audit events must be written against q.engagement_id (verified from DB).
    """
    q = get_questionnaire(
        db,
        questionnaire_id=questionnaire_id,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
    )
    if q.status in ("submitted", "finalized"):
        return q

    now = utc_iso8601_z_now()
    q.status = "submitted"
    q.submitted_at = now
    q.submitted_by = actor
    q.updated_at = now
    db.flush()

    _link_responses_to_findings(db, questionnaire=q, tenant_id=tenant_id)
    return q


def _link_responses_to_findings(
    db: Session,
    *,
    questionnaire: FaQuestionnaire,
    tenant_id: str,
) -> None:
    """Create FaEvidenceLink records between assessed responses and matching findings.

    Normalizes all nist_ai_rmf_mappings to short canonical control IDs before
    matching, supporting all three stored shapes:
      - string:  "NIST-AI-RMF-GOVERN-1.2"
      - dict:    {"control_id": "NIST-AI-RMF-GOVERN-1.2"}
      - dict:    {"function": "GOVERN", "category": "GOVERN-1.2", ...}

    Each created FaEvidenceLink records full deterministic lineage in
    link_metadata for audit replay and regulator review.
    """
    from api.db_models_field_assessment import FaEvidenceLink, FaNormalizedFinding

    responses = list_responses(
        db, questionnaire_id=questionnaire.id, tenant_id=tenant_id
    )
    assessed = [r for r in responses if r.response_status in ASSESSED_STATUSES]
    if not assessed:
        return

    assessed_control_ids = {r.control_id for r in assessed}
    response_by_control = {r.control_id: r for r in assessed}

    findings = list(
        db.scalars(
            select(FaNormalizedFinding).where(
                FaNormalizedFinding.engagement_id == questionnaire.engagement_id,
                FaNormalizedFinding.tenant_id == tenant_id,
            )
        )
    )

    now = utc_iso8601_z_now()
    for finding in findings:
        raw_mappings: list[Any] = finding.nist_ai_rmf_mappings or []
        matched_controls: list[str] = []
        for m in raw_mappings:
            normalized = normalize_nist_control(m)
            if normalized and normalized in assessed_control_ids:
                matched_controls.append(normalized)

        for control_id in matched_controls:
            response = response_by_control.get(control_id)
            if response is None:
                continue
            link = FaEvidenceLink(
                id=_new_id(),
                tenant_id=tenant_id,
                engagement_id=questionnaire.engagement_id,
                source_entity_type="normalized_finding",
                source_entity_id=finding.id,
                evidence_entity_type="questionnaire_response",
                evidence_entity_id=response.id,
                link_metadata={
                    "control_id": control_id,
                    "questionnaire_id": questionnaire.id,
                    "response_status": response.response_status,
                    "source_type": "questionnaire",
                    "source_question_id": response.control_id,
                    "source_response_id": response.id,
                    "matched_control_id": control_id,
                    "link_reason": "nist_control_match",
                },
                created_at=now,
                schema_version="1.0",
            )
            try:
                db.add(link)
                db.flush()
            except IntegrityError:
                db.rollback()


# ---------------------------------------------------------------------------
# Coverage summary
# ---------------------------------------------------------------------------


def get_coverage(
    db: Session,
    *,
    questionnaire_id: str,
    tenant_id: str,
) -> dict[str, Any]:
    responses = list_responses(
        db, questionnaire_id=questionnaire_id, tenant_id=tenant_id
    )
    total = len(responses)
    by_status: dict[str, int] = {}
    by_category: dict[str, dict[str, int]] = {}

    for r in responses:
        by_status[r.response_status] = by_status.get(r.response_status, 0) + 1
        cat = by_category.setdefault(r.category, {})
        cat[r.response_status] = cat.get(r.response_status, 0) + 1

    assessed = sum(by_status.get(s, 0) for s in ASSESSED_STATUSES)
    implemented = by_status.get("implemented", 0)
    not_applicable = by_status.get("not_applicable", 0)
    applicable = total - not_applicable
    coverage_pct = round(implemented / applicable * 100, 1) if applicable > 0 else 0.0

    return {
        "total_controls": total,
        "assessed_count": assessed,
        "not_assessed_count": by_status.get("not_assessed", 0),
        "implemented_count": implemented,
        "partial_count": by_status.get("partial", 0),
        "not_implemented_count": by_status.get("not_implemented", 0),
        "not_applicable_count": not_applicable,
        "coverage_pct": coverage_pct,
        "by_category": by_category,
    }
