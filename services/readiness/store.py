"""Readiness persistence layer (SQLAlchemy).

All queries are tenant-scoped: platform-level records (tenant_id=None) are
readable by any operator with sufficient scope; tenant-linked records are
only visible within the owning tenant's context.

Framework definitions are immutable once activated — mutations to structure
(domains, controls, maturity tiers) are rejected after framework activation.

Assessment records are immutable once finalized — results and evidence
references cannot be added or modified after finalization.

No mutable module-level state. ReadinessStore is stateless and receives
a Session at call time. All mutations emit a ReadinessAuditEvent before
returning.
"""

from __future__ import annotations

import json as _json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional, cast

from sqlalchemy.orm import Session

from api.db_models import (
    ReadinessAssessmentRecord,
    ReadinessAssessmentResultRecord,
    ReadinessAuditEventRecord,
    ReadinessControlRecord,
    ReadinessControlReferenceRecord,
    ReadinessDomainRecord,
    ReadinessEvidenceReferenceRecord,
    ReadinessFrameworkRecord,
    ReadinessFrameworkVersionRecord,
    ReadinessMaturityTierRecord,
    ReadinessScoringContractRecord,
)
from services.readiness.audit import (
    _get_previous_event_hash,
    compute_event_hash,
    emit_readiness_event,
)
from services.readiness.models import (
    Assessment,
    AssessmentOutcome,
    AssessmentResult,
    AssessmentStatus,
    Control,
    ControlReference,
    Domain,
    EvidenceReference,
    EvidenceType,
    Framework,
    FrameworkStatus,
    FrameworkVersion,
    IMMUTABLE_FRAMEWORK_STATUSES,
    MaturityTier,
    ReadinessAuditEvent,
    ReadinessEventType,
    ScoringContract,
    assert_assessment_mutable,
    validate_assessment_transition,
    validate_framework_transition,
)

log = logging.getLogger("frostgate.readiness.store")

_MAX_PAGE = 200
_DEFAULT_PAGE = 50


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _utcnow_iso() -> str:
    return _utcnow().isoformat()


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------


class ReadinessStoreError(Exception):
    """Base error for readiness store operations."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


class FrameworkNotFound(ReadinessStoreError):
    def __init__(self, framework_id: str) -> None:
        super().__init__("READY-001", f"Framework not found: {framework_id}")


class FrameworkVersionNotFound(ReadinessStoreError):
    def __init__(self, version_id: str) -> None:
        super().__init__("READY-002", f"Framework version not found: {version_id}")


class DomainNotFound(ReadinessStoreError):
    def __init__(self, domain_id: str) -> None:
        super().__init__("READY-003", f"Domain not found: {domain_id}")


class ControlNotFound(ReadinessStoreError):
    def __init__(self, control_id: str) -> None:
        super().__init__("READY-004", f"Control not found: {control_id}")


class MaturityTierNotFound(ReadinessStoreError):
    def __init__(self, tier_id: str) -> None:
        super().__init__("READY-005", f"Maturity tier not found: {tier_id}")


class AssessmentNotFound(ReadinessStoreError):
    def __init__(self, assessment_id: str) -> None:
        super().__init__("READY-006", f"Assessment not found: {assessment_id}")


class AssessmentResultNotFound(ReadinessStoreError):
    def __init__(self, result_id: str) -> None:
        super().__init__("READY-007", f"Assessment result not found: {result_id}")


class EvidenceReferenceNotFound(ReadinessStoreError):
    def __init__(self, evidence_id: str) -> None:
        super().__init__("READY-008", f"Evidence reference not found: {evidence_id}")


class ScoringContractNotFound(ReadinessStoreError):
    def __init__(self, contract_id: str) -> None:
        super().__init__("READY-009", f"Scoring contract not found: {contract_id}")


class InvalidFrameworkTransition(ReadinessStoreError):
    def __init__(self, from_status: str, to_status: str) -> None:
        super().__init__(
            "READY-010",
            f"Invalid framework transition: {from_status!r} → {to_status!r}",
        )


class InvalidAssessmentTransition(ReadinessStoreError):
    def __init__(self, from_status: str, to_status: str) -> None:
        super().__init__(
            "READY-011",
            f"Invalid assessment transition: {from_status!r} → {to_status!r}",
        )


class AssessmentImmutableError(ReadinessStoreError):
    def __init__(self, assessment_id: str, status: str) -> None:
        super().__init__(
            "READY-012",
            f"Assessment {assessment_id!r} is immutable (status={status!r}). "
            "Finalized and archived assessments cannot be modified.",
        )


class FrameworkImmutableError(ReadinessStoreError):
    def __init__(self, framework_id: str, status: str) -> None:
        super().__init__(
            "READY-013",
            f"Framework {framework_id!r} structure is immutable (status={status!r}). "
            "Domains and controls cannot be added to an active or deprecated framework.",
        )


class ConcurrentModificationError(ReadinessStoreError):
    def __init__(self, resource_id: str) -> None:
        super().__init__(
            "READY-014",
            f"Resource {resource_id!r} was modified concurrently — retry the operation",
        )


class DuplicateSlug(ReadinessStoreError):
    def __init__(self, slug: str, resource_type: str = "framework") -> None:
        super().__init__("READY-015", f"{resource_type} slug already in use: {slug!r}")


class TenantIsolationError(ReadinessStoreError):
    def __init__(self) -> None:
        super().__init__(
            "READY-016",
            "Cross-tenant access denied",
        )


class FrameworkNotActiveError(ReadinessStoreError):
    def __init__(self, framework_id: str, status: str) -> None:
        super().__init__(
            "READY-017",
            f"Assessments can only be created against ACTIVE frameworks. "
            f"Framework {framework_id!r} has status={status!r}.",
        )


# ---------------------------------------------------------------------------
# Internal conversion helpers
# ---------------------------------------------------------------------------


def _framework_orm_to_domain(row: ReadinessFrameworkRecord) -> Framework:
    return Framework(
        framework_id=row.framework_id,
        framework_name=row.framework_name,
        framework_slug=row.framework_slug,
        framework_version=row.framework_version,
        framework_status=FrameworkStatus(row.framework_status),
        framework_description=row.framework_description,
        created_by=row.created_by,
        created_at=row.created_at,
        updated_at=row.updated_at,
        tenant_id=row.tenant_id,
        framework_metadata=_load_json(row.framework_metadata_json),
        compatibility_metadata=_load_json(row.compatibility_metadata_json),
        deprecation_metadata=_load_json(row.deprecation_metadata_json),
        activated_at=row.activated_at,
        deprecated_at=row.deprecated_at,
        retired_at=row.retired_at,
        state_version=getattr(row, "state_version", 0) or 0,
    )


def _framework_version_orm_to_domain(
    row: ReadinessFrameworkVersionRecord,
) -> FrameworkVersion:
    return FrameworkVersion(
        version_id=row.version_id,
        framework_id=row.framework_id,
        version_tag=row.version_tag,
        version_status=row.version_status,
        schema_hash=row.schema_hash,
        created_by=row.created_by,
        created_at=row.created_at,
        compatibility_metadata=_load_json(row.compatibility_metadata_json),
        deprecation_note=row.deprecation_note,
    )


def _domain_orm_to_domain(row: ReadinessDomainRecord) -> Domain:
    return Domain(
        domain_id=row.domain_id,
        framework_id=row.framework_id,
        domain_name=row.domain_name,
        domain_slug=row.domain_slug,
        domain_description=row.domain_description,
        domain_order=row.domain_order,
        created_by=row.created_by,
        created_at=row.created_at,
        tenant_id=row.tenant_id,
        domain_metadata=_load_json(row.domain_metadata_json),
        maturity_applicability=_load_json(row.maturity_applicability_json),
        domain_parent_id=row.domain_parent_id,
    )


def _control_orm_to_domain(row: ReadinessControlRecord) -> Control:
    return Control(
        control_id=row.control_id,
        framework_id=row.framework_id,
        domain_id=row.domain_id,
        control_identifier=row.control_identifier,
        control_name=row.control_name,
        control_description=row.control_description,
        created_by=row.created_by,
        created_at=row.created_at,
        tenant_id=row.tenant_id,
        control_metadata=_load_json(row.control_metadata_json),
        applicability_metadata=_load_json(row.applicability_metadata_json),
        evidence_requirements=_load_json(row.evidence_requirements_json),
        maturity_mapping_metadata=_load_json(row.maturity_mapping_metadata_json),
        scoring_compatibility_metadata=_load_json(
            row.scoring_compatibility_metadata_json
        ),
    )


def _control_ref_orm_to_domain(
    row: ReadinessControlReferenceRecord,
) -> ControlReference:
    return ControlReference(
        reference_id=row.reference_id,
        source_control_id=row.source_control_id,
        source_framework_id=row.source_framework_id,
        target_control_id=row.target_control_id,
        target_framework_id=row.target_framework_id,
        mapping_type=row.mapping_type,
        created_by=row.created_by,
        created_at=row.created_at,
        mapping_metadata=_load_json(row.mapping_metadata_json),
    )


def _maturity_tier_orm_to_domain(row: ReadinessMaturityTierRecord) -> MaturityTier:
    return MaturityTier(
        tier_id=row.tier_id,
        framework_id=row.framework_id,
        tier_identifier=row.tier_identifier,
        tier_name=row.tier_name,
        tier_order=row.tier_order,
        tier_criteria=row.tier_criteria,
        created_by=row.created_by,
        created_at=row.created_at,
        tenant_id=row.tenant_id,
        tier_metadata=_load_json(row.tier_metadata_json),
        readiness_classification=row.readiness_classification,
    )


def _assessment_orm_to_domain(row: ReadinessAssessmentRecord) -> Assessment:
    return Assessment(
        assessment_id=row.assessment_id,
        tenant_id=row.tenant_id,
        framework_id=row.framework_id,
        framework_version_tag=row.framework_version_tag,
        assessment_status=AssessmentStatus(row.assessment_status),
        snapshot_version=row.snapshot_version,
        assessment_name=row.assessment_name,
        assessment_description=row.assessment_description,
        created_by=row.created_by,
        created_at=row.created_at,
        updated_at=row.updated_at,
        assessment_metadata=_load_json(row.assessment_metadata_json),
        actor_metadata=_load_json(row.actor_metadata_json),
        scoring_contract_id=row.scoring_contract_id,
        activated_at=row.activated_at,
        finalized_at=row.finalized_at,
        archived_at=row.archived_at,
        state_version=getattr(row, "state_version", 0) or 0,
    )


def _assessment_result_orm_to_domain(
    row: ReadinessAssessmentResultRecord,
) -> AssessmentResult:
    evidence_ids: list[str] = []
    if row.evidence_reference_ids_json:
        try:
            evidence_ids = _json.loads(row.evidence_reference_ids_json)
        except (ValueError, TypeError):
            evidence_ids = []
    return AssessmentResult(
        result_id=row.result_id,
        assessment_id=row.assessment_id,
        control_id=row.control_id,
        maturity_tier_id=row.maturity_tier_id,
        outcome=AssessmentOutcome(row.outcome),
        actor=row.actor,
        timestamp=row.timestamp,
        tenant_id=row.tenant_id,
        evaluation_metadata=_load_json(row.evaluation_metadata_json),
        scoring_metadata=_load_json(row.scoring_metadata_json),
        evidence_reference_ids=evidence_ids,
        notes=row.notes,
    )


def _evidence_ref_orm_to_domain(
    row: ReadinessEvidenceReferenceRecord,
) -> EvidenceReference:
    control_ids: list[str] = []
    if row.control_ids_json:
        try:
            control_ids = _json.loads(row.control_ids_json)
        except (ValueError, TypeError):
            control_ids = []
    return EvidenceReference(
        evidence_id=row.evidence_id,
        assessment_id=row.assessment_id,
        evidence_type=EvidenceType(row.evidence_type),
        evidence_title=row.evidence_title,
        submitted_by=row.submitted_by,
        submitted_at=row.submitted_at,
        tenant_id=row.tenant_id,
        evidence_source_metadata=_load_json(row.evidence_source_metadata_json),
        evidence_ownership_metadata=_load_json(row.evidence_ownership_metadata_json),
        evidence_integrity_metadata=_load_json(row.evidence_integrity_metadata_json),
        evidence_classification=row.evidence_classification,
        effective_date=row.effective_date,
        expiration_date=row.expiration_date,
        control_ids=control_ids,
        notes=row.notes,
    )


def _scoring_contract_orm_to_domain(
    row: ReadinessScoringContractRecord,
) -> ScoringContract:
    return ScoringContract(
        contract_id=row.contract_id,
        framework_id=row.framework_id,
        scoring_schema_version=row.scoring_schema_version,
        created_by=row.created_by,
        created_at=row.created_at,
        tenant_id=row.tenant_id,
        normalization_metadata=_load_json(row.normalization_metadata_json),
        weighting_metadata=_load_json(row.weighting_metadata_json),
        compatibility_metadata=_load_json(row.compatibility_metadata_json),
        scoring_metadata=_load_json(row.scoring_metadata_json),
        is_active=bool(row.is_active),
    )


def _load_json(value: Optional[str]) -> dict[str, Any]:
    if not value:
        return {}
    try:
        result = _json.loads(value)
        return result if isinstance(result, dict) else {}
    except (ValueError, TypeError):
        return {}


def _dump_json(value: Optional[dict[str, Any]]) -> str:
    return _json.dumps(value or {}, sort_keys=True)


# ---------------------------------------------------------------------------
# Store — stateless, session-injected
# ---------------------------------------------------------------------------


class ReadinessStore:
    """Persistence operations for the readiness domain.

    Receives a SQLAlchemy Session at each call. No hidden state.
    All mutations emit a ReadinessAuditEvent before returning.
    """

    # ------------------------------------------------------------------
    # Framework operations
    # ------------------------------------------------------------------

    def create_framework(
        self,
        db: Session,
        *,
        framework_name: str,
        framework_slug: str,
        framework_version: str,
        created_by: str,
        tenant_id: Optional[str] = None,
        framework_description: Optional[str] = None,
        framework_metadata: Optional[dict] = None,
        compatibility_metadata: Optional[dict] = None,
    ) -> Framework:
        existing_slug = (
            db.query(ReadinessFrameworkRecord)
            .filter(ReadinessFrameworkRecord.framework_slug == framework_slug)
            .first()
        )
        if existing_slug is not None:
            raise DuplicateSlug(framework_slug, "framework")

        framework_id = str(uuid.uuid4())
        now = _utcnow()
        now_iso = now.isoformat()

        row = ReadinessFrameworkRecord(
            framework_id=framework_id,
            framework_name=framework_name,
            framework_slug=framework_slug,
            framework_version=framework_version,
            framework_status=FrameworkStatus.DRAFT.value,
            framework_description=framework_description,
            tenant_id=tenant_id,
            framework_metadata_json=_dump_json(framework_metadata),
            compatibility_metadata_json=_dump_json(compatibility_metadata),
            deprecation_metadata_json=_dump_json({}),
            created_by=created_by,
            created_at=now,
            updated_at=now,
            state_version=0,
        )
        db.add(row)
        db.flush()

        self._emit_event(
            db,
            resource_type="framework",
            resource_id=framework_id,
            event_type=ReadinessEventType.FRAMEWORK_CREATED,
            actor=created_by,
            outcome="success",
            tenant_id=tenant_id,
            framework_id=framework_id,
            now_iso=now_iso,
            details={
                "framework_slug": framework_slug,
                "framework_version": framework_version,
                "framework_status": FrameworkStatus.DRAFT.value,
            },
        )

        return _framework_orm_to_domain(row)

    def get_framework(
        self,
        db: Session,
        *,
        framework_id: str,
        tenant_id: Optional[str] = None,
    ) -> Framework:
        row = self._require_framework(db, framework_id, tenant_id)
        return _framework_orm_to_domain(row)

    def list_frameworks(
        self,
        db: Session,
        *,
        tenant_id: Optional[str] = None,
        status: Optional[FrameworkStatus] = None,
        limit: int = _DEFAULT_PAGE,
        offset: int = 0,
    ) -> list[Framework]:
        limit = min(limit, _MAX_PAGE)
        q = db.query(ReadinessFrameworkRecord)
        if tenant_id is not None:
            q = q.filter(
                (ReadinessFrameworkRecord.tenant_id == tenant_id)
                | (ReadinessFrameworkRecord.tenant_id.is_(None))
            )
        if status is not None:
            q = q.filter(ReadinessFrameworkRecord.framework_status == status.value)
        rows = (
            q.order_by(ReadinessFrameworkRecord.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return [_framework_orm_to_domain(r) for r in rows]

    def transition_framework_status(
        self,
        db: Session,
        *,
        framework_id: str,
        to_status: FrameworkStatus,
        actor: str,
        tenant_id: Optional[str] = None,
    ) -> Framework:
        row = self._require_framework(db, framework_id, tenant_id)
        from_status = FrameworkStatus(row.framework_status)

        try:
            validate_framework_transition(from_status, to_status)
        except ValueError as exc:
            raise InvalidFrameworkTransition(
                from_status.value, to_status.value
            ) from exc

        now = _utcnow()
        now_iso = now.isoformat()
        current_version = getattr(row, "state_version", 0) or 0

        updates: dict[str, Any] = {
            "framework_status": to_status.value,
            "state_version": current_version + 1,
            "updated_at": now,
        }
        if to_status == FrameworkStatus.ACTIVE:
            updates["activated_at"] = now
        elif to_status == FrameworkStatus.DEPRECATED:
            updates["deprecated_at"] = now
        elif to_status == FrameworkStatus.RETIRED:
            updates["retired_at"] = now

        rows_affected = (
            db.query(ReadinessFrameworkRecord)
            .filter(
                ReadinessFrameworkRecord.framework_id == framework_id,
                ReadinessFrameworkRecord.state_version == current_version,
            )
            .update(cast(dict[Any, Any], updates), synchronize_session="evaluate")
        )
        if rows_affected == 0:
            raise ConcurrentModificationError(framework_id)
        db.flush()
        db.refresh(row)

        event_type_map = {
            FrameworkStatus.ACTIVE: ReadinessEventType.FRAMEWORK_ACTIVATED,
            FrameworkStatus.DEPRECATED: ReadinessEventType.FRAMEWORK_DEPRECATED,
            FrameworkStatus.RETIRED: ReadinessEventType.FRAMEWORK_RETIRED,
        }
        event_type = event_type_map.get(
            to_status, ReadinessEventType.FRAMEWORK_ACTIVATED
        )

        self._emit_event(
            db,
            resource_type="framework",
            resource_id=framework_id,
            event_type=event_type,
            actor=actor,
            outcome="success",
            tenant_id=row.tenant_id,
            framework_id=framework_id,
            now_iso=now_iso,
            details={"framework_status": to_status.value},
        )

        return _framework_orm_to_domain(row)

    # ------------------------------------------------------------------
    # Framework version operations
    # ------------------------------------------------------------------

    def create_framework_version(
        self,
        db: Session,
        *,
        framework_id: str,
        version_tag: str,
        created_by: str,
        tenant_id: Optional[str] = None,
        schema_hash: Optional[str] = None,
        compatibility_metadata: Optional[dict] = None,
    ) -> FrameworkVersion:
        fw_row = self._require_framework(db, framework_id, tenant_id)
        fw_status = FrameworkStatus(fw_row.framework_status)
        if fw_status in IMMUTABLE_FRAMEWORK_STATUSES:
            raise FrameworkImmutableError(framework_id, fw_status.value)

        version_id = str(uuid.uuid4())
        now = _utcnow()
        now_iso = now.isoformat()

        row = ReadinessFrameworkVersionRecord(
            version_id=version_id,
            framework_id=framework_id,
            version_tag=version_tag,
            version_status="active",
            schema_hash=schema_hash,
            created_by=created_by,
            created_at=now,
            compatibility_metadata_json=_dump_json(compatibility_metadata),
        )
        db.add(row)
        db.flush()

        self._emit_event(
            db,
            resource_type="framework_version",
            resource_id=version_id,
            event_type=ReadinessEventType.FRAMEWORK_VERSION_CREATED,
            actor=created_by,
            outcome="success",
            tenant_id=tenant_id,
            framework_id=framework_id,
            now_iso=now_iso,
            details={"version_tag": version_tag, "framework_id": framework_id},
        )

        return _framework_version_orm_to_domain(row)

    def list_framework_versions(
        self,
        db: Session,
        *,
        framework_id: str,
        tenant_id: Optional[str] = None,
        limit: int = _DEFAULT_PAGE,
        offset: int = 0,
    ) -> list[FrameworkVersion]:
        self._require_framework(db, framework_id, tenant_id)
        limit = min(limit, _MAX_PAGE)
        rows = (
            db.query(ReadinessFrameworkVersionRecord)
            .filter(ReadinessFrameworkVersionRecord.framework_id == framework_id)
            .order_by(ReadinessFrameworkVersionRecord.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return [_framework_version_orm_to_domain(r) for r in rows]

    # ------------------------------------------------------------------
    # Domain operations
    # ------------------------------------------------------------------

    def create_domain(
        self,
        db: Session,
        *,
        framework_id: str,
        domain_name: str,
        domain_slug: str,
        domain_description: str,
        domain_order: int,
        created_by: str,
        tenant_id: Optional[str] = None,
        domain_metadata: Optional[dict] = None,
        maturity_applicability: Optional[dict] = None,
        domain_parent_id: Optional[str] = None,
    ) -> Domain:
        fw_row = self._require_framework(db, framework_id, tenant_id)
        fw_status = FrameworkStatus(fw_row.framework_status)
        if fw_status in (
            FrameworkStatus.ACTIVE,
            FrameworkStatus.DEPRECATED,
            FrameworkStatus.RETIRED,
        ):
            raise FrameworkImmutableError(framework_id, fw_status.value)

        domain_id = str(uuid.uuid4())
        now = _utcnow()
        now_iso = now.isoformat()

        row = ReadinessDomainRecord(
            domain_id=domain_id,
            framework_id=framework_id,
            domain_name=domain_name,
            domain_slug=domain_slug,
            domain_description=domain_description,
            domain_order=domain_order,
            tenant_id=tenant_id,
            domain_metadata_json=_dump_json(domain_metadata),
            maturity_applicability_json=_dump_json(maturity_applicability),
            domain_parent_id=domain_parent_id,
            created_by=created_by,
            created_at=now,
        )
        db.add(row)
        db.flush()

        self._emit_event(
            db,
            resource_type="domain",
            resource_id=domain_id,
            event_type=ReadinessEventType.DOMAIN_CREATED,
            actor=created_by,
            outcome="success",
            tenant_id=tenant_id,
            framework_id=framework_id,
            now_iso=now_iso,
            details={"domain_slug": domain_slug, "framework_id": framework_id},
        )

        return _domain_orm_to_domain(row)

    def list_domains(
        self,
        db: Session,
        *,
        framework_id: str,
        tenant_id: Optional[str] = None,
        limit: int = _DEFAULT_PAGE,
        offset: int = 0,
    ) -> list[Domain]:
        self._require_framework(db, framework_id, tenant_id)
        limit = min(limit, _MAX_PAGE)
        q = db.query(ReadinessDomainRecord).filter(
            ReadinessDomainRecord.framework_id == framework_id
        )
        if tenant_id is not None:
            q = q.filter(
                (ReadinessDomainRecord.tenant_id == tenant_id)
                | (ReadinessDomainRecord.tenant_id.is_(None))
            )
        rows = (
            q.order_by(ReadinessDomainRecord.domain_order.asc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return [_domain_orm_to_domain(r) for r in rows]

    def get_domain(
        self,
        db: Session,
        *,
        domain_id: str,
        tenant_id: Optional[str] = None,
    ) -> Domain:
        q = db.query(ReadinessDomainRecord).filter(
            ReadinessDomainRecord.domain_id == domain_id
        )
        if tenant_id is not None:
            q = q.filter(
                (ReadinessDomainRecord.tenant_id == tenant_id)
                | (ReadinessDomainRecord.tenant_id.is_(None))
            )
        row = q.first()
        if row is None:
            raise DomainNotFound(domain_id)
        return _domain_orm_to_domain(row)

    # ------------------------------------------------------------------
    # Control operations
    # ------------------------------------------------------------------

    def create_control(
        self,
        db: Session,
        *,
        framework_id: str,
        domain_id: str,
        control_identifier: str,
        control_name: str,
        control_description: str,
        created_by: str,
        tenant_id: Optional[str] = None,
        control_metadata: Optional[dict] = None,
        applicability_metadata: Optional[dict] = None,
        evidence_requirements: Optional[dict] = None,
        maturity_mapping_metadata: Optional[dict] = None,
        scoring_compatibility_metadata: Optional[dict] = None,
    ) -> Control:
        fw_row = self._require_framework(db, framework_id, tenant_id)
        fw_status = FrameworkStatus(fw_row.framework_status)
        if fw_status in (
            FrameworkStatus.ACTIVE,
            FrameworkStatus.DEPRECATED,
            FrameworkStatus.RETIRED,
        ):
            raise FrameworkImmutableError(framework_id, fw_status.value)

        self.get_domain(db, domain_id=domain_id, tenant_id=tenant_id)

        control_id = str(uuid.uuid4())
        now = _utcnow()
        now_iso = now.isoformat()

        row = ReadinessControlRecord(
            control_id=control_id,
            framework_id=framework_id,
            domain_id=domain_id,
            control_identifier=control_identifier,
            control_name=control_name,
            control_description=control_description,
            tenant_id=tenant_id,
            control_metadata_json=_dump_json(control_metadata),
            applicability_metadata_json=_dump_json(applicability_metadata),
            evidence_requirements_json=_dump_json(evidence_requirements),
            maturity_mapping_metadata_json=_dump_json(maturity_mapping_metadata),
            scoring_compatibility_metadata_json=_dump_json(
                scoring_compatibility_metadata
            ),
            created_by=created_by,
            created_at=now,
        )
        db.add(row)
        db.flush()

        self._emit_event(
            db,
            resource_type="control",
            resource_id=control_id,
            event_type=ReadinessEventType.CONTROL_CREATED,
            actor=created_by,
            outcome="success",
            tenant_id=tenant_id,
            framework_id=framework_id,
            now_iso=now_iso,
            details={
                "control_identifier": control_identifier,
                "framework_id": framework_id,
                "domain_id": domain_id,
            },
        )

        return _control_orm_to_domain(row)

    def get_control(
        self,
        db: Session,
        *,
        control_id: str,
        tenant_id: Optional[str] = None,
    ) -> Control:
        q = db.query(ReadinessControlRecord).filter(
            ReadinessControlRecord.control_id == control_id
        )
        if tenant_id is not None:
            q = q.filter(
                (ReadinessControlRecord.tenant_id == tenant_id)
                | (ReadinessControlRecord.tenant_id.is_(None))
            )
        row = q.first()
        if row is None:
            raise ControlNotFound(control_id)
        return _control_orm_to_domain(row)

    def list_controls(
        self,
        db: Session,
        *,
        framework_id: str,
        domain_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        limit: int = _DEFAULT_PAGE,
        offset: int = 0,
    ) -> list[Control]:
        self._require_framework(db, framework_id, tenant_id)
        limit = min(limit, _MAX_PAGE)
        q = db.query(ReadinessControlRecord).filter(
            ReadinessControlRecord.framework_id == framework_id
        )
        if domain_id is not None:
            q = q.filter(ReadinessControlRecord.domain_id == domain_id)
        if tenant_id is not None:
            q = q.filter(
                (ReadinessControlRecord.tenant_id == tenant_id)
                | (ReadinessControlRecord.tenant_id.is_(None))
            )
        rows = (
            q.order_by(ReadinessControlRecord.created_at.asc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return [_control_orm_to_domain(r) for r in rows]

    def create_control_reference(
        self,
        db: Session,
        *,
        source_control_id: str,
        source_framework_id: str,
        target_control_id: str,
        target_framework_id: str,
        mapping_type: str,
        created_by: str,
        mapping_metadata: Optional[dict] = None,
    ) -> ControlReference:
        reference_id = str(uuid.uuid4())
        now = _utcnow()
        now_iso = now.isoformat()

        row = ReadinessControlReferenceRecord(
            reference_id=reference_id,
            source_control_id=source_control_id,
            source_framework_id=source_framework_id,
            target_control_id=target_control_id,
            target_framework_id=target_framework_id,
            mapping_type=mapping_type,
            mapping_metadata_json=_dump_json(mapping_metadata),
            created_by=created_by,
            created_at=now,
        )
        db.add(row)
        db.flush()

        self._emit_event(
            db,
            resource_type="control_reference",
            resource_id=reference_id,
            event_type=ReadinessEventType.CONTROL_REFERENCE_CREATED,
            actor=created_by,
            outcome="success",
            now_iso=now_iso,
            details={
                "mapping_type": mapping_type,
                "source_framework_id": source_framework_id,
                "target_framework_id": target_framework_id,
            },
        )

        return _control_ref_orm_to_domain(row)

    # ------------------------------------------------------------------
    # Maturity tier operations
    # ------------------------------------------------------------------

    def create_maturity_tier(
        self,
        db: Session,
        *,
        framework_id: str,
        tier_identifier: str,
        tier_name: str,
        tier_order: int,
        tier_criteria: str,
        created_by: str,
        tenant_id: Optional[str] = None,
        tier_metadata: Optional[dict] = None,
        readiness_classification: Optional[str] = None,
    ) -> MaturityTier:
        fw_row = self._require_framework(db, framework_id, tenant_id)
        fw_status = FrameworkStatus(fw_row.framework_status)
        if fw_status in (
            FrameworkStatus.ACTIVE,
            FrameworkStatus.DEPRECATED,
            FrameworkStatus.RETIRED,
        ):
            raise FrameworkImmutableError(framework_id, fw_status.value)

        tier_id = str(uuid.uuid4())
        now = _utcnow()
        now_iso = now.isoformat()

        row = ReadinessMaturityTierRecord(
            tier_id=tier_id,
            framework_id=framework_id,
            tier_identifier=tier_identifier,
            tier_name=tier_name,
            tier_order=tier_order,
            tier_criteria=tier_criteria,
            tenant_id=tenant_id,
            tier_metadata_json=_dump_json(tier_metadata),
            readiness_classification=readiness_classification,
            created_by=created_by,
            created_at=now,
        )
        db.add(row)
        db.flush()

        self._emit_event(
            db,
            resource_type="maturity_tier",
            resource_id=tier_id,
            event_type=ReadinessEventType.MATURITY_TIER_CREATED,
            actor=created_by,
            outcome="success",
            tenant_id=tenant_id,
            framework_id=framework_id,
            now_iso=now_iso,
            details={
                "tier_identifier": tier_identifier,
                "tier_order": tier_order,
                "framework_id": framework_id,
            },
        )

        return _maturity_tier_orm_to_domain(row)

    def list_maturity_tiers(
        self,
        db: Session,
        *,
        framework_id: str,
        tenant_id: Optional[str] = None,
        limit: int = _DEFAULT_PAGE,
        offset: int = 0,
    ) -> list[MaturityTier]:
        self._require_framework(db, framework_id, tenant_id)
        limit = min(limit, _MAX_PAGE)
        q = db.query(ReadinessMaturityTierRecord).filter(
            ReadinessMaturityTierRecord.framework_id == framework_id
        )
        if tenant_id is not None:
            q = q.filter(
                (ReadinessMaturityTierRecord.tenant_id == tenant_id)
                | (ReadinessMaturityTierRecord.tenant_id.is_(None))
            )
        rows = (
            q.order_by(ReadinessMaturityTierRecord.tier_order.asc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return [_maturity_tier_orm_to_domain(r) for r in rows]

    def get_maturity_tier(
        self,
        db: Session,
        *,
        tier_id: str,
        tenant_id: Optional[str] = None,
    ) -> MaturityTier:
        q = db.query(ReadinessMaturityTierRecord).filter(
            ReadinessMaturityTierRecord.tier_id == tier_id
        )
        if tenant_id is not None:
            q = q.filter(
                (ReadinessMaturityTierRecord.tenant_id == tenant_id)
                | (ReadinessMaturityTierRecord.tenant_id.is_(None))
            )
        row = q.first()
        if row is None:
            raise MaturityTierNotFound(tier_id)
        return _maturity_tier_orm_to_domain(row)

    # ------------------------------------------------------------------
    # Assessment operations
    # ------------------------------------------------------------------

    def create_assessment(
        self,
        db: Session,
        *,
        tenant_id: str,
        framework_id: str,
        framework_version_tag: str,
        created_by: str,
        assessment_name: Optional[str] = None,
        assessment_description: Optional[str] = None,
        assessment_metadata: Optional[dict] = None,
        actor_metadata: Optional[dict] = None,
        scoring_contract_id: Optional[str] = None,
    ) -> Assessment:
        fw_row = self._require_framework(db, framework_id, tenant_id)
        fw_status = FrameworkStatus(fw_row.framework_status)
        if fw_status != FrameworkStatus.ACTIVE:
            raise FrameworkNotActiveError(framework_id, fw_status.value)

        assessment_id = str(uuid.uuid4())
        now = _utcnow()
        now_iso = now.isoformat()

        row = ReadinessAssessmentRecord(
            assessment_id=assessment_id,
            tenant_id=tenant_id,
            framework_id=framework_id,
            framework_version_tag=framework_version_tag,
            assessment_status=AssessmentStatus.DRAFT.value,
            snapshot_version=0,
            assessment_name=assessment_name,
            assessment_description=assessment_description,
            assessment_metadata_json=_dump_json(assessment_metadata),
            actor_metadata_json=_dump_json(actor_metadata),
            scoring_contract_id=scoring_contract_id,
            created_by=created_by,
            created_at=now,
            updated_at=now,
            state_version=0,
        )
        db.add(row)
        db.flush()

        self._emit_event(
            db,
            resource_type="assessment",
            resource_id=assessment_id,
            event_type=ReadinessEventType.ASSESSMENT_CREATED,
            actor=created_by,
            outcome="success",
            tenant_id=tenant_id,
            framework_id=framework_id,
            assessment_id=assessment_id,
            now_iso=now_iso,
            details={
                "assessment_id": assessment_id,
                "assessment_status": AssessmentStatus.DRAFT.value,
                "framework_version_tag": framework_version_tag,
            },
        )

        return _assessment_orm_to_domain(row)

    def get_assessment(
        self,
        db: Session,
        *,
        assessment_id: str,
        tenant_id: str,
    ) -> Assessment:
        row = self._require_assessment(db, assessment_id, tenant_id)
        return _assessment_orm_to_domain(row)

    def list_assessments(
        self,
        db: Session,
        *,
        tenant_id: str,
        framework_id: Optional[str] = None,
        status: Optional[AssessmentStatus] = None,
        limit: int = _DEFAULT_PAGE,
        offset: int = 0,
    ) -> list[Assessment]:
        limit = min(limit, _MAX_PAGE)
        q = db.query(ReadinessAssessmentRecord).filter(
            ReadinessAssessmentRecord.tenant_id == tenant_id
        )
        if framework_id is not None:
            q = q.filter(ReadinessAssessmentRecord.framework_id == framework_id)
        if status is not None:
            q = q.filter(ReadinessAssessmentRecord.assessment_status == status.value)
        rows = (
            q.order_by(ReadinessAssessmentRecord.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return [_assessment_orm_to_domain(r) for r in rows]

    def transition_assessment_status(
        self,
        db: Session,
        *,
        assessment_id: str,
        to_status: AssessmentStatus,
        actor: str,
        tenant_id: str,
    ) -> Assessment:
        row = self._require_assessment(db, assessment_id, tenant_id)
        from_status = AssessmentStatus(row.assessment_status)

        try:
            validate_assessment_transition(from_status, to_status)
        except ValueError as exc:
            raise InvalidAssessmentTransition(
                from_status.value, to_status.value
            ) from exc

        now = _utcnow()
        now_iso = now.isoformat()
        current_version = getattr(row, "state_version", 0) or 0
        current_snapshot = row.snapshot_version or 0

        updates: dict[str, Any] = {
            "assessment_status": to_status.value,
            "state_version": current_version + 1,
            "updated_at": now,
        }
        if to_status == AssessmentStatus.ACTIVE:
            updates["activated_at"] = now
        elif to_status == AssessmentStatus.FINALIZED:
            updates["finalized_at"] = now
            updates["snapshot_version"] = current_snapshot + 1
        elif to_status == AssessmentStatus.ARCHIVED:
            updates["archived_at"] = now

        rows_affected = (
            db.query(ReadinessAssessmentRecord)
            .filter(
                ReadinessAssessmentRecord.assessment_id == assessment_id,
                ReadinessAssessmentRecord.tenant_id == tenant_id,
                ReadinessAssessmentRecord.state_version == current_version,
            )
            .update(cast(dict[Any, Any], updates), synchronize_session="evaluate")
        )
        if rows_affected == 0:
            raise ConcurrentModificationError(assessment_id)
        db.flush()
        db.refresh(row)

        event_type_map = {
            AssessmentStatus.ACTIVE: ReadinessEventType.ASSESSMENT_ACTIVATED,
            AssessmentStatus.FINALIZED: ReadinessEventType.ASSESSMENT_FINALIZED,
            AssessmentStatus.ARCHIVED: ReadinessEventType.ASSESSMENT_ARCHIVED,
            AssessmentStatus.DRAFT: ReadinessEventType.ASSESSMENT_CREATED,
        }
        event_type = event_type_map.get(
            to_status, ReadinessEventType.ASSESSMENT_ACTIVATED
        )

        self._emit_event(
            db,
            resource_type="assessment",
            resource_id=assessment_id,
            event_type=event_type,
            actor=actor,
            outcome="success",
            tenant_id=tenant_id,
            framework_id=row.framework_id,
            assessment_id=assessment_id,
            now_iso=now_iso,
            details={
                "assessment_status": to_status.value,
                "assessment_id": assessment_id,
                "snapshot_version": updates.get("snapshot_version", current_snapshot),
            },
        )

        return _assessment_orm_to_domain(row)

    # ------------------------------------------------------------------
    # Assessment result operations
    # ------------------------------------------------------------------

    def record_assessment_result(
        self,
        db: Session,
        *,
        assessment_id: str,
        control_id: str,
        outcome: AssessmentOutcome,
        actor: str,
        tenant_id: str,
        maturity_tier_id: Optional[str] = None,
        evaluation_metadata: Optional[dict] = None,
        scoring_metadata: Optional[dict] = None,
        evidence_reference_ids: Optional[list[str]] = None,
        notes: Optional[str] = None,
    ) -> AssessmentResult:
        assessment_row = self._require_assessment(db, assessment_id, tenant_id)
        assessment = _assessment_orm_to_domain(assessment_row)

        try:
            assert_assessment_mutable(assessment)
        except ValueError as exc:
            raise AssessmentImmutableError(
                assessment_id, assessment.assessment_status.value
            ) from exc

        result_id = str(uuid.uuid4())
        now = _utcnow()
        now_iso = now.isoformat()

        row = ReadinessAssessmentResultRecord(
            result_id=result_id,
            assessment_id=assessment_id,
            control_id=control_id,
            maturity_tier_id=maturity_tier_id,
            outcome=outcome.value,
            actor=actor,
            timestamp=now,
            tenant_id=tenant_id,
            evaluation_metadata_json=_dump_json(evaluation_metadata),
            scoring_metadata_json=_dump_json(scoring_metadata),
            evidence_reference_ids_json=_json.dumps(evidence_reference_ids or []),
            notes=notes,
        )
        db.add(row)
        db.flush()

        self._emit_event(
            db,
            resource_type="assessment_result",
            resource_id=result_id,
            event_type=ReadinessEventType.ASSESSMENT_RESULT_RECORDED,
            actor=actor,
            outcome="success",
            tenant_id=tenant_id,
            assessment_id=assessment_id,
            now_iso=now_iso,
            details={
                "result_id": result_id,
                "outcome": outcome.value,
                "assessment_id": assessment_id,
                "control_id": control_id,
            },
        )

        return _assessment_result_orm_to_domain(row)

    def list_assessment_results(
        self,
        db: Session,
        *,
        assessment_id: str,
        tenant_id: str,
        limit: int = _DEFAULT_PAGE,
        offset: int = 0,
    ) -> list[AssessmentResult]:
        self._require_assessment(db, assessment_id, tenant_id)
        limit = min(limit, _MAX_PAGE)
        rows = (
            db.query(ReadinessAssessmentResultRecord)
            .filter(
                ReadinessAssessmentResultRecord.assessment_id == assessment_id,
                ReadinessAssessmentResultRecord.tenant_id == tenant_id,
            )
            .order_by(ReadinessAssessmentResultRecord.timestamp.asc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return [_assessment_result_orm_to_domain(r) for r in rows]

    # ------------------------------------------------------------------
    # Evidence reference operations
    # ------------------------------------------------------------------

    def attach_evidence_reference(
        self,
        db: Session,
        *,
        assessment_id: str,
        evidence_type: EvidenceType,
        evidence_title: str,
        submitted_by: str,
        tenant_id: str,
        evidence_source_metadata: Optional[dict] = None,
        evidence_ownership_metadata: Optional[dict] = None,
        evidence_integrity_metadata: Optional[dict] = None,
        evidence_classification: Optional[str] = None,
        effective_date: Optional[datetime] = None,
        expiration_date: Optional[datetime] = None,
        control_ids: Optional[list[str]] = None,
        notes: Optional[str] = None,
    ) -> EvidenceReference:
        assessment_row = self._require_assessment(db, assessment_id, tenant_id)
        assessment = _assessment_orm_to_domain(assessment_row)

        try:
            assert_assessment_mutable(assessment)
        except ValueError as exc:
            raise AssessmentImmutableError(
                assessment_id, assessment.assessment_status.value
            ) from exc

        evidence_id = str(uuid.uuid4())
        now = _utcnow()
        now_iso = now.isoformat()
        submitted_at = _utcnow()

        row = ReadinessEvidenceReferenceRecord(
            evidence_id=evidence_id,
            assessment_id=assessment_id,
            evidence_type=evidence_type.value,
            evidence_title=evidence_title,
            submitted_by=submitted_by,
            submitted_at=submitted_at,
            tenant_id=tenant_id,
            evidence_source_metadata_json=_dump_json(evidence_source_metadata),
            evidence_ownership_metadata_json=_dump_json(evidence_ownership_metadata),
            evidence_integrity_metadata_json=_dump_json(evidence_integrity_metadata),
            evidence_classification=evidence_classification,
            effective_date=effective_date,
            expiration_date=expiration_date,
            control_ids_json=_json.dumps(control_ids or []),
            notes=notes,
        )
        db.add(row)
        db.flush()

        self._emit_event(
            db,
            resource_type="evidence_reference",
            resource_id=evidence_id,
            event_type=ReadinessEventType.EVIDENCE_REFERENCE_ATTACHED,
            actor=submitted_by,
            outcome="success",
            tenant_id=tenant_id,
            assessment_id=assessment_id,
            now_iso=now_iso,
            details={
                "evidence_id": evidence_id,
                "evidence_type": evidence_type.value,
                "evidence_classification": evidence_classification or "",
                "assessment_id": assessment_id,
            },
        )

        return _evidence_ref_orm_to_domain(row)

    def list_evidence_references(
        self,
        db: Session,
        *,
        assessment_id: str,
        tenant_id: str,
        limit: int = _DEFAULT_PAGE,
        offset: int = 0,
    ) -> list[EvidenceReference]:
        self._require_assessment(db, assessment_id, tenant_id)
        limit = min(limit, _MAX_PAGE)
        rows = (
            db.query(ReadinessEvidenceReferenceRecord)
            .filter(
                ReadinessEvidenceReferenceRecord.assessment_id == assessment_id,
                ReadinessEvidenceReferenceRecord.tenant_id == tenant_id,
            )
            .order_by(ReadinessEvidenceReferenceRecord.submitted_at.asc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return [_evidence_ref_orm_to_domain(r) for r in rows]

    # ------------------------------------------------------------------
    # Scoring contract operations
    # ------------------------------------------------------------------

    def create_scoring_contract(
        self,
        db: Session,
        *,
        framework_id: str,
        scoring_schema_version: str,
        created_by: str,
        tenant_id: Optional[str] = None,
        normalization_metadata: Optional[dict] = None,
        weighting_metadata: Optional[dict] = None,
        compatibility_metadata: Optional[dict] = None,
        scoring_metadata: Optional[dict] = None,
    ) -> ScoringContract:
        fw_row = self._require_framework(db, framework_id, tenant_id)
        fw_status = FrameworkStatus(fw_row.framework_status)
        if fw_status in IMMUTABLE_FRAMEWORK_STATUSES:
            raise FrameworkImmutableError(framework_id, fw_status.value)

        contract_id = str(uuid.uuid4())
        now = _utcnow()
        now_iso = now.isoformat()

        row = ReadinessScoringContractRecord(
            contract_id=contract_id,
            framework_id=framework_id,
            scoring_schema_version=scoring_schema_version,
            tenant_id=tenant_id,
            normalization_metadata_json=_dump_json(normalization_metadata),
            weighting_metadata_json=_dump_json(weighting_metadata),
            compatibility_metadata_json=_dump_json(compatibility_metadata),
            scoring_metadata_json=_dump_json(scoring_metadata),
            is_active=True,
            created_by=created_by,
            created_at=now,
        )
        db.add(row)
        db.flush()

        self._emit_event(
            db,
            resource_type="scoring_contract",
            resource_id=contract_id,
            event_type=ReadinessEventType.SCORING_CONTRACT_CREATED,
            actor=created_by,
            outcome="success",
            tenant_id=tenant_id,
            framework_id=framework_id,
            now_iso=now_iso,
            details={
                "contract_id": contract_id,
                "scoring_schema_version": scoring_schema_version,
                "framework_id": framework_id,
            },
        )

        return _scoring_contract_orm_to_domain(row)

    def get_scoring_contract(
        self,
        db: Session,
        *,
        contract_id: str,
        tenant_id: Optional[str] = None,
    ) -> ScoringContract:
        q = db.query(ReadinessScoringContractRecord).filter(
            ReadinessScoringContractRecord.contract_id == contract_id
        )
        if tenant_id is not None:
            q = q.filter(
                (ReadinessScoringContractRecord.tenant_id == tenant_id)
                | (ReadinessScoringContractRecord.tenant_id.is_(None))
            )
        row = q.first()
        if row is None:
            raise ScoringContractNotFound(contract_id)
        return _scoring_contract_orm_to_domain(row)

    def list_scoring_contracts(
        self,
        db: Session,
        *,
        framework_id: str,
        tenant_id: Optional[str] = None,
        limit: int = _DEFAULT_PAGE,
        offset: int = 0,
    ) -> list[ScoringContract]:
        self._require_framework(db, framework_id, tenant_id)
        limit = min(limit, _MAX_PAGE)
        q = db.query(ReadinessScoringContractRecord).filter(
            ReadinessScoringContractRecord.framework_id == framework_id
        )
        if tenant_id is not None:
            q = q.filter(
                (ReadinessScoringContractRecord.tenant_id == tenant_id)
                | (ReadinessScoringContractRecord.tenant_id.is_(None))
            )
        rows = (
            q.order_by(ReadinessScoringContractRecord.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return [_scoring_contract_orm_to_domain(r) for r in rows]

    # ------------------------------------------------------------------
    # Audit event query
    # ------------------------------------------------------------------

    def list_audit_events(
        self,
        db: Session,
        *,
        resource_type: str,
        resource_id: str,
        tenant_id: Optional[str] = None,
        limit: int = _DEFAULT_PAGE,
        offset: int = 0,
    ) -> list[ReadinessAuditEvent]:
        from services.readiness.models import ReadinessAuditEvent as AuditEventDomain

        limit = min(limit, _MAX_PAGE)
        q = db.query(ReadinessAuditEventRecord).filter(
            ReadinessAuditEventRecord.resource_type == resource_type,
            ReadinessAuditEventRecord.resource_id == resource_id,
        )
        if tenant_id is not None:
            q = q.filter(
                (ReadinessAuditEventRecord.tenant_id == tenant_id)
                | (ReadinessAuditEventRecord.tenant_id.is_(None))
            )
        rows = (
            q.order_by(ReadinessAuditEventRecord.timestamp.asc())
            .offset(offset)
            .limit(limit)
            .all()
        )

        result = []
        for row in rows:
            result.append(
                AuditEventDomain(
                    event_id=row.event_id,
                    resource_type=row.resource_type,
                    resource_id=row.resource_id,
                    event_type=ReadinessEventType(row.event_type),
                    actor=row.actor,
                    outcome=row.outcome,
                    timestamp=row.timestamp,
                    tenant_id=row.tenant_id,
                    framework_id=row.framework_id,
                    assessment_id=row.assessment_id,
                    details=_load_json(row.details_json),
                    event_hash=row.event_hash,
                    previous_event_hash=row.previous_event_hash,
                )
            )
        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _require_framework(
        self,
        db: Session,
        framework_id: str,
        tenant_id: Optional[str],
    ) -> ReadinessFrameworkRecord:
        q = db.query(ReadinessFrameworkRecord).filter(
            ReadinessFrameworkRecord.framework_id == framework_id
        )
        if tenant_id is not None:
            q = q.filter(
                (ReadinessFrameworkRecord.tenant_id == tenant_id)
                | (ReadinessFrameworkRecord.tenant_id.is_(None))
            )
        row = q.first()
        if row is None:
            raise FrameworkNotFound(framework_id)
        return row

    def _require_assessment(
        self,
        db: Session,
        assessment_id: str,
        tenant_id: str,
    ) -> ReadinessAssessmentRecord:
        row = (
            db.query(ReadinessAssessmentRecord)
            .filter(
                ReadinessAssessmentRecord.assessment_id == assessment_id,
                ReadinessAssessmentRecord.tenant_id == tenant_id,
            )
            .first()
        )
        if row is None:
            raise AssessmentNotFound(assessment_id)
        return row

    def _emit_event(
        self,
        db: Session,
        *,
        resource_type: str,
        resource_id: str,
        event_type: ReadinessEventType,
        actor: str,
        outcome: str,
        now_iso: str,
        tenant_id: Optional[str] = None,
        framework_id: Optional[str] = None,
        assessment_id: Optional[str] = None,
        details: Optional[dict] = None,
    ) -> None:
        event_id = str(uuid.uuid4())
        details_json = _json.dumps(details or {}, sort_keys=True)

        previous_hash = _get_previous_event_hash(db, resource_type, resource_id)
        event_hash = compute_event_hash(
            event_id=event_id,
            resource_type=resource_type,
            resource_id=resource_id,
            event_type=event_type.value,
            actor=actor,
            timestamp_iso=now_iso,
            outcome=outcome,
            previous_event_hash=previous_hash,
        )

        event_row = ReadinessAuditEventRecord(
            event_id=event_id,
            resource_type=resource_type,
            resource_id=resource_id,
            tenant_id=tenant_id,
            framework_id=framework_id,
            assessment_id=assessment_id,
            event_type=event_type.value,
            actor=actor,
            outcome=outcome,
            details_json=details_json,
            event_hash=event_hash,
            previous_event_hash=previous_hash,
            timestamp=_utcnow(),
        )
        db.add(event_row)
        db.flush()

        emit_readiness_event(
            event_id=event_id,
            resource_type=resource_type,
            resource_id=resource_id,
            event_type=event_type,
            actor=actor,
            timestamp_iso=now_iso,
            outcome=outcome,
            tenant_id=tenant_id,
            framework_id=framework_id,
            assessment_id=assessment_id,
            details=details,
            event_hash=event_hash,
            previous_event_hash=previous_hash,
        )
