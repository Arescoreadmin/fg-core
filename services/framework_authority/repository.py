# mypy: ignore-errors
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from sqlalchemy import and_, or_, select, text
from sqlalchemy.orm import Session

from api.db import set_tenant_context
from api.db_models_framework_authority import (
    ControlFrameworkMappingAuditRecord,
    ControlFrameworkMappingRecord,
    FrameworkAuthorityFrameworkControlRecord,
    FrameworkAuthorityFrameworkRecord,
)
from services.enterprise_controls_extension.service import EnterpriseControlsService
from services.framework_authority.schemas import (
    ControlFrameworkMappingCreateRequest,
    ControlFrameworkMappingTransitionRequest,
    ControlFrameworkMappingUpdateRequest,
    FrameworkControlCreateRequest,
    FrameworkControlStatus,
    FrameworkControlUpdateRequest,
    FrameworkCreateRequest,
    FrameworkStatus,
    FrameworkTransitionRequest,
    FrameworkUpdateRequest,
    MAPPING_TRANSITION_EVENT,
    MAPPING_TYPE_PRECEDENCE,
    MAPPED_MAPPING_TYPES,
    MappingAuditEventType,
    MappingStatus,
    MappingType,
    ScopeType,
    validate_framework_transition,
    validate_mapping_transition,
)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class FrameworkAuthorityError(Exception):
    pass


class FrameworkAuthorityNotFound(FrameworkAuthorityError):
    pass


class FrameworkAuthorityConflict(FrameworkAuthorityError):
    pass


class FrameworkAuthorityInvalidTransition(FrameworkAuthorityError):
    pass


class FrameworkAuthorityPermissionDenied(FrameworkAuthorityError):
    pass


class FrameworkAuthorityRepository:
    def __init__(self, seed_service: EnterpriseControlsService | None = None) -> None:
        self._seed_service = seed_service or EnterpriseControlsService()

    def list_frameworks(
        self, db: Session, *, tenant_id: str
    ) -> list[FrameworkAuthorityFrameworkRecord]:
        stmt = (
            select(FrameworkAuthorityFrameworkRecord)
            .where(self._framework_visibility_clause(tenant_id))
            .order_by(
                FrameworkAuthorityFrameworkRecord.scope_type.asc(),
                FrameworkAuthorityFrameworkRecord.framework_key.asc(),
                FrameworkAuthorityFrameworkRecord.version.asc(),
                FrameworkAuthorityFrameworkRecord.id.asc(),
            )
        )
        return list(db.execute(stmt).scalars().all())

    def get_framework_visible(
        self, db: Session, *, tenant_id: str, framework_id: str
    ) -> FrameworkAuthorityFrameworkRecord:
        stmt = select(FrameworkAuthorityFrameworkRecord).where(
            FrameworkAuthorityFrameworkRecord.id == framework_id,
            self._framework_visibility_clause(tenant_id),
        )
        row = db.execute(stmt).scalar_one_or_none()
        if row is None:
            raise FrameworkAuthorityNotFound("framework_not_found")
        return row

    def create_framework(
        self,
        db: Session,
        *,
        tenant_id: str,
        actor: str,
        allow_system_write: bool,
        payload: FrameworkCreateRequest,
    ) -> FrameworkAuthorityFrameworkRecord:
        del actor
        scope_type = payload.scope_type
        record_tenant_id = tenant_id if scope_type == ScopeType.TENANT else None
        if scope_type == ScopeType.SYSTEM and not allow_system_write:
            raise FrameworkAuthorityPermissionDenied("system_framework_write_denied")
        self._ensure_framework_identity_available(
            db,
            tenant_id=record_tenant_id,
            scope_type=scope_type,
            framework_key=payload.framework_key,
            version=payload.version,
        )
        row = FrameworkAuthorityFrameworkRecord(
            tenant_id=record_tenant_id,
            scope_type=scope_type.value,
            framework_key=payload.framework_key,
            name=payload.name,
            version=payload.version,
            category=payload.category,
            publisher=payload.publisher,
            description=payload.description,
            status=payload.status.value,
            effective_date=payload.effective_date,
            retired_date=payload.retired_date,
            schema_version=payload.schema_version,
        )
        db.add(row)
        db.flush()
        return row

    def update_framework(
        self,
        db: Session,
        *,
        tenant_id: str,
        framework_id: str,
        allow_system_write: bool,
        payload: FrameworkUpdateRequest,
    ) -> FrameworkAuthorityFrameworkRecord:
        row = self.get_framework_visible(
            db, tenant_id=tenant_id, framework_id=framework_id
        )
        self._ensure_framework_write_allowed(
            row=row,
            tenant_id=tenant_id,
            allow_system_write=allow_system_write,
        )
        for field in (
            "name",
            "category",
            "publisher",
            "description",
            "effective_date",
            "retired_date",
        ):
            value = getattr(payload, field)
            if value is not None:
                setattr(row, field, value)
        row.updated_at = _utcnow()
        db.flush()
        return row

    def transition_framework(
        self,
        db: Session,
        *,
        tenant_id: str,
        framework_id: str,
        allow_system_write: bool,
        payload: FrameworkTransitionRequest,
    ) -> FrameworkAuthorityFrameworkRecord:
        row = self.get_framework_visible(
            db, tenant_id=tenant_id, framework_id=framework_id
        )
        self._ensure_framework_write_allowed(
            row=row,
            tenant_id=tenant_id,
            allow_system_write=allow_system_write,
        )
        try:
            validate_framework_transition(
                FrameworkStatus(row.status),
                payload.to_status,
            )
        except ValueError as exc:
            raise FrameworkAuthorityInvalidTransition(str(exc)) from exc
        row.status = payload.to_status.value
        if payload.to_status == FrameworkStatus.RETIRED and row.retired_date is None:
            row.retired_date = _utcnow().date()
        row.updated_at = _utcnow()
        db.flush()
        return row

    def list_framework_controls(
        self, db: Session, *, tenant_id: str, framework_id: str
    ) -> list[FrameworkAuthorityFrameworkControlRecord]:
        framework = self.get_framework_visible(
            db, tenant_id=tenant_id, framework_id=framework_id
        )
        stmt = (
            select(FrameworkAuthorityFrameworkControlRecord)
            .where(
                FrameworkAuthorityFrameworkControlRecord.framework_id == framework.id
            )
            .order_by(
                FrameworkAuthorityFrameworkControlRecord.control_ref.asc(),
                FrameworkAuthorityFrameworkControlRecord.id.asc(),
            )
        )
        return list(db.execute(stmt).scalars().all())

    def get_framework_control_visible(
        self,
        db: Session,
        *,
        tenant_id: str,
        framework_id: str,
        framework_control_id: str,
    ) -> FrameworkAuthorityFrameworkControlRecord:
        framework = self.get_framework_visible(
            db, tenant_id=tenant_id, framework_id=framework_id
        )
        stmt = select(FrameworkAuthorityFrameworkControlRecord).where(
            FrameworkAuthorityFrameworkControlRecord.id == framework_control_id,
            FrameworkAuthorityFrameworkControlRecord.framework_id == framework.id,
        )
        row = db.execute(stmt).scalar_one_or_none()
        if row is None:
            raise FrameworkAuthorityNotFound("framework_control_not_found")
        return row

    def create_framework_control(
        self,
        db: Session,
        *,
        tenant_id: str,
        framework_id: str,
        allow_system_write: bool,
        payload: FrameworkControlCreateRequest,
    ) -> FrameworkAuthorityFrameworkControlRecord:
        framework = self.get_framework_visible(
            db, tenant_id=tenant_id, framework_id=framework_id
        )
        self._ensure_framework_write_allowed(
            row=framework,
            tenant_id=tenant_id,
            allow_system_write=allow_system_write,
        )
        existing = db.execute(
            select(FrameworkAuthorityFrameworkControlRecord).where(
                FrameworkAuthorityFrameworkControlRecord.framework_id == framework.id,
                FrameworkAuthorityFrameworkControlRecord.control_ref
                == payload.control_ref,
            )
        ).scalar_one_or_none()
        if existing is not None:
            raise FrameworkAuthorityConflict("framework_control_ref_exists")
        row = FrameworkAuthorityFrameworkControlRecord(
            framework_id=framework.id,
            tenant_id=framework.tenant_id,
            scope_type=framework.scope_type,
            control_ref=payload.control_ref,
            title=payload.title,
            description=payload.description,
            domain=payload.domain,
            family=payload.family,
            clause=payload.clause,
            objective=payload.objective,
            implementation_guidance=payload.implementation_guidance,
            status=payload.status.value,
            schema_version=payload.schema_version,
        )
        db.add(row)
        db.flush()
        return row

    def update_framework_control(
        self,
        db: Session,
        *,
        tenant_id: str,
        framework_id: str,
        framework_control_id: str,
        allow_system_write: bool,
        payload: FrameworkControlUpdateRequest,
    ) -> FrameworkAuthorityFrameworkControlRecord:
        row = self.get_framework_control_visible(
            db,
            tenant_id=tenant_id,
            framework_id=framework_id,
            framework_control_id=framework_control_id,
        )
        framework = self.get_framework_visible(
            db, tenant_id=tenant_id, framework_id=framework_id
        )
        self._ensure_framework_write_allowed(
            row=framework,
            tenant_id=tenant_id,
            allow_system_write=allow_system_write,
        )
        for field in (
            "title",
            "description",
            "domain",
            "family",
            "clause",
            "objective",
            "implementation_guidance",
        ):
            value = getattr(payload, field)
            if value is not None:
                setattr(row, field, value)
        if payload.status is not None:
            row.status = payload.status.value
        row.updated_at = _utcnow()
        db.flush()
        return row

    def create_mapping(
        self,
        db: Session,
        *,
        tenant_id: str,
        control_id: str,
        actor: str,
        payload: ControlFrameworkMappingCreateRequest,
    ) -> ControlFrameworkMappingRecord:
        self.assert_control_owned_by_tenant(
            db, tenant_id=tenant_id, control_id=control_id
        )
        framework = self.get_framework_visible(
            db, tenant_id=tenant_id, framework_id=payload.framework_id
        )
        framework_control = self.get_framework_control_visible(
            db,
            tenant_id=tenant_id,
            framework_id=framework.id,
            framework_control_id=payload.framework_control_id,
        )
        if (
            framework.scope_type == ScopeType.TENANT.value
            and framework.tenant_id != tenant_id
        ):
            raise FrameworkAuthorityNotFound("framework_not_found")
        duplicate = db.execute(
            select(ControlFrameworkMappingRecord).where(
                ControlFrameworkMappingRecord.tenant_id == tenant_id,
                ControlFrameworkMappingRecord.control_id == control_id,
                ControlFrameworkMappingRecord.framework_control_id
                == framework_control.id,
                ControlFrameworkMappingRecord.status.in_(
                    [MappingStatus.DRAFT.value, MappingStatus.ACTIVE.value]
                ),
            )
        ).scalar_one_or_none()
        if duplicate is not None:
            raise FrameworkAuthorityConflict("control_framework_mapping_exists")
        row = ControlFrameworkMappingRecord(
            tenant_id=tenant_id,
            control_id=control_id,
            framework_id=framework.id,
            framework_control_id=framework_control.id,
            mapping_type=payload.mapping_type.value,
            coverage_level=payload.coverage_level.value,
            confidence=payload.confidence,
            rationale=payload.rationale,
            mapped_by=actor,
            mapped_at=_utcnow(),
            status=payload.status.value,
            schema_version=payload.schema_version,
        )
        db.add(row)
        db.flush()
        self._write_mapping_audit(
            db,
            tenant_id=tenant_id,
            mapping_id=row.id,
            event_type=MappingAuditEventType.CREATED,
            actor=actor,
            old_state={},
            new_state=self.serialize_mapping(row),
            reason="created",
            schema_version=row.schema_version,
        )
        return row

    def list_mappings_for_control(
        self, db: Session, *, tenant_id: str, control_id: str
    ) -> list[ControlFrameworkMappingRecord]:
        self.assert_control_owned_by_tenant(
            db, tenant_id=tenant_id, control_id=control_id
        )
        stmt = (
            select(ControlFrameworkMappingRecord)
            .where(
                ControlFrameworkMappingRecord.tenant_id == tenant_id,
                ControlFrameworkMappingRecord.control_id == control_id,
            )
            .order_by(
                ControlFrameworkMappingRecord.mapped_at.desc(),
                ControlFrameworkMappingRecord.id.asc(),
            )
        )
        return list(db.execute(stmt).scalars().all())

    def list_mappings_for_framework(
        self, db: Session, *, tenant_id: str, framework_id: str
    ) -> list[ControlFrameworkMappingRecord]:
        framework = self.get_framework_visible(
            db, tenant_id=tenant_id, framework_id=framework_id
        )
        stmt = (
            select(ControlFrameworkMappingRecord)
            .where(
                ControlFrameworkMappingRecord.tenant_id == tenant_id,
                ControlFrameworkMappingRecord.framework_id == framework.id,
            )
            .order_by(
                ControlFrameworkMappingRecord.mapped_at.desc(),
                ControlFrameworkMappingRecord.id.asc(),
            )
        )
        return list(db.execute(stmt).scalars().all())

    def get_mapping(
        self, db: Session, *, tenant_id: str, mapping_id: str
    ) -> ControlFrameworkMappingRecord:
        stmt = select(ControlFrameworkMappingRecord).where(
            ControlFrameworkMappingRecord.id == mapping_id,
            ControlFrameworkMappingRecord.tenant_id == tenant_id,
        )
        row = db.execute(stmt).scalar_one_or_none()
        if row is None:
            raise FrameworkAuthorityNotFound("control_framework_mapping_not_found")
        self.get_framework_visible(
            db, tenant_id=tenant_id, framework_id=row.framework_id
        )
        return row

    def update_mapping(
        self,
        db: Session,
        *,
        tenant_id: str,
        mapping_id: str,
        actor: str,
        payload: ControlFrameworkMappingUpdateRequest,
    ) -> ControlFrameworkMappingRecord:
        row = self.get_mapping(db, tenant_id=tenant_id, mapping_id=mapping_id)
        old_state = self.serialize_mapping(row)
        if MappingStatus(row.status) in {
            MappingStatus.REJECTED,
            MappingStatus.SUPERSEDED,
            MappingStatus.RETIRED,
        }:
            raise FrameworkAuthorityConflict("control_framework_mapping_terminal")
        for field in ("mapping_type", "coverage_level", "confidence", "rationale"):
            value = getattr(payload, field)
            if value is None:
                continue
            if isinstance(value, Enum):
                setattr(row, field, value.value)
            else:
                setattr(row, field, value)
        row.updated_at = _utcnow()
        db.flush()
        self._write_mapping_audit(
            db,
            tenant_id=tenant_id,
            mapping_id=row.id,
            event_type=MappingAuditEventType.UPDATED,
            actor=actor,
            old_state=old_state,
            new_state=self.serialize_mapping(row),
            reason="updated",
            schema_version=row.schema_version,
        )
        return row

    def transition_mapping(
        self,
        db: Session,
        *,
        tenant_id: str,
        mapping_id: str,
        actor: str,
        payload: ControlFrameworkMappingTransitionRequest,
    ) -> ControlFrameworkMappingRecord:
        row = self.get_mapping(db, tenant_id=tenant_id, mapping_id=mapping_id)
        old_state = self.serialize_mapping(row)
        try:
            validate_mapping_transition(MappingStatus(row.status), payload.to_status)
        except ValueError as exc:
            raise FrameworkAuthorityInvalidTransition(str(exc)) from exc
        row.status = payload.to_status.value
        row.updated_at = _utcnow()
        db.flush()
        self._write_mapping_audit(
            db,
            tenant_id=tenant_id,
            mapping_id=row.id,
            event_type=MAPPING_TRANSITION_EVENT[payload.to_status],
            actor=actor,
            old_state=old_state,
            new_state=self.serialize_mapping(row),
            reason=payload.reason or payload.to_status.value.lower(),
            schema_version=row.schema_version,
        )
        return row

    def list_mapping_audit(
        self, db: Session, *, tenant_id: str, mapping_id: str
    ) -> list[ControlFrameworkMappingAuditRecord]:
        self.get_mapping(db, tenant_id=tenant_id, mapping_id=mapping_id)
        stmt = (
            select(ControlFrameworkMappingAuditRecord)
            .where(
                ControlFrameworkMappingAuditRecord.tenant_id == tenant_id,
                ControlFrameworkMappingAuditRecord.mapping_id == mapping_id,
            )
            .order_by(
                ControlFrameworkMappingAuditRecord.event_at.asc(),
                ControlFrameworkMappingAuditRecord.id.asc(),
            )
        )
        return list(db.execute(stmt).scalars().all())

    def framework_coverage(
        self, db: Session, *, tenant_id: str, framework_id: str
    ) -> dict[str, Any]:
        framework = self.get_framework_visible(
            db, tenant_id=tenant_id, framework_id=framework_id
        )
        control_rows = self.list_framework_controls(
            db, tenant_id=tenant_id, framework_id=framework.id
        )
        relevant_controls = [
            row
            for row in control_rows
            if FrameworkControlStatus(row.status) != FrameworkControlStatus.RETIRED
        ]
        mappings = self.list_mappings_for_framework(
            db, tenant_id=tenant_id, framework_id=framework.id
        )
        active_mappings = [
            m for m in mappings if MappingStatus(m.status) == MappingStatus.ACTIVE
        ]
        by_framework_control: dict[str, list[ControlFrameworkMappingRecord]] = {}
        for mapping in active_mappings:
            by_framework_control.setdefault(mapping.framework_control_id, []).append(
                mapping
            )
        total = len(relevant_controls)
        full_count = 0
        partial_count = 0
        supporting_count = 0
        not_applicable_count = 0
        mapped_ids: set[str] = set()
        confidence_values: list[int] = []
        for control in relevant_controls:
            candidates = by_framework_control.get(control.id, [])
            if not candidates:
                continue
            for candidate in candidates:
                confidence_values.append(int(candidate.confidence))
            selected_type = self._best_mapping_type(candidates)
            if selected_type == MappingType.FULL:
                full_count += 1
                mapped_ids.add(control.id)
            elif selected_type == MappingType.PARTIAL:
                partial_count += 1
                mapped_ids.add(control.id)
            elif selected_type == MappingType.SUPPORTING:
                supporting_count += 1
                mapped_ids.add(control.id)
            elif selected_type == MappingType.NOT_APPLICABLE:
                not_applicable_count += 1
            elif selected_type in MAPPED_MAPPING_TYPES:
                mapped_ids.add(control.id)
        mapped_controls = len(mapped_ids)
        unmapped_controls = max(total - mapped_controls - not_applicable_count, 0)
        coverage_percentage = (
            round((mapped_controls / total) * 100, 2) if total else 0.0
        )
        average_confidence = (
            round(sum(confidence_values) / len(confidence_values), 2)
            if confidence_values
            else 0.0
        )
        return {
            "framework_id": framework.id,
            "framework_key": framework.framework_key,
            "framework_version": framework.version,
            "total_framework_controls": total,
            "mapped_framework_controls": mapped_controls,
            "unmapped_framework_controls": unmapped_controls,
            "full_coverage_count": full_count,
            "partial_coverage_count": partial_count,
            "supporting_count": supporting_count,
            "not_applicable_count": not_applicable_count,
            "coverage_percentage": coverage_percentage,
            "average_confidence": average_confidence,
        }

    def control_coverage(
        self, db: Session, *, tenant_id: str, control_id: str
    ) -> dict[str, Any]:
        mappings = self.list_mappings_for_control(
            db, tenant_id=tenant_id, control_id=control_id
        )
        active_mappings = [
            m for m in mappings if MappingStatus(m.status) == MappingStatus.ACTIVE
        ]
        grouped: dict[str, list[ControlFrameworkMappingRecord]] = {}
        for mapping in active_mappings:
            grouped.setdefault(mapping.framework_id, []).append(mapping)
        framework_coverage: list[dict[str, Any]] = []
        for framework_id, framework_mappings in sorted(grouped.items()):
            framework = self.get_framework_visible(
                db, tenant_id=tenant_id, framework_id=framework_id
            )
            confidence_values = [int(item.confidence) for item in framework_mappings]
            covered_ids = {
                item.framework_control_id
                for item in framework_mappings
                if MappingType(item.mapping_type) in MAPPED_MAPPING_TYPES
            }
            total_controls = len(
                [
                    row
                    for row in self.list_framework_controls(
                        db, tenant_id=tenant_id, framework_id=framework.id
                    )
                    if FrameworkControlStatus(row.status)
                    != FrameworkControlStatus.RETIRED
                ]
            )
            coverage_percentage = (
                round((len(covered_ids) / total_controls) * 100, 2)
                if total_controls
                else 0.0
            )
            framework_coverage.append(
                {
                    "framework_id": framework.id,
                    "framework_key": framework.framework_key,
                    "framework_version": framework.version,
                    "framework_name": framework.name,
                    "framework_controls_covered": len(covered_ids),
                    "coverage_percentage": coverage_percentage,
                    "average_confidence": round(
                        sum(confidence_values) / len(confidence_values), 2
                    )
                    if confidence_values
                    else 0.0,
                    "mappings": [
                        self.enrich_mapping(db, tenant_id=tenant_id, row=item)
                        for item in framework_mappings
                    ],
                }
            )
        return {
            "control_id": control_id,
            "mapped_frameworks": len(framework_coverage),
            "framework_coverage": framework_coverage,
        }

    def enrich_mapping(
        self, db: Session, *, tenant_id: str, row: ControlFrameworkMappingRecord
    ) -> dict[str, Any]:
        framework = self.get_framework_visible(
            db, tenant_id=tenant_id, framework_id=row.framework_id
        )
        stmt = select(FrameworkAuthorityFrameworkControlRecord).where(
            FrameworkAuthorityFrameworkControlRecord.id == row.framework_control_id,
            FrameworkAuthorityFrameworkControlRecord.framework_id == framework.id,
        )
        control = db.execute(stmt).scalar_one_or_none()
        if control is None:
            raise FrameworkAuthorityNotFound("framework_control_not_found")
        return {
            "id": row.id,
            "tenant_id": row.tenant_id,
            "control_id": row.control_id,
            "framework_id": row.framework_id,
            "framework_control_id": row.framework_control_id,
            "framework_key": framework.framework_key,
            "framework_version": framework.version,
            "framework_name": framework.name,
            "framework_scope_type": framework.scope_type,
            "control_ref": control.control_ref,
            "framework_control_title": control.title,
            "mapping_type": row.mapping_type,
            "coverage_level": row.coverage_level,
            "confidence": row.confidence,
            "rationale": row.rationale,
            "mapped_by": row.mapped_by,
            "mapped_at": row.mapped_at,
            "status": row.status,
            "schema_version": row.schema_version,
            "created_at": row.created_at,
            "updated_at": row.updated_at,
        }

    def serialize_mapping(self, row: ControlFrameworkMappingRecord) -> dict[str, Any]:
        return {
            "id": row.id,
            "tenant_id": row.tenant_id,
            "control_id": row.control_id,
            "framework_id": row.framework_id,
            "framework_control_id": row.framework_control_id,
            "mapping_type": row.mapping_type,
            "coverage_level": row.coverage_level,
            "confidence": row.confidence,
            "rationale": row.rationale,
            "mapped_by": row.mapped_by,
            "mapped_at": row.mapped_at.isoformat() if row.mapped_at else "",
            "status": row.status,
            "schema_version": row.schema_version,
            "created_at": row.created_at.isoformat() if row.created_at else "",
            "updated_at": row.updated_at.isoformat() if row.updated_at else "",
        }

    def assert_control_owned_by_tenant(
        self, db: Session, *, tenant_id: str, control_id: str
    ) -> None:
        self._seed_service.seed_minimal(db)
        set_tenant_context(db, tenant_id)
        control_row = db.execute(
            text(
                "SELECT 1 FROM enterprise_control_catalog WHERE control_id = :control_id"
            ),
            {"control_id": control_id},
        ).first()
        if control_row is None:
            raise FrameworkAuthorityNotFound("control_not_found")
        state_row = db.execute(
            text(
                "SELECT 1 FROM tenant_control_state "
                "WHERE tenant_id = :tenant_id AND control_id = :control_id"
            ),
            {"tenant_id": tenant_id, "control_id": control_id},
        ).first()
        if state_row is None:
            raise FrameworkAuthorityNotFound("control_not_found")

    def _ensure_framework_identity_available(
        self,
        db: Session,
        *,
        tenant_id: str | None,
        scope_type: ScopeType,
        framework_key: str,
        version: str,
    ) -> None:
        if tenant_id is None:
            tenant_clause = FrameworkAuthorityFrameworkRecord.tenant_id.is_(None)
        else:
            tenant_clause = FrameworkAuthorityFrameworkRecord.tenant_id == tenant_id
        stmt = select(FrameworkAuthorityFrameworkRecord).where(
            FrameworkAuthorityFrameworkRecord.scope_type == scope_type.value,
            FrameworkAuthorityFrameworkRecord.framework_key == framework_key,
            FrameworkAuthorityFrameworkRecord.version == version,
            tenant_clause,
        )
        if db.execute(stmt).scalar_one_or_none() is not None:
            raise FrameworkAuthorityConflict("framework_identity_exists")

    def _framework_visibility_clause(self, tenant_id: str) -> Any:
        return or_(
            and_(
                FrameworkAuthorityFrameworkRecord.scope_type == ScopeType.SYSTEM.value,
                FrameworkAuthorityFrameworkRecord.tenant_id.is_(None),
            ),
            and_(
                FrameworkAuthorityFrameworkRecord.scope_type == ScopeType.TENANT.value,
                FrameworkAuthorityFrameworkRecord.tenant_id == tenant_id,
            ),
        )

    def _ensure_framework_write_allowed(
        self,
        *,
        row: FrameworkAuthorityFrameworkRecord,
        tenant_id: str,
        allow_system_write: bool,
    ) -> None:
        if row.scope_type == ScopeType.SYSTEM.value and not allow_system_write:
            raise FrameworkAuthorityPermissionDenied("system_framework_write_denied")
        if row.scope_type == ScopeType.TENANT.value and row.tenant_id != tenant_id:
            raise FrameworkAuthorityNotFound("framework_not_found")

    def _write_mapping_audit(
        self,
        db: Session,
        *,
        tenant_id: str,
        mapping_id: str,
        event_type: MappingAuditEventType,
        actor: str,
        old_state: dict[str, Any],
        new_state: dict[str, Any],
        reason: str,
        schema_version: int,
    ) -> None:
        row = ControlFrameworkMappingAuditRecord(
            tenant_id=tenant_id,
            mapping_id=mapping_id,
            event_type=event_type.value,
            actor=actor,
            event_at=_utcnow(),
            old_state=old_state,
            new_state=new_state,
            reason=reason,
            schema_version=schema_version,
        )
        db.add(row)
        db.flush()

    def _best_mapping_type(
        self, rows: list[ControlFrameworkMappingRecord]
    ) -> MappingType:
        present = {MappingType(row.mapping_type) for row in rows}
        for mapping_type in MAPPING_TYPE_PRECEDENCE:
            if mapping_type in present:
                return mapping_type
        return MappingType.RELATED
