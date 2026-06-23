from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from services.framework_authority.repository import (
    FrameworkAuthorityConflict,
    FrameworkAuthorityInvalidTransition,
    FrameworkAuthorityNotFound,
    FrameworkAuthorityPermissionDenied,
    FrameworkAuthorityRepository,
)
from services.framework_authority.schemas import (
    ControlFrameworkMappingCreateRequest,
    ControlFrameworkMappingTransitionRequest,
    ControlFrameworkMappingUpdateRequest,
    FrameworkControlCreateRequest,
    FrameworkControlUpdateRequest,
    FrameworkCreateRequest,
    FrameworkTransitionRequest,
    FrameworkUpdateRequest,
)

try:
    from prometheus_client import Counter as _PrometheusCounter
except Exception:  # pragma: no cover
    _COUNTER_CLS: Any | None = None
else:
    _COUNTER_CLS = _PrometheusCounter


class _NoopCounter:
    def inc(self, amount: float = 1.0) -> None:
        del amount


def _counter_factory(name: str, documentation: str) -> Any:
    if _COUNTER_CLS is None:
        return _NoopCounter()
    return _COUNTER_CLS(name, documentation)


FRAMEWORKS_TOTAL = _counter_factory(
    "frostgate_frameworks_total",
    "Framework authority framework records created.",
)
FRAMEWORK_CONTROLS_TOTAL = _counter_factory(
    "frostgate_framework_controls_total",
    "Framework authority framework control records created.",
)
CONTROL_FRAMEWORK_MAPPINGS_TOTAL = _counter_factory(
    "frostgate_control_framework_mappings_total",
    "Control to framework mappings created.",
)
CONTROL_FRAMEWORK_MAPPING_TRANSITIONS_TOTAL = _counter_factory(
    "frostgate_control_framework_mapping_transitions_total",
    "Control to framework mapping transitions executed.",
)
FRAMEWORK_COVERAGE_VIEWS_TOTAL = _counter_factory(
    "frostgate_framework_coverage_views_total",
    "Framework coverage views generated.",
)


class FrameworkAuthorityEngine:
    def __init__(self, repository: FrameworkAuthorityRepository | None = None) -> None:
        self.repository = repository or FrameworkAuthorityRepository()

    def list_frameworks(self, db: Session, *, tenant_id: str):
        return self.repository.list_frameworks(db, tenant_id=tenant_id)

    def get_framework(self, db: Session, *, tenant_id: str, framework_id: str):
        return self.repository.get_framework_visible(
            db, tenant_id=tenant_id, framework_id=framework_id
        )

    def create_framework(
        self,
        db: Session,
        *,
        tenant_id: str,
        actor: str,
        allow_system_write: bool,
        payload: FrameworkCreateRequest,
    ):
        row = self.repository.create_framework(
            db,
            tenant_id=tenant_id,
            actor=actor,
            allow_system_write=allow_system_write,
            payload=payload,
        )
        FRAMEWORKS_TOTAL.inc()
        return row

    def update_framework(
        self,
        db: Session,
        *,
        tenant_id: str,
        framework_id: str,
        allow_system_write: bool,
        payload: FrameworkUpdateRequest,
    ):
        return self.repository.update_framework(
            db,
            tenant_id=tenant_id,
            framework_id=framework_id,
            allow_system_write=allow_system_write,
            payload=payload,
        )

    def transition_framework(
        self,
        db: Session,
        *,
        tenant_id: str,
        framework_id: str,
        allow_system_write: bool,
        payload: FrameworkTransitionRequest,
    ):
        return self.repository.transition_framework(
            db,
            tenant_id=tenant_id,
            framework_id=framework_id,
            allow_system_write=allow_system_write,
            payload=payload,
        )

    def create_framework_control(
        self,
        db: Session,
        *,
        tenant_id: str,
        framework_id: str,
        allow_system_write: bool,
        payload: FrameworkControlCreateRequest,
    ):
        row = self.repository.create_framework_control(
            db,
            tenant_id=tenant_id,
            framework_id=framework_id,
            allow_system_write=allow_system_write,
            payload=payload,
        )
        FRAMEWORK_CONTROLS_TOTAL.inc()
        return row

    def list_framework_controls(
        self, db: Session, *, tenant_id: str, framework_id: str
    ):
        return self.repository.list_framework_controls(
            db, tenant_id=tenant_id, framework_id=framework_id
        )

    def get_framework_control(
        self,
        db: Session,
        *,
        tenant_id: str,
        framework_id: str,
        framework_control_id: str,
    ):
        return self.repository.get_framework_control_visible(
            db,
            tenant_id=tenant_id,
            framework_id=framework_id,
            framework_control_id=framework_control_id,
        )

    def update_framework_control(
        self,
        db: Session,
        *,
        tenant_id: str,
        framework_id: str,
        framework_control_id: str,
        allow_system_write: bool,
        payload: FrameworkControlUpdateRequest,
    ):
        return self.repository.update_framework_control(
            db,
            tenant_id=tenant_id,
            framework_id=framework_id,
            framework_control_id=framework_control_id,
            allow_system_write=allow_system_write,
            payload=payload,
        )

    def create_mapping(
        self,
        db: Session,
        *,
        tenant_id: str,
        control_id: str,
        actor: str,
        payload: ControlFrameworkMappingCreateRequest,
    ):
        row = self.repository.create_mapping(
            db,
            tenant_id=tenant_id,
            control_id=control_id,
            actor=actor,
            payload=payload,
        )
        CONTROL_FRAMEWORK_MAPPINGS_TOTAL.inc()
        return row

    def list_mappings_for_control(
        self, db: Session, *, tenant_id: str, control_id: str
    ) -> list[dict[str, Any]]:
        rows = self.repository.list_mappings_for_control(
            db, tenant_id=tenant_id, control_id=control_id
        )
        return [
            self.repository.enrich_mapping(db, tenant_id=tenant_id, row=row)
            for row in rows
        ]

    def list_mappings_for_framework(
        self, db: Session, *, tenant_id: str, framework_id: str
    ) -> list[dict[str, Any]]:
        rows = self.repository.list_mappings_for_framework(
            db, tenant_id=tenant_id, framework_id=framework_id
        )
        return [
            self.repository.enrich_mapping(db, tenant_id=tenant_id, row=row)
            for row in rows
        ]

    def get_mapping(
        self, db: Session, *, tenant_id: str, mapping_id: str
    ) -> dict[str, Any]:
        row = self.repository.get_mapping(
            db, tenant_id=tenant_id, mapping_id=mapping_id
        )
        return self.repository.enrich_mapping(db, tenant_id=tenant_id, row=row)

    def update_mapping(
        self,
        db: Session,
        *,
        tenant_id: str,
        mapping_id: str,
        actor: str,
        payload: ControlFrameworkMappingUpdateRequest,
    ) -> dict[str, Any]:
        row = self.repository.update_mapping(
            db,
            tenant_id=tenant_id,
            mapping_id=mapping_id,
            actor=actor,
            payload=payload,
        )
        return self.repository.enrich_mapping(db, tenant_id=tenant_id, row=row)

    def transition_mapping(
        self,
        db: Session,
        *,
        tenant_id: str,
        mapping_id: str,
        actor: str,
        payload: ControlFrameworkMappingTransitionRequest,
    ) -> dict[str, Any]:
        row = self.repository.transition_mapping(
            db,
            tenant_id=tenant_id,
            mapping_id=mapping_id,
            actor=actor,
            payload=payload,
        )
        CONTROL_FRAMEWORK_MAPPING_TRANSITIONS_TOTAL.inc()
        return self.repository.enrich_mapping(db, tenant_id=tenant_id, row=row)

    def list_mapping_audit(self, db: Session, *, tenant_id: str, mapping_id: str):
        return self.repository.list_mapping_audit(
            db, tenant_id=tenant_id, mapping_id=mapping_id
        )

    def framework_coverage(
        self, db: Session, *, tenant_id: str, framework_id: str
    ) -> dict[str, Any]:
        FRAMEWORK_COVERAGE_VIEWS_TOTAL.inc()
        return self.repository.framework_coverage(
            db, tenant_id=tenant_id, framework_id=framework_id
        )

    def control_coverage(
        self, db: Session, *, tenant_id: str, control_id: str
    ) -> dict[str, Any]:
        FRAMEWORK_COVERAGE_VIEWS_TOTAL.inc()
        return self.repository.control_coverage(
            db, tenant_id=tenant_id, control_id=control_id
        )


__all__ = [
    "CONTROL_FRAMEWORK_MAPPINGS_TOTAL",
    "CONTROL_FRAMEWORK_MAPPING_TRANSITIONS_TOTAL",
    "FRAMEWORK_CONTROLS_TOTAL",
    "FRAMEWORK_COVERAGE_VIEWS_TOTAL",
    "FRAMEWORKS_TOTAL",
    "FrameworkAuthorityConflict",
    "FrameworkAuthorityEngine",
    "FrameworkAuthorityInvalidTransition",
    "FrameworkAuthorityNotFound",
    "FrameworkAuthorityPermissionDenied",
]
