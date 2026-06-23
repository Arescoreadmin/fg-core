from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    CheckConstraint,
    Column,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import DeclarativeBase

from services.framework_authority.schemas import (
    CoverageLevel,
    FrameworkControlStatus,
    FrameworkStatus,
    MappingAuditEventType,
    MappingStatus,
    MappingType,
    ScopeType,
)

try:
    from api.db_models import Base
except ImportError:

    class Base(DeclarativeBase):  # type: ignore[no-redef]
        pass


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _new_uuid() -> str:
    return str(uuid.uuid4())


class FrameworkAuthorityFrameworkRecord(Base):
    __tablename__ = "fa_frameworks"
    __table_args__ = (
        UniqueConstraint(
            "scope_type",
            "tenant_id",
            "framework_key",
            "version",
            name="uq_fa_framework_identity",
        ),
        CheckConstraint(
            "scope_type IN ('SYSTEM','TENANT')", name="chk_fa_framework_scope"
        ),
        CheckConstraint(
            "status IN ('DRAFT','ACTIVE','RETIRED')", name="chk_fa_framework_status"
        ),
        CheckConstraint(
            "(scope_type = 'SYSTEM' AND tenant_id IS NULL) OR "
            "(scope_type = 'TENANT' AND tenant_id IS NOT NULL)",
            name="chk_fa_framework_scope_tenant",
        ),
        Index("ix_fa_frameworks_tenant_status", "tenant_id", "status"),
        Index("ix_fa_frameworks_scope_key", "scope_type", "framework_key"),
    )

    id = Column(String(36), primary_key=True, default=_new_uuid)
    tenant_id = Column(String(128), nullable=True)
    scope_type = Column(String(16), nullable=False, default=ScopeType.TENANT.value)
    framework_key = Column(String(128), nullable=False)
    name = Column(String(255), nullable=False)
    version = Column(String(64), nullable=False)
    category = Column(String(128), nullable=False)
    publisher = Column(String(255), nullable=False)
    description = Column(Text, nullable=False, default="")
    status = Column(String(16), nullable=False, default=FrameworkStatus.DRAFT.value)
    effective_date = Column(Date, nullable=True)
    retired_date = Column(Date, nullable=True)
    schema_version = Column(Integer, nullable=False, default=1)
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        server_default=func.now(),
    )
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        server_default=func.now(),
        onupdate=_utcnow,
    )


class FrameworkAuthorityFrameworkControlRecord(Base):
    __tablename__ = "fa_framework_controls"
    __table_args__ = (
        UniqueConstraint(
            "framework_id", "control_ref", name="uq_fa_framework_controls_ref"
        ),
        CheckConstraint(
            "scope_type IN ('SYSTEM','TENANT')", name="chk_fa_framework_control_scope"
        ),
        CheckConstraint(
            "status IN ('DRAFT','ACTIVE','DEPRECATED','RETIRED')",
            name="chk_fa_framework_control_status",
        ),
        CheckConstraint(
            "(scope_type = 'SYSTEM' AND tenant_id IS NULL) OR "
            "(scope_type = 'TENANT' AND tenant_id IS NOT NULL)",
            name="chk_fa_framework_control_scope_tenant",
        ),
        Index("ix_fa_framework_controls_framework", "framework_id", "status"),
        Index(
            "ix_fa_framework_controls_tenant_scope",
            "tenant_id",
            "scope_type",
            "control_ref",
        ),
    )

    id = Column(String(36), primary_key=True, default=_new_uuid)
    framework_id = Column(
        String(36),
        ForeignKey("fa_frameworks.id", ondelete="CASCADE"),
        nullable=False,
    )
    tenant_id = Column(String(128), nullable=True)
    scope_type = Column(String(16), nullable=False, default=ScopeType.TENANT.value)
    control_ref = Column(String(255), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False, default="")
    domain = Column(String(255), nullable=False, default="")
    family = Column(String(255), nullable=False, default="")
    clause = Column(String(255), nullable=False, default="")
    objective = Column(Text, nullable=False, default="")
    implementation_guidance = Column(Text, nullable=False, default="")
    status = Column(
        String(16), nullable=False, default=FrameworkControlStatus.DRAFT.value
    )
    schema_version = Column(Integer, nullable=False, default=1)
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        server_default=func.now(),
    )
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        server_default=func.now(),
        onupdate=_utcnow,
    )


class ControlFrameworkMappingRecord(Base):
    __tablename__ = "control_framework_mappings"
    __table_args__ = (
        CheckConstraint(
            "mapping_type IN "
            "('FULL','PARTIAL','SUPPORTING','COMPENSATING','RELATED','NOT_APPLICABLE')",
            name="chk_control_framework_mapping_type",
        ),
        CheckConstraint(
            "coverage_level IN ('NONE','LOW','MEDIUM','HIGH','COMPLETE')",
            name="chk_control_framework_coverage_level",
        ),
        CheckConstraint(
            "status IN ('DRAFT','ACTIVE','SUPERSEDED','REJECTED','RETIRED')",
            name="chk_control_framework_mapping_status",
        ),
        CheckConstraint(
            "confidence >= 0 AND confidence <= 100",
            name="chk_control_framework_confidence",
        ),
        Index("ix_cfm_tenant_control", "tenant_id", "control_id"),
        Index("ix_cfm_tenant_framework", "tenant_id", "framework_id"),
        Index("ix_cfm_framework_control_status", "framework_control_id", "status"),
    )

    id = Column(String(36), primary_key=True, default=_new_uuid)
    tenant_id = Column(String(128), nullable=False)
    control_id = Column(String(255), nullable=False)
    framework_id = Column(
        String(36),
        ForeignKey("fa_frameworks.id", ondelete="CASCADE"),
        nullable=False,
    )
    framework_control_id = Column(
        String(36),
        ForeignKey("fa_framework_controls.id", ondelete="CASCADE"),
        nullable=False,
    )
    mapping_type = Column(String(32), nullable=False, default=MappingType.RELATED.value)
    coverage_level = Column(String(16), nullable=False, default=CoverageLevel.LOW.value)
    confidence = Column(Integer, nullable=False, default=0)
    rationale = Column(Text, nullable=False, default="")
    mapped_by = Column(String(255), nullable=False)
    mapped_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        server_default=func.now(),
    )
    status = Column(String(16), nullable=False, default=MappingStatus.DRAFT.value)
    schema_version = Column(Integer, nullable=False, default=1)
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        server_default=func.now(),
    )
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        server_default=func.now(),
        onupdate=_utcnow,
    )


class ControlFrameworkMappingAuditRecord(Base):
    __tablename__ = "control_framework_mapping_audits"
    __table_args__ = (
        CheckConstraint(
            "event_type IN "
            "('CREATED','UPDATED','ACTIVATED','SUPERSEDED','REJECTED','RETIRED')",
            name="chk_control_framework_mapping_audit_event_type",
        ),
        Index("ix_cfm_audit_tenant_mapping", "tenant_id", "mapping_id", "event_at"),
    )

    id = Column(String(36), primary_key=True, default=_new_uuid)
    tenant_id = Column(String(128), nullable=False)
    mapping_id = Column(
        String(36),
        ForeignKey("control_framework_mappings.id", ondelete="CASCADE"),
        nullable=False,
    )
    event_type = Column(
        String(16), nullable=False, default=MappingAuditEventType.CREATED.value
    )
    actor = Column(String(255), nullable=False)
    event_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        server_default=func.now(),
    )
    old_state = Column(JSON, nullable=False, default=dict)
    new_state = Column(JSON, nullable=False, default=dict)
    reason = Column(Text, nullable=False, default="")
    schema_version = Column(Integer, nullable=False, default=1)
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        server_default=func.now(),
    )
