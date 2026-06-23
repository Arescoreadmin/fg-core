from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal, ROUND_HALF_UP
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ScopeType(str, Enum):
    SYSTEM = "SYSTEM"
    TENANT = "TENANT"


class FrameworkStatus(str, Enum):
    DRAFT = "DRAFT"
    ACTIVE = "ACTIVE"
    RETIRED = "RETIRED"


class FrameworkControlStatus(str, Enum):
    DRAFT = "DRAFT"
    ACTIVE = "ACTIVE"
    DEPRECATED = "DEPRECATED"
    RETIRED = "RETIRED"


class MappingType(str, Enum):
    FULL = "FULL"
    PARTIAL = "PARTIAL"
    SUPPORTING = "SUPPORTING"
    COMPENSATING = "COMPENSATING"
    RELATED = "RELATED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class CoverageLevel(str, Enum):
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    COMPLETE = "COMPLETE"


class MappingStatus(str, Enum):
    DRAFT = "DRAFT"
    ACTIVE = "ACTIVE"
    SUPERSEDED = "SUPERSEDED"
    REJECTED = "REJECTED"
    RETIRED = "RETIRED"


class MappingAuditEventType(str, Enum):
    CREATED = "CREATED"
    UPDATED = "UPDATED"
    ACTIVATED = "ACTIVATED"
    SUPERSEDED = "SUPERSEDED"
    REJECTED = "REJECTED"
    RETIRED = "RETIRED"


VALID_FRAMEWORK_TRANSITIONS: dict[FrameworkStatus, frozenset[FrameworkStatus]] = {
    FrameworkStatus.DRAFT: frozenset({FrameworkStatus.ACTIVE}),
    FrameworkStatus.ACTIVE: frozenset({FrameworkStatus.RETIRED}),
    FrameworkStatus.RETIRED: frozenset(),
}

VALID_MAPPING_TRANSITIONS: dict[MappingStatus, frozenset[MappingStatus]] = {
    MappingStatus.DRAFT: frozenset({MappingStatus.ACTIVE, MappingStatus.REJECTED}),
    MappingStatus.ACTIVE: frozenset({MappingStatus.SUPERSEDED, MappingStatus.RETIRED}),
    MappingStatus.SUPERSEDED: frozenset(),
    MappingStatus.REJECTED: frozenset(),
    MappingStatus.RETIRED: frozenset(),
}

MAPPING_TRANSITION_EVENT: dict[MappingStatus, MappingAuditEventType] = {
    MappingStatus.ACTIVE: MappingAuditEventType.ACTIVATED,
    MappingStatus.SUPERSEDED: MappingAuditEventType.SUPERSEDED,
    MappingStatus.REJECTED: MappingAuditEventType.REJECTED,
    MappingStatus.RETIRED: MappingAuditEventType.RETIRED,
}

MAPPING_TYPE_PRECEDENCE: tuple[MappingType, ...] = (
    MappingType.FULL,
    MappingType.PARTIAL,
    MappingType.SUPPORTING,
    MappingType.COMPENSATING,
    MappingType.RELATED,
    MappingType.NOT_APPLICABLE,
)

MAPPED_MAPPING_TYPES: frozenset[MappingType] = frozenset(
    {
        MappingType.FULL,
        MappingType.PARTIAL,
        MappingType.SUPPORTING,
        MappingType.COMPENSATING,
        MappingType.RELATED,
    }
)


def validate_framework_transition(
    from_status: FrameworkStatus, to_status: FrameworkStatus
) -> None:
    allowed = VALID_FRAMEWORK_TRANSITIONS.get(from_status, frozenset())
    if to_status not in allowed:
        raise ValueError(
            f"invalid_framework_transition:{from_status.value}->{to_status.value}"
        )


def validate_mapping_transition(
    from_status: MappingStatus, to_status: MappingStatus
) -> None:
    allowed = VALID_MAPPING_TRANSITIONS.get(from_status, frozenset())
    if to_status not in allowed:
        raise ValueError(
            f"invalid_mapping_transition:{from_status.value}->{to_status.value}"
        )


def normalize_confidence(value: int | float | Decimal) -> int:
    numeric = Decimal(str(value))
    if numeric < 0 or numeric > 100:
        raise ValueError("confidence_must_be_between_0_and_100")
    return int(numeric.quantize(Decimal("1"), rounding=ROUND_HALF_UP))


class FrameworkCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    framework_key: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=255)
    version: str = Field(min_length=1, max_length=64)
    category: str = Field(min_length=1, max_length=128)
    publisher: str = Field(min_length=1, max_length=255)
    description: str = Field(default="", max_length=4000)
    effective_date: date | None = None
    retired_date: date | None = None
    scope_type: ScopeType = ScopeType.TENANT
    status: FrameworkStatus = FrameworkStatus.DRAFT
    schema_version: int = Field(default=1, ge=1)


class FrameworkUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=255)
    category: str | None = Field(default=None, min_length=1, max_length=128)
    publisher: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=4000)
    effective_date: date | None = None
    retired_date: date | None = None


class FrameworkTransitionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    to_status: FrameworkStatus


class FrameworkControlCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    control_ref: str = Field(min_length=1, max_length=255)
    title: str = Field(min_length=1, max_length=255)
    description: str = Field(default="", max_length=4000)
    domain: str = Field(default="", max_length=255)
    family: str = Field(default="", max_length=255)
    clause: str = Field(default="", max_length=255)
    objective: str = Field(default="", max_length=4000)
    implementation_guidance: str = Field(default="", max_length=4000)
    status: FrameworkControlStatus = FrameworkControlStatus.DRAFT
    schema_version: int = Field(default=1, ge=1)


class FrameworkControlUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=4000)
    domain: str | None = Field(default=None, max_length=255)
    family: str | None = Field(default=None, max_length=255)
    clause: str | None = Field(default=None, max_length=255)
    objective: str | None = Field(default=None, max_length=4000)
    implementation_guidance: str | None = Field(default=None, max_length=4000)
    status: FrameworkControlStatus | None = None


class ControlFrameworkMappingCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    framework_id: str = Field(min_length=1, max_length=64)
    framework_control_id: str = Field(min_length=1, max_length=64)
    mapping_type: MappingType
    coverage_level: CoverageLevel
    confidence: int = Field(ge=0, le=100)
    rationale: str = Field(min_length=1, max_length=4000)
    status: MappingStatus = MappingStatus.DRAFT
    schema_version: int = Field(default=1, ge=1)

    _normalize_confidence = field_validator("confidence", mode="before")(
        normalize_confidence
    )


class ControlFrameworkMappingUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mapping_type: MappingType | None = None
    coverage_level: CoverageLevel | None = None
    confidence: int | None = Field(default=None, ge=0, le=100)
    rationale: str | None = Field(default=None, min_length=1, max_length=4000)

    @field_validator("confidence", mode="before")
    @classmethod
    def _normalize_optional_confidence(cls, value: Any) -> Any:
        if value is None:
            return None
        return normalize_confidence(value)


class ControlFrameworkMappingTransitionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    to_status: MappingStatus
    reason: str = Field(default="", max_length=4000)


class FrameworkResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str | None
    scope_type: ScopeType
    framework_key: str
    name: str
    version: str
    category: str
    publisher: str
    description: str
    status: FrameworkStatus
    effective_date: date | None
    retired_date: date | None
    schema_version: int
    created_at: datetime
    updated_at: datetime


class FrameworkControlResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    framework_id: str
    tenant_id: str | None
    scope_type: ScopeType
    control_ref: str
    title: str
    description: str
    domain: str
    family: str
    clause: str
    objective: str
    implementation_guidance: str
    status: FrameworkControlStatus
    schema_version: int
    created_at: datetime
    updated_at: datetime


class ControlFrameworkMappingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    control_id: str
    framework_id: str
    framework_control_id: str
    framework_key: str
    framework_version: str
    framework_name: str
    framework_scope_type: ScopeType
    control_ref: str
    framework_control_title: str
    mapping_type: MappingType
    coverage_level: CoverageLevel
    confidence: int
    rationale: str
    mapped_by: str
    mapped_at: datetime
    status: MappingStatus
    schema_version: int
    created_at: datetime
    updated_at: datetime


class ControlFrameworkMappingAuditResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    mapping_id: str
    event_type: MappingAuditEventType
    actor: str
    event_at: datetime
    old_state: dict[str, Any]
    new_state: dict[str, Any]
    reason: str
    schema_version: int
    created_at: datetime


class FrameworkCoverageResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    framework_id: str
    framework_key: str
    framework_version: str
    total_framework_controls: int
    mapped_framework_controls: int
    unmapped_framework_controls: int
    full_coverage_count: int
    partial_coverage_count: int
    supporting_count: int
    not_applicable_count: int
    coverage_percentage: float
    average_confidence: float


class FrameworkCoverageDetailResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    framework_id: str
    framework_key: str
    framework_version: str
    framework_name: str
    framework_controls_covered: int
    coverage_percentage: float
    average_confidence: float
    mappings: list[ControlFrameworkMappingResponse]


class ControlFrameworkCoverageResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    control_id: str
    mapped_frameworks: int
    framework_coverage: list[FrameworkCoverageDetailResponse]
