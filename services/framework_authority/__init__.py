from __future__ import annotations

from importlib import import_module
from typing import Any

__all__ = [
    "CONTROL_FRAMEWORK_MAPPINGS_TOTAL",
    "CONTROL_FRAMEWORK_MAPPING_TRANSITIONS_TOTAL",
    "FRAMEWORK_CONTROLS_TOTAL",
    "FRAMEWORK_COVERAGE_VIEWS_TOTAL",
    "FRAMEWORKS_TOTAL",
    "ControlFrameworkCoverageResponse",
    "ControlFrameworkMappingAuditResponse",
    "ControlFrameworkMappingCreateRequest",
    "ControlFrameworkMappingResponse",
    "ControlFrameworkMappingTransitionRequest",
    "ControlFrameworkMappingUpdateRequest",
    "CoverageLevel",
    "FrameworkAuthorityConflict",
    "FrameworkAuthorityEngine",
    "FrameworkAuthorityInvalidTransition",
    "FrameworkAuthorityNotFound",
    "FrameworkAuthorityPermissionDenied",
    "FrameworkAuthorityRepository",
    "FrameworkControlCreateRequest",
    "FrameworkControlResponse",
    "FrameworkControlStatus",
    "FrameworkControlUpdateRequest",
    "FrameworkCoverageResponse",
    "FrameworkCreateRequest",
    "FrameworkResponse",
    "FrameworkStatus",
    "FrameworkTransitionRequest",
    "FrameworkUpdateRequest",
    "MappingStatus",
    "MappingType",
    "ScopeType",
    "VALID_FRAMEWORK_TRANSITIONS",
    "VALID_MAPPING_TRANSITIONS",
    "validate_framework_transition",
    "validate_mapping_transition",
]

_SCHEMA_EXPORTS = {
    "ControlFrameworkCoverageResponse",
    "ControlFrameworkMappingAuditResponse",
    "ControlFrameworkMappingCreateRequest",
    "ControlFrameworkMappingResponse",
    "ControlFrameworkMappingTransitionRequest",
    "ControlFrameworkMappingUpdateRequest",
    "CoverageLevel",
    "FrameworkControlCreateRequest",
    "FrameworkControlResponse",
    "FrameworkControlStatus",
    "FrameworkControlUpdateRequest",
    "FrameworkCoverageResponse",
    "FrameworkCreateRequest",
    "FrameworkResponse",
    "FrameworkStatus",
    "FrameworkTransitionRequest",
    "FrameworkUpdateRequest",
    "MappingStatus",
    "MappingType",
    "ScopeType",
    "VALID_FRAMEWORK_TRANSITIONS",
    "VALID_MAPPING_TRANSITIONS",
    "validate_framework_transition",
    "validate_mapping_transition",
}
_ENGINE_EXPORTS = {
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
}
_REPOSITORY_EXPORTS = {"FrameworkAuthorityRepository"}


def __getattr__(name: str) -> Any:
    if name in _SCHEMA_EXPORTS:
        module = import_module("services.framework_authority.schemas")
        return getattr(module, name)
    if name in _ENGINE_EXPORTS:
        module = import_module("services.framework_authority.engine")
        return getattr(module, name)
    if name in _REPOSITORY_EXPORTS:
        module = import_module("services.framework_authority.repository")
        return getattr(module, name)
    raise AttributeError(name)
