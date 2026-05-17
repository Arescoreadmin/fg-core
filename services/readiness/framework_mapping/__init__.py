"""Enterprise Framework Mapping & Crosswalk Governance Engine.

Public API surface — all stable exports from this package.

Consumers import from this package, not from submodules, to allow
internal refactoring without breaking callers.
"""

from .crosswalk import (
    build_crosswalk,
    find_control_mappings,
    find_many_to_one_mappings,
    find_one_to_many_mappings,
)
from .hashing import (
    compute_mapping_hash,
    replay_mapping_hash,
    verify_mapping_hash,
)
from .models import (
    FRAMEWORK_SLUG_FROSTGATE,
    FRAMEWORK_SLUG_HIPAA_AI,
    FRAMEWORK_SLUG_ISO_42001,
    FRAMEWORK_SLUG_NIST_AI_RMF,
    FRAMEWORK_SLUG_SOC2_AI,
    ControlInheritance,
    CrosswalkEntry,
    FrameworkMapping,
    FrameworkMappingVersion,
    FrameworkNamespace,
    JurisdictionApplicability,
    MappingAuthorityLevel,
    MappingCompatibilityRecord,
    MappingControlScope,
    MappingGapRecord,
    MappingGapType,
    MappingGranularity,
    MappingHashRecord,
    MappingProvenance,
    MappingRelationship,
    MappingRelationshipType,
    MappingReviewStatus,
    MappingScope,
    MappingStatus,
    MappingValidationRecord,
    MappingValidationType,
)
from .validation import (
    _VALIDATOR_VERSION,
    REASON_COMPATIBILITY_INCOMPATIBLE,
    REASON_COMPATIBILITY_VERSION_MISMATCH,
    REASON_CYCLIC_INHERITANCE,
    REASON_DUPLICATE_RELATIONSHIP,
    REASON_FRAMEWORK_ID_MISMATCH,
    REASON_INVALID_CONFIDENCE_VALUE,
    REASON_MISSING_MAPPING_RATIONALE,
    REASON_MISSING_SOURCE_AUTHORITY,
    REASON_SCOPE_TENANT_MISMATCH,
    REASON_SELF_INHERITANCE,
    REASON_SELF_MAPPING,
    REASON_SELF_SUPERSESSION,
    REASON_TENANT_ISOLATION_VIOLATION,
    REASON_VERSION_TAG_EMPTY,
    detect_cyclic_inheritance,
    detect_missing_inheritance_targets,
    detect_orphaned_relationships,
    detect_unmapped_controls,
    validate_control_inheritance,
    validate_framework_mapping,
    validate_mapping_relationship,
    validate_mapping_version,
)

__all__ = [
    # Enumerations
    "MappingRelationshipType",
    "MappingStatus",
    "MappingScope",
    "MappingValidationType",
    "MappingGapType",
    "MappingAuthorityLevel",
    "MappingReviewStatus",
    "MappingGranularity",
    # Provenance and compatibility
    "MappingProvenance",
    "MappingCompatibilityRecord",
    # Jurisdiction, scope, and namespace types
    "JurisdictionApplicability",
    "MappingControlScope",
    "FrameworkNamespace",
    # Core mapping types
    "MappingRelationship",
    "ControlInheritance",
    "FrameworkMappingVersion",
    "FrameworkMapping",
    # Output types
    "MappingValidationRecord",
    "MappingHashRecord",
    "MappingGapRecord",
    "CrosswalkEntry",
    # Validation functions
    "validate_mapping_relationship",
    "validate_control_inheritance",
    "validate_framework_mapping",
    "validate_mapping_version",
    "detect_cyclic_inheritance",
    "detect_unmapped_controls",
    "detect_orphaned_relationships",
    "detect_missing_inheritance_targets",
    # Crosswalk functions
    "build_crosswalk",
    "find_control_mappings",
    "find_one_to_many_mappings",
    "find_many_to_one_mappings",
    # Hashing functions
    "compute_mapping_hash",
    "replay_mapping_hash",
    "verify_mapping_hash",
    # Reason codes
    "REASON_SELF_MAPPING",
    "REASON_TENANT_ISOLATION_VIOLATION",
    "REASON_MISSING_SOURCE_AUTHORITY",
    "REASON_MISSING_MAPPING_RATIONALE",
    "REASON_FRAMEWORK_ID_MISMATCH",
    "REASON_COMPATIBILITY_VERSION_MISMATCH",
    "REASON_COMPATIBILITY_INCOMPATIBLE",
    "REASON_INVALID_CONFIDENCE_VALUE",
    "REASON_SELF_INHERITANCE",
    "REASON_DUPLICATE_RELATIONSHIP",
    "REASON_SCOPE_TENANT_MISMATCH",
    "REASON_CYCLIC_INHERITANCE",
    "REASON_VERSION_TAG_EMPTY",
    "REASON_SELF_SUPERSESSION",
    # Version constant
    "_VALIDATOR_VERSION",
    # Well-known framework slug constants
    "FRAMEWORK_SLUG_NIST_AI_RMF",
    "FRAMEWORK_SLUG_ISO_42001",
    "FRAMEWORK_SLUG_SOC2_AI",
    "FRAMEWORK_SLUG_HIPAA_AI",
    "FRAMEWORK_SLUG_FROSTGATE",
]
