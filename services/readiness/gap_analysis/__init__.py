"""Enterprise Gap Analysis & Remediation Prioritization Engine.

Public API surface — all stable exports from this package.

Consumers import from this package, not from submodules, to allow
internal refactoring without breaking callers.
"""

from .detection import (
    build_dependency_chains,
    build_maturity_blockers,
    build_readiness_blockers,
    detect_cycles_in_dependencies,
    detect_incomplete_assessment_gap,
    detect_missing_controls,
    detect_stale_evidence,
    detect_threshold_gaps,
    detect_weak_controls,
    gap_sort_key,
    stale_evidence_to_gaps,
)
from .engine import (
    _ANALYSIS_VERSION,
    GapAnalysisEngine,
    GapAnalysisError,
    GapAnalysisFrameworkMismatchError,
    GapAnalysisInput,
    GapAnalysisInputError,
    GapAnalysisTenantIsolationError,
)
from .hashing import (
    compute_gap_analysis_hash,
    replay_gap_analysis_hash,
    verify_gap_analysis_hash,
)
from .models import (
    CompensatingControl,
    DependencyChain,
    EvidenceFreshnessRecord,
    ExceptionType,
    GapAnalysisResult,
    GapClassification,
    GapDependency,
    GapDependencyType,
    GapReplayContract,
    GapSeverity,
    GovernanceOverride,
    MaturityBlocker,
    OverrideType,
    PolicyException,
    ReadinessBlocker,
    ReadinessGap,
    ReadinessImpactEstimate,
    RemediationIntegrityRecord,
    RemediationRecommendation,
)
from .prioritization import (
    build_remediation_recommendations,
    estimate_readiness_impact,
    prioritize_gaps,
)

__all__ = [
    # Enumerations
    "GapSeverity",
    "GapClassification",
    "GapDependencyType",
    "ExceptionType",
    "OverrideType",
    # Core gap models
    "ReadinessGap",
    "EvidenceFreshnessRecord",
    "GapDependency",
    "DependencyChain",
    "ReadinessBlocker",
    "MaturityBlocker",
    "ReadinessImpactEstimate",
    "RemediationRecommendation",
    "PolicyException",
    "CompensatingControl",
    "GovernanceOverride",
    "RemediationIntegrityRecord",
    "GapReplayContract",
    "GapAnalysisResult",
    # Engine
    "GapAnalysisEngine",
    "GapAnalysisInput",
    "GapAnalysisError",
    "GapAnalysisTenantIsolationError",
    "GapAnalysisFrameworkMismatchError",
    "GapAnalysisInputError",
    # Detection functions
    "detect_missing_controls",
    "detect_weak_controls",
    "detect_stale_evidence",
    "stale_evidence_to_gaps",
    "detect_threshold_gaps",
    "detect_incomplete_assessment_gap",
    "detect_cycles_in_dependencies",
    "build_dependency_chains",
    "build_readiness_blockers",
    "build_maturity_blockers",
    "gap_sort_key",
    # Prioritization functions
    "prioritize_gaps",
    "estimate_readiness_impact",
    "build_remediation_recommendations",
    # Hashing functions
    "compute_gap_analysis_hash",
    "replay_gap_analysis_hash",
    "verify_gap_analysis_hash",
    # Version constant
    "_ANALYSIS_VERSION",
]
