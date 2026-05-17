"""Enterprise Gap Analysis & Remediation Prioritization Engine — analysis engine.

Pure Python. No I/O. No SQLAlchemy. No LLMs. No randomness.

Caller loads all data into GapAnalysisInput; engine runs gap analysis
deterministically and returns a frozen GapAnalysisResult. The engine
never mutates its inputs.

Tenant isolation contract:
  - assessment.tenant_id must match results and evidence_refs tenant_ids.
  - Cross-tenant access raises GapAnalysisTenantIsolationError.
  - Engine validates this before any analysis.

Framework isolation contract:
  - All results and evidence_refs must reference controls from the declared
    framework. Cross-framework result contamination raises GapAnalysisError.

Input contract:
  - GapAnalysisInput.score_output is required — the engine consumes the
    already-computed ScoreOutput rather than rerunning scoring logic.
  - critical_control_ids and required_control_ids are sourced from the
    scoring contract metadata; caller must extract them before constructing input.
  - NOT_APPLICABLE controls must be excluded from controls tuple by the caller
    when they should not appear in gap detection (or pass them in and they are
    skipped because they will appear in score_output.not_applicable_controls).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from services.readiness.models import (
    Assessment,
    AssessmentResult,
    Control,
    Domain,
    EvidenceReference,
    Framework,
    MaturityTier,
)
from services.readiness.scoring.models import ScoreOutput

from .detection import (
    build_dependency_chains,
    build_maturity_blockers,
    build_readiness_blockers,
    detect_incomplete_assessment_gap,
    detect_missing_controls,
    detect_stale_evidence,
    detect_threshold_gaps,
    detect_weak_controls,
    stale_evidence_to_gaps,
)
from .models import (
    CompensatingControl,
    GapAnalysisResult,
    GapDependency,
    GapReplayContract,
    GovernanceOverride,
    PolicyException,
    ReadinessGap,
)
from .prioritization import (
    build_remediation_recommendations,
    estimate_readiness_impact,
    prioritize_gaps,
)

log = logging.getLogger("frostgate.readiness.gap_analysis.engine")

_ANALYSIS_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class GapAnalysisError(Exception):
    """Base class for gap analysis engine errors."""


class GapAnalysisTenantIsolationError(GapAnalysisError):
    """Results or evidence from a different tenant were loaded."""


class GapAnalysisFrameworkMismatchError(GapAnalysisError):
    """Results reference controls that do not belong to the declared framework."""


class GapAnalysisInputError(GapAnalysisError):
    """Invalid or inconsistent GapAnalysisInput configuration."""


# ---------------------------------------------------------------------------
# Input contract
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GapAnalysisInput:
    """All data required to run gap analysis. The engine performs no I/O.

    score_output: must be produced by ReadinessScoreEngine for the same
        assessment and framework.
    critical_control_ids: controls whose absence or failure is CRITICAL severity.
    required_control_ids: controls whose absence or failure is HIGH severity.
    default_freshness_window_days: default evidence freshness window (days).
        Per-evidence override via evidence_source_metadata["freshness_window_days"].
    gap_dependencies: external dependency declarations between gaps.
    policy_exceptions: active policy exceptions to annotate in output.
    compensating_controls: active compensating controls to annotate in output.
    governance_overrides: active governed overrides to apply during prioritization.
    scoring_contract_version / maturity_model_version / mapping_version /
    evidence_snapshot_version: version pins for replay contract.
    """

    assessment: Assessment
    framework: Framework
    controls: tuple[Control, ...]
    domains: tuple[Domain, ...]
    maturity_tiers: tuple[MaturityTier, ...]
    results: tuple[AssessmentResult, ...]
    evidence_refs: tuple[EvidenceReference, ...]
    score_output: ScoreOutput
    critical_control_ids: frozenset[str] = frozenset()
    required_control_ids: frozenset[str] = frozenset()
    default_freshness_window_days: int = 90
    gap_dependencies: tuple[GapDependency, ...] = ()
    policy_exceptions: tuple[PolicyException, ...] = ()
    compensating_controls: tuple[CompensatingControl, ...] = ()
    governance_overrides: tuple[GovernanceOverride, ...] = ()
    scoring_contract_version: Optional[str] = None
    maturity_model_version: Optional[str] = None
    mapping_version: Optional[str] = None
    evidence_snapshot_version: Optional[str] = None


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class GapAnalysisEngine:
    """Deterministic readiness gap analysis engine.

    Usage::

        engine = GapAnalysisEngine()
        result = engine.analyze(gap_analysis_input)

    The engine is stateless and thread-safe. A single instance may be reused
    across requests. All configuration comes from GapAnalysisInput.
    """

    def analyze(
        self,
        inp: GapAnalysisInput,
        *,
        result_id: str,
        analyzed_at: Optional[datetime] = None,
    ) -> GapAnalysisResult:
        """Run gap analysis. Returns a frozen GapAnalysisResult.

        Raises GapAnalysisError subclasses on invalid input.
        analyzed_at defaults to UTC now if not provided.
        """
        if analyzed_at is None:
            analyzed_at = datetime.now(tz=timezone.utc)

        self._validate(inp)

        tenant_id = inp.assessment.tenant_id
        framework_id = inp.framework.framework_id
        framework_version = inp.framework.framework_version
        so = inp.score_output

        # Set of controls whose outcome is NOT_APPLICABLE (excluded from gap detection)
        not_applicable_ids = frozenset(so.not_applicable_controls)
        # Set of controls that have been evaluated (any outcome except NOT_EVALUATED)
        evaluated_ids = frozenset(
            cid for cid, cs in so.control_scores.items() if cs.is_evaluated
        )
        # Controls applicable to this assessment (not N/A)
        applicable_controls = tuple(
            c for c in inp.controls if c.control_id not in not_applicable_ids
        )
        control_scores = tuple(so.control_scores.values())
        domain_scores = tuple(so.domain_scores.values())

        # ---------------------------------------------------------------------------
        # 1. Detect missing controls
        # ---------------------------------------------------------------------------
        missing_gaps = detect_missing_controls(
            applicable_controls,
            evaluated_ids,
            critical_control_ids=inp.critical_control_ids,
            required_control_ids=inp.required_control_ids,
            framework_id=framework_id,
            framework_version=framework_version,
            tenant_id=tenant_id,
            detected_at=analyzed_at,
        )

        # ---------------------------------------------------------------------------
        # 2. Detect weak / failed controls
        # ---------------------------------------------------------------------------
        weak_gaps = detect_weak_controls(
            control_scores,
            weak_threshold=50.0,
            required_control_ids=inp.required_control_ids,
            critical_control_ids=inp.critical_control_ids,
            framework_id=framework_id,
            framework_version=framework_version,
            tenant_id=tenant_id,
            detected_at=analyzed_at,
        )

        # ---------------------------------------------------------------------------
        # 3. Detect stale evidence
        # ---------------------------------------------------------------------------
        freshness_records = detect_stale_evidence(
            inp.evidence_refs,
            default_freshness_window_days=inp.default_freshness_window_days,
            framework_id=framework_id,
            framework_version=framework_version,
            as_of=analyzed_at,
            tenant_id=tenant_id,
        )
        stale_gaps = stale_evidence_to_gaps(
            freshness_records,
            required_control_ids=inp.required_control_ids,
            detected_at=analyzed_at,
        )

        # ---------------------------------------------------------------------------
        # 4. Detect threshold failures (from score output)
        # ---------------------------------------------------------------------------
        threshold_gaps = detect_threshold_gaps(
            so.threshold_failures,
            domain_scores,
            framework_id=framework_id,
            framework_version=framework_version,
            tenant_id=tenant_id,
            detected_at=analyzed_at,
        )

        # ---------------------------------------------------------------------------
        # 5. Detect incomplete assessment
        # ---------------------------------------------------------------------------
        incomplete_gap = detect_incomplete_assessment_gap(
            so.completion_percentage,
            framework_id=framework_id,
            framework_version=framework_version,
            tenant_id=tenant_id,
            assessment_id=inp.assessment.assessment_id,
            detected_at=analyzed_at,
        )

        # ---------------------------------------------------------------------------
        # 6. Merge and deduplicate gaps (by gap_id)
        # ---------------------------------------------------------------------------
        all_gaps_dict: dict[str, ReadinessGap] = {}
        for gap in (
            *missing_gaps,
            *weak_gaps,
            *stale_gaps,
            *threshold_gaps,
        ):
            if gap.gap_id not in all_gaps_dict:
                all_gaps_dict[gap.gap_id] = gap
        if incomplete_gap is not None and incomplete_gap.gap_id not in all_gaps_dict:
            all_gaps_dict[incomplete_gap.gap_id] = incomplete_gap

        all_gaps_raw = tuple(all_gaps_dict.values())

        # ---------------------------------------------------------------------------
        # 7. Prioritize gaps (apply overrides)
        # ---------------------------------------------------------------------------
        prioritized_gaps = prioritize_gaps(all_gaps_raw, inp.governance_overrides)

        # ---------------------------------------------------------------------------
        # 8. Build blockers
        # ---------------------------------------------------------------------------
        readiness_blockers = build_readiness_blockers(
            prioritized_gaps, tenant_id=tenant_id
        )
        # Use the first maturity tier as the current target (if any gaps are maturity blockers)
        current_tier_id = so.maturity_tier_id
        maturity_blockers = build_maturity_blockers(
            prioritized_gaps, current_tier_id, tenant_id=tenant_id
        )

        # ---------------------------------------------------------------------------
        # 9. Build dependency chains
        # ---------------------------------------------------------------------------
        gap_ids_set = frozenset(g.gap_id for g in prioritized_gaps)
        dependency_chains = build_dependency_chains(gap_ids_set, inp.gap_dependencies)

        # ---------------------------------------------------------------------------
        # 10. Estimate readiness impact
        # ---------------------------------------------------------------------------
        total_control_count = len(applicable_controls)
        impact_estimates = tuple(
            estimate_readiness_impact(
                gap,
                control_scores,
                domain_scores,
                total_control_count=total_control_count,
            )
            for gap in prioritized_gaps
        )

        # ---------------------------------------------------------------------------
        # 11. Build remediation recommendations
        # ---------------------------------------------------------------------------
        recommendations = build_remediation_recommendations(
            prioritized_gaps,
            dependency_chains,
            impact_estimates,
            readiness_blockers,
            maturity_blockers,
            inp.compensating_controls,
            inp.policy_exceptions,
        )

        # ---------------------------------------------------------------------------
        # 12. Build replay contract
        # ---------------------------------------------------------------------------
        replay_contract = GapReplayContract(
            contract_id=f"replay::{result_id}",
            result_id=result_id,
            framework_version=framework_version,
            analysis_version=_ANALYSIS_VERSION,
            scoring_contract_version=inp.scoring_contract_version,
            maturity_model_version=inp.maturity_model_version,
            mapping_version=inp.mapping_version,
            evidence_snapshot_version=inp.evidence_snapshot_version,
        )

        return GapAnalysisResult(
            result_id=result_id,
            framework_id=framework_id,
            framework_version=framework_version,
            analysis_version=_ANALYSIS_VERSION,
            analyzed_at=analyzed_at,
            gaps=prioritized_gaps,
            readiness_blockers=readiness_blockers,
            maturity_blockers=maturity_blockers,
            dependency_chains=dependency_chains,
            remediation_recommendations=recommendations,
            impact_estimates=impact_estimates,
            policy_exceptions=inp.policy_exceptions,
            compensating_controls=inp.compensating_controls,
            governance_overrides=inp.governance_overrides,
            evidence_freshness_records=freshness_records,
            replay_contract=replay_contract,
            assessment_id=inp.assessment.assessment_id,
            tenant_id=tenant_id,
            scoring_contract_version=inp.scoring_contract_version,
            maturity_model_version=inp.maturity_model_version,
            mapping_version=inp.mapping_version,
            evidence_snapshot_version=inp.evidence_snapshot_version,
        )

    # ---------------------------------------------------------------------------
    # Validation
    # ---------------------------------------------------------------------------

    def _validate(self, inp: GapAnalysisInput) -> None:
        """Validate tenant isolation and framework consistency. Fail-closed."""
        tenant_id = inp.assessment.tenant_id

        # Tenant isolation: all results must match assessment.tenant_id
        for result in inp.results:
            if result.tenant_id != tenant_id:
                raise GapAnalysisTenantIsolationError(
                    f"AssessmentResult {result.result_id!r} has tenant_id"
                    f" {result.tenant_id!r} but assessment tenant is {tenant_id!r}."
                )

        # Tenant isolation: all evidence refs must match
        for ref in inp.evidence_refs:
            if ref.tenant_id != tenant_id:
                raise GapAnalysisTenantIsolationError(
                    f"EvidenceReference {ref.evidence_id!r} has tenant_id"
                    f" {ref.tenant_id!r} but assessment tenant is {tenant_id!r}."
                )

        # Score output tenant isolation
        if inp.score_output.tenant_id != tenant_id:
            raise GapAnalysisTenantIsolationError(
                f"ScoreOutput tenant_id {inp.score_output.tenant_id!r} does not"
                f" match assessment tenant_id {tenant_id!r}."
            )

        # Framework consistency
        framework_id = inp.framework.framework_id
        if inp.score_output.framework_id != framework_id:
            raise GapAnalysisFrameworkMismatchError(
                f"ScoreOutput framework_id {inp.score_output.framework_id!r} does"
                f" not match declared framework_id {framework_id!r}."
            )

        # Freshness window must be positive
        if inp.default_freshness_window_days <= 0:
            raise GapAnalysisInputError(
                f"default_freshness_window_days must be > 0;"
                f" got {inp.default_freshness_window_days}."
            )
