"""Enterprise Gap Analysis & Remediation Prioritization Engine — prioritization.

All functions are:
  - Pure Python. No I/O. No side effects. No randomness.
  - Deterministic: identical inputs → identical priority ordering.
  - Explainable: priority classification includes rationale metadata.
  - Override-aware: GovernanceOverride modifies effective values without
    mutating the original calculated output.

Prioritization contract:
  - Gaps are ordered by (effective_severity DESC, classification_rank DESC, gap_id ASC).
  - GovernanceOverride.SEVERITY overrides the effective_severity used for ordering
    but does NOT mutate gap.gap_severity.
  - CompensatingControl records reduce estimated_readiness_impact in recommendations
    but do NOT suppress the original gap record or its lineage.
  - PolicyException records annotate recommendations but do NOT suppress gaps.

Remediation classification contract:
  - Classification strings are stable identifiers, not narrative prose.
  - Mapping: MISSING_CONTROL → "address_missing_control",
             FAILED_CONTROL  → "resolve_failed_control",
             PARTIALLY_IMPLEMENTED → "improve_partial_implementation",
             WEAK_CONTROL → "strengthen_weak_control",
             STALE_EVIDENCE → "refresh_stale_evidence",
             INCOMPLETE_ASSESSMENT → "complete_assessment",
             MISSING_REQUIRED_EVIDENCE → "provide_required_evidence",
             FAILED_MATURITY_GATE → "resolve_maturity_gate",
             FAILED_READINESS_THRESHOLD → "resolve_readiness_threshold",
             FAILED_PREREQUISITE_CONTROL → "resolve_prerequisite_control",
             (all others) → "resolve_governance_gap".
"""

from __future__ import annotations

from services.readiness.scoring.models import ControlScore, DomainScore

from .detection import _CLASSIFICATION_RANK, _SEVERITY_RANK
from .models import (
    CompensatingControl,
    DependencyChain,
    GapClassification,
    GapSeverity,
    GovernanceOverride,
    MaturityBlocker,
    OverrideType,
    PolicyException,
    ReadinessBlocker,
    ReadinessGap,
    ReadinessImpactEstimate,
    RemediationRecommendation,
)

# ---------------------------------------------------------------------------
# Remediation classification mapping
# ---------------------------------------------------------------------------

_REMEDIATION_CLASSIFICATION: dict[GapClassification, str] = {
    GapClassification.MISSING_CONTROL: "address_missing_control",
    GapClassification.FAILED_CONTROL: "resolve_failed_control",
    GapClassification.PARTIALLY_IMPLEMENTED: "improve_partial_implementation",
    GapClassification.WEAK_CONTROL: "strengthen_weak_control",
    GapClassification.STALE_EVIDENCE: "refresh_stale_evidence",
    GapClassification.INCOMPLETE_ASSESSMENT: "complete_assessment",
    GapClassification.MISSING_REQUIRED_EVIDENCE: "provide_required_evidence",
    GapClassification.FAILED_MATURITY_GATE: "resolve_maturity_gate",
    GapClassification.FAILED_READINESS_THRESHOLD: "resolve_readiness_threshold",
    GapClassification.FAILED_PREREQUISITE_CONTROL: "resolve_prerequisite_control",
    GapClassification.MISSING_FRAMEWORK_MAPPING: "resolve_governance_gap",
    GapClassification.UNSUPPORTED_GOVERNANCE_COVERAGE: "resolve_governance_gap",
    GapClassification.MISSING_DEPENDENCY_CHAIN: "resolve_governance_gap",
    GapClassification.UNSUPPORTED_OPERATIONAL_GOVERNANCE: "resolve_governance_gap",
    GapClassification.UNSUPPORTED_RUNTIME_GOVERNANCE: "resolve_governance_gap",
    GapClassification.UNSUPPORTED_PROVENANCE_ENFORCEMENT: "resolve_governance_gap",
}


# ---------------------------------------------------------------------------
# Override application
# ---------------------------------------------------------------------------


def _effective_severity(
    gap: ReadinessGap,
    overrides: tuple[GovernanceOverride, ...],
) -> GapSeverity:
    """Return the effective GapSeverity for a gap, considering active overrides.

    An override with type=SEVERITY for this gap_id overrides the effective severity.
    The original gap.gap_severity is NOT mutated. The most recent override (by
    approved_at DESC, then override_id ASC for tie-breaking) wins.
    """
    severity_overrides = [
        o
        for o in overrides
        if o.gap_id == gap.gap_id and o.override_type == OverrideType.SEVERITY
    ]
    if not severity_overrides:
        return gap.gap_severity
    # Most recent override wins; tie-break by override_id for determinism
    winning = sorted(
        severity_overrides,
        key=lambda o: (-o.approved_at.timestamp(), o.override_id),
    )[0]
    try:
        return GapSeverity(winning.overridden_value)
    except ValueError:
        return gap.gap_severity


def _priority_sort_key_with_overrides(
    gap: ReadinessGap,
    overrides: tuple[GovernanceOverride, ...],
) -> tuple[int, int, str]:
    """Deterministic sort key applying severity overrides.

    (effective_severity DESC, classification_rank DESC, gap_id ASC)
    """
    effective = _effective_severity(gap, overrides)
    return (
        -_SEVERITY_RANK.get(effective, 0),
        -_CLASSIFICATION_RANK.get(gap.gap_classification, 0),
        gap.gap_id,
    )


# ---------------------------------------------------------------------------
# Gap prioritization
# ---------------------------------------------------------------------------


def prioritize_gaps(
    gaps: tuple[ReadinessGap, ...],
    overrides: tuple[GovernanceOverride, ...] = (),
) -> tuple[ReadinessGap, ...]:
    """Return gaps ordered by deterministic priority with override support.

    Ordering: (effective_severity DESC, classification_rank DESC, gap_id ASC).
    GovernanceOverride.SEVERITY adjusts effective ordering without mutating gaps.
    Original gaps are returned unmodified — no field mutation occurs.
    """
    return tuple(
        sorted(
            gaps,
            key=lambda g: _priority_sort_key_with_overrides(g, overrides),
        )
    )


# ---------------------------------------------------------------------------
# Impact estimation
# ---------------------------------------------------------------------------


def estimate_readiness_impact(
    gap: ReadinessGap,
    control_scores: tuple[ControlScore, ...],
    domain_scores: tuple[DomainScore, ...],
    *,
    total_control_count: int,
) -> ReadinessImpactEstimate:
    """Estimate the readiness impact of resolving a single gap.

    All impact values are in [0.0, 1.0] and represent estimated fractional
    improvement if the gap were fully resolved.

    framework_impact: estimated overall score improvement fraction.
      = (affected_control_weight / total_weight) * potential_score_gain / 100.0
    domain_impact: per-domain estimated improvement fraction.
    maturity_impact: 1.0 if gap is maturity blocker, 0.0 otherwise.
    governance_coverage_impact: estimated coverage improvement fraction.
    remediation_impact: composite (average of non-zero impacts).

    Estimate ID: "est::{gap.gap_id}".
    """
    affected_ids = frozenset(gap.affected_control_ids)

    # Framework impact: proportional to affected control weight vs total
    affected_scores = [cs for cs in control_scores if cs.control_id in affected_ids]
    all_weights = sum(cs.weight for cs in control_scores if cs.is_applicable)
    # Potential score gain = (100 - current_raw) per affected control
    potential_gain = sum(
        max(0.0, 100.0 - cs.raw_score) * cs.weight
        for cs in affected_scores
        if cs.is_applicable
    )
    framework_impact = (
        (potential_gain / (all_weights * 100.0)) if all_weights > 0.0 else 0.0
    )
    framework_impact = min(framework_impact, 1.0)

    # Domain impact
    domain_impact_dict: dict[str, float] = {}
    for ds in domain_scores:
        domain_ctl_scores = [
            cs for cs in affected_scores if cs.domain_id == ds.domain_id
        ]
        if not domain_ctl_scores:
            continue
        domain_total_weight = sum(
            cs.weight
            for cs in control_scores
            if cs.domain_id == ds.domain_id and cs.is_applicable
        )
        if domain_total_weight > 0.0:
            domain_potential = sum(
                max(0.0, 100.0 - cs.raw_score) * cs.weight
                for cs in domain_ctl_scores
                if cs.is_applicable
            )
            domain_impact_dict[ds.domain_id] = min(
                domain_potential / (domain_total_weight * 100.0), 1.0
            )

    maturity_impact = 1.0 if gap.is_maturity_blocker else 0.0

    # Coverage impact: each missing/failed control improves coverage proportionally
    governance_coverage_impact = (
        min(len(affected_ids) / max(total_control_count, 1), 1.0)
        if gap.gap_classification
        in (
            GapClassification.MISSING_CONTROL,
            GapClassification.FAILED_CONTROL,
        )
        else framework_impact * 0.5
    )

    non_zero = [
        v
        for v in [framework_impact, maturity_impact, governance_coverage_impact]
        if v > 0.0
    ]
    remediation_impact = (sum(non_zero) / len(non_zero)) if non_zero else 0.0

    return ReadinessImpactEstimate(
        estimate_id=f"est::{gap.gap_id}",
        gap_id=gap.gap_id,
        maturity_impact=round(maturity_impact, 6),
        framework_impact=round(framework_impact, 6),
        remediation_impact=round(remediation_impact, 6),
        governance_coverage_impact=round(governance_coverage_impact, 6),
        domain_impact={k: round(v, 6) for k, v in domain_impact_dict.items()},
        estimation_rationale=(
            f"Gap classification={gap.gap_classification.value},"
            f" affected_controls={len(affected_ids)},"
            f" framework_impact={framework_impact:.4f}."
        ),
    )


# ---------------------------------------------------------------------------
# Remediation recommendation builder
# ---------------------------------------------------------------------------


def build_remediation_recommendations(
    gaps: tuple[ReadinessGap, ...],
    dependency_chains: tuple[DependencyChain, ...],
    impact_estimates: tuple[ReadinessImpactEstimate, ...],
    readiness_blockers: tuple[ReadinessBlocker, ...],
    maturity_blockers: tuple[MaturityBlocker, ...],
    compensating_controls: tuple[CompensatingControl, ...],
    policy_exceptions: tuple[PolicyException, ...],
) -> tuple[RemediationRecommendation, ...]:
    """Build a structured RemediationRecommendation for each gap.

    Recommendations are deterministic — no narrative generation, no AI inference.
    CompensatingControls reduce estimated_readiness_impact by 50%.
    PolicyExceptions annotate the recommendation but do NOT suppress it.
    Dependency IDs reference GapDependency.dependency_id; the caller must
    ensure those IDs are consistent.

    Recommendation ID: "rec::{gap.gap_id}".
    """
    # Build fast lookups
    impact_by_gap: dict[str, ReadinessImpactEstimate] = {
        e.gap_id: e for e in impact_estimates
    }
    chain_by_gap: dict[str, DependencyChain] = {}
    for chain in dependency_chains:
        for gid in chain.ordered_gap_ids:
            chain_by_gap[gid] = chain

    blocker_ids_by_gap: dict[str, list[str]] = {}
    for b in readiness_blockers:
        blocker_ids_by_gap.setdefault(b.gap_id, []).append(b.blocker_id)
    for mb in maturity_blockers:
        blocker_ids_by_gap.setdefault(mb.gap_id, []).append(mb.blocker_id)

    comp_ids_by_gap: dict[str, list[str]] = {}
    for cc in compensating_controls:
        comp_ids_by_gap.setdefault(cc.gap_id, []).append(cc.compensating_id)

    exception_control_ids: frozenset[str] = frozenset(
        cid for exc in policy_exceptions for cid in exc.affected_control_ids
    )

    recommendations: list[RemediationRecommendation] = []
    for gap in gaps:
        estimate = impact_by_gap.get(gap.gap_id)
        raw_impact = estimate.remediation_impact if estimate else 0.0

        # CompensatingControl reduces but does NOT eliminate the impact
        has_compensating = bool(comp_ids_by_gap.get(gap.gap_id))
        effective_impact = raw_impact * 0.5 if has_compensating else raw_impact

        remediation_classification = _REMEDIATION_CLASSIFICATION.get(
            gap.gap_classification, "resolve_governance_gap"
        )

        # Dependency IDs from chain (gap_ids preceding this one in the chain)
        gap_chain = chain_by_gap.get(gap.gap_id)
        dependency_ids: tuple[str, ...] = ()
        if gap_chain and not gap_chain.has_cycle:
            idx = (
                list(gap_chain.ordered_gap_ids).index(gap.gap_id)
                if gap.gap_id in gap_chain.ordered_gap_ids
                else -1
            )
            if idx > 0:
                # prerequisites come before this gap in ordered list
                dependency_ids = gap_chain.ordered_gap_ids[:idx]

        has_exception = bool(
            exception_control_ids & frozenset(gap.affected_control_ids)
        )

        maturity_implications = (
            "Resolving this gap is required for maturity tier eligibility."
            if gap.is_maturity_blocker
            else "No direct maturity tier implication."
        )
        governance_rationale = (
            f"Gap classification {gap.gap_classification.value} detected at severity"
            f" {gap.gap_severity.value}."
            + (" Policy exception on record." if has_exception else "")
            + (
                " Compensating control active; residual risk remains."
                if has_compensating
                else ""
            )
        )

        domain_ids: tuple[str, ...] = (gap.domain_id,) if gap.domain_id else ()

        recommendations.append(
            RemediationRecommendation(
                recommendation_id=f"rec::{gap.gap_id}",
                gap_id=gap.gap_id,
                remediation_classification=remediation_classification,
                remediation_rationale=gap.gap_rationale,
                affected_control_ids=gap.affected_control_ids,
                affected_domain_ids=domain_ids,
                affected_framework_ids=gap.affected_framework_ids,
                estimated_readiness_impact=round(effective_impact, 6),
                maturity_implications=maturity_implications,
                governance_rationale=governance_rationale,
                dependency_ids=dependency_ids,
                blocker_ids=tuple(sorted(blocker_ids_by_gap.get(gap.gap_id, []))),
                compensating_control_ids=tuple(
                    sorted(comp_ids_by_gap.get(gap.gap_id, []))
                ),
            )
        )

    # Sort deterministically: impact DESC, gap_id ASC
    return tuple(
        sorted(
            recommendations,
            key=lambda r: (-r.estimated_readiness_impact, r.gap_id),
        )
    )
