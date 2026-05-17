"""Enterprise Gap Analysis & Remediation Prioritization Engine — gap detection.

All functions are:
  - Pure Python. No I/O. No side effects. No randomness.
  - Deterministic: identical inputs → identical detection outputs.
  - Fail-closed: gaps are never silently suppressed.
  - Framework-version aware: all detection is scoped to (framework_id, version).
  - Tenant-safe: detection does not cross tenant boundaries.

Detection coverage:
  - Missing controls: controls with no AssessmentResult.
  - Weak controls: controls with low scores or partial compliance.
  - Failed controls: controls with NON_COMPLIANT outcome.
  - Stale evidence: evidence past its freshness window.
  - Failed maturity gates: threshold failures from scoring output.
  - Failed readiness thresholds: overall score below contract threshold.
  - Incomplete assessments: completion < 100% of applicable controls.
  - Dependency cycles: DFS-based cycle detection on GapDependency graph.

Gap ID contract:
  - Gap IDs are deterministic: {framework_id}::{control_id or evidence_id}::{classification}
  - Freshness record IDs are deterministic: {framework_id}::{evidence_id}::freshness
  - Blocker IDs: blocker::{gap_id}
  - Maturity blocker IDs: matblocker::{gap_id}::{tier_id}
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from services.readiness.models import AssessmentOutcome, Control, EvidenceReference
from services.readiness.scoring.models import (
    ControlScore,
    DomainScore,
    ThresholdFailure,
)

from .models import (
    DependencyChain,
    EvidenceFreshnessRecord,
    GapClassification,
    GapDependency,
    GapSeverity,
    MaturityBlocker,
    ReadinessBlocker,
    ReadinessGap,
)

# ---------------------------------------------------------------------------
# Severity ranking (used by prioritization)
# ---------------------------------------------------------------------------

_SEVERITY_RANK: dict[GapSeverity, int] = {
    GapSeverity.BLOCKING: 5,
    GapSeverity.CRITICAL: 4,
    GapSeverity.HIGH: 3,
    GapSeverity.MODERATE: 2,
    GapSeverity.LOW: 1,
    GapSeverity.INFORMATIONAL: 0,
}

_CLASSIFICATION_RANK: dict[GapClassification, int] = {
    GapClassification.MISSING_CONTROL: 9,
    GapClassification.FAILED_CONTROL: 8,
    GapClassification.FAILED_MATURITY_GATE: 7,
    GapClassification.FAILED_READINESS_THRESHOLD: 7,
    GapClassification.MISSING_REQUIRED_EVIDENCE: 6,
    GapClassification.FAILED_PREREQUISITE_CONTROL: 5,
    GapClassification.INCOMPLETE_ASSESSMENT: 4,
    GapClassification.STALE_EVIDENCE: 3,
    GapClassification.WEAK_CONTROL: 2,
    GapClassification.PARTIALLY_IMPLEMENTED: 2,
    GapClassification.MISSING_FRAMEWORK_MAPPING: 1,
    GapClassification.UNSUPPORTED_GOVERNANCE_COVERAGE: 1,
    GapClassification.MISSING_DEPENDENCY_CHAIN: 1,
    GapClassification.UNSUPPORTED_OPERATIONAL_GOVERNANCE: 1,
    GapClassification.UNSUPPORTED_RUNTIME_GOVERNANCE: 1,
    GapClassification.UNSUPPORTED_PROVENANCE_ENFORCEMENT: 1,
}


def gap_sort_key(gap: ReadinessGap) -> tuple[int, int, str]:
    """Deterministic sort key: (severity DESC, classification rank DESC, gap_id ASC)."""
    return (
        -_SEVERITY_RANK.get(gap.gap_severity, 0),
        -_CLASSIFICATION_RANK.get(gap.gap_classification, 0),
        gap.gap_id,
    )


# ---------------------------------------------------------------------------
# Missing control detection
# ---------------------------------------------------------------------------


def detect_missing_controls(
    controls: tuple[Control, ...],
    evaluated_control_ids: frozenset[str],
    *,
    critical_control_ids: frozenset[str],
    required_control_ids: frozenset[str],
    framework_id: str,
    framework_version: str,
    tenant_id: Optional[str],
    detected_at: datetime,
) -> tuple[ReadinessGap, ...]:
    """Detect controls that have no assessment result.

    critical_control_ids: controls whose absence is CRITICAL/BLOCKING.
    required_control_ids: controls whose absence is HIGH.
    Other missing controls: MODERATE.

    A control is 'missing' if it is not in evaluated_control_ids.
    NOT_APPLICABLE controls are excluded — the caller must not include them.
    """
    gaps: list[ReadinessGap] = []
    for ctrl in controls:
        if ctrl.control_id in evaluated_control_ids:
            continue
        if ctrl.control_id in critical_control_ids:
            severity = GapSeverity.CRITICAL
            is_blocker = True
            is_maturity_blocker = True
        elif ctrl.control_id in required_control_ids:
            severity = GapSeverity.HIGH
            is_blocker = True
            is_maturity_blocker = True
        else:
            severity = GapSeverity.MODERATE
            is_blocker = False
            is_maturity_blocker = False

        gaps.append(
            ReadinessGap(
                gap_id=f"{framework_id}::{ctrl.control_id}::missing_control",
                gap_classification=GapClassification.MISSING_CONTROL,
                gap_severity=severity,
                framework_id=framework_id,
                framework_version=framework_version,
                gap_rationale=f"Control {ctrl.control_identifier!r} has no assessment result.",
                detected_at=detected_at,
                is_blocker=is_blocker,
                is_maturity_blocker=is_maturity_blocker,
                affected_control_ids=(ctrl.control_id,),
                affected_framework_ids=(framework_id,),
                evidence_ids=(),
                control_id=ctrl.control_id,
                domain_id=ctrl.domain_id,
                tenant_id=tenant_id,
            )
        )
    return tuple(sorted(gaps, key=gap_sort_key))


# ---------------------------------------------------------------------------
# Weak and failed control detection
# ---------------------------------------------------------------------------


def detect_weak_controls(
    control_scores: tuple[ControlScore, ...],
    *,
    weak_threshold: float,
    required_control_ids: frozenset[str],
    critical_control_ids: frozenset[str],
    framework_id: str,
    framework_version: str,
    tenant_id: Optional[str],
    detected_at: datetime,
) -> tuple[ReadinessGap, ...]:
    """Detect controls with low scores, partial compliance, or non-compliance.

    NON_COMPLIANT → FAILED_CONTROL gap (HIGH or CRITICAL based on criticality).
    PARTIALLY_COMPLIANT → PARTIALLY_IMPLEMENTED gap (MODERATE).
    raw_score < weak_threshold (and applicable, evaluated) → WEAK_CONTROL (LOW).
    """
    gaps: list[ReadinessGap] = []
    for cs in control_scores:
        if not cs.is_applicable:
            continue
        if not cs.is_evaluated:
            continue

        if cs.outcome == AssessmentOutcome.NON_COMPLIANT:
            if cs.control_id in critical_control_ids:
                severity = GapSeverity.CRITICAL
                is_blocker = True
                is_maturity_blocker = True
            elif cs.control_id in required_control_ids:
                severity = GapSeverity.HIGH
                is_blocker = True
                is_maturity_blocker = True
            else:
                severity = GapSeverity.HIGH
                is_blocker = False
                is_maturity_blocker = False

            gaps.append(
                ReadinessGap(
                    gap_id=f"{framework_id}::{cs.control_id}::failed_control",
                    gap_classification=GapClassification.FAILED_CONTROL,
                    gap_severity=severity,
                    framework_id=framework_id,
                    framework_version=framework_version,
                    gap_rationale=(
                        f"Control {cs.control_identifier!r} is non-compliant"
                        f" (score={cs.raw_score:.1f})."
                    ),
                    detected_at=detected_at,
                    is_blocker=is_blocker,
                    is_maturity_blocker=is_maturity_blocker,
                    affected_control_ids=(cs.control_id,),
                    affected_framework_ids=(framework_id,),
                    evidence_ids=(),
                    control_id=cs.control_id,
                    domain_id=cs.domain_id,
                    tenant_id=tenant_id,
                )
            )
        elif cs.outcome == AssessmentOutcome.PARTIALLY_COMPLIANT:
            gaps.append(
                ReadinessGap(
                    gap_id=f"{framework_id}::{cs.control_id}::partially_implemented",
                    gap_classification=GapClassification.PARTIALLY_IMPLEMENTED,
                    gap_severity=GapSeverity.MODERATE,
                    framework_id=framework_id,
                    framework_version=framework_version,
                    gap_rationale=(
                        f"Control {cs.control_identifier!r} is partially implemented"
                        f" (score={cs.raw_score:.1f})."
                    ),
                    detected_at=detected_at,
                    is_blocker=False,
                    is_maturity_blocker=False,
                    affected_control_ids=(cs.control_id,),
                    affected_framework_ids=(framework_id,),
                    evidence_ids=(),
                    control_id=cs.control_id,
                    domain_id=cs.domain_id,
                    tenant_id=tenant_id,
                )
            )
        elif cs.is_evaluated and cs.raw_score < weak_threshold:
            gaps.append(
                ReadinessGap(
                    gap_id=f"{framework_id}::{cs.control_id}::weak_control",
                    gap_classification=GapClassification.WEAK_CONTROL,
                    gap_severity=GapSeverity.LOW,
                    framework_id=framework_id,
                    framework_version=framework_version,
                    gap_rationale=(
                        f"Control {cs.control_identifier!r} score {cs.raw_score:.1f}"
                        f" is below weak threshold {weak_threshold:.1f}."
                    ),
                    detected_at=detected_at,
                    is_blocker=False,
                    is_maturity_blocker=False,
                    affected_control_ids=(cs.control_id,),
                    affected_framework_ids=(framework_id,),
                    evidence_ids=(),
                    control_id=cs.control_id,
                    domain_id=cs.domain_id,
                    tenant_id=tenant_id,
                )
            )

    return tuple(sorted(gaps, key=gap_sort_key))


# ---------------------------------------------------------------------------
# Stale evidence detection
# ---------------------------------------------------------------------------


def detect_stale_evidence(
    evidence_refs: tuple[EvidenceReference, ...],
    *,
    default_freshness_window_days: int,
    framework_id: str,
    framework_version: str,
    as_of: datetime,
    tenant_id: Optional[str],
) -> tuple[EvidenceFreshnessRecord, ...]:
    """Evaluate evidence freshness for all evidence references.

    Returns an EvidenceFreshnessRecord for every evidence_ref, whether stale or not.
    Staleness is determined by: (as_of - submitted_at).days > freshness_window_days.

    Per-evidence freshness window override: if evidence_ref.evidence_source_metadata
    contains "freshness_window_days" (int), that value overrides the default.
    """
    records: list[EvidenceFreshnessRecord] = []
    for ref in evidence_refs:
        submitted = ref.submitted_at
        window_days = int(
            ref.evidence_source_metadata.get(
                "freshness_window_days", default_freshness_window_days
            )
        )
        age_days = (as_of - submitted).days
        is_stale = age_days > window_days
        staleness_days = (age_days - window_days) if is_stale else None

        control_id = ref.control_ids[0] if ref.control_ids else None

        records.append(
            EvidenceFreshnessRecord(
                freshness_id=f"{framework_id}::{ref.evidence_id}::freshness",
                evidence_id=ref.evidence_id,
                control_id=control_id,
                framework_id=framework_id,
                framework_version=framework_version,
                submitted_at=submitted,
                freshness_window_days=window_days,
                is_stale=is_stale,
                staleness_days=staleness_days,
                evaluated_at=as_of,
                tenant_id=tenant_id,
            )
        )

    return tuple(sorted(records, key=lambda r: r.freshness_id))


def stale_evidence_to_gaps(
    freshness_records: tuple[EvidenceFreshnessRecord, ...],
    *,
    required_control_ids: frozenset[str],
    detected_at: datetime,
) -> tuple[ReadinessGap, ...]:
    """Convert stale EvidenceFreshnessRecords to ReadinessGap records.

    Evidence linked to required controls → HIGH severity.
    Other stale evidence → MODERATE severity.
    """
    gaps: list[ReadinessGap] = []
    for rec in freshness_records:
        if not rec.is_stale:
            continue
        is_required = (
            rec.control_id is not None and rec.control_id in required_control_ids
        )
        severity = GapSeverity.HIGH if is_required else GapSeverity.MODERATE
        gaps.append(
            ReadinessGap(
                gap_id=f"{rec.framework_id}::{rec.evidence_id}::stale_evidence",
                gap_classification=GapClassification.STALE_EVIDENCE,
                gap_severity=severity,
                framework_id=rec.framework_id,
                framework_version=rec.framework_version,
                gap_rationale=(
                    f"Evidence {rec.evidence_id!r} is {rec.staleness_days} day(s)"
                    f" past its {rec.freshness_window_days}-day freshness window."
                ),
                detected_at=detected_at,
                is_blocker=False,
                is_maturity_blocker=is_required,
                affected_control_ids=((rec.control_id,) if rec.control_id else ()),
                affected_framework_ids=(rec.framework_id,),
                evidence_ids=(rec.evidence_id,),
                control_id=rec.control_id,
                domain_id=None,
                tenant_id=rec.tenant_id,
            )
        )
    return tuple(sorted(gaps, key=gap_sort_key))


# ---------------------------------------------------------------------------
# Threshold and maturity gate detection
# ---------------------------------------------------------------------------


def detect_threshold_gaps(
    threshold_failures: tuple[ThresholdFailure, ...],
    domain_scores: tuple[DomainScore, ...],
    *,
    framework_id: str,
    framework_version: str,
    tenant_id: Optional[str],
    detected_at: datetime,
) -> tuple[ReadinessGap, ...]:
    """Detect gaps from scoring threshold failures.

    required_control failures → FAILED_PREREQUISITE_CONTROL gap (CRITICAL).
    maturity_gate failures → FAILED_MATURITY_GATE gap (HIGH, is_maturity_blocker).
    overall_pass / domain_minimum failures → FAILED_READINESS_THRESHOLD gap (HIGH).
    """
    # Map domain_name → domain_id so domain_minimum failures resolve to IDs not display names
    domain_id_by_name: dict[str, str] = {
        ds.domain_name: ds.domain_id for ds in domain_scores
    }

    gaps: list[ReadinessGap] = []
    for failure in threshold_failures:
        if failure.threshold_type == "required_control":
            gaps.append(
                ReadinessGap(
                    gap_id=f"{framework_id}::{failure.threshold_name}::failed_prerequisite",
                    gap_classification=GapClassification.FAILED_PREREQUISITE_CONTROL,
                    gap_severity=GapSeverity.CRITICAL,
                    framework_id=framework_id,
                    framework_version=framework_version,
                    gap_rationale=failure.message,
                    detected_at=detected_at,
                    is_blocker=True,
                    is_maturity_blocker=True,
                    affected_control_ids=(failure.threshold_name,),
                    affected_framework_ids=(framework_id,),
                    evidence_ids=(),
                    control_id=failure.threshold_name,
                    domain_id=None,
                    tenant_id=tenant_id,
                )
            )
        elif failure.threshold_type == "maturity_gate":
            gaps.append(
                ReadinessGap(
                    gap_id=f"{framework_id}::{failure.threshold_name}::failed_maturity_gate",
                    gap_classification=GapClassification.FAILED_MATURITY_GATE,
                    gap_severity=GapSeverity.HIGH,
                    framework_id=framework_id,
                    framework_version=framework_version,
                    gap_rationale=failure.message,
                    detected_at=detected_at,
                    is_blocker=False,
                    is_maturity_blocker=True,
                    affected_control_ids=(),
                    affected_framework_ids=(framework_id,),
                    evidence_ids=(),
                    control_id=None,
                    domain_id=None,
                    tenant_id=tenant_id,
                )
            )
        else:
            # overall_pass or domain_minimum
            affected_domain = (
                domain_id_by_name.get(failure.threshold_name)
                if failure.threshold_type == "domain_minimum"
                else None
            )
            gaps.append(
                ReadinessGap(
                    gap_id=f"{framework_id}::{failure.threshold_name}::failed_threshold",
                    gap_classification=GapClassification.FAILED_READINESS_THRESHOLD,
                    gap_severity=GapSeverity.HIGH,
                    framework_id=framework_id,
                    framework_version=framework_version,
                    gap_rationale=failure.message,
                    detected_at=detected_at,
                    is_blocker=True,
                    is_maturity_blocker=False,
                    affected_control_ids=(),
                    affected_framework_ids=(framework_id,),
                    evidence_ids=(),
                    control_id=None,
                    domain_id=affected_domain,
                    tenant_id=tenant_id,
                )
            )
    return tuple(sorted(gaps, key=gap_sort_key))


def detect_incomplete_assessment_gap(
    completion_percentage: float,
    *,
    framework_id: str,
    framework_version: str,
    tenant_id: Optional[str],
    assessment_id: Optional[str],
    detected_at: datetime,
) -> Optional[ReadinessGap]:
    """Detect an incomplete assessment gap when completion_percentage < 100.0.

    Returns None if the assessment is fully complete.
    """
    if completion_percentage >= 100.0:
        return None
    subject = assessment_id or framework_id
    return ReadinessGap(
        gap_id=f"{framework_id}::assessment::{subject}::incomplete",
        gap_classification=GapClassification.INCOMPLETE_ASSESSMENT,
        gap_severity=GapSeverity.MODERATE,
        framework_id=framework_id,
        framework_version=framework_version,
        gap_rationale=(
            f"Assessment is {completion_percentage:.1f}% complete;"
            " not all applicable controls have been evaluated."
        ),
        detected_at=detected_at,
        is_blocker=False,
        is_maturity_blocker=False,
        affected_control_ids=(),
        affected_framework_ids=(framework_id,),
        evidence_ids=(),
        control_id=None,
        domain_id=None,
        tenant_id=tenant_id,
    )


# ---------------------------------------------------------------------------
# Dependency cycle detection
# ---------------------------------------------------------------------------


def detect_cycles_in_dependencies(
    dependencies: tuple[GapDependency, ...],
) -> tuple[tuple[str, str], ...]:
    """Detect cycles in the gap dependency graph using DFS.

    Returns a tuple of (dependent_gap_id, prerequisite_gap_id) pairs that
    participate in a cycle. Empty tuple means no cycles.

    Graph direction: dependent → prerequisite (follows the resolution order).
    """
    graph: dict[str, set[str]] = {}
    for dep in dependencies:
        if dep.dependent_gap_id not in graph:
            graph[dep.dependent_gap_id] = set()
        graph[dep.dependent_gap_id].add(dep.prerequisite_gap_id)

    WHITE, GRAY, BLACK = 0, 1, 2
    color: dict[str, int] = {node: WHITE for node in graph}
    cycles: list[tuple[str, str]] = []

    def _dfs(node: str) -> None:
        color[node] = GRAY
        for prereq in graph.get(node, set()):
            prereq_color = color.get(prereq, BLACK)
            if prereq_color == GRAY:
                cycles.append((node, prereq))
            elif prereq_color == WHITE:
                _dfs(prereq)
        color[node] = BLACK

    for node in list(graph):
        if color[node] == WHITE:
            _dfs(node)

    return tuple(sorted(cycles))


# ---------------------------------------------------------------------------
# Dependency chain builder
# ---------------------------------------------------------------------------


def build_dependency_chains(
    gap_ids: frozenset[str],
    dependencies: tuple[GapDependency, ...],
) -> tuple[DependencyChain, ...]:
    """Build ordered dependency chains from GapDependency records.

    Each connected component of the dependency graph becomes one DependencyChain.
    Chains are ordered topologically (prerequisites first) using Kahn's algorithm.
    If a cycle exists in a component, has_cycle=True and cycle_gap_ids records
    the participants; ordering falls back to sorted gap_id for determinism.

    Chain IDs are deterministic: "chain::{sorted first-gap-id in component}".
    """
    # Build adjacency: dependent → set of prerequisites
    adj: dict[str, set[str]] = {gid: set() for gid in gap_ids}
    for dep in dependencies:
        if dep.dependent_gap_id in adj and dep.prerequisite_gap_id in gap_ids:
            adj[dep.dependent_gap_id].add(dep.prerequisite_gap_id)

    # Find connected components (undirected)
    visited: set[str] = set()
    components: list[set[str]] = []

    def _collect(node: str, component: set[str]) -> None:
        component.add(node)
        visited.add(node)
        for neighbor in adj.get(node, set()):
            if neighbor not in visited and neighbor in gap_ids:
                _collect(neighbor, component)
        # Also traverse in reverse (nodes that depend on this one)
        for other, prereqs in adj.items():
            if node in prereqs and other not in visited and other in gap_ids:
                _collect(other, component)

    for gid in sorted(gap_ids):
        if gid not in visited:
            component: set[str] = set()
            _collect(gid, component)
            if len(component) > 1 or (
                len(component) == 1 and bool(adj.get(list(component)[0]))
            ):
                components.append(component)

    chains: list[DependencyChain] = []
    for component in components:
        cycle_pairs = detect_cycles_in_dependencies(
            tuple(d for d in dependencies if d.dependent_gap_id in component)
        )
        has_cycle = len(cycle_pairs) > 0
        cycle_gap_ids: tuple[str, ...] = tuple(
            sorted({gid for pair in cycle_pairs for gid in pair})
        )

        if not has_cycle:
            # Kahn's algorithm for topological sort
            in_degree: dict[str, int] = {gid: 0 for gid in component}
            for gid in component:
                for prereq in adj.get(gid, set()):
                    if prereq in component:
                        in_degree[gid] += 1

            # Start with nodes that have no prerequisites (in_degree=0), sorted for determinism
            queue: list[str] = sorted(g for g in component if in_degree[g] == 0)
            ordered: list[str] = []
            while queue:
                node = queue.pop(0)
                ordered.append(node)
                # Find nodes that depend on this node (node is their prerequisite)
                for dependent in sorted(component):
                    if node in adj.get(dependent, set()):
                        in_degree[dependent] -= 1
                        if in_degree[dependent] == 0:
                            queue.append(dependent)
            # Add any remaining (shouldn't happen without cycle, but defensive)
            for gid in sorted(component):
                if gid not in ordered:
                    ordered.append(gid)
        else:
            # Cycle: fall back to sorted order
            ordered = sorted(component)

        chain_id = f"chain::{sorted(component)[0]}"
        chains.append(
            DependencyChain(
                chain_id=chain_id,
                ordered_gap_ids=tuple(ordered),
                has_cycle=has_cycle,
                cycle_gap_ids=cycle_gap_ids,
            )
        )

    return tuple(sorted(chains, key=lambda c: c.chain_id))


# ---------------------------------------------------------------------------
# Blocker builders
# ---------------------------------------------------------------------------


def build_readiness_blockers(
    gaps: tuple[ReadinessGap, ...],
    *,
    tenant_id: Optional[str],
) -> tuple[ReadinessBlocker, ...]:
    """Extract gaps that are readiness blockers and return ReadinessBlocker records.

    Blocker ID: "blocker::{gap_id}".
    """
    blockers: list[ReadinessBlocker] = []
    for gap in gaps:
        if not gap.is_blocker:
            continue
        blockers.append(
            ReadinessBlocker(
                blocker_id=f"blocker::{gap.gap_id}",
                gap_id=gap.gap_id,
                blocker_rationale=gap.gap_rationale,
                severity=gap.gap_severity,
                affected_framework_ids=gap.affected_framework_ids,
                affected_control_ids=gap.affected_control_ids,
                tenant_id=tenant_id,
            )
        )
    return tuple(sorted(blockers, key=lambda b: b.blocker_id))


def build_maturity_blockers(
    gaps: tuple[ReadinessGap, ...],
    maturity_tier_id: Optional[str],
    *,
    tenant_id: Optional[str],
) -> tuple[MaturityBlocker, ...]:
    """Extract maturity-blocking gaps and return MaturityBlocker records.

    Only produced when maturity_tier_id is provided.
    Blocker ID: "matblocker::{gap_id}::{tier_id}".
    """
    if maturity_tier_id is None:
        return ()
    blockers: list[MaturityBlocker] = []
    for gap in gaps:
        if not gap.is_maturity_blocker:
            continue
        blockers.append(
            MaturityBlocker(
                blocker_id=f"matblocker::{gap.gap_id}::{maturity_tier_id}",
                gap_id=gap.gap_id,
                maturity_tier_id=maturity_tier_id,
                blocker_rationale=gap.gap_rationale,
                affected_control_ids=gap.affected_control_ids,
                tenant_id=tenant_id,
            )
        )
    return tuple(sorted(blockers, key=lambda b: b.blocker_id))
