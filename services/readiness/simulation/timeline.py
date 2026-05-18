"""Governance timeline integration for simulation projections.

All functions are pure Python: no I/O, no side effects.

# governance_timeline_seam: SimulationTimelineEntry objects feed into the governance
# timeline API (GET /control-plane/governance/timeline). The timeline API aggregates
# simulation runs, monitoring drift events, and alert lifecycle transitions into a
# unified governance event stream. Integration: after build_timeline_entry(), push to
# timeline store before committing the simulation transaction.
"""

from __future__ import annotations

import hashlib

from .models import (
    SimulationClassification,
    SimulationProjection,
    SimulationTimelineEntry,
)


def _derive_entry_id(
    simulation_id: str,
    event_type: str,
    occurred_at_iso: str,
) -> str:
    """Deterministic SHA-256[:24] entry identity."""
    raw = f"{simulation_id}:{event_type}:{occurred_at_iso}"
    return hashlib.sha256(raw.encode()).hexdigest()[:24]


def _build_summary(projection: SimulationProjection) -> str:
    """Derive a short human-readable summary from the projection outcome."""
    direction = projection.readiness_projection.direction.value
    uncertainty = projection.uncertainty.value
    scenario = projection.scenario_type.value
    warnings = len(projection.warnings)
    critical = sum(
        1 for w in projection.warnings if w.severity.value in ("critical", "blocking")
    )
    parts = [
        f"Scenario: {scenario}.",
        f"Readiness direction: {direction}.",
        f"Uncertainty: {uncertainty}.",
    ]
    if warnings:
        parts.append(f"{warnings} warning(s)")
        if critical:
            parts.append(f"({critical} critical/blocking).")
        else:
            parts.append(".")
    else:
        parts.append("No warnings.")
    return " ".join(parts)


def build_timeline_entry(
    projection: SimulationProjection,
    classification: SimulationClassification,
) -> SimulationTimelineEntry:
    """Build an immutable timeline entry from a SimulationProjection.

    The entry_id is deterministic: SHA-256[:24] of (simulation_id, scenario_type, simulated_at_iso).
    timeline_summary is a short human-readable description of the projection outcome.
    """
    entry_id = _derive_entry_id(
        projection.simulation_id,
        projection.scenario_type.value,
        projection.simulated_at_iso,
    )
    total_warnings = len(projection.warnings)
    total_critical = sum(
        1 for w in projection.warnings if w.severity.value in ("critical", "blocking")
    )
    return SimulationTimelineEntry(
        entry_id=entry_id,
        simulation_id=projection.simulation_id,
        tenant_id=projection.tenant_id,
        classification=classification,
        scenario_type=projection.scenario_type,
        uncertainty=projection.uncertainty,
        risk_direction=projection.readiness_projection.direction,
        total_warnings=total_warnings,
        total_critical_warnings=total_critical,
        simulated_at_iso=projection.simulated_at_iso,
        assessment_id=projection.assessment_id,
        framework_id=projection.framework_id,
        timeline_summary=_build_summary(projection),
    )
