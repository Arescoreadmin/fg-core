"""Timeline adapters — pure functions that convert domain objects to TimelineEvent.

No I/O, no side effects.  Callers pass the result to TimelineStore.record().

Covered sources:
  simulation  — SimulationTimelineEntry  → SourceType.SIMULATION
  report      — GovernanceReport         → SourceType.GOVERNANCE_REPORT
"""

from __future__ import annotations

from datetime import datetime, timezone

from services.governance.timeline.identity import derive_event_id
from services.governance.timeline.models import SourceType, TimelineEvent


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def simulation_entry_to_timeline_event(entry) -> TimelineEvent:
    """Convert a SimulationTimelineEntry to a TimelineEvent.

    event_type is always "simulation.completed" — the entry is built after the
    projection finishes, so "completed" is the accurate lifecycle moment.
    replay_eligible=True because simulation projections are deterministic.
    """
    event_id = derive_event_id(
        tenant_id=entry.tenant_id,
        source_type=SourceType.SIMULATION.value,
        source_id=entry.simulation_id,
        event_type="simulation.completed",
        occurred_at=entry.simulated_at_iso,
    )
    payload = {
        "scenario_type": entry.scenario_type.value,
        "uncertainty": entry.uncertainty.value,
        "risk_direction": entry.risk_direction.value,
        "total_warnings": entry.total_warnings,
        "total_critical_warnings": entry.total_critical_warnings,
        "timeline_summary": entry.timeline_summary,
    }
    if entry.assessment_id:
        payload["assessment_id"] = entry.assessment_id
    if entry.framework_id:
        payload["framework_id"] = entry.framework_id

    return TimelineEvent(
        event_id=event_id,
        tenant_id=entry.tenant_id,
        source_type=SourceType.SIMULATION,
        source_id=entry.simulation_id,
        event_type="simulation.completed",
        occurred_at=entry.simulated_at_iso,
        recorded_at=_now_iso(),
        payload=payload,
        classification=entry.classification.value,
        replay_eligible=True,
    )


def governance_report_to_timeline_event(report) -> TimelineEvent:
    """Convert a GovernanceReport to a TimelineEvent.

    event_type is "report.generated".
    manifest_hash is set so downstream consumers can verify determinism.
    replay_eligible=True because reports are deterministic from their inputs.
    """
    event_id = derive_event_id(
        tenant_id=report.tenant_id,
        source_type=SourceType.GOVERNANCE_REPORT.value,
        source_id=report.report_id,
        event_type="report.generated",
        occurred_at=report.generated_at,
    )
    return TimelineEvent(
        event_id=event_id,
        tenant_id=report.tenant_id,
        source_type=SourceType.GOVERNANCE_REPORT,
        source_id=report.report_id,
        event_type="report.generated",
        occurred_at=report.generated_at,
        recorded_at=_now_iso(),
        payload={
            "assessment_id": report.assessment_id,
            "findings_count": len(report.findings),
            "schema_version": report.schema_version,
        },
        classification="internal",
        manifest_hash=report.manifest_hash,
        replay_eligible=True,
    )
