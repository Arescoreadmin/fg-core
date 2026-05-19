"""Timeline adapters — pure functions that convert domain objects to TimelineEvent.

No I/O, no side effects.  Callers pass the result to TimelineStore.record().

Design invariants:
  - All payloads carry schema_version, event_version, event_origin, and causal
    lineage fields (parent_event_id, causation_id, correlation_id) so event
    graphs can be reconstructed and contracts can evolve independently.
  - Payloads are serialized with sorted keys (deterministic ordering) so
    replay verification never drifts due to dict insertion order.
  - event_origin="live" marks events generated from real requests.
    Replayed/reconstructed/imported events MUST override this field.

Adapter registry:
  TIMELINE_ADAPTERS maps SourceType → adapter callable.
  PR 101 adds MONITORING, ALERT, EVIDENCE entries.

Covered sources:
  simulation  — SimulationTimelineEntry  → SourceType.SIMULATION
  report      — GovernanceReport         → SourceType.GOVERNANCE_REPORT
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable

from services.governance.timeline.identity import derive_event_id
from services.governance.timeline.models import SourceType, TimelineEvent

_EVENT_VERSION = "1.0"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _normalize_iso(ts: str) -> str:
    """Normalize any ISO 8601 UTC timestamp to canonical millisecond+Z form.

    Producers (simulation engine, report engine) use datetime.isoformat() which
    emits microseconds and a +00:00 suffix — e.g. 2026-05-19T00:00:00.123456+00:00.
    The timeline store orders events lexicographically on occurred_at; mixing
    +00:00 and Z formats within the same second breaks sort order and cursor math.

    All adapters MUST normalize occurred_at through this function so every event
    in the store uses the same format: YYYY-MM-DDTHH:MM:SS.mmmZ.
    """
    ts = ts.strip()
    if ts.endswith("Z"):
        dt = datetime.fromisoformat(ts[:-1] + "+00:00")
    else:
        dt = datetime.fromisoformat(ts).astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _sorted_payload(d: dict[str, Any]) -> dict[str, Any]:
    """Return a new dict with top-level keys in sorted order.

    Deterministic key order ensures stable serialization across Python
    versions and implementations — required for replay verification.
    """
    return dict(sorted(d.items()))


def _lineage(
    parent_event_id: str | None = None,
    causation_id: str | None = None,
    correlation_id: str | None = None,
) -> dict[str, Any]:
    """Causal lineage fields for event graph reconstruction.

    Always included (as None when unknown) so consumers can rely on the
    presence of these keys without defensive attribute checks.  Future
    chained flows (simulation → alert → remediation) will populate them.
    """
    return {
        "parent_event_id": parent_event_id,
        "causation_id": causation_id,
        "correlation_id": correlation_id,
    }


def simulation_entry_to_timeline_event(
    entry,
    *,
    parent_event_id: str | None = None,
    causation_id: str | None = None,
    correlation_id: str | None = None,
) -> TimelineEvent:
    """Convert a SimulationTimelineEntry to a TimelineEvent.

    event_type is always "simulation.completed" — the entry is built after the
    projection finishes, so "completed" is the accurate lifecycle moment.
    replay_eligible=True because simulation projections are deterministic.
    """
    occurred_at = _normalize_iso(entry.simulated_at_iso)
    event_id = derive_event_id(
        tenant_id=entry.tenant_id,
        source_type=SourceType.SIMULATION.value,
        source_id=entry.simulation_id,
        event_type="simulation.completed",
        occurred_at=occurred_at,
    )
    payload: dict[str, Any] = {
        "schema_version": _EVENT_VERSION,
        "event_origin": "live",
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

    payload.update(_lineage(parent_event_id, causation_id, correlation_id))

    return TimelineEvent(
        event_id=event_id,
        tenant_id=entry.tenant_id,
        source_type=SourceType.SIMULATION,
        source_id=entry.simulation_id,
        event_type="simulation.completed",
        occurred_at=occurred_at,
        recorded_at=_now_iso(),
        payload=_sorted_payload(payload),
        classification=entry.classification.value,
        replay_eligible=True,
        event_version=_EVENT_VERSION,
    )


def governance_report_to_timeline_event(
    report,
    *,
    parent_event_id: str | None = None,
    causation_id: str | None = None,
    correlation_id: str | None = None,
) -> TimelineEvent:
    """Convert a GovernanceReport to a TimelineEvent.

    event_type is "report.generated".
    manifest_hash is set so downstream consumers can verify determinism.
    replay_eligible=True because reports are deterministic from their inputs.
    """
    occurred_at = _normalize_iso(report.generated_at)
    event_id = derive_event_id(
        tenant_id=report.tenant_id,
        source_type=SourceType.GOVERNANCE_REPORT.value,
        source_id=report.report_id,
        event_type="report.generated",
        occurred_at=occurred_at,
    )
    payload: dict[str, Any] = {
        "schema_version": _EVENT_VERSION,
        "event_origin": "live",
        "assessment_id": report.assessment_id,
        "findings_count": len(report.findings),
        "report_schema_version": report.schema_version,
    }
    payload.update(_lineage(parent_event_id, causation_id, correlation_id))

    return TimelineEvent(
        event_id=event_id,
        tenant_id=report.tenant_id,
        source_type=SourceType.GOVERNANCE_REPORT,
        source_id=report.report_id,
        event_type="report.generated",
        occurred_at=occurred_at,
        recorded_at=_now_iso(),
        payload=_sorted_payload(payload),
        classification="internal",
        manifest_hash=report.manifest_hash,
        replay_eligible=True,
        event_version=_EVENT_VERSION,
    )


# ---------------------------------------------------------------------------
# Adapter registry — dispatch table for PR 101+ sources
# ---------------------------------------------------------------------------

TIMELINE_ADAPTERS: dict[SourceType, Callable[..., TimelineEvent]] = {
    SourceType.SIMULATION: simulation_entry_to_timeline_event,
    SourceType.GOVERNANCE_REPORT: governance_report_to_timeline_event,
    # PR 101: MONITORING, ALERT, EVIDENCE
    # PR 102: EXPORT, REPLAY
}
