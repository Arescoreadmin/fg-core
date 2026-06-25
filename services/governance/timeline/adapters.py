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

Covered sources:
  simulation  — SimulationTimelineEntry  → SourceType.SIMULATION
  report      — GovernanceReport         → SourceType.GOVERNANCE_REPORT
  monitoring  — MonitoringRunRecord      → SourceType.MONITORING
  alert       — AlertRunRecord           → SourceType.ALERT
  evidence    — EvidenceReference        → SourceType.EVIDENCE
  export      — ExportTimelineEntry      → SourceType.EXPORT
  replay      — ReplayTimelineEntry      → SourceType.REPLAY
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable

from services.governance.timeline.identity import derive_event_id
from services.governance.timeline.models import SourceType, TimelineEvent

from services.canonical import utc_iso8601_z_now

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


def monitoring_run_to_timeline_event(
    record,
    *,
    parent_event_id: str | None = None,
    causation_id: str | None = None,
    correlation_id: str | None = None,
) -> TimelineEvent:
    """Convert a MonitoringRunRecord to a TimelineEvent.

    event_type is "monitoring.completed".
    replay_eligible=True because snapshots are deterministically reconstructable.
    """
    occurred_at = _normalize_iso(record.completed_at_iso)
    event_id = derive_event_id(
        tenant_id=record.tenant_id,
        source_type=SourceType.MONITORING.value,
        source_id=record.run_id,
        event_type="monitoring.completed",
        occurred_at=occurred_at,
    )
    payload: dict[str, Any] = {
        "schema_version": _EVENT_VERSION,
        "event_origin": "live",
        "snapshot_id": record.snapshot_id,
        "domains_evaluated": list(record.domains_evaluated),
        "total_drift_events": record.total_drift_events,
        "critical_or_blocking_count": record.critical_or_blocking_count,
        "evaluation_success": record.evaluation_success,
        "monitoring_contract_version": record.monitoring_contract_version,
        "evaluation_engine_version": record.evaluation_engine_version,
    }
    if record.assessment_id:
        payload["assessment_id"] = record.assessment_id
    if record.framework_ids:
        payload["framework_ids"] = list(record.framework_ids)
    if record.error_summary:
        payload["error_summary"] = record.error_summary

    payload.update(_lineage(parent_event_id, causation_id, correlation_id))

    return TimelineEvent(
        event_id=event_id,
        tenant_id=record.tenant_id,
        source_type=SourceType.MONITORING,
        source_id=record.run_id,
        event_type="monitoring.completed",
        occurred_at=occurred_at,
        recorded_at=_now_iso(),
        payload=_sorted_payload(payload),
        classification="internal",
        replay_eligible=True,
        event_version=_EVENT_VERSION,
    )


def alert_run_to_timeline_event(
    record,
    *,
    parent_event_id: str | None = None,
    causation_id: str | None = None,
    correlation_id: str | None = None,
) -> TimelineEvent:
    """Convert an AlertRunRecord to a TimelineEvent.

    event_type is "alert.run_completed".
    source_monitoring_run_id is included in payload as causal linkage.
    replay_eligible=True because alert generation is deterministic from its snapshot.
    """
    occurred_at = _normalize_iso(record.generation_timestamp_iso)
    event_id = derive_event_id(
        tenant_id=record.tenant_id,
        source_type=SourceType.ALERT.value,
        source_id=record.run_id,
        event_type="alert.run_completed",
        occurred_at=occurred_at,
    )
    payload: dict[str, Any] = {
        "schema_version": _EVENT_VERSION,
        "event_origin": "live",
        "source_monitoring_run_id": record.source_monitoring_run_id,
        "total_alerts_generated": record.total_alerts_generated,
        "total_alerts_deduplicated": record.total_alerts_deduplicated,
        "total_alerts_suppressed": record.total_alerts_suppressed,
        "alert_generation_version": record.alert_generation_version,
        "escalation_policy_version": record.escalation_policy_version,
        "completed": record.completed,
    }
    if record.assessment_id:
        payload["assessment_id"] = record.assessment_id
    if record.error_summary:
        payload["error_summary"] = record.error_summary

    payload.update(_lineage(parent_event_id, causation_id, correlation_id))

    return TimelineEvent(
        event_id=event_id,
        tenant_id=record.tenant_id,
        source_type=SourceType.ALERT,
        source_id=record.run_id,
        event_type="alert.run_completed",
        occurred_at=occurred_at,
        recorded_at=_now_iso(),
        payload=_sorted_payload(payload),
        classification="internal",
        replay_eligible=True,
        event_version=_EVENT_VERSION,
    )


def evidence_submitted_to_timeline_event(
    evidence,
    *,
    parent_event_id: str | None = None,
    causation_id: str | None = None,
    correlation_id: str | None = None,
) -> TimelineEvent:
    """Convert an EvidenceReference to a TimelineEvent.

    event_type is "evidence.submitted".
    replay_eligible=False — evidence submission involves external state that
    cannot be deterministically reconstructed from governance metadata alone.
    """
    submitted_at = evidence.submitted_at
    if isinstance(submitted_at, datetime):
        if submitted_at.tzinfo is None:
            submitted_at = submitted_at.replace(tzinfo=timezone.utc)
        submitted_at_iso = submitted_at.astimezone(timezone.utc).isoformat()
    else:
        submitted_at_iso = str(submitted_at)

    occurred_at = _normalize_iso(submitted_at_iso)
    event_id = derive_event_id(
        tenant_id=evidence.tenant_id,
        source_type=SourceType.EVIDENCE.value,
        source_id=evidence.evidence_id,
        event_type="evidence.submitted",
        occurred_at=occurred_at,
    )
    payload: dict[str, Any] = {
        "schema_version": _EVENT_VERSION,
        "event_origin": "live",
        "assessment_id": evidence.assessment_id,
        "evidence_type": evidence.evidence_type.value
        if hasattr(evidence.evidence_type, "value")
        else str(evidence.evidence_type),
    }
    if evidence.evidence_classification:
        payload["evidence_classification"] = evidence.evidence_classification
    if evidence.control_ids:
        payload["control_ids"] = list(evidence.control_ids)

    payload.update(_lineage(parent_event_id, causation_id, correlation_id))

    classification = evidence.evidence_classification or "internal"

    return TimelineEvent(
        event_id=event_id,
        tenant_id=evidence.tenant_id,
        source_type=SourceType.EVIDENCE,
        source_id=evidence.evidence_id,
        event_type="evidence.submitted",
        occurred_at=occurred_at,
        recorded_at=_now_iso(),
        payload=_sorted_payload(payload),
        classification=classification,
        replay_eligible=False,
        event_version=_EVENT_VERSION,
    )


def export_to_timeline_event(
    entry,
    *,
    parent_event_id: str | None = None,
    causation_id: str | None = None,
    correlation_id: str | None = None,
) -> TimelineEvent:
    """Convert an ExportTimelineEntry to a TimelineEvent.

    event_type is "export.completed".
    manifest_hash is set on the envelope for downstream hash verification.
    replay_eligible=True because the manifest_hash enables deterministic re-verification.
    classification="confidential" because governance export artifacts carry regulated content.
    """
    occurred_at = _normalize_iso(entry.exported_at_iso)
    event_id = derive_event_id(
        tenant_id=entry.tenant_id,
        source_type=SourceType.EXPORT.value,
        source_id=entry.export_id,
        event_type="export.completed",
        occurred_at=occurred_at,
    )
    payload: dict[str, Any] = {
        "schema_version": _EVENT_VERSION,
        "event_origin": "live",
        "report_id": entry.report_id,
        "export_format": entry.export_format,
        "export_version": entry.export_version,
    }
    if entry.assessment_id:
        payload["assessment_id"] = entry.assessment_id

    payload.update(_lineage(parent_event_id, causation_id, correlation_id))

    return TimelineEvent(
        event_id=event_id,
        tenant_id=entry.tenant_id,
        source_type=SourceType.EXPORT,
        source_id=entry.export_id,
        event_type="export.completed",
        occurred_at=occurred_at,
        recorded_at=_now_iso(),
        payload=_sorted_payload(payload),
        classification="confidential",
        manifest_hash=entry.manifest_hash,
        replay_eligible=True,
        event_version=_EVENT_VERSION,
    )


def replay_verify_to_timeline_event(
    entry,
    *,
    parent_event_id: str | None = None,
    causation_id: str | None = None,
    correlation_id: str | None = None,
) -> TimelineEvent:
    """Convert a ReplayTimelineEntry to a TimelineEvent.

    event_type is "replay.verified".
    manifest_hash is set to the actual hash computed during verification.
    replay_eligible=False — replay verification is a point-in-time check;
    re-running it constitutes a new verification, not a reconstruction of this one.
    """
    occurred_at = _normalize_iso(entry.replayed_at_iso)
    event_id = derive_event_id(
        tenant_id=entry.tenant_id,
        source_type=SourceType.REPLAY.value,
        source_id=entry.replay_id,
        event_type="replay.verified",
        occurred_at=occurred_at,
    )
    payload: dict[str, Any] = {
        "schema_version": _EVENT_VERSION,
        "event_origin": "live",
        "report_id": entry.report_id,
        "verified": entry.verified,
        "replay_contract_version": entry.replay_contract_version,
    }
    if entry.assessment_id:
        payload["assessment_id"] = entry.assessment_id
    if entry.expected_manifest_hash:
        payload["expected_manifest_hash"] = entry.expected_manifest_hash

    payload.update(_lineage(parent_event_id, causation_id, correlation_id))

    return TimelineEvent(
        event_id=event_id,
        tenant_id=entry.tenant_id,
        source_type=SourceType.REPLAY,
        source_id=entry.replay_id,
        event_type="replay.verified",
        occurred_at=occurred_at,
        recorded_at=_now_iso(),
        payload=_sorted_payload(payload),
        classification="internal",
        manifest_hash=entry.actual_manifest_hash,
        replay_eligible=False,
        event_version=_EVENT_VERSION,
    )


# ---------------------------------------------------------------------------
# Adapter registry
# ---------------------------------------------------------------------------


def field_assessment_to_timeline_event(
    *,
    tenant_id: str,
    engagement_id: str,
    event_type: str,
    occurred_at: str | None = None,
    payload: dict[str, object] | None = None,
    replay_eligible: bool = False,
) -> TimelineEvent:
    """Convert field assessment lifecycle activity into TimelineEvent."""
    now = occurred_at or utc_iso8601_z_now()

    return TimelineEvent(
        event_id=derive_event_id(
            tenant_id=tenant_id,
            source_type=SourceType.FIELD_ASSESSMENT.value,
            source_id=engagement_id,
            event_type=event_type,
            occurred_at=now,
        ),
        tenant_id=tenant_id,
        source_type=SourceType.FIELD_ASSESSMENT,
        source_id=engagement_id,
        event_type=event_type,
        occurred_at=now,
        recorded_at=utc_iso8601_z_now(),
        payload=payload or {},
        replay_eligible=replay_eligible,
    )


def risk_governance_to_timeline_event(
    *,
    tenant_id: str,
    source_id: str,
    event_type: str,
    occurred_at: str,
    payload: dict[str, object] | None = None,
    replay_eligible: bool = False,
) -> TimelineEvent:
    """Convert risk governance workflow activity into TimelineEvent."""
    occurred_at = _normalize_iso(occurred_at)

    return TimelineEvent(
        event_id=derive_event_id(
            tenant_id=tenant_id,
            source_type=SourceType.RISK_GOVERNANCE.value,
            source_id=source_id,
            event_type=event_type,
            occurred_at=occurred_at,
        ),
        tenant_id=tenant_id,
        source_type=SourceType.RISK_GOVERNANCE,
        source_id=source_id,
        event_type=event_type,
        occurred_at=occurred_at,
        recorded_at=utc_iso8601_z_now(),
        payload=payload or {},
        replay_eligible=replay_eligible,
    )


def control_registry_to_timeline_event(
    *,
    tenant_id: str,
    source_id: str,
    event_type: str,
    occurred_at: str,
    payload: dict[str, object] | None = None,
    replay_eligible: bool = False,
) -> TimelineEvent:
    """Convert control registry lifecycle activity into TimelineEvent."""
    occurred_at = _normalize_iso(occurred_at)

    return TimelineEvent(
        event_id=derive_event_id(
            tenant_id=tenant_id,
            source_type=SourceType.CONTROL_REGISTRY.value,
            source_id=source_id,
            event_type=event_type,
            occurred_at=occurred_at,
        ),
        tenant_id=tenant_id,
        source_type=SourceType.CONTROL_REGISTRY,
        source_id=source_id,
        event_type=event_type,
        occurred_at=occurred_at,
        recorded_at=utc_iso8601_z_now(),
        payload=payload or {},
        replay_eligible=replay_eligible,
    )


def governance_portal_to_timeline_event(
    *,
    tenant_id: str,
    source_id: str,
    event_type: str,
    occurred_at: str,
    payload: dict[str, object] | None = None,
    replay_eligible: bool = False,
) -> TimelineEvent:
    """Convert governance portal activity into TimelineEvent."""
    occurred_at = _normalize_iso(occurred_at)

    return TimelineEvent(
        event_id=derive_event_id(
            tenant_id=tenant_id,
            source_type=SourceType.GOVERNANCE_PORTAL.value,
            source_id=source_id,
            event_type=event_type,
            occurred_at=occurred_at,
        ),
        tenant_id=tenant_id,
        source_type=SourceType.GOVERNANCE_PORTAL,
        source_id=source_id,
        event_type=event_type,
        occurred_at=occurred_at,
        recorded_at=utc_iso8601_z_now(),
        payload=payload or {},
        replay_eligible=replay_eligible,
    )


def governance_reporting_to_timeline_event(
    *,
    tenant_id: str,
    source_id: str,
    event_type: str,
    occurred_at: str,
    payload: dict[str, object] | None = None,
    replay_eligible: bool = False,
) -> TimelineEvent:
    """Convert governance reporting activity into TimelineEvent."""
    occurred_at = _normalize_iso(occurred_at)
    return TimelineEvent(
        event_id=derive_event_id(
            tenant_id=tenant_id,
            source_type=SourceType.GOVERNANCE_REPORTING.value,
            source_id=source_id,
            event_type=event_type,
            occurred_at=occurred_at,
        ),
        tenant_id=tenant_id,
        source_type=SourceType.GOVERNANCE_REPORTING,
        source_id=source_id,
        event_type=event_type,
        occurred_at=occurred_at,
        recorded_at=utc_iso8601_z_now(),
        payload=payload or {},
        replay_eligible=replay_eligible,
    )


def verification_workflow_to_timeline_event(
    *,
    tenant_id: str,
    source_id: str,
    event_type: str,
    occurred_at: str,
    payload: dict[str, object] | None = None,
    replay_eligible: bool = False,
) -> TimelineEvent:
    """Convert verification workflow activity into TimelineEvent."""
    occurred_at = _normalize_iso(occurred_at)
    return TimelineEvent(
        event_id=derive_event_id(
            tenant_id=tenant_id,
            source_type=SourceType.VERIFICATION_WORKFLOW.value,
            source_id=source_id,
            event_type=event_type,
            occurred_at=occurred_at,
        ),
        tenant_id=tenant_id,
        source_type=SourceType.VERIFICATION_WORKFLOW,
        source_id=source_id,
        event_type=event_type,
        occurred_at=occurred_at,
        recorded_at=utc_iso8601_z_now(),
        payload=payload or {},
        replay_eligible=replay_eligible,
    )


def evidence_freshness_to_timeline_event(
    *,
    tenant_id: str,
    source_id: str,
    event_type: str,
    occurred_at: str,
    payload: dict[str, object] | None = None,
    replay_eligible: bool = False,
) -> TimelineEvent:
    """Convert evidence freshness activity into TimelineEvent."""
    occurred_at = _normalize_iso(occurred_at)
    return TimelineEvent(
        event_id=derive_event_id(
            tenant_id=tenant_id,
            source_type=SourceType.EVIDENCE_FRESHNESS.value,
            source_id=source_id,
            event_type=event_type,
            occurred_at=occurred_at,
        ),
        tenant_id=tenant_id,
        source_type=SourceType.EVIDENCE_FRESHNESS,
        source_id=source_id,
        event_type=event_type,
        occurred_at=occurred_at,
        recorded_at=utc_iso8601_z_now(),
        payload=payload or {},
        replay_eligible=replay_eligible,
    )


def freshness_score_history_to_timeline_event(
    *,
    tenant_id: str,
    source_id: str,
    event_type: str,
    occurred_at: str,
    payload: dict[str, object] | None = None,
    replay_eligible: bool = False,
) -> TimelineEvent:
    """Convert freshness score history activity into TimelineEvent."""
    occurred_at = _normalize_iso(occurred_at)
    return TimelineEvent(
        event_id=derive_event_id(
            tenant_id=tenant_id,
            source_type=SourceType.FRESHNESS_SCORE_HISTORY.value,
            source_id=source_id,
            event_type=event_type,
            occurred_at=occurred_at,
        ),
        tenant_id=tenant_id,
        source_type=SourceType.FRESHNESS_SCORE_HISTORY,
        source_id=source_id,
        event_type=event_type,
        occurred_at=occurred_at,
        recorded_at=utc_iso8601_z_now(),
        payload=payload or {},
        replay_eligible=replay_eligible,
    )


def control_effectiveness_to_timeline_event(
    *,
    tenant_id: str,
    source_id: str,
    event_type: str,
    occurred_at: str,
    payload: dict[str, object] | None = None,
    replay_eligible: bool = False,
) -> TimelineEvent:
    """Convert control effectiveness calculation into TimelineEvent."""
    occurred_at = _normalize_iso(occurred_at)
    return TimelineEvent(
        event_id=derive_event_id(
            tenant_id=tenant_id,
            source_type=SourceType.CONTROL_EFFECTIVENESS.value,
            source_id=source_id,
            event_type=event_type,
            occurred_at=occurred_at,
        ),
        tenant_id=tenant_id,
        source_type=SourceType.CONTROL_EFFECTIVENESS,
        source_id=source_id,
        event_type=event_type,
        occurred_at=occurred_at,
        recorded_at=utc_iso8601_z_now(),
        payload=payload or {},
        replay_eligible=replay_eligible,
    )


TIMELINE_ADAPTERS: dict[SourceType, Callable[..., TimelineEvent]] = {
    SourceType.SIMULATION: simulation_entry_to_timeline_event,
    SourceType.GOVERNANCE_REPORT: governance_report_to_timeline_event,
    SourceType.MONITORING: monitoring_run_to_timeline_event,
    SourceType.ALERT: alert_run_to_timeline_event,
    SourceType.EVIDENCE: evidence_submitted_to_timeline_event,
    SourceType.EXPORT: export_to_timeline_event,
    SourceType.REPLAY: replay_verify_to_timeline_event,
    SourceType.FIELD_ASSESSMENT: field_assessment_to_timeline_event,
    SourceType.RISK_GOVERNANCE: risk_governance_to_timeline_event,
    SourceType.CONTROL_REGISTRY: control_registry_to_timeline_event,
    SourceType.GOVERNANCE_PORTAL: governance_portal_to_timeline_event,
    SourceType.GOVERNANCE_REPORTING: governance_reporting_to_timeline_event,
    SourceType.VERIFICATION_WORKFLOW: verification_workflow_to_timeline_event,
    SourceType.EVIDENCE_FRESHNESS: evidence_freshness_to_timeline_event,
    SourceType.FRESHNESS_SCORE_HISTORY: freshness_score_history_to_timeline_event,
    SourceType.CONTROL_EFFECTIVENESS: control_effectiveness_to_timeline_event,
}
