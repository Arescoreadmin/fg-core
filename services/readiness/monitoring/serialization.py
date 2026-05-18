"""Export-safe deterministic serialization for monitoring outputs.

All functions are pure Python: no I/O, no side effects.

Serialization contract:
  - Output is deterministic: identical DriftSnapshot → identical serialized form.
  - All dicts use sort_keys=True for canonical ordering.
  - No secrets, vectors, prompts, raw evidence bodies, PHI, or internal topology.
  - All export-safe fields are preserved; no additional scrubbing needed downstream.
  - Historical snapshots remain deserializable by future consumers that are version-aware.
"""

from __future__ import annotations

import json

from .models import DriftEvent, DriftSnapshot


def serialize_event(event: DriftEvent) -> dict:
    return {
        "event_fingerprint": event.event_fingerprint,
        "drift_type": event.drift_type.value,
        "severity": event.severity.value,
        "certainty": event.certainty.value,
        "affected_scope": event.affected_scope,
        "affected_control_ids": sorted(event.affected_control_ids),
        "affected_evidence_ids": sorted(event.affected_evidence_ids),
        "affected_framework_ids": sorted(event.affected_framework_ids),
        "drift_detail": event.drift_detail,
        "monitoring_source": event.monitoring_source,
        "evaluation_timestamp_iso": event.evaluation_timestamp_iso,
        "temporal_boundary_start": event.temporal_boundary_start,
        "temporal_boundary_end": event.temporal_boundary_end,
        "provenance_metadata": {k: v for k, v in event.provenance_metadata},
    }


def serialize_snapshot(snapshot: DriftSnapshot) -> dict:
    return {
        "snapshot_id": snapshot.snapshot_id,
        "monitoring_run_id": snapshot.monitoring_run_id,
        "evaluation_timestamp_iso": snapshot.evaluation_timestamp_iso,
        "monitoring_contract_version": snapshot.monitoring_contract_version,
        "evaluation_engine_version": snapshot.evaluation_engine_version,
        "drift_classification_version": snapshot.drift_classification_version,
        "severity_classification_version": snapshot.severity_classification_version,
        "tenant_id": snapshot.tenant_id,
        "assessment_id": snapshot.assessment_id,
        "framework_ids": sorted(snapshot.framework_ids),
        "eval_window_start_iso": snapshot.eval_window_start_iso,
        "eval_window_end_iso": snapshot.eval_window_end_iso,
        "evidence_freshness_window_days": snapshot.evidence_freshness_window_days,
        "total_drift_events": snapshot.total_drift_events,
        "critical_or_blocking_count": snapshot.critical_or_blocking_count,
        "domains_evaluated": list(snapshot.domains_evaluated),
        "replay_contract_metadata": {
            k: v for k, v in snapshot.replay_contract_metadata
        },
        "events": [serialize_event(e) for e in snapshot.events],
    }


def snapshot_to_json(snapshot: DriftSnapshot) -> str:
    # attestation_seam: cryptographic signing of the canonical JSON goes here.
    # The output of json.dumps(..., sort_keys=True) is the canonical byte sequence
    # to sign. A detached signature record (key_id, algorithm, signature_b64)
    # stored alongside snapshot_json enables regulator/auditor/legal attestation
    # without modifying the snapshot payload itself.
    return json.dumps(serialize_snapshot(snapshot), sort_keys=True)


def snapshot_from_json(raw: str) -> dict:
    """Deserialize a stored snapshot JSON string. Returns a plain dict for API use."""
    return json.loads(raw)
