"""Export-safe deterministic serialization for alerting outputs.

All functions are pure Python: no I/O, no side effects.

Serialization contract:
  - Output is deterministic: identical AlertInstance → identical serialized form.
  - All dicts use sort_keys=True for canonical ordering.
  - No secrets, vectors, prompts, raw evidence bodies, PHI, or internal topology.
  - alert_run_output_json is NEVER exposed in API responses (stored internally only).
  - Historical alerts remain deserializable by future consumers that are version-aware.

Security invariants:
  - No "prompt" keys.
  - No "vector" or "embedding" keys.
  - No "secret" keys.
  - No PHI (patient health information) field names.
  - No "snapshot_json" or "alert_run_output_json" in serialized alert payloads.

# regulator_export_seam: the canonical JSON produced here is the input to regulator-grade
# export pipelines. A signed export wraps this payload with a detached Ed25519 or ECDSA-P256
# signature over the SHA-256 of the canonical bytes, enabling external auditors to verify
# alert provenance without re-running evaluation. The export boundary is this module —
# no transformation required before forwarding to a regulator export queue.
"""

from __future__ import annotations

import json

from .models import (
    AlertDeduplicationRecord,
    AlertEngineOutput,
    AlertInstance,
    AlertLifecycleTransition,
    AlertSuppressionRecord,
)

_FORBIDDEN_KEYS = frozenset(
    {
        "prompt",
        "vector",
        "embedding",
        "secret",
        "phi",
        "snapshot_json",
        "alert_run_output_json",
    }
)


def serialize_alert_instance(alert: AlertInstance) -> dict:
    """Serialize an AlertInstance to an export-safe dict.

    Returns a canonical dict with sort_keys ordering.
    No forbidden keys (prompt, vector, secret, PHI) are present.
    """
    return {
        "alert_instance_id": alert.alert_instance_id,
        "alert_fingerprint": alert.alert_fingerprint,
        "alert_rule_id": alert.alert_rule_id,
        "alert_rule_class": alert.alert_rule_class.value,
        "source_monitoring_run_id": alert.source_monitoring_run_id,
        "source_drift_event_fingerprint": alert.source_drift_event_fingerprint,
        "source_drift_snapshot_id": alert.source_drift_snapshot_id,
        "tenant_id": alert.tenant_id,
        "assessment_id": alert.assessment_id,
        "severity": alert.severity.value,
        "certainty": alert.certainty.value,
        "lifecycle_state": alert.lifecycle_state.value,
        "affected_scope": alert.affected_scope,
        "affected_control_ids": sorted(alert.affected_control_ids),
        "affected_evidence_ids": sorted(alert.affected_evidence_ids),
        "affected_framework_ids": sorted(alert.affected_framework_ids),
        "alert_detail": alert.alert_detail,
        "generated_at_iso": alert.generated_at_iso,
        "evaluation_window_start_iso": alert.evaluation_window_start_iso,
        "evaluation_window_end_iso": alert.evaluation_window_end_iso,
        "alert_generation_version": alert.alert_generation_version,
        "escalation_policy_version": alert.escalation_policy_version,
        "replay_contract_metadata": {k: v for k, v in alert.replay_contract_metadata},
    }


def serialize_dedup_record(record: AlertDeduplicationRecord) -> dict:
    return {
        "dedup_window_key": record.dedup_window_key,
        "alert_rule_id": record.alert_rule_id,
        "tenant_id": record.tenant_id,
        "first_seen_iso": record.first_seen_iso,
        "last_seen_iso": record.last_seen_iso,
        "occurrence_count": record.occurrence_count,
        "suppressed_count": record.suppressed_count,
        "window_start_iso": record.window_start_iso,
        "window_end_iso": record.window_end_iso,
    }


def serialize_alert_run_output(output: AlertEngineOutput) -> dict:
    """Serialize an AlertEngineOutput to an export-safe dict.

    NOTE: This serialized form is stored as alert_run_output_json internally.
    It is NEVER directly exposed in API responses — the API layer deserializes
    and returns individual alert records, not the raw run output JSON.
    """
    return {
        "run_id": output.run_id,
        "generation_timestamp_iso": output.generation_timestamp_iso,
        "total_alerts_generated": output.total_alerts_generated,
        "total_alerts_deduplicated": output.total_alerts_deduplicated,
        "total_alerts_suppressed": output.total_alerts_suppressed,
        "alerts": [serialize_alert_instance(a) for a in output.alerts],
        "dedup_records": [serialize_dedup_record(r) for r in output.dedup_records],
    }


def alert_output_to_json(output: AlertEngineOutput) -> str:
    """Serialize AlertEngineOutput to a canonical JSON string.

    Canonical: sort_keys=True for deterministic ordering.

    # signed_attestation_seam: this canonical JSON string is the byte sequence
    # to sign for governance attestation. A detached signature record
    # (key_id, algorithm, signature_b64) stored alongside this JSON enables
    # regulator/auditor/legal attestation without modifying the payload.
    """
    return json.dumps(serialize_alert_run_output(output), sort_keys=True)


def alert_output_from_json(raw: str) -> dict:
    """Deserialize a stored alert run output JSON string.

    Returns a plain dict for API use. Never re-exposes alert_run_output_json.
    """
    return json.loads(raw)


def serialize_lifecycle_transition(transition: AlertLifecycleTransition) -> dict:
    return {
        "transition_id": transition.transition_id,
        "alert_instance_id": transition.alert_instance_id,
        "tenant_id": transition.tenant_id,
        "from_state": transition.from_state.value,
        "to_state": transition.to_state.value,
        "actor": transition.actor,
        "reason": transition.reason,
        "transitioned_at_iso": transition.transitioned_at_iso,
        "replay_safe_metadata": {k: v for k, v in transition.replay_safe_metadata},
    }


def serialize_suppression_record(record: AlertSuppressionRecord) -> dict:
    return {
        "suppression_id": record.suppression_id,
        "alert_instance_id": record.alert_instance_id,
        "tenant_id": record.tenant_id,
        "suppression_reason": record.suppression_reason,
        "suppression_actor": record.suppression_actor,
        "suppression_source": record.suppression_source,
        "suppressed_at_iso": record.suppressed_at_iso,
        "expires_at_iso": record.expires_at_iso,
        "suppression_lineage_metadata": {
            k: v for k, v in record.suppression_lineage_metadata
        },
    }
