"""Deterministic monitoring identity derivation.

All functions are pure Python: no I/O, no side effects, no randomness.

Identity contract:
  - Replay-equivalent inputs MUST produce replay-equivalent identities.
  - Identities are SHA-256 digests of sorted, canonical JSON representations.
  - No timestamp-only identities (timestamps break replay equivalence).
  - No random UUIDs.
  - No insertion-order-dependent serialization.

Monitoring run identity:
  Derived from: tenant_id, assessment_id (or ""), framework_id (or ""),
  eval_window_start_iso, eval_window_end_iso, monitoring_contract_version.
  → Two runs with identical governance scope and evaluation window produce
    identical run_ids (idempotent scheduling).

Snapshot identity:
  Derived from: monitoring_run_id, evaluation_timestamp_iso.
  → Stable within a single run across replay.

Event fingerprint (for deduplication):
  Derived from: drift_type, affected_scope, monitoring_run_id,
  sorted(affected_control_ids).
  → Duplicate drift events within one run share a fingerprint.
"""

from __future__ import annotations

import hashlib
import json


def derive_monitoring_run_id(
    tenant_id: str,
    assessment_id: str,
    framework_id: str,
    eval_window_start_iso: str,
    eval_window_end_iso: str,
    monitoring_contract_version: str,
) -> str:
    """Derive a deterministic monitoring run ID from canonical governance inputs.

    Two evaluations with identical inputs produce the same run_id — enabling
    idempotent scheduling: submitting the same run twice is safe.
    """
    payload = json.dumps(
        {
            "tenant_id": tenant_id,
            "assessment_id": assessment_id,
            "framework_id": framework_id,
            "eval_window_start": eval_window_start_iso,
            "eval_window_end": eval_window_end_iso,
            "monitoring_contract_version": monitoring_contract_version,
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()[:32]


def derive_snapshot_id(
    monitoring_run_id: str,
    evaluation_timestamp_iso: str,
) -> str:
    """Derive a deterministic snapshot ID from the run and evaluation timestamp."""
    payload = json.dumps(
        {
            "monitoring_run_id": monitoring_run_id,
            "evaluation_timestamp_iso": evaluation_timestamp_iso,
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()[:32]


def derive_event_fingerprint(
    drift_type: str,
    affected_scope: str,
    monitoring_run_id: str,
    affected_control_ids: tuple[str, ...],
) -> str:
    """Derive a deterministic event fingerprint for deduplication.

    Events with identical fingerprints within a single run are duplicates.
    Deduplication keeps the highest-severity event.
    """
    payload = json.dumps(
        {
            "drift_type": drift_type,
            "affected_scope": affected_scope,
            "run_id": monitoring_run_id,
            "controls": sorted(affected_control_ids),
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()[:24]
