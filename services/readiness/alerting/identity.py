"""Deterministic alert identity derivation.

All functions are pure Python: no I/O, no side effects, no randomness.

Identity contract:
  - Replay-equivalent inputs MUST produce replay-equivalent identities.
  - Identities are SHA-256 digests of sorted, canonical JSON representations.
  - No timestamp-only identities (timestamps break replay equivalence).
  - No random UUIDs.
  - No insertion-order-dependent serialization.

Alert instance identity:
  Derived from: rule_id, source_run_id, source_event_fingerprint, tenant_id.
  → Two alerts generated from identical drift events under the same rule produce
    identical alert_instance_ids (idempotent generation).

Alert fingerprint (for deduplication):
  Derived from: rule_id, source_event_fingerprint, tenant_id, assessment_id.
  → Alerts sharing a fingerprint within a cooldown window are deduplicated.
"""

from __future__ import annotations

import hashlib
import json


def derive_alert_instance_id(
    rule_id: str,
    source_run_id: str,
    source_event_fingerprint: str,
    tenant_id: str,
) -> str:
    """Derive a deterministic alert instance ID.

    Two alerts from the same drift event under the same rule produce the
    same alert_instance_id — enabling idempotent alert generation.
    """
    payload = json.dumps(
        {
            "rule_id": rule_id,
            "source_run_id": source_run_id,
            "source_event_fingerprint": source_event_fingerprint,
            "tenant_id": tenant_id,
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()[:32]


def derive_alert_fingerprint(
    rule_id: str,
    source_event_fingerprint: str,
    tenant_id: str,
    assessment_id: str,
) -> str:
    """Derive a deterministic alert fingerprint for deduplication.

    Alerts with identical fingerprints within a cooldown window are candidates
    for deduplication. The fingerprint encodes what was collapsed.
    """
    payload = json.dumps(
        {
            "rule_id": rule_id,
            "source_event_fingerprint": source_event_fingerprint,
            "tenant_id": tenant_id,
            "assessment_id": assessment_id,
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()[:24]


def derive_suppression_id(
    alert_instance_id: str,
    suppression_actor: str,
    suppressed_at_iso: str,
) -> str:
    """Derive a deterministic suppression ID."""
    payload = json.dumps(
        {
            "alert_instance_id": alert_instance_id,
            "suppression_actor": suppression_actor,
            "suppressed_at_iso": suppressed_at_iso,
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()[:24]


def derive_escalation_id(
    alert_instance_id: str,
    escalation_target_class: str,
    escalated_at_iso: str,
) -> str:
    """Derive a deterministic escalation ID."""
    payload = json.dumps(
        {
            "alert_instance_id": alert_instance_id,
            "escalation_target_class": escalation_target_class,
            "escalated_at_iso": escalated_at_iso,
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()[:24]


def derive_transition_id(
    alert_instance_id: str,
    from_state: str,
    to_state: str,
    transitioned_at_iso: str,
) -> str:
    """Derive a deterministic lifecycle transition ID."""
    payload = json.dumps(
        {
            "alert_instance_id": alert_instance_id,
            "from_state": from_state,
            "to_state": to_state,
            "transitioned_at_iso": transitioned_at_iso,
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()[:24]
