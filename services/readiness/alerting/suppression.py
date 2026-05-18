"""Alert suppression — deterministic suppression management.

All functions are pure Python: no I/O, no side effects, no randomness.

Suppression contract:
  - Suppressions have explicit expiration (no permanent hidden suppression).
  - Suppressed alerts remain visible as SUPPRESSED (never erased).
  - is_suppressed() checks both the active list and expiration timestamps.
  - Expired suppressions do NOT make an alert suppressed.
  - create_suppression() always returns an immutable AlertSuppressionRecord.

Expiration contract:
  - expires_at_iso=None means the suppression does NOT expire (policy-driven).
  - Expired suppressions are records of past suppression — not deleted.
  - The caller is responsible for comparing now_iso to expires_at_iso.
"""

from __future__ import annotations

from .identity import derive_suppression_id
from .models import AlertSuppressionRecord


def is_suppressed(
    alert_instance_id: str,
    active_suppressions: list[AlertSuppressionRecord],
    now_iso: str,
) -> bool:
    """Return True if the alert is currently suppressed by any active suppression.

    A suppression is active if:
      - Its alert_instance_id matches.
      - Its expires_at_iso is None (no expiration) or is after now_iso.

    ISO 8601 string comparison works correctly for UTC timestamps in this format.
    """
    for suppression in active_suppressions:
        if suppression.alert_instance_id != alert_instance_id:
            continue
        if suppression.expires_at_iso is None:
            # No expiration — suppression is active indefinitely.
            return True
        # Check expiration via ISO string comparison (UTC only).
        if suppression.expires_at_iso > now_iso:
            return True
    return False


def create_suppression(
    alert_instance_id: str,
    tenant_id: str,
    reason: str,
    actor: str,
    source: str,
    now_iso: str,
    expires_at_iso: str | None,
) -> AlertSuppressionRecord:
    """Create an immutable suppression record.

    # signed_attestation_seam: suppression records are governance artifacts that
    # may require regulator-grade attestation. At this boundary, a detached
    # signature (key_id, algorithm, signature_b64) over the canonical suppression
    # record JSON can be attached for audit chain integrity. This enables external
    # auditors to verify that suppression was authorized and non-repudiable.
    """
    suppression_id = derive_suppression_id(
        alert_instance_id=alert_instance_id,
        suppression_actor=actor,
        suppressed_at_iso=now_iso,
    )
    return AlertSuppressionRecord(
        suppression_id=suppression_id,
        alert_instance_id=alert_instance_id,
        tenant_id=tenant_id,
        suppression_reason=reason,
        suppression_actor=actor,
        suppression_source=source,
        suppressed_at_iso=now_iso,
        expires_at_iso=expires_at_iso,
        suppression_lineage_metadata=(
            ("suppression_id", suppression_id),
            ("actor", actor),
            ("source", source),
        ),
    )
