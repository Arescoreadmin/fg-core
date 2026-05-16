"""Readiness audit event emission.

Produces structured, immutable audit records for every readiness lifecycle
action. Records must be replayable for SOC/legal export.

No secrets or credentials are ever logged.
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any, Optional

from services.readiness.models import ReadinessEventType

log = logging.getLogger("frostgate.readiness.audit")

_SAFE_DETAIL_KEYS = frozenset(
    {
        "framework_id",
        "framework_slug",
        "framework_version",
        "framework_status",
        "version_tag",
        "domain_id",
        "domain_slug",
        "control_id",
        "control_identifier",
        "tier_id",
        "tier_identifier",
        "tier_order",
        "assessment_id",
        "assessment_status",
        "framework_version_tag",
        "snapshot_version",
        "result_id",
        "outcome",
        "evidence_id",
        "evidence_type",
        "evidence_classification",
        "contract_id",
        "scoring_schema_version",
        "resource_type",
        "resource_id",
        "mapping_type",
    }
)


def compute_event_hash(
    *,
    event_id: str,
    resource_type: str,
    resource_id: str,
    event_type: str,
    actor: str,
    timestamp_iso: str,
    outcome: str,
    previous_event_hash: Optional[str] = None,
) -> str:
    """Return SHA-256 hex of a canonical event representation.

    The canonical form is a deterministically sorted JSON object. The
    previous_event_hash chains events into a tamper-evident sequence:
    any tampering with a prior event invalidates all subsequent hashes.
    """
    canonical: dict[str, Any] = {
        "event_id": event_id,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "event_type": event_type,
        "actor": actor,
        "timestamp": timestamp_iso,
        "outcome": outcome,
        "previous_event_hash": previous_event_hash or "",
    }
    payload = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def _get_previous_event_hash(
    db: Any, resource_type: str, resource_id: str
) -> Optional[str]:
    """Return the event_hash of the most recent audit event for this resource."""
    from api.db_models import ReadinessAuditEventRecord

    row = (
        db.query(ReadinessAuditEventRecord)
        .filter(
            ReadinessAuditEventRecord.resource_type == resource_type,
            ReadinessAuditEventRecord.resource_id == resource_id,
        )
        .order_by(
            ReadinessAuditEventRecord.timestamp.desc(),
            ReadinessAuditEventRecord.id.desc(),
        )
        .first()
    )
    if row is None:
        return None
    return getattr(row, "event_hash", None)


def emit_readiness_event(
    *,
    event_id: str,
    resource_type: str,
    resource_id: str,
    event_type: ReadinessEventType,
    actor: str,
    timestamp_iso: str,
    outcome: str,
    tenant_id: Optional[str] = None,
    framework_id: Optional[str] = None,
    assessment_id: Optional[str] = None,
    details: Optional[dict[str, Any]] = None,
    event_hash: Optional[str] = None,
    previous_event_hash: Optional[str] = None,
) -> None:
    """Emit a structured audit log entry for a readiness lifecycle event.

    All readiness mutations MUST call this before returning to the caller.
    Fields are structured for SIEM ingestion. No stack traces, no secrets.
    """
    record: dict[str, Any] = {
        "audit_domain": "readiness",
        "event_id": event_id,
        "event_type": event_type.value,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "actor": actor,
        "timestamp": timestamp_iso,
        "outcome": outcome,
    }

    if tenant_id is not None:
        record["tenant_id"] = tenant_id
    if framework_id is not None:
        record["framework_id"] = framework_id
    if assessment_id is not None:
        record["assessment_id"] = assessment_id
    if event_hash is not None:
        record["event_hash"] = event_hash
    if previous_event_hash is not None:
        record["previous_event_hash"] = previous_event_hash
    if details:
        record["details"] = {k: v for k, v in details.items() if k in _SAFE_DETAIL_KEYS}

    log.info("readiness_audit_event %s", record)
