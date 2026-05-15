"""Provisioning audit event emission.

Produces structured, immutable audit records for every provisioning lifecycle
action. Records must be replayable for SOC/legal export.

No secrets or credentials are ever logged.
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any, Optional

from services.provisioning.models import OrgEventType

log = logging.getLogger("frostgate.provisioning.audit")

_SAFE_DETAIL_KEYS = frozenset(
    {
        "org_name",
        "slug",
        "compliance_classification",
        "deployment_tier",
        "onboarding_state",
        "lifecycle_status",
        "env_assignment_id",
        "env_target",
        "retry_count",
        "failure_category",
        "workflow_state",
        "validation_passed",
        "region",
    }
)


def compute_event_hash(
    *,
    event_id: str,
    organization_id: str,
    event_type: str,
    actor: str,
    timestamp_iso: str,
    outcome: str,
    previous_event_hash: Optional[str] = None,
) -> str:
    """Return SHA-256 hex of a canonical event representation.

    The canonical form is a deterministically sorted JSON object of the fields
    listed above. previous_event_hash chains events into a tamper-evident
    sequence: any tampering with a prior event invalidates all subsequent hashes.
    """
    canonical: dict[str, Any] = {
        "event_id": event_id,
        "organization_id": organization_id,
        "event_type": event_type,
        "actor": actor,
        "timestamp": timestamp_iso,
        "outcome": outcome,
        "previous_event_hash": previous_event_hash or "",
    }
    payload = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def _get_previous_event_hash(db: Any, organization_id: str) -> Optional[str]:
    """Return the event_hash of the most recent audit event for this org."""
    from api.db_models import ProvisioningAuditEventRecord

    row = (
        db.query(ProvisioningAuditEventRecord)
        .filter(ProvisioningAuditEventRecord.organization_id == organization_id)
        .order_by(ProvisioningAuditEventRecord.timestamp.desc())
        .first()
    )
    if row is None:
        return None
    return getattr(row, "event_hash", None)


def emit_provisioning_event(
    *,
    event_id: str,
    organization_id: str,
    event_type: OrgEventType,
    actor: str,
    timestamp_iso: str,
    outcome: str,
    provisioning_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    env_id: Optional[str] = None,
    workflow_state: Optional[str] = None,
    failure_reason: Optional[str] = None,
    details: Optional[dict[str, Any]] = None,
    event_hash: Optional[str] = None,
    previous_event_hash: Optional[str] = None,
) -> None:
    """Emit a structured audit log entry for a provisioning event.

    This is the canonical audit emission point. All provisioning mutations
    MUST call this before returning to the caller.

    Fields are structured for SIEM ingestion. No stack traces, no secrets,
    no raw error messages are included.
    """
    record: dict[str, Any] = {
        "audit_domain": "provisioning",
        "event_id": event_id,
        "event_type": event_type.value,
        "organization_id": organization_id,
        "actor": actor,
        "timestamp": timestamp_iso,
        "outcome": outcome,
    }

    if provisioning_id is not None:
        record["provisioning_id"] = provisioning_id
    if tenant_id is not None:
        record["tenant_id"] = tenant_id
    if env_id is not None:
        record["env_id"] = env_id
    if workflow_state is not None:
        record["workflow_state"] = workflow_state
    if failure_reason is not None:
        record["failure_reason"] = failure_reason
    if event_hash is not None:
        record["event_hash"] = event_hash
    if previous_event_hash is not None:
        record["previous_event_hash"] = previous_event_hash
    if details:
        record["details"] = {k: v for k, v in details.items() if k in _SAFE_DETAIL_KEYS}

    log.info("provisioning_audit_event %s", record)
