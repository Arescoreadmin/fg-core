"""Operational governance audit event emission.

Produces structured, immutable audit records for every governance lifecycle
action. Records must be replayable for SOC/legal/compliance export.

SECURITY: No raw secrets, credentials, infrastructure topology, or
privileged internal state are ever logged.
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any, Optional

log = logging.getLogger("frostgate.ops_governance.audit")

# Explicit allowlist — unknown keys are silently dropped.
_SAFE_DETAIL_KEYS = frozenset(
    {
        "lifecycle_state",
        "from_state",
        "to_state",
        "env_type",
        "compliance_classification",
        "isolation_level",
        "residency_classification",
        "recovery_readiness",
        "secret_classification",
        "secret_type",
        "rotation_state",
        "rotation_policy_days",
        "retention_state",
        "retention_classification",
        "retention_days",
        "legal_hold",
        "export_state",
        "export_scope",
        "export_classification",
        "backup_scope",
        "backup_state",
        "restore_state",
        "restore_scope",
        "validation_state",
        "recovery_state",
        "recovery_type",
        "drill_mode",
        "failure_category",
        "resource_type",
        "resource_id",
        "policy_ref",
        "override_reason",
    }
)


def compute_governance_event_hash(
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


def _get_previous_event_hash(db: Any, resource_id: str) -> Optional[str]:
    from api.db_models import OpsGovernanceAuditEventRecord

    row = (
        db.query(OpsGovernanceAuditEventRecord)
        .filter(OpsGovernanceAuditEventRecord.resource_id == resource_id)
        .order_by(OpsGovernanceAuditEventRecord.timestamp.desc())
        .first()
    )
    if row is None:
        return None
    return getattr(row, "event_hash", None)


def emit_governance_event(
    *,
    event_id: str,
    resource_type: str,
    resource_id: str,
    event_type: str,
    actor: str,
    timestamp_iso: str,
    outcome: str,
    tenant_id: Optional[str] = None,
    environment_id: Optional[str] = None,
    policy_state: Optional[str] = None,
    operational_context: Optional[str] = None,
    failure_reason: Optional[str] = None,
    details: Optional[dict[str, Any]] = None,
    event_hash: Optional[str] = None,
    previous_event_hash: Optional[str] = None,
) -> None:
    record: dict[str, Any] = {
        "audit_domain": "ops_governance",
        "event_id": event_id,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "event_type": event_type,
        "actor": actor,
        "timestamp": timestamp_iso,
        "outcome": outcome,
    }
    if tenant_id is not None:
        record["tenant_id"] = tenant_id
    if environment_id is not None:
        record["environment_id"] = environment_id
    if policy_state is not None:
        record["policy_state"] = policy_state
    if operational_context is not None:
        record["operational_context"] = operational_context
    if failure_reason is not None:
        record["failure_reason"] = failure_reason
    if event_hash is not None:
        record["event_hash"] = event_hash
    if previous_event_hash is not None:
        record["previous_event_hash"] = previous_event_hash
    if details:
        record["details"] = {k: v for k, v in details.items() if k in _SAFE_DETAIL_KEYS}

    log.info("ops_governance_audit_event %s", record)
