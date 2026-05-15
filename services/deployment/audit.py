"""Deployment audit event emission.

Produces structured, immutable audit records for every deployment lifecycle
action. Records must be replayable for SOC/legal export.

No secrets or credentials are ever logged.
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any, Optional

from services.deployment.models import (
    DeploymentEventType,
    DeploymentState,
)

log = logging.getLogger("frostgate.deployment.audit")

_SAFE_DETAIL_KEYS = frozenset(
    {
        "version_ref",
        "strategy",
        "artifact_hash",
        "rollback_from_id",
        "rollback_reason",
        "health_readiness",
        "health_liveness",
        "health_smoke_test",
        "health_validation",
        "rollback_trigger_reason",
        "compliance_classification",
        "env_type",
        "approval_granted_by",
        "approval_reason",
        "approval_policy_version",
        "spec_commit_sha",
        "spec_contract_hash",
        "spec_topology_hash",
        "spec_policy_bundle_version",
    }
)


def compute_event_hash(
    *,
    event_id: str,
    deployment_id: str,
    event_type: str,
    actor: str,
    timestamp_iso: str,
    from_state: Optional[str] = None,
    to_state: Optional[str] = None,
    previous_event_hash: Optional[str] = None,
) -> str:
    """Return SHA-256 hex of a canonical event representation.

    The canonical form is a deterministically sorted JSON object of the fields
    listed above. previous_event_hash chains events into a tamper-evident
    sequence: any tampering with a prior event invalidates all subsequent hashes.
    """
    canonical: dict[str, Any] = {
        "event_id": event_id,
        "deployment_id": deployment_id,
        "event_type": event_type,
        "actor": actor,
        "timestamp": timestamp_iso,
        "from_state": from_state or "",
        "to_state": to_state or "",
        "previous_event_hash": previous_event_hash or "",
    }
    payload = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def emit_deployment_event(
    *,
    event_id: str,
    deployment_id: str,
    env_id: str,
    event_type: DeploymentEventType,
    actor: str,
    timestamp_iso: str,
    tenant_id: Optional[str] = None,
    from_state: Optional[DeploymentState] = None,
    to_state: Optional[DeploymentState] = None,
    details: Optional[dict[str, Any]] = None,
    event_hash: Optional[str] = None,
    previous_event_hash: Optional[str] = None,
    trace_id: Optional[str] = None,
) -> None:
    """Emit a structured audit log entry for a deployment event.

    This is the canonical audit emission point. All deployment mutations
    MUST call this before returning to the caller.

    Fields are structured for SIEM ingestion. No stack traces, no secrets,
    no raw error messages are included.
    """
    record: dict[str, Any] = {
        "audit_domain": "deployment",
        "event_id": event_id,
        "event_type": event_type.value,
        "deployment_id": deployment_id,
        "env_id": env_id,
        "actor": actor,
        "timestamp": timestamp_iso,
    }

    if tenant_id is not None:
        record["tenant_id"] = tenant_id
    if from_state is not None:
        record["from_state"] = from_state.value
    if to_state is not None:
        record["to_state"] = to_state.value
    if event_hash is not None:
        record["event_hash"] = event_hash
    if previous_event_hash is not None:
        record["previous_event_hash"] = previous_event_hash
    if trace_id is not None:
        record["trace_id"] = trace_id
    if details:
        record["details"] = {k: v for k, v in details.items() if k in _SAFE_DETAIL_KEYS}

    log.info("deployment_audit_event %s", record)
