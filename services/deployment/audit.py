"""Deployment audit event emission.

Produces structured, immutable audit records for every deployment lifecycle
action. Records must be replayable for SOC/legal export.

No secrets or credentials are ever logged.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from services.deployment.models import (
    DeploymentEventType,
    DeploymentState,
)

log = logging.getLogger("frostgate.deployment.audit")


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
    if trace_id is not None:
        record["trace_id"] = trace_id
    if details:
        # Only safe, bounded fields from details are forwarded.
        safe_keys = {
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
        }
        record["details"] = {k: v for k, v in details.items() if k in safe_keys}

    log.info("deployment_audit_event %s", record)
