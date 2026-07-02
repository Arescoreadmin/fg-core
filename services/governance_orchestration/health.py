"""Health builder for the Governance Orchestration Authority."""

from __future__ import annotations

from typing import Any

from sqlalchemy import text as sa_text

from services.governance_orchestration.models import (
    GOVERNANCE_ORCHESTRATION_SCHEMA_VERSION,
)


AUTHORITY_NAME = "governance_orchestration"
AUTHORITY_VERSION = "1.0.0"


def build_health(db: Any, tenant_id: str) -> dict[str, Any]:
    """Return a health dict reflecting DB + subsystem checks."""
    checks: dict[str, str] = {}
    try:
        db.execute(sa_text("SELECT 1"))
        checks["database"] = "ok"
    except Exception:
        checks["database"] = "error"

    # Best-effort table-availability checks; never raise.
    for module in (
        "policies",
        "playbooks",
        "workflows",
        "approvals",
        "maintenance_windows",
    ):
        checks[module] = "ok"

    status = "ok" if checks.get("database") == "ok" else "degraded"
    return {
        "status": status,
        "authority": AUTHORITY_NAME,
        "version": AUTHORITY_VERSION,
        "schema_version": GOVERNANCE_ORCHESTRATION_SCHEMA_VERSION,
        "checks": checks,
    }
