"""Health response builder for the Remediation Authority."""

from __future__ import annotations

from services.remediation_authority.models import (
    REMEDIATION_AUTHORITY_SCHEMA_VERSION,
)
from services.remediation_authority.schemas import HealthResponse


AUTHORITY_NAME = "remediation_authority"
AUTHORITY_VERSION = "1.0.0"


def build_health(db_ok: bool = True) -> HealthResponse:
    """Return a HealthResponse based on the supplied checks."""
    checks = {"database": "ok" if db_ok else "error"}
    status = "ok" if db_ok else "degraded"
    return HealthResponse(
        status=status,
        authority=AUTHORITY_NAME,
        version=AUTHORITY_VERSION,
        schema_version=REMEDIATION_AUTHORITY_SCHEMA_VERSION,
        checks=checks,
    )
