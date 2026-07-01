"""Health response helper for the Engagement Portal."""

from __future__ import annotations

from services.canonical import utc_iso8601_z_now
from services.engagement_portal.models import PORTAL_SCHEMA_VERSION
from services.engagement_portal.schemas import HealthResponse


def get_health_response() -> HealthResponse:
    """Return a deterministic health payload (no tenant context)."""
    return HealthResponse(
        status="ok",
        schema_version=PORTAL_SCHEMA_VERSION,
        timestamp=utc_iso8601_z_now(),
    )
