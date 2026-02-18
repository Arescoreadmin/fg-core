from __future__ import annotations

from pydantic import BaseModel, Field


class DashboardContext(BaseModel):
    """Shared dashboard filter/drilldown context used across registry + snapshot."""

    time_range: str = Field(default="24h", min_length=2, max_length=32)
    source: str | None = Field(default=None, max_length=128)
    threat_level: str | None = Field(default=None, max_length=32)
    event_type: str | None = Field(default=None, max_length=128)
    q: str | None = Field(default=None, max_length=256)


DEFAULT_DASHBOARD_CONTEXT = DashboardContext()
