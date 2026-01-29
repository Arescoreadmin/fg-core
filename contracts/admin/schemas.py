"""Admin Gateway API Schemas.

Shared Pydantic models for admin-gateway API contracts.
"""

from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    """Health check response schema."""

    status: Literal["ok", "degraded", "unhealthy"] = Field(
        description="Service health status"
    )
    service: str = Field(description="Service name")
    version: str = Field(description="Service version")
    timestamp: datetime = Field(description="Response timestamp")
    request_id: Optional[str] = Field(default=None, description="Request tracking ID")


class VersionResponse(BaseModel):
    """Version information response schema."""

    service: str = Field(description="Service name")
    version: str = Field(description="Semantic version string")
    api_version: str = Field(description="API version")
    build_commit: Optional[str] = Field(default=None, description="Git commit hash")
    build_time: Optional[str] = Field(default=None, description="Build timestamp")


class AuditLogEntry(BaseModel):
    """Audit log entry schema."""

    timestamp: datetime = Field(description="Event timestamp")
    request_id: str = Field(description="Request tracking ID")
    action: str = Field(description="Action performed")
    actor: Optional[str] = Field(default=None, description="Actor identifier")
    resource: Optional[str] = Field(default=None, description="Resource affected")
    resource_id: Optional[str] = Field(default=None, description="Resource identifier")
    details: Optional[dict[str, Any]] = Field(
        default=None,
        description="Additional details",
        json_schema_extra={"additionalProperties": True},
    )
    outcome: Literal["success", "failure", "error"] = Field(
        description="Action outcome"
    )
    ip_address: Optional[str] = Field(default=None, description="Client IP address")
    user_agent: Optional[str] = Field(default=None, description="Client user agent")
