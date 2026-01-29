"""Admin Gateway API Schemas.

Shared Pydantic models for admin-gateway API contracts.
"""

from datetime import datetime
from typing import Any, Literal, Optional, Union

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


class AuditEvent(BaseModel):
    """Audit event schema."""

    id: Union[str, int] = Field(description="Audit event identifier")
    ts: datetime = Field(description="Event timestamp (RFC3339)")
    tenant_id: str = Field(description="Tenant identifier")
    actor: Optional[str] = Field(default=None, description="Actor identifier")
    action: str = Field(description="Action performed")
    status: Literal["success", "deny", "error"] = Field(
        description="Action outcome"
    )
    resource_type: Optional[str] = Field(
        default=None, description="Resource type"
    )
    resource_id: Optional[str] = Field(
        default=None, description="Resource identifier"
    )
    request_id: Optional[str] = Field(default=None, description="Request tracking ID")
    ip: Optional[str] = Field(default=None, description="Client IP address")
    user_agent: Optional[str] = Field(default=None, description="Client user agent")
    meta: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional metadata",
        json_schema_extra={"additionalProperties": True},
    )
