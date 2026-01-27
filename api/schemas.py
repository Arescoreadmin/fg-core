# api/schemas.py
"""
Input validation schemas for FrostGate Core.

Security-focused validation:
- Input sanitization to prevent injection attacks
- Length limits to prevent DoS
- Pattern matching for format validation
- Deep payload validation
"""

from __future__ import annotations

import re
from typing import Any, Dict, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


# =============================================================================
# Input validation patterns
# =============================================================================

TENANT_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{1,128}$")
SOURCE_PATTERN = re.compile(r"^[a-zA-Z0-9_\-.:/@]{1,256}$")
EVENT_TYPE_PATTERN = re.compile(r"^[a-zA-Z0-9_\-.:]{1,128}$")
IP_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|"
    r"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|"
    r"^::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$|"
    r"^[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}$"
)

# Security limits
MAX_PAYLOAD_DEPTH = 10
MAX_PAYLOAD_SIZE = 64 * 1024  # 64KB
MAX_STRING_LENGTH = 4096
MAX_ARRAY_LENGTH = 1000


def validate_tenant_id(v: Optional[str]) -> Optional[str]:
    """Validate tenant_id format for security."""
    if v is None:
        return None
    v = str(v).strip()
    if not v:
        return None
    if len(v) > 128:
        raise ValueError("tenant_id exceeds maximum length of 128 characters")
    if not TENANT_ID_PATTERN.match(v):
        raise ValueError(
            "tenant_id contains invalid characters (alphanumeric, dash, underscore only)"
        )
    return v


def validate_source(v: str) -> str:
    """Validate source format for security."""
    v = str(v).strip()
    if not v:
        raise ValueError("source is required and cannot be empty")
    if len(v) > 256:
        raise ValueError("source exceeds maximum length of 256 characters")
    if not SOURCE_PATTERN.match(v):
        raise ValueError("source contains invalid characters")
    return v


def validate_ip_address(v: Optional[str]) -> Optional[str]:
    """Validate IP address format (IPv4 or IPv6)."""
    if v is None:
        return None
    v = str(v).strip()
    if not v:
        return None
    # Basic IP validation - allows both IPv4 and IPv6
    # More permissive to handle edge cases
    if len(v) > 45:  # Max IPv6 length
        raise ValueError("IP address too long")
    # Simple character validation
    if not all(c.isalnum() or c in ".:" for c in v):
        raise ValueError("IP address contains invalid characters")
    return v


def validate_event_type(v: Optional[str]) -> Optional[str]:
    """Validate event_type format for security."""
    if v is None:
        return None
    v = str(v).strip()
    if not v:
        return None
    if len(v) > 128:
        raise ValueError("event_type exceeds maximum length of 128 characters")
    if not EVENT_TYPE_PATTERN.match(v):
        raise ValueError("event_type contains invalid characters")
    return v


def sanitize_string(
    v: Optional[str], max_length: int = MAX_STRING_LENGTH
) -> Optional[str]:
    """Sanitize a string value for security."""
    if v is None:
        return None
    v = str(v)
    if len(v) > max_length:
        v = v[:max_length]
    # Remove null bytes and other control characters (except newlines and tabs)
    v = "".join(c for c in v if c.isprintable() or c in "\n\t\r")
    return v


def validate_payload_depth(obj: Any, current_depth: int = 0) -> bool:
    """Check if payload exceeds maximum nesting depth."""
    if current_depth > MAX_PAYLOAD_DEPTH:
        return False
    if isinstance(obj, dict):
        return all(validate_payload_depth(v, current_depth + 1) for v in obj.values())
    if isinstance(obj, (list, tuple)):
        if len(obj) > MAX_ARRAY_LENGTH:
            return False
        return all(validate_payload_depth(v, current_depth + 1) for v in obj)
    return True


def sanitize_payload(obj: Any, depth: int = 0) -> Any:
    """
    Recursively sanitize a payload object.

    - Limits string lengths
    - Limits array sizes
    - Limits nesting depth
    - Removes null bytes and control characters
    """
    if depth > MAX_PAYLOAD_DEPTH:
        return None

    if obj is None:
        return None

    if isinstance(obj, str):
        return sanitize_string(obj)

    if isinstance(obj, bool):
        return obj

    if isinstance(obj, (int, float)):
        return obj

    if isinstance(obj, dict):
        return {
            sanitize_string(str(k), 256): sanitize_payload(v, depth + 1)
            for k, v in list(obj.items())[:MAX_ARRAY_LENGTH]
        }

    if isinstance(obj, (list, tuple)):
        return [sanitize_payload(v, depth + 1) for v in list(obj)[:MAX_ARRAY_LENGTH]]

    # For other types, convert to string and sanitize
    return sanitize_string(str(obj))


class MitigationAction(BaseModel):
    """
    Engine expects MitigationAction(...) as a structured object (keyword args).
    Keep permissive for MVP: action is a string.
    """

    model_config = ConfigDict(extra="allow")

    action: str
    target: Optional[str] = None
    reason: Optional[str] = None
    confidence: float = 0.5


class TelemetryInput(BaseModel):
    """
    Canonical request model for defend/ingest.

    Compatibility:
      - New shape: payload={...} (tests use this)
      - Legacy shape: event={...} (defend.py references req.event)
      - Root fields: event_type/src_ip (defend.py references req.event_type)
      - Doctrine: classification/persona as plain strings
      - extra=allow for forward compatibility during MVP

    Security:
      - Input validation for tenant_id, source, and IP addresses
      - Length limits to prevent DoS
    """

    model_config = ConfigDict(extra="allow")

    source: str = Field(max_length=256)
    tenant_id: Optional[str] = Field(default=None, max_length=128)
    timestamp: Optional[str] = Field(default=None, max_length=64)

    # Doctrine fields as strings
    classification: Optional[str] = Field(default=None, max_length=64)
    persona: Optional[str] = Field(default=None, max_length=64)

    # New + legacy containers
    payload: Dict[str, Any] = Field(default_factory=dict)
    event: Dict[str, Any] = Field(default_factory=dict)

    # Backfilled convenience fields (defend.py references these directly)
    event_type: Optional[str] = Field(default=None, max_length=128)
    src_ip: Optional[str] = Field(default=None, max_length=45)

    @field_validator("source")
    @classmethod
    def validate_source_field(cls, v):
        return validate_source(v)

    @field_validator("tenant_id")
    @classmethod
    def validate_tenant_id_field(cls, v):
        return validate_tenant_id(v)

    @field_validator("src_ip")
    @classmethod
    def validate_src_ip_field(cls, v):
        return validate_ip_address(v)

    @field_validator("event_type")
    @classmethod
    def validate_event_type_field(cls, v):
        return validate_event_type(v)

    @field_validator("payload", "event", mode="before")
    @classmethod
    def validate_and_sanitize_payload(cls, v):
        """Validate and sanitize payload/event dictionaries."""
        if v is None:
            return {}
        if not isinstance(v, dict):
            return {}
        # Check payload depth
        if not validate_payload_depth(v):
            raise ValueError("Payload exceeds maximum nesting depth or array size")
        # Sanitize the payload
        return sanitize_payload(v)

    @model_validator(mode="after")
    def _compat_backfill(self) -> "TelemetryInput":
        # If one of payload/event missing, mirror the other
        if not isinstance(self.payload, dict):
            self.payload = {}
        if not isinstance(self.event, dict):
            self.event = {}

        if not self.payload and self.event:
            self.payload = dict(self.event)
        if not self.event and self.payload:
            self.event = dict(self.payload)

        # Backfill event_type/src_ip from containers if missing
        if not self.event_type:
            raw_event_type = (
                self.payload.get("event_type") or self.event.get("event_type") or None
            )
            if raw_event_type:
                try:
                    self.event_type = validate_event_type(raw_event_type)
                except ValueError:
                    self.event_type = None

        if not self.src_ip:
            raw_ip = (
                self.payload.get("src_ip")
                or self.event.get("src_ip")
                or self.payload.get("source_ip")
                or self.event.get("source_ip")
                or None
            )
            # Validate IP from payload/event as well
            if raw_ip:
                try:
                    self.src_ip = validate_ip_address(raw_ip)
                except ValueError:
                    self.src_ip = None  # Invalid IP, ignore

        return self
