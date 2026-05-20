"""SignedManifest schema — cryptographic proof of what was accessed."""

from __future__ import annotations

from pydantic import BaseModel, Field


class SignedManifest(BaseModel):
    """HMAC-signed record of every Graph endpoint called during the scan."""

    model_config = {"frozen": True}

    manifest_id: str  # UUID hex
    endpoints_called: list[str] = Field(default_factory=list)
    record_counts: dict[str, int] = Field(default_factory=dict)
    call_timestamps: dict[str, str] = Field(default_factory=dict)  # ISO 8601
    response_structure_hashes: dict[str, str] = Field(
        default_factory=dict
    )  # sha256(sorted keys)
    manifest_hmac: str  # HMAC-SHA256 of entire manifest
    signed_at: str  # ISO 8601
