"""services/evidence_freshness_authority/schemas.py — Pydantic schemas for Evidence Freshness Authority.

All request schemas use extra="forbid" to prevent field injection.
All response schemas use extra="forbid" for contract stability.

PR 14.6.7 — Evidence Freshness Authority
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from services.evidence_freshness_authority.models import (
    FreshnessCriticality,
    FreshnessState,
)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class FreshnessPolicyNotFound(Exception):
    pass


class FreshnessRecordNotFound(Exception):
    pass


class FreshnessRecordConflict(Exception):
    pass


class FreshnessExceptionNotFound(Exception):
    pass


class FreshnessPolicyConflict(Exception):
    pass


# ---------------------------------------------------------------------------
# Request schemas — Policy
# ---------------------------------------------------------------------------


class CreateFreshnessPolicyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(default=None)
    evidence_type: Optional[str] = Field(default=None, max_length=64)
    review_interval_days: int = Field(default=90, ge=1)
    verification_interval_days: int = Field(default=180, ge=1)
    expiration_interval_days: int = Field(default=365, ge=1)
    criticality: FreshnessCriticality = FreshnessCriticality.MEDIUM
    enabled: bool = True


class UpdateFreshnessPolicyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    description: Optional[str] = Field(default=None)
    evidence_type: Optional[str] = Field(default=None, max_length=64)
    review_interval_days: Optional[int] = Field(default=None, ge=1)
    verification_interval_days: Optional[int] = Field(default=None, ge=1)
    expiration_interval_days: Optional[int] = Field(default=None, ge=1)
    criticality: Optional[FreshnessCriticality] = Field(default=None)
    enabled: Optional[bool] = Field(default=None)


# ---------------------------------------------------------------------------
# Request schemas — Freshness Record
# ---------------------------------------------------------------------------


def _validate_iso_datetime(v: Optional[str]) -> Optional[str]:
    if v is None:
        return v
    try:
        datetime.fromisoformat(v.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        raise ValueError("must be a valid ISO 8601 datetime string")
    return v


class CreateFreshnessRecordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(..., min_length=1, max_length=64)
    policy_id: Optional[str] = Field(default=None, max_length=64)
    review_due_at: Optional[str] = Field(default=None)
    verification_due_at: Optional[str] = Field(default=None)
    expiration_due_at: Optional[str] = Field(default=None)
    last_reviewed_at: Optional[str] = Field(default=None)
    last_verified_at: Optional[str] = Field(default=None)

    @field_validator(
        "review_due_at",
        "verification_due_at",
        "expiration_due_at",
        "last_reviewed_at",
        "last_verified_at",
        mode="before",
    )
    @classmethod
    def _validate_timestamps(cls, v: Optional[str]) -> Optional[str]:
        return _validate_iso_datetime(v)


class UpdateFreshnessRecordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy_id: Optional[str] = Field(default=None, max_length=64)
    review_due_at: Optional[str] = Field(default=None)
    verification_due_at: Optional[str] = Field(default=None)
    expiration_due_at: Optional[str] = Field(default=None)
    last_reviewed_at: Optional[str] = Field(default=None)
    last_verified_at: Optional[str] = Field(default=None)

    @field_validator(
        "review_due_at",
        "verification_due_at",
        "expiration_due_at",
        "last_reviewed_at",
        "last_verified_at",
        mode="before",
    )
    @classmethod
    def _validate_timestamps(cls, v: Optional[str]) -> Optional[str]:
        return _validate_iso_datetime(v)


# ---------------------------------------------------------------------------
# Request schemas — Exception
# ---------------------------------------------------------------------------


class CreateFreshnessExceptionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(..., min_length=1, max_length=64)
    reason: str = Field(..., min_length=1)
    approved_by: str = Field(..., min_length=1, max_length=255)
    expires_at: str = Field(..., description="ISO 8601 UTC expiration timestamp")

    @field_validator("expires_at", mode="before")
    @classmethod
    def _validate_expires_at(cls, v: Optional[str]) -> Optional[str]:
        return _validate_iso_datetime(v)


class RevokeFreshnessExceptionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(..., min_length=1)


# ---------------------------------------------------------------------------
# Response schemas — Policy
# ---------------------------------------------------------------------------


class FreshnessPolicyResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    name: str
    description: Optional[str]
    evidence_type: Optional[str]
    review_interval_days: int
    verification_interval_days: int
    expiration_interval_days: int
    criticality: str
    enabled: bool
    created_at: str
    updated_at: str


class FreshnessPolicyListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[FreshnessPolicyResponse]
    total: int


# ---------------------------------------------------------------------------
# Response schemas — Freshness Record
# ---------------------------------------------------------------------------


class FreshnessRecordResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    evidence_id: str
    policy_id: Optional[str]
    review_due_at: Optional[str]
    verification_due_at: Optional[str]
    expiration_due_at: Optional[str]
    last_reviewed_at: Optional[str]
    last_verified_at: Optional[str]
    freshness_score: int
    freshness_state: FreshnessState
    created_at: str
    updated_at: str


class FreshnessRecordListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[FreshnessRecordResponse]
    total: int


# ---------------------------------------------------------------------------
# Response schemas — Exception
# ---------------------------------------------------------------------------


class FreshnessExceptionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    tenant_id: str
    evidence_id: str
    reason: str
    approved_by: str
    expires_at: str
    status: str
    created_at: str


class FreshnessExceptionListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[FreshnessExceptionResponse]
    total: int


# ---------------------------------------------------------------------------
# Response schemas — Dashboard & Analytics
# ---------------------------------------------------------------------------


class FreshnessDashboardResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fresh_count: int
    due_soon_count: int
    review_required_count: int
    verification_required_count: int
    stale_count: int
    expired_count: int
    total: int
    avg_freshness_score: float
    freshness_exceptions_count: int
    coverage_at_risk_count: int


class FreshnessCGINSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    snapshot_at: str
    tenant_id: str
    fresh_evidence: int
    stale_evidence: int
    expired_evidence: int
    avg_freshness_score: float
    coverage_at_risk: int
    freshness_exceptions_count: int
