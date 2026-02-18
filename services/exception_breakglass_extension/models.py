from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class ExceptionRequestCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subject_type: str
    subject_id: str
    justification: str
    expires_at_utc: str
    scope: str | None = None
    risk_tier: str | None = None


class ExceptionApproval(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approver_role: str
    notes: str | None = None


class BreakglassSessionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str
    expires_at_utc: str
