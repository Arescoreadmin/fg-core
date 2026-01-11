from __future__ import annotations

from enum import Enum
from typing import Literal, Optional

from pydantic import BaseModel, Field


class ClassificationRing(str, Enum):
    UNCLASS = "UNCLASS"
    CUI = "CUI"
    SECRET = "SECRET"


class Persona(str, Enum):
    GUARDIAN = "guardian"
    SENTINEL = "sentinel"


class TIEDEstimate(BaseModel):
    service_impact: float = Field(default=0.0, ge=0.0, le=1.0)
    user_impact: float = Field(default=0.0, ge=0.0, le=1.0)
    gating_decision: Literal["allow", "require_approval", "reject"] = "allow"
    notes: Optional[str] = None


class TieD(BaseModel):
    roe_applied: bool = False
    disruption_limited: bool = False
    ao_required: bool = False

    persona: Optional[Persona] = None
    classification: Optional[ClassificationRing] = None

    service_impact: float = Field(default=0.0, ge=0.0, le=1.0)
    user_impact: float = Field(default=0.0, ge=0.0, le=1.0)

    gating_decision: Literal["allow", "require_approval", "reject"] = "allow"
    policy_version: str = "doctrine-v1"
