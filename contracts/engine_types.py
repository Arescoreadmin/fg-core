from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional


class ClassificationRing(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    SECRET = "SECRET"
    TOP_SECRET = "TOP_SECRET"


class Persona(str, Enum):
    GUARDIAN = "guardian"
    SENTINEL = "sentinel"


@dataclass(frozen=True)
class MitigationAction:
    action: str
    target: Optional[str] = None
    reason: Optional[str] = None
    confidence: float = 0.5
    meta: Optional[Dict[str, Any]] = None


@dataclass(frozen=True)
class TIEDEstimate:
    service_impact: float
    user_impact: float
    gating_decision: str
    notes: Optional[str] = None


@dataclass(frozen=True)
class TelemetryInput:
    source: str
    tenant_id: Optional[str] = None
    timestamp: Optional[str] = None
    classification: Optional[str] = None
    persona: Optional[str] = None
    payload: Dict[str, Any] = field(default_factory=dict)
    event: Dict[str, Any] = field(default_factory=dict)
    event_type: Optional[str] = None
    src_ip: Optional[str] = None
