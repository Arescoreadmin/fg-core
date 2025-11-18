# api/schemas.py
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class TelemetryInput(BaseModel):
    """Simplified telemetry envelope for MVP."""
    source: str = Field(..., description="Service or node name")
    tenant_id: str = Field(..., description="Tenant or environment id")
    timestamp: str = Field(..., description="ISO8601 timestamp")
    payload: Dict[str, Any] = Field(..., description="Raw log / event / metric batch")


class MitigationAction(BaseModel):
    action: str = Field(..., description="What to do (block_ip, throttle_user, alert, etc.)")
    target: str = Field(..., description="IP, user, service, etc.")
    reason: str = Field(..., description="Plain language reason")
    confidence: float = Field(..., ge=0.0, le=1.0)


class ExplainBlock(BaseModel):
    summary: str
    rules_triggered: List[str] = []
    anomaly_score: float = 0.0
    llm_note: Optional[str] = None


class DefendResponse(BaseModel):
    threat_level: str = Field(..., description="low | medium | high | critical")
    mitigations: List[MitigationAction] = []
    explain: ExplainBlock
    ai_adversarial_score: float = 0.0
    pq_fallback: bool = False
    clock_drift_ms: int = 0
