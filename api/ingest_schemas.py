from __future__ import annotations

from typing import Any, Dict, Optional
from pydantic import BaseModel, Field

from api.schemas import TelemetryInput


class IngestRequest(TelemetryInput):
    event_id: str


class IngestResponse(BaseModel):
    status: str = "ok"
    event_id: str
    tenant_id: str
    source: str
    event_type: str
    decision: Dict[str, Any] = Field(default_factory=dict)
    config_hash: str

    # Optional convenience fields (for UI / search / filtering)
    threat_level: Optional[str] = None
    latency_ms: Optional[int] = None
    persisted: bool = True
