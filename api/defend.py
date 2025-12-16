from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from typing import Any, List, Literal, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.auth import verify_api_key
from api.db import get_db
from api.db_models import DecisionRecord
from api.ratelimit import rate_limit_guard

router = APIRouter(
    prefix="/defend",
    tags=["defend"],
    dependencies=[Depends(verify_api_key), Depends(rate_limit_guard)],
)

# ---------- Models ----------

class TelemetryInput(BaseModel):
    source: str = Field(..., description="Telemetry source identifier (e.g., edge gateway id)")
    tenant_id: str = Field(..., description="Tenant identifier")
    timestamp: datetime = Field(..., description="Event timestamp (UTC)")
    payload: dict[str, Any] = Field(default_factory=dict, description="Raw telemetry payload")


class MitigationAction(BaseModel):
    action: str
    target: Optional[str] = None
    reason: str
    confidence: float = 1.0
    meta: Optional[dict[str, Any]] = None


class DecisionExplain(BaseModel):
    summary: str
    rules_triggered: List[str] = []
    anomaly_score: float = 0.0
    llm_note: Optional[str] = None
    tie_d: Optional[dict[str, Any]] = None


class DefendResponse(BaseModel):
    threat_level: Literal["none", "low", "medium", "high"]
    mitigations: List[MitigationAction] = []
    explain: DecisionExplain
    ai_adversarial_score: float = 0.0
    pq_fallback: bool = False
    clock_drift_ms: int


# ---------- Helpers ----------

def _to_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _event_age_ms(event_ts: datetime) -> int:
    now = datetime.now(timezone.utc)
    return int((now - _to_utc(event_ts)).total_seconds() * 1000)


def _clock_drift_ms(event_ts: datetime) -> int:
    age_ms = _event_age_ms(event_ts)
    stale_ms = int(os.getenv("FG_CLOCK_STALE_MS", "300000"))  # 5 min
    return 0 if abs(age_ms) > stale_ms else age_ms


# ---------- Route ----------

@router.post("", response_model=DefendResponse)
async def defend(request: TelemetryInput, db: Session = Depends(get_db)) -> DefendResponse:
    """
    MVP defender:
      - If payload.event_type == "auth" and failed_auths >= 5 -> high + block_ip
      - Otherwise -> low
    Logs decisions best-effort into DB.
    """
    start = time.perf_counter()
    payload = request.payload or {}

    event_type = payload.get("event_type")
    failed_auths = int(payload.get("failed_auths") or 0)
    src_ip = payload.get("src_ip")

    mitigations: list[MitigationAction] = []
    rules_triggered: list[str] = []
    threat_level: Literal["none", "low", "medium", "high"] = "low"
    anomaly_score = 0.1

    if event_type == "auth" and failed_auths >= 5 and src_ip:
        threat_level = "high"
        rules_triggered.append("rule:ssh_bruteforce")
        mitigations.append(
            MitigationAction(
                action="block_ip",
                target=src_ip,
                reason=f"{failed_auths} failed auth attempts detected",
                confidence=0.92,
            )
        )
        anomaly_score = 0.8
    else:
        rules_triggered.append("rule:default_allow")

    event_age_ms = _event_age_ms(request.timestamp)
    drift_ms = _clock_drift_ms(request.timestamp)
    latency_ms = int((time.perf_counter() - start) * 1000)

    decision = DefendResponse(
        threat_level=threat_level,
        mitigations=mitigations,
        explain=DecisionExplain(
            summary=f"MVP decision for tenant={request.tenant_id}, source={request.source}",
            rules_triggered=rules_triggered,
            anomaly_score=anomaly_score,
            llm_note="MVP stub – rules only.",
            tie_d={
                "event_age_ms": event_age_ms,
                "clock_drift_ms_reported": drift_ms,
                "latency_ms": latency_ms,
            },
        ),
        ai_adversarial_score=0.0,
        pq_fallback=False,
        clock_drift_ms=drift_ms,
    )

    # Best-effort persistence
    try:
        record = DecisionRecord.from_request_and_response(
            request=request,
            response=decision,
            latency_ms=latency_ms,
        )
        db.add(record)
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass

    return decision
