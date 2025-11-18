# api/main.py
from datetime import datetime, timezone
from typing import Dict, Any

from fastapi import FastAPI, Request, Header
from loguru import logger

from .schemas import TelemetryInput, DefendResponse, MitigationAction, ExplainBlock
from .config import settings

app = FastAPI(
    title="FrostGate Core API",
    version="0.1.0",
    description="MVP defense API for FrostGate Core `/defend`."
)


@app.on_event("startup")
async def startup_event():
    logger.info("FrostGate Core API starting in env={}", settings.env)


@app.get("/health")
async def health() -> Dict[str, Any]:
    return {"status": "ok", "env": settings.env}


@app.get("/status")
async def status() -> Dict[str, Any]:
    # Stubbed for now; later wire to real metrics
    return {
        "service": "frostgate-core",
        "version": "0.1.0",
        "env": settings.env,
        "components": {
            "ensemble": "stub",
            "merkle_anchor": "pending",
            "supervisor": "pending",
        },
    }


@app.post("/defend", response_model=DefendResponse)
async def defend(
    telemetry: TelemetryInput,
    request: Request,
    x_pq_fallback: str | None = Header(default=None, alias=settings.pq_fallback_header),
):
    """
    MVP implementation:
    - Very dumb heuristics just to exercise the contract.
    - Later this becomes the ensemble (rules + anomaly + LLM) call.
    """
    now = datetime.now(timezone.utc)
    # naive drift (MVP) – assume timestamp is UTC ISO8601
    try:
        ts = datetime.fromisoformat(telemetry.timestamp.replace("Z", "+00:00"))
        clock_drift_ms = int((now - ts).total_seconds() * 1000)
    except Exception:
        clock_drift_ms = 0

    # Toy "rule engine"
    payload = telemetry.payload
    source_ip = payload.get("src_ip") or payload.get("source_ip", "unknown")
    event_type = payload.get("event_type", "unknown")
    failed_auths = int(payload.get("failed_auths", 0))

    rules_triggered: list[str] = []
    mitigations: list[MitigationAction] = []
    threat_level = "low"
    anomaly_score = 0.1
    ai_adv_score = 0.0

    if failed_auths >= 10:
        rules_triggered.append("rule:ssh_bruteforce")
        threat_level = "high"
        mitigations.append(
            MitigationAction(
                action="block_ip",
                target=source_ip,
                reason=f"{failed_auths} failed auth attempts detected",
                confidence=0.92,
            )
        )
        anomaly_score = 0.8

    if event_type == "suspicious_llm_usage":
        rules_triggered.append("rule:ai-assisted-attack")
        ai_adv_score = 0.7
        if threat_level == "low":
            threat_level = "medium"

    pq_fallback = bool(x_pq_fallback)

    explain = ExplainBlock(
        summary=f"MVP decision for tenant={telemetry.tenant_id}, source={telemetry.source}",
        rules_triggered=rules_triggered,
        anomaly_score=anomaly_score,
        llm_note="MVP stub – no real LLM yet.",
    )

    resp = DefendResponse(
        threat_level=threat_level,
        mitigations=mitigations,
        explain=explain,
        ai_adversarial_score=ai_adv_score,
        pq_fallback=pq_fallback,
        clock_drift_ms=clock_drift_ms,
    )

    logger.info(
        "defend decision",
        extra={
            "tenant_id": telemetry.tenant_id,
            "source": telemetry.source,
            "threat_level": threat_level,
            "rules": rules_triggered,
        },
    )
    return resp


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("api.main:app", host="0.0.0.0", port=8080, reload=True)
