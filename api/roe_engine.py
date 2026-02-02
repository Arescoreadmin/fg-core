from __future__ import annotations

import os
from typing import Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

from engine.doctrine import apply_doctrine
from engine.evaluate import Mitigation as EngineMitigation


def _env_bool(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return str(v).strip().lower() in {"1", "true", "yes", "y", "on"}


class ROEPolicy(BaseModel):
    policy_id: str = "roe-default"
    max_disruption: int = 1
    ao_required_actions: list[str] = Field(default_factory=lambda: ["block_ip"])


class ROEEvaluationRequest(BaseModel):
    persona: Optional[str] = None
    classification: Optional[str] = None
    mitigations: list[dict] = Field(default_factory=list)


class ROEEvaluationResponse(BaseModel):
    gating_decision: str
    reason: str
    policy: ROEPolicy


router = APIRouter(prefix="/roe", tags=["roe"])


@router.get("/policy", response_model=ROEPolicy)
async def get_policy() -> ROEPolicy:
    return ROEPolicy()


@router.post("/evaluate", response_model=ROEEvaluationResponse)
async def evaluate_roe(req: ROEEvaluationRequest) -> ROEEvaluationResponse:
    # Convert dict mitigations into engine Mitigation objects
    mits: list[EngineMitigation] = []
    for m in req.mitigations or []:
        if not isinstance(m, dict):
            continue
        mits.append(
            EngineMitigation(
                action=str(m.get("action", "")),
                target=m.get("target"),
                reason=str(m.get("reason", "")),
                confidence=float(m.get("confidence", 1.0) or 1.0),
                meta=m.get("meta"),
            )
        )

    _, tie_d = apply_doctrine(req.persona, req.classification, mits)

    gating = str(tie_d.get("gating_decision", "allow"))
    if gating == "require_approval":
        reason = "Guardian persona requires approval for disruptive actions."
    else:
        reason = "No ROE constraints triggered."

    return ROEEvaluationResponse(
        gating_decision=gating,
        reason=reason,
        policy=ROEPolicy(),
    )


def roe_engine_enabled() -> bool:
    return _env_bool("FG_ROE_ENGINE_ENABLED", False)
