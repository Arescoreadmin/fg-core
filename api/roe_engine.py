from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, cast

from fastapi import APIRouter
from pydantic import BaseModel, Field

from engine.doctrine import apply_doctrine

from api.config.startup_validation import compliance_module_enabled


@dataclass(slots=True)
class _DoctrineMitigation:
    """
    Boundary-safe mitigation object for doctrine evaluation.

    Keeps the API layer decoupled from engine-internal mitigation types while
    preserving the attribute shape consumed by doctrine evaluation.
    """

    action: str
    target: Any = None
    reason: str = ""
    confidence: float = 1.0
    meta: Any = field(default=None)


class ROEPolicy(BaseModel):
    policy_id: str = "roe-default"
    max_disruption: int = 1
    ao_required_actions: list[str] = Field(default_factory=lambda: ["block_ip"])


class ROEEvaluationRequest(BaseModel):
    persona: str | None = None
    classification: str | None = None
    mitigations: list[dict[str, Any]] = Field(default_factory=list)


class ROEEvaluationResponse(BaseModel):
    gating_decision: str
    reason: str
    policy: ROEPolicy


router = APIRouter(prefix="/roe", tags=["roe"])


@router.get("/policy", response_model=ROEPolicy)
async def get_policy() -> ROEPolicy:
    return ROEPolicy()


def _coerce_confidence(value: Any) -> float:
    try:
        return float(value if value is not None else 1.0)
    except (TypeError, ValueError):
        return 1.0


def _build_mitigations(
    raw_mitigations: list[dict[str, Any]],
) -> list[_DoctrineMitigation]:
    mitigations: list[_DoctrineMitigation] = []

    for raw in raw_mitigations:
        if not isinstance(raw, dict):
            continue

        mitigations.append(
            _DoctrineMitigation(
                action=str(raw.get("action", "")),
                target=raw.get("target"),
                reason=str(raw.get("reason", "")),
                confidence=_coerce_confidence(raw.get("confidence")),
                meta=raw.get("meta"),
            )
        )

    return mitigations


@router.post("/evaluate", response_model=ROEEvaluationResponse)
async def evaluate_roe(req: ROEEvaluationRequest) -> ROEEvaluationResponse:
    mitigations = _build_mitigations(req.mitigations)

    _, tie_d = apply_doctrine(
        req.persona,
        req.classification,
        cast(list[Any], mitigations),
    )

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
    return compliance_module_enabled("roe_engine")
