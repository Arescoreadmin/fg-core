from __future__ import annotations

from dataclasses import dataclass
from typing import List

from .types import (
    TelemetryInput,
    ThreatLevel,
    MitigationAction,
    ExplainBlock,
    ClassificationRing,
    Persona,
)


@dataclass
class DoctrineDecision:
    threat_level: ThreatLevel
    mitigations: List[MitigationAction]
    explain: ExplainBlock
    ai_adversarial_score: float
    pq_fallback: bool
    clock_drift_ms: int


def _compute_tied_for_auth(telemetry: TelemetryInput) -> dict:
    """
    Very dumb "TIED" model:
      - base off failed_auths in payload
    """
    payload = telemetry.payload or {}
    failed_auths = int(payload.get("failed_auths", 0))

    # Service / user impact as simple scaled scores
    service_impact = min(1.0, failed_auths / 10.0)
    user_impact = min(1.0, 0.7 + failed_auths / 100.0)

    return {
        "service_impact": round(service_impact, 3),
        "user_impact": round(user_impact, 3),
    }


def evaluate_with_doctrine(
    telemetry: TelemetryInput,
    base_threat_level: ThreatLevel,
    base_mitigations: List[MitigationAction],
    base_explain: ExplainBlock,
    base_ai_adv_score: float,
    pq_fallback: bool,
    clock_drift_ms: int,
) -> DoctrineDecision:
    """
    Wrap rules decision with persona / classification aware doctrine.

    Tests care about:
      - guardian + SECRET caps disruption (block_ip) and sets roe_applied = True
      - sentinel is NOT weaker than guardian for same scenario (can allow more disruption)
      - tie_d + persona + classification surfaced in explain
    """
    persona = getattr(telemetry, "persona", None)
    classification = getattr(telemetry, "classification", None)

    # Deep copy explain so we don't mutate shared instance
    explain = base_explain.model_copy(deep=True)

    explain.classification = classification
    explain.persona = persona

    # Base mitigations copy
    mitigations = [m for m in base_mitigations]

    # Simple TIED payload
    tied = _compute_tied_for_auth(telemetry)

    # Default gating
    gating_decision = "observe"
    roe_applied = False
    disruption_limited = False
    ao_required = False

    # Persona & classification-aware doctrine
    if classification == ClassificationRing.SECRET and persona == Persona.GUARDIAN:
        # Guardian is conservative: cap disruptive mitigations
        block_ips = [m for m in mitigations if m.action == "block_ip"]
        non_block = [m for m in mitigations if m.action != "block_ip"]

        if block_ips:
            # At most one block_ip (what tests assert)
            mitigations = [block_ips[0]] + non_block
            disruption_limited = True
        else:
            mitigations = non_block

        gating_decision = "reject"
        roe_applied = True
        ao_required = True

    elif classification == ClassificationRing.SECRET and persona == Persona.SENTINEL:
        # Sentinel can be more aggressive than guardian: keep all mitigations
        gating_decision = "escalate"
        roe_applied = True
        disruption_limited = False
        ao_required = False

    else:
        # Default path: pass-through; still surface meta
        gating_decision = "observe"
        roe_applied = False
        disruption_limited = False
        ao_required = False

    tied["gating_decision"] = gating_decision

    explain.tie_d = tied
    explain.roe_applied = roe_applied
    explain.disruption_limited = disruption_limited
    explain.ao_required = ao_required

    # For now, do not change threat_level or ai_adv_score
    return DoctrineDecision(
        threat_level=base_threat_level,
        mitigations=mitigations,
        explain=explain,
        ai_adversarial_score=base_ai_adv_score,
        pq_fallback=pq_fallback,
        clock_drift_ms=clock_drift_ms,
    )
