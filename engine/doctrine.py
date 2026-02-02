from __future__ import annotations

from typing import Any, Literal, Optional, Tuple

from engine.evaluate import Mitigation

GatingDecision = Literal["allow", "require_approval", "reject"]


def apply_doctrine(
    persona: Optional[str],
    classification: Optional[str],
    mitigations: list[Mitigation],
) -> Tuple[list[Mitigation], dict[str, Any]]:
    """
    Engine-owned doctrine / ROE bundling.

    Contract expected by API layer:
      returns (mitigations_after_doctrine, tie_d_dict)

    tie_d_dict keys align with api.schemas_doctrine.TieD.
    """
    persona_v = (persona or "").strip().lower() or None
    class_v = (classification or "").strip().upper() or None

    roe_applied = False
    disruption_limited = False
    ao_required = False

    out = list(mitigations or [])

    # baseline impact model (simple deterministic placeholders)
    base_impact = 0.0
    base_user_impact = 0.0
    if any(m.action == "block_ip" for m in out):
        base_impact = 0.35
        base_user_impact = 0.20

    gating_decision: GatingDecision = "allow"

    # Guardian + SECRET: conservative doctrine
    if persona_v == "guardian" and class_v == "SECRET":
        roe_applied = True
        ao_required = True

        # cap disruptive mitigations to 1 block_ip
        block_ips = [m for m in out if m.action == "block_ip"]
        if len(block_ips) > 1:
            disruption_limited = True
            first = block_ips[0]
            out = [m for m in out if m.action != "block_ip"]
            out.insert(0, first)

        # approval required if any disruptive action present
        gating_decision = (
            "require_approval" if any(m.action == "block_ip" for m in out) else "allow"
        )

        # blast radius reduction when limiting
        if disruption_limited:
            base_impact = max(0.0, base_impact - 0.10)
            base_user_impact = max(0.0, base_user_impact - 0.05)

    tie_d = {
        "roe_applied": bool(roe_applied),
        "disruption_limited": bool(disruption_limited),
        "ao_required": bool(ao_required),
        "persona": persona_v,
        "classification": class_v,
        "service_impact": float(min(1.0, max(0.0, base_impact))),
        "user_impact": float(min(1.0, max(0.0, base_user_impact))),
        "gating_decision": gating_decision,
    }

    return out, tie_d
