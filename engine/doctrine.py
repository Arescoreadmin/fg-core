from __future__ import annotations

from typing import Any, Optional, Tuple

from engine.evaluate import Mitigation


def apply_doctrine(
    persona: Optional[str],
    classification: Optional[str],
    mitigations: list[Mitigation],
) -> Tuple[list[Mitigation], dict[str, Any]]:
    """
    Engine-owned doctrine application (INV-004).

    Contract expected by tests:
      - tie_d must always exist and include:
          roe_applied, disruption_limited, ao_required,
          persona, classification,
          service_impact, user_impact,
          gating_decision ("allow" | "require_approval" | "reject")
      - guardian + SECRET:
          - roe_applied=True
          - ao_required=True
          - cap block_ip mitigations to 1
          - gating_decision present (require_approval if block_ip used else allow)
    """
    persona_v = (persona or "").strip().lower() or None
    class_v = (classification or "").strip().upper() or None

    out = list(mitigations or [])

    roe_applied = False
    disruption_limited = False
    ao_required = False

    # baseline impacts
    base_impact = 0.0
    base_user_impact = 0.0
    if any(m.action == "block_ip" for m in out):
        base_impact = 0.35
        base_user_impact = 0.20

    # default gating
    gating_decision: str = "allow"

    if persona_v == "guardian" and class_v == "SECRET":
        roe_applied = True
        ao_required = True

        # cap block_ip to 1
        block_ips = [m for m in out if m.action == "block_ip"]
        if len(block_ips) > 1:
            disruption_limited = True
            first = block_ips[0]
            out = [m for m in out if m.action != "block_ip"]
            out.insert(0, first)

        if disruption_limited:
            base_impact = max(0.0, base_impact - 0.10)
            base_user_impact = max(0.0, base_user_impact - 0.05)

        gating_decision = (
            "require_approval" if any(m.action == "block_ip" for m in out) else "allow"
        )

    tie_d = {
        "roe_applied": roe_applied,
        "disruption_limited": disruption_limited,
        "ao_required": ao_required,
        "persona": persona_v,
        "classification": class_v,
        "service_impact": float(min(1.0, max(0.0, base_impact))),
        "user_impact": float(min(1.0, max(0.0, base_user_impact))),
        "gating_decision": gating_decision,
    }

    return out, tie_d
