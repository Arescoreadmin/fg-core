from __future__ import annotations

import os


class GovernanceRiskExtension:
    def enabled(self) -> bool:
        return (os.getenv("FG_GOVERNANCE_RISK_EXTENSION_ENABLED") or "0").strip() in {
            "1",
            "true",
            "yes",
            "on",
        }

    def evaluate(
        self, *, proposed_by: str, approver: str, required_roles: list[str]
    ) -> dict[str, object]:
        sod_ok = proposed_by != approver
        quorum = max(1, len(required_roles))
        risk_tier = "high" if "ciso" in required_roles else "medium"
        return {
            "enabled": self.enabled(),
            "risk_tier": risk_tier,
            "quorum_required": quorum,
            "sod_ok": sod_ok,
        }
