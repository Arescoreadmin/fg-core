from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

POLICY_ID = "doctrine-v1"

_DISRUPTIVE_ACTIONS = ["block", "block_ip", "quarantine", "terminate"]

_POLICY_DEFINITION: dict[str, Any] = {
    "policy_id": POLICY_ID,
    "policy_kind": "doctrine",
    "disruptive_actions": _DISRUPTIVE_ACTIONS,
    "baseline_impact": {"service_impact": 0.35, "user_impact": 0.20},
    "impact_reduction_on_limit": {"service_impact": 0.10, "user_impact": 0.05},
    "rules": [
        {
            "persona": "guardian",
            "classification": "SECRET",
            "roe_applied": True,
            "ao_required": True,
            "disruptive_action_cap": 1,
            "gating_decision": "require_approval_if_disruptive",
        },
        {
            "persona": "sentinel",
            "classification": "*",
            "disruptive_action_cap": 3,
        },
    ],
}


@dataclass(frozen=True)
class PolicyFingerprint:
    policy_id: str
    policy_hash: str
    policy_bytes: bytes


def _canonical_policy_bytes() -> bytes:
    payload = json.dumps(
        _POLICY_DEFINITION,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return payload.encode("utf-8")


def _sha256_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


@lru_cache(maxsize=1)
def get_active_policy_fingerprint() -> PolicyFingerprint:
    policy_bytes = _canonical_policy_bytes()
    return PolicyFingerprint(
        policy_id=POLICY_ID,
        policy_hash=_sha256_hex(policy_bytes),
        policy_bytes=policy_bytes,
    )
