from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import os
from pathlib import Path

from services.dashboard_contracts import load_json_contract

_POLICY_ROOT = Path("contracts/dashboard").resolve()
_POLICY_PATH = _POLICY_ROOT / "widget_runtime_policy.json"

REASON_POLICY_DISABLED = "WIDGET_DISABLED_BY_POLICY"
REASON_PERSONA_DISABLED = "WIDGET_NOT_ALLOWED_FOR_PERSONA"
REASON_TENANT_DISABLED = "WIDGET_DISABLED_FOR_TENANT"
REASON_FEATURE_FLAG = "WIDGET_DISABLED_BY_FEATURE_FLAG"


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason_code: str | None = None


@lru_cache(maxsize=1)
def load_runtime_policy() -> dict:
    if not _POLICY_PATH.exists():
        return {
            "global_default": {"enabled": True},
            "persona_overrides": {},
            "tenant_overrides": {},
            "feature_flag_overrides": [],
            "disabled": [],
        }
    payload = load_json_contract(_POLICY_PATH, root=_POLICY_ROOT)
    if not isinstance(payload, dict):
        return {"disabled": []}
    return payload


def _flag_true(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _disabled_in_list(disabled: object, widget_id: str) -> bool:
    return isinstance(disabled, list) and widget_id in {str(x) for x in disabled}


def evaluate_widget_policy(*, tenant_id: str, persona: str, widget_id: str) -> PolicyDecision:
    policy = load_runtime_policy()

    global_default = policy.get("global_default")
    if isinstance(global_default, dict) and not bool(global_default.get("enabled", True)):
        return PolicyDecision(False, REASON_POLICY_DISABLED)

    persona_overrides = policy.get("persona_overrides")
    if isinstance(persona_overrides, dict):
        p = persona_overrides.get(persona)
        if isinstance(p, dict) and _disabled_in_list(p.get("disabled_widgets"), widget_id):
            return PolicyDecision(False, REASON_PERSONA_DISABLED)

    tenant_overrides = policy.get("tenant_overrides")
    if isinstance(tenant_overrides, dict):
        t = tenant_overrides.get(tenant_id)
        if isinstance(t, dict):
            if _disabled_in_list(t.get("disabled_widgets"), widget_id):
                return PolicyDecision(False, REASON_TENANT_DISABLED)
            tp = t.get("persona_overrides")
            if isinstance(tp, dict):
                p = tp.get(persona)
                if isinstance(p, dict) and _disabled_in_list(
                    p.get("disabled_widgets"), widget_id
                ):
                    return PolicyDecision(False, REASON_PERSONA_DISABLED)

    feature_flags = policy.get("feature_flag_overrides")
    if isinstance(feature_flags, list):
        for item in feature_flags:
            if not isinstance(item, dict):
                continue
            if str(item.get("widget_id") or "") != widget_id:
                continue
            env_flag = str(item.get("env_flag") or "").strip()
            if not env_flag:
                continue
            if _flag_true(env_flag) and not bool(item.get("enabled", False)):
                return PolicyDecision(False, REASON_FEATURE_FLAG)

    legacy = policy.get("disabled")
    if isinstance(legacy, list):
        for item in legacy:
            if not isinstance(item, dict):
                continue
            t = str(item.get("tenant_id") or "*")
            p = str(item.get("persona") or "*")
            w = str(item.get("widget_id") or "")
            if w != widget_id:
                continue
            if t not in {"*", tenant_id}:
                continue
            if p not in {"*", persona}:
                continue
            return PolicyDecision(False, REASON_POLICY_DISABLED)

    return PolicyDecision(True, None)


def widget_allowed(*, tenant_id: str, persona: str, widget_id: str) -> tuple[bool, str | None]:
    decision = evaluate_widget_policy(
        tenant_id=tenant_id,
        persona=persona,
        widget_id=widget_id,
    )
    return decision.allowed, decision.reason_code


def policy_hash() -> str:
    import hashlib
    import json

    payload = load_runtime_policy()
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()
