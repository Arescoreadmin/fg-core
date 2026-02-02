from __future__ import annotations

"""
Single decision-path evaluator (INV-004).

This module standardizes decision output for BOTH /defend and /ingest.

Underlying rules engines may return:
  - legacy tuple: (threat_level, mitigations, rules_triggered, anomaly_score, ai_adv_score)
  - dict (newer engines)

We normalize to a stable JSON-safe shape:
{
  "threat_level": "...",
  "mitigations": [...],
  "rules_triggered": [...],
  "anomaly_score": float,
  "score": int,
  "tie_d": {...},
  # optional extras (kept for observability / backward compat):
  "ai_adversarial_score": float,
  "tenant_id": str,
  "source": str,
  "event_type": str,
}
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, Literal

ThreatLevel = Literal["none", "low", "medium", "high", "critical"]


try:
    # Some repos expose engine.evaluate_rules at package top-level
    from engine import evaluate_rules as _evaluate_rules  # type: ignore
except Exception:
    from engine.rules import evaluate_rules as _evaluate_rules  # type: ignore


@dataclass(frozen=True)
class Mitigation:
    action: str
    target: Optional[str]
    reason: str
    confidence: float = 1.0
    meta: Optional[dict[str, Any]] = None


def _to_jsonable_mitigations(mits: Any) -> List[Dict[str, Any]]:
    if not mits:
        return []
    out: List[Dict[str, Any]] = []
    for m in mits:
        # Pydantic v2
        if hasattr(m, "model_dump"):
            out.append(m.model_dump())
        # Pydantic v1
        elif hasattr(m, "dict"):
            out.append(m.dict())
        # plain dict already
        elif isinstance(m, dict):
            out.append(m)
        # our engine Mitigation dataclass
        elif isinstance(m, Mitigation):
            out.append(
                {
                    "action": m.action,
                    "target": m.target,
                    "reason": m.reason,
                    "confidence": float(m.confidence),
                    "meta": m.meta,
                }
            )
        else:
            out.append({"raw": str(m)})
    return out


def _to_mitigation_objects(mits: Any) -> List[Mitigation]:
    """
    Convert arbitrary mitigation shapes into canonical Mitigation objects.
    This keeps /defend logic from having to guess types.
    """
    if not mits:
        return []
    out: List[Mitigation] = []
    for m in mits:
        if isinstance(m, Mitigation):
            out.append(m)
            continue
        if hasattr(m, "model_dump"):
            d = m.model_dump()
        elif hasattr(m, "dict"):
            d = m.dict()
        elif isinstance(m, dict):
            d = m
        else:
            d = {"action": "unknown", "target": None, "reason": str(m)}

        out.append(
            Mitigation(
                action=str(d.get("action") or "unknown"),
                target=(str(d["target"]) if d.get("target") is not None else None),
                reason=str(d.get("reason") or ""),
                confidence=float(d.get("confidence") or 1.0),
                meta=(d.get("meta") if isinstance(d.get("meta"), dict) else None),
            )
        )
    return out


def _safe_int(v: Any, default: int = 0) -> int:
    try:
        if v is None:
            return default
        return int(v)
    except Exception:
        return default


def _safe_float(v: Any, default: float = 0.0) -> float:
    try:
        if v is None:
            return default
        return float(v)
    except Exception:
        return default


def evaluate_telemetry(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Single decision path evaluator (INV-004).

    Takes the raw telemetry payload (the same shape API receives),
    calls the rules engine, and returns a normalized dict that both
    /defend and /ingest can format without drift.
    """
    telemetry: Dict[str, Any] = payload if isinstance(payload, dict) else {}

    result = _evaluate_rules(telemetry)

    # Base identity fields (useful for logs and for /ingest storage)
    tenant_id = str(telemetry.get("tenant_id", "unknown"))
    source = str(telemetry.get("source", "unknown"))
    event_type = str(telemetry.get("event_type", telemetry.get("event", "unknown")))

    # If the rules engine returns dict, normalize keys and ensure json-safe mitigations
    if isinstance(result, dict):
        out = dict(result)

        out.setdefault("tenant_id", tenant_id)
        out.setdefault("source", source)
        out.setdefault("event_type", event_type)

        out["mitigations"] = _to_jsonable_mitigations(out.get("mitigations"))

        rules_triggered = out.get("rules_triggered")
        rules = out.get("rules")

        if rules_triggered is None and rules is not None:
            out["rules_triggered"] = list(rules or [])
        elif rules_triggered is not None:
            out["rules_triggered"] = list(rules_triggered or [])

        if "rules" not in out and "rules_triggered" in out:
            out["rules"] = list(out.get("rules_triggered") or [])

        out["anomaly_score"] = _safe_float(out.get("anomaly_score"), 0.0)
        out["score"] = _safe_int(out.get("score"), 0)

        out.setdefault("tie_d", {})

        if "ai_adversarial_score" in out:
            out["ai_adversarial_score"] = _safe_float(out.get("ai_adversarial_score"), 0.0)
        elif "ai_adv_score" in out:
            out["ai_adversarial_score"] = _safe_float(out.get("ai_adv_score"), 0.0)

        out.setdefault("threat_level", "low")
        return out

    # Legacy tuple normalization
    try:
        threat_level, mitigations, rules_triggered, anomaly_score, ai_adv_score = result  # type: ignore[misc]
    except Exception:
        return {
            "tenant_id": tenant_id,
            "source": source,
            "event_type": event_type,
            "threat_level": "low",
            "mitigations": [],
            "rules_triggered": [],
            "rules": [],
            "anomaly_score": 0.0,
            "ai_adversarial_score": 0.0,
            "score": 0,
            "tie_d": {},
            "error": f"Unexpected evaluate_rules return: {type(result)}",
        }

    rules_list = list(rules_triggered or [])

    return {
        "tenant_id": tenant_id,
        "source": source,
        "event_type": event_type,
        "threat_level": str(threat_level or "low"),
        "mitigations": _to_jsonable_mitigations(mitigations),
        "rules_triggered": rules_list,
        "rules": rules_list,
        "anomaly_score": _safe_float(anomaly_score, 0.0),
        "ai_adversarial_score": _safe_float(ai_adv_score, 0.0),
        "score": 0,
        "tie_d": {},
    }


def evaluate_tuple(req_or_payload: Any) -> Tuple[ThreatLevel, List[str], List[Mitigation], float, int]:
    """
    Canonical tuple form used by /defend after INV-004 cleanup.

    Accepts either:
      - TelemetryInput-like object (has .tenant_id/.source/.event_type/.payload etc)
      - raw dict payload

    Returns:
      (threat_level, rules_triggered, mitigations, anomaly_score, score)
    """
    if isinstance(req_or_payload, dict):
        payload = req_or_payload
    else:
        # convert object -> dict in the same shape ingest already uses
        payload = {
            "tenant_id": getattr(req_or_payload, "tenant_id", None),
            "source": getattr(req_or_payload, "source", None),
            "event_type": getattr(req_or_payload, "event_type", None),
            "payload": getattr(req_or_payload, "payload", None),
            "event": getattr(req_or_payload, "event", None),
            "persona": getattr(req_or_payload, "persona", None),
            "classification": getattr(req_or_payload, "classification", None),
            "meta": getattr(req_or_payload, "meta", None),
        }

    out = evaluate_telemetry(payload)

    threat_level = str(out.get("threat_level") or "low").lower()
    rules = list(out.get("rules_triggered") or out.get("rules") or [])
    mitigations = _to_mitigation_objects(out.get("mitigations") or [])
    anomaly = _safe_float(out.get("anomaly_score"), 0.0)
    score = _safe_int(out.get("score"), 0)

    # normalize threat_level to allowed set
    if threat_level not in {"none", "low", "medium", "high", "critical"}:
        threat_level = "low"

    return threat_level, rules, mitigations, anomaly, score


# Backwards compatibility: older code imports engine.evaluate.evaluate()
def evaluate(telemetry: Dict[str, Any]) -> Dict[str, Any]:
    return evaluate_telemetry(telemetry)
