from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, Optional, Tuple

ThreatLevel = Literal["none", "low", "medium", "high", "critical"]


@dataclass(frozen=True)
class Mitigation:
    action: str
    target: Optional[str]
    reason: str
    confidence: float = 1.0
    meta: Optional[dict[str, Any]] = None


# =============================================================================
# Normalization helpers (engine-owned)
# =============================================================================


def _coerce_event_type(req: Any) -> str:
    et = getattr(req, "event_type", None)
    payload = getattr(req, "payload", None)
    event = getattr(req, "event", None)

    if not et and isinstance(payload, dict):
        et = payload.get("event_type")
    if not et and isinstance(event, dict):
        et = event.get("event_type")

    et = (et or "").strip()
    return et or "unknown"


def _coerce_event_payload(req: Any) -> dict[str, Any]:
    event = getattr(req, "event", None)
    payload = getattr(req, "payload", None)

    if isinstance(event, dict) and event:
        return dict(event)
    if isinstance(payload, dict) and payload:
        return dict(payload)
    return {}


def _normalize_ip(payload: dict[str, Any]) -> Optional[str]:
    v = (
        payload.get("src_ip")
        or payload.get("source_ip")
        or payload.get("source_ip_addr")
        or payload.get("ip")
        or payload.get("remote_ip")
    )
    if v is None:
        return None
    s = str(v).strip()
    return s or None


def _normalize_failed_auths(payload: dict[str, Any]) -> int:
    raw = (
        payload.get("failed_auths")
        or payload.get("fail_count")
        or payload.get("failures")
        or payload.get("attempts")
        or payload.get("failed_attempts")
        or 0
    )
    try:
        return int(raw)
    except Exception:
        return 0


# =============================================================================
# Scoring (engine-owned)
# =============================================================================

RULE_SCORES: dict[str, int] = {
    "rule:ssh_bruteforce": 90,
    "rule:default_allow": 0,
}


def _threat_from_score(score: int) -> ThreatLevel:
    if score >= 95:
        return "critical"
    if score >= 80:
        return "high"
    if score >= 50:
        return "medium"
    if score >= 20:
        return "low"
    return "none"


def evaluate(req: Any) -> Tuple[ThreatLevel, list[str], list[Mitigation], float, int]:
    """
    Canonical evaluation entrypoint (INV-004).

    Returns:
      (threat_level, rules_triggered, mitigations, anomaly_score, score)
    """
    et = _coerce_event_type(req)
    body = _coerce_event_payload(req)

    failed_auths = _normalize_failed_auths(body)
    src_ip = _normalize_ip(body)

    rules_triggered: list[str] = []
    mitigations: list[Mitigation] = []
    anomaly_score = 0.1

    # MVP rule: auth brute force => block_ip
    if (
        et in ("auth", "auth.bruteforce", "auth_attempt")
        and failed_auths >= 5
        and src_ip
    ):
        rules_triggered.append("rule:ssh_bruteforce")
        mitigations.append(
            Mitigation(
                action="block_ip",
                target=src_ip,
                reason=f"{failed_auths} failed auth attempts detected",
                confidence=0.92,
            )
        )
        anomaly_score = 0.8
    else:
        rules_triggered.append("rule:default_allow")

    score = sum(RULE_SCORES.get(r, 0) for r in rules_triggered)
    threat_level = _threat_from_score(score)
    return threat_level, rules_triggered, mitigations, anomaly_score, score
