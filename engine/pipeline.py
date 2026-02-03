# engine/pipeline.py
"""
Unified Decision Pipeline - SINGLE SOURCE OF TRUTH.

This module provides a single entry point for all decision evaluation.
Both /defend and /ingest MUST use this module for consistent behavior.

Hardening: Day 1 - Created to eliminate dual decision paths.

P0 Invariants:
  - Same input MUST produce same output regardless of entry point
  - Doctrine application is mandatory for all decisions
  - TieD is always present in output (never None)
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional

from engine.policy_fingerprint import get_active_policy_fingerprint

log = logging.getLogger("frostgate.pipeline")

# Type alias for threat levels
ThreatLevel = Literal["none", "low", "medium", "high", "critical"]


@dataclass
class PipelineInput:
    """
    Normalized input for the decision pipeline.

    All entry points (defend, ingest) MUST convert their input to this format.
    """

    tenant_id: str
    source: str
    event_type: str
    payload: Dict[str, Any] = field(default_factory=dict)
    timestamp: Optional[str] = None

    # Doctrine context
    persona: Optional[str] = None
    classification: Optional[str] = None

    # Optional metadata
    event_id: Optional[str] = None
    meta: Optional[Dict[str, Any]] = None


@dataclass
class TieD:
    """
    Trust, Impact, Escalation, Decision metadata.

    P0: This MUST always be present in pipeline output (never None).
    """

    roe_applied: bool = False
    disruption_limited: bool = False
    ao_required: bool = False

    persona: Optional[str] = None
    classification: Optional[str] = None

    service_impact: float = 0.0
    user_impact: float = 0.0

    gating_decision: Literal["allow", "require_approval", "reject"] = "allow"
    policy_version: str = "doctrine-v1"
    policy_hash: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "roe_applied": self.roe_applied,
            "disruption_limited": self.disruption_limited,
            "ao_required": self.ao_required,
            "persona": self.persona,
            "classification": self.classification,
            "service_impact": self.service_impact,
            "user_impact": self.user_impact,
            "gating_decision": self.gating_decision,
            "policy_version": self.policy_version,
            "policy_hash": self.policy_hash,
        }


@dataclass
class Mitigation:
    """A single mitigation action."""

    action: str
    target: Optional[str] = None
    reason: str = ""
    confidence: float = 0.5
    meta: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "target": self.target,
            "reason": self.reason,
            "confidence": self.confidence,
            "meta": self.meta,
        }


@dataclass
class PipelineResult:
    """
    Unified output from the decision pipeline.

    P0 Invariants:
      - tie_d is NEVER None
      - event_id is always computed
      - clock_drift_ms is always present
    """

    threat_level: ThreatLevel
    mitigations: List[Mitigation]
    rules_triggered: List[str]
    score: int
    anomaly_score: float
    ai_adversarial_score: float

    # Doctrine output
    tie_d: TieD

    # Derived fields
    event_id: str
    clock_drift_ms: int
    explanation_brief: str

    # Doctrine flags (surfaced for backward compat)
    roe_applied: bool = False
    disruption_limited: bool = False
    ao_required: bool = False
    policy_hash: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "threat_level": self.threat_level,
            "mitigations": [m.to_dict() for m in self.mitigations],
            "rules_triggered": self.rules_triggered,
            "score": self.score,
            "anomaly_score": self.anomaly_score,
            "ai_adversarial_score": self.ai_adversarial_score,
            "tie_d": self.tie_d.to_dict(),
            "event_id": self.event_id,
            "clock_drift_ms": self.clock_drift_ms,
            "explanation_brief": self.explanation_brief,
            "roe_applied": self.roe_applied,
            "disruption_limited": self.disruption_limited,
            "ao_required": self.ao_required,
            "policy_hash": self.policy_hash,
        }


# =============================================================================
# Rule Scoring (MVP)
# =============================================================================

RULE_SCORES: Dict[str, int] = {
    "rule:ssh_bruteforce": 90,
    "rule:ai-assisted-attack": 60,
    "rule:missing_failed_count": 40,
    "rule:default_allow": 0,
}


def _threat_from_score(score: int) -> ThreatLevel:
    """Map score to threat level."""
    if score >= 95:
        return "critical"
    if score >= 80:
        return "high"
    if score >= 50:
        return "medium"
    if score >= 20:
        return "low"
    return "none"


# =============================================================================
# Event ID and Clock Drift
# =============================================================================


def _canonical_json(obj: Any) -> str:
    """Canonical JSON serialization for hashing."""
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )


def _compute_event_id(inp: PipelineInput) -> str:
    """Compute deterministic event ID from input."""
    ts = inp.timestamp or datetime.now(timezone.utc).isoformat()
    raw = f"{inp.tenant_id}|{inp.source}|{ts}|{inp.event_type}|{_canonical_json(inp.payload)}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _compute_clock_drift_ms(timestamp: Optional[str]) -> int:
    """Compute clock drift from event timestamp."""
    if not timestamp:
        return 0

    try:
        ts_str = timestamp.strip()
        if ts_str.endswith("Z"):
            ts_str = ts_str[:-1] + "+00:00"
        event_dt = datetime.fromisoformat(ts_str)
        if event_dt.tzinfo is None:
            event_dt = event_dt.replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)
        age_ms = int(abs((now - event_dt).total_seconds()) * 1000)

        stale_ms = int(os.getenv("FG_CLOCK_STALE_MS", "300000"))
        return 0 if age_ms > stale_ms else age_ms
    except Exception:
        return 0


# =============================================================================
# Core Evaluation
# =============================================================================


def _normalize_ip(payload: Dict[str, Any]) -> Optional[str]:
    """Extract IP from payload with fallbacks."""
    for key in ("src_ip", "source_ip", "ip", "client_ip", "remote_ip"):
        v = payload.get(key)
        if v:
            s = str(v).strip()
            if s:
                return s
    return None


def _normalize_failed_auths(payload: Dict[str, Any]) -> int:
    """Extract failed auth count from payload with fallbacks."""
    for key in (
        "failed_auths",
        "failed_attempts",
        "attempts",
        "count",
        "failures",
        "fail_count",
        "num_failures",
        "failed_logins",
    ):
        v = payload.get(key)
        if v is not None:
            try:
                return int(v)
            except (ValueError, TypeError):
                continue
    return 0


def _evaluate_rules(inp: PipelineInput) -> tuple:
    """
    Core rules evaluation.

    Returns:
        (threat_level, mitigations, rules_triggered, anomaly_score, ai_adv_score, score)
    """
    rules_triggered: List[str] = []
    mitigations: List[Mitigation] = []
    anomaly_score = 0.1
    ai_adv_score = 0.0

    et = (inp.event_type or "unknown").lower()
    payload = inp.payload or {}

    src_ip = _normalize_ip(payload)
    failed_auths = _normalize_failed_auths(payload)

    # Normalize bruteforce event types
    is_bruteforce_event = any(x in et for x in ("bruteforce", "brute_force"))
    is_auth_event = et in ("auth", "auth_attempt", "login")

    # Rule: SSH/Auth brute force
    if (is_bruteforce_event or is_auth_event) and failed_auths >= 5 and src_ip:
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

    # Rule: High threshold bruteforce (implicit from count)
    elif failed_auths >= 10 and src_ip:
        rules_triggered.append("rule:ssh_bruteforce")
        mitigations.append(
            Mitigation(
                action="block_ip",
                target=src_ip,
                reason=f"{failed_auths} failed auth attempts detected (implicit)",
                confidence=0.85,
            )
        )
        anomaly_score = 0.75

    # Rule: Malformed bruteforce telemetry
    elif is_bruteforce_event and failed_auths == 0:
        rules_triggered.append("rule:missing_failed_count")
        anomaly_score = 0.4

    # Rule: AI-assisted attack marker
    if et == "suspicious_llm_usage":
        rules_triggered.append("rule:ai-assisted-attack")
        ai_adv_score = 0.7

    # Default rule if nothing triggered
    if not rules_triggered:
        rules_triggered.append("rule:default_allow")

    # Compute score and threat level
    score = sum(RULE_SCORES.get(r, 0) for r in rules_triggered)
    threat_level = _threat_from_score(score)

    return threat_level, mitigations, rules_triggered, anomaly_score, ai_adv_score, score


# =============================================================================
# Doctrine Application
# =============================================================================


def _apply_doctrine(
    inp: PipelineInput,
    threat_level: ThreatLevel,
    mitigations: List[Mitigation],
    score: int,
    *,
    policy_id: str,
    policy_hash: str,
) -> tuple:
    """
    Apply doctrine rules to mitigations.

    This is the SINGLE SOURCE OF TRUTH for doctrine application.

    Returns:
        (filtered_mitigations, tie_d, roe_applied, disruption_limited, ao_required)
    """
    persona_v = (inp.persona or "").strip().lower() or None
    class_v = (inp.classification or "").strip().upper() or None

    roe_applied = False
    disruption_limited = False
    ao_required = False

    out = list(mitigations)

    # Baseline impacts
    base_impact = 0.0
    base_user_impact = 0.0

    disruptive_actions = {"block_ip", "block", "quarantine", "terminate"}
    has_disruptive = any(m.action.lower() in disruptive_actions for m in out)

    if has_disruptive:
        base_impact = 0.35
        base_user_impact = 0.20

    # Guardian + SECRET triggers ROE
    if persona_v == "guardian" and class_v == "SECRET":
        roe_applied = True
        ao_required = True

        # Cap disruptive actions to 1
        disruptive_mits = [m for m in out if m.action.lower() in disruptive_actions]
        if len(disruptive_mits) > 1:
            disruption_limited = True
            first = disruptive_mits[0]
            out = [m for m in out if m.action.lower() not in disruptive_actions]
            out.insert(0, first)

        if disruption_limited:
            base_impact = max(0.0, base_impact - 0.10)
            base_user_impact = max(0.0, base_user_impact - 0.05)

    # Sentinel allows more disruptive actions
    elif persona_v == "sentinel":
        max_disruptive = 3
        disruptive_mits = [m for m in out if m.action.lower() in disruptive_actions]
        if len(disruptive_mits) > max_disruptive:
            disruption_limited = True
            kept = disruptive_mits[:max_disruptive]
            out = [m for m in out if m.action.lower() not in disruptive_actions]
            out = kept + out

    # Compute gating decision
    gating_decision: Literal["allow", "require_approval", "reject"] = "allow"
    if persona_v == "guardian" and class_v == "SECRET":
        remaining_disruptive = any(m.action.lower() in disruptive_actions for m in out)
        gating_decision = "require_approval" if remaining_disruptive else "allow"

    tie_d = TieD(
        roe_applied=roe_applied,
        disruption_limited=disruption_limited,
        ao_required=ao_required,
        persona=persona_v,
        classification=class_v,
        service_impact=float(min(1.0, max(0.0, base_impact))),
        user_impact=float(min(1.0, max(0.0, base_user_impact))),
        gating_decision=gating_decision,
        policy_version=policy_id,
        policy_hash=policy_hash,
    )

    return out, tie_d, roe_applied, disruption_limited, ao_required


# =============================================================================
# Unified Pipeline Entry Point
# =============================================================================


def evaluate(inp: PipelineInput) -> PipelineResult:
    """
    SINGLE ENTRY POINT for all decision evaluation.

    Both /defend and /ingest MUST call this function.

    P0 Invariants:
      - Same input produces same output
      - TieD is always present
      - Doctrine is always applied
    """
    # 1. Compute event identity
    event_id = inp.event_id or _compute_event_id(inp)
    clock_drift_ms = _compute_clock_drift_ms(inp.timestamp)

    # 2. Evaluate rules
    threat_level, mitigations, rules_triggered, anomaly_score, ai_adv_score, score = (
        _evaluate_rules(inp)
    )

    # 3. Policy selection + doctrine application
    fingerprint = get_active_policy_fingerprint()
    filtered_mits, tie_d, roe_applied, disruption_limited, ao_required = _apply_doctrine(
        inp,
        threat_level,
        mitigations,
        score,
        policy_id=fingerprint.policy_id,
        policy_hash=fingerprint.policy_hash,
    )

    # 4. Build explanation
    explanation_brief = f"{inp.event_type}: {threat_level} ({score})"

    return PipelineResult(
        threat_level=threat_level,
        mitigations=filtered_mits,
        rules_triggered=rules_triggered,
        score=score,
        anomaly_score=anomaly_score,
        ai_adversarial_score=ai_adv_score,
        tie_d=tie_d,
        event_id=event_id,
        clock_drift_ms=clock_drift_ms,
        explanation_brief=explanation_brief,
        roe_applied=roe_applied,
        disruption_limited=disruption_limited,
        ao_required=ao_required,
        policy_hash=fingerprint.policy_hash,
    )


def evaluate_dict(telemetry: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluate telemetry dict and return dict result.

    Convenience wrapper for /ingest compatibility.
    """
    inp = PipelineInput(
        tenant_id=telemetry.get("tenant_id") or "unknown",
        source=telemetry.get("source") or "unknown",
        event_type=telemetry.get("event_type") or "unknown",
        payload=telemetry.get("payload") or {},
        timestamp=telemetry.get("timestamp"),
        persona=telemetry.get("persona"),
        classification=telemetry.get("classification"),
        event_id=telemetry.get("event_id"),
        meta=telemetry.get("meta"),
    )

    result = evaluate(inp)
    return result.to_dict()
