"""Trust Intelligence Layer — PR 1.8.

Transforms Trust Infrastructure outputs (PRs 1.1–1.7A) into actionable
governance intelligence. Sits above all prior trust authorities.

Every output is:
  Deterministic    — same inputs produce same outputs every time
  Explainable      — every recommendation traces to specific evidence
  Auditable        — all scoring uses named, exported constants
  Tenant scoped    — no cross-tenant intelligence leakage possible
  Future safe      — works for humans, agents, autonomous systems, AGI

Architecture:
  Part 1   calculate_trust_posture()           — 6 posture levels
  Part 2   calculate_trust_trend()             — direction + velocity (4 windows)
  Part 3   generate_trust_priorities()         — ranked remediation priorities
  Part 4   calculate_trust_risk()              — 7-category risk decomposition
  Part 5   generate_trust_insights()           — explainable operational insights
  Part 6   detect_trust_hotspots()             — degradation concentration detection
  Part 7   generate_executive_actions()        — board-ready action items
  Part 8   generate_governance_recommendations() — AI/Agent/AGI governance
  Part 9   forecast_trust_posture()            — deterministic trend extrapolation
  Part 10  generate_trust_intelligence_graph() — intelligence graph (nodes + edges)

No machine learning. No LLMs. No adaptive weighting.
Every calculation is reproducible from source evidence.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

TRUST_INTELLIGENCE_VERSION: str = "trust-intelligence-v1"

# ---------------------------------------------------------------------------
# Posture thresholds
# ---------------------------------------------------------------------------
_POSTURE_EXCELLENT: int = 90  # 90–100 → excellent
_POSTURE_HEALTHY: int = 75  # 75–89  → healthy
_POSTURE_STABLE: int = 60  # 60–74  → stable
_POSTURE_WATCH: int = 45  # 45–59  → watch
_POSTURE_DEGRADED: int = 25  # 25–44  → degraded
#                               0–24   → critical

# ---------------------------------------------------------------------------
# Trend thresholds (inclusive at boundary)
# ---------------------------------------------------------------------------
_TREND_RAPID_THRESHOLD: int = 10  # abs(delta) >= 10 → rapidly_*
_TREND_VELOCITY_RAPID: int = 20  # abs(delta) >= 20 → rapid
_TREND_VELOCITY_SIGNIFICANT: int = 12
_TREND_VELOCITY_MODERATE: int = 6
_TREND_VELOCITY_LOW: int = 2

# ---------------------------------------------------------------------------
# Risk thresholds
# ---------------------------------------------------------------------------
_RISK_CRITICAL_THRESHOLD: int = 75
_RISK_HIGH_THRESHOLD: int = 55
_RISK_MEDIUM_THRESHOLD: int = 35
_RISK_LOW_THRESHOLD: int = 15

# ---------------------------------------------------------------------------
# Posture score weights (must sum to 1.0)
# ---------------------------------------------------------------------------
_WEIGHT_CONFIDENCE: float = 0.50
_WEIGHT_REPLAY: float = 0.20
_WEIGHT_GRAPH: float = 0.15
_WEIGHT_AUTHORITY: float = 0.10
_WEIGHT_ENFORCEMENT: float = 0.05

# ---------------------------------------------------------------------------
# Drift modifiers applied after weighted score
# ---------------------------------------------------------------------------
_DRIFT_RAPIDLY_IMPROVING: int = 8
_DRIFT_IMPROVING: int = 3
_DRIFT_STABLE: int = 0
_DRIFT_DEGRADING: int = -5
_DRIFT_RAPIDLY_DEGRADING: int = -12

# ---------------------------------------------------------------------------
# Forecast windows
# ---------------------------------------------------------------------------
_FORECAST_WINDOWS: tuple[int, ...] = (30, 90, 180, 365)

# ---------------------------------------------------------------------------
# Intelligence graph node type constants
# ---------------------------------------------------------------------------
GRAPH_NODE_POSTURE: str = "trust_posture"
GRAPH_NODE_TREND: str = "trust_trend"
GRAPH_NODE_RISK: str = "trust_risk"
GRAPH_NODE_PRIORITY: str = "trust_priority"
GRAPH_NODE_RECOMMENDATION: str = "trust_recommendation"
GRAPH_NODE_FORECAST: str = "trust_forecast"
GRAPH_NODE_INSIGHT: str = "trust_insight"
GRAPH_NODE_HOTSPOT: str = "trust_hotspot"


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _posture_from_score(score: int) -> str:
    """Return posture level label for a numeric score in [0, 100]."""
    if score >= _POSTURE_EXCELLENT:
        return "excellent"
    if score >= _POSTURE_HEALTHY:
        return "healthy"
    if score >= _POSTURE_STABLE:
        return "stable"
    if score >= _POSTURE_WATCH:
        return "watch"
    if score >= _POSTURE_DEGRADED:
        return "degraded"
    return "critical"


def _risk_from_score(score: int) -> str:
    """Return risk level label for a numeric score in [0, 100]."""
    if score >= _RISK_CRITICAL_THRESHOLD:
        return "critical"
    if score >= _RISK_HIGH_THRESHOLD:
        return "high"
    if score >= _RISK_MEDIUM_THRESHOLD:
        return "medium"
    if score >= _RISK_LOW_THRESHOLD:
        return "low"
    return "none"


def _velocity_from_delta(delta: int) -> str:
    """Return velocity label from absolute delta magnitude."""
    abs_delta = abs(delta)
    if abs_delta >= _TREND_VELOCITY_RAPID:
        return "rapid"
    if abs_delta >= _TREND_VELOCITY_SIGNIFICANT:
        return "significant"
    if abs_delta >= _TREND_VELOCITY_MODERATE:
        return "moderate"
    if abs_delta >= _TREND_VELOCITY_LOW:
        return "low"
    return "minimal"


def _trend_from_delta(delta: int) -> str:
    """Return trend direction from signed delta.

    Inclusive at boundary: delta >= _TREND_RAPID_THRESHOLD → rapidly_improving,
    delta <= -_TREND_RAPID_THRESHOLD → rapidly_degrading.
    """
    if delta >= _TREND_RAPID_THRESHOLD:
        return "rapidly_improving"
    if delta > 0:
        return "improving"
    if delta <= -_TREND_RAPID_THRESHOLD:
        return "rapidly_degrading"
    if delta < 0:
        return "degrading"
    return "stable"


def _clamp(value: int, lo: int = 0, hi: int = 100) -> int:
    """Clamp integer value to [lo, hi]."""
    return max(lo, min(hi, value))


def _parse_iso(dt_str: str) -> datetime | None:
    """Try multiple ISO 8601 formats; return None on any failure."""
    if not dt_str:
        return None
    formats = (
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%d",
    )
    for fmt in formats:
        try:
            dt = datetime.strptime(dt_str, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except (ValueError, TypeError):
            continue
    return None


def _get_ts(snapshot: dict[str, Any]) -> datetime | None:
    """Extract a datetime from a snapshot using any known timestamp key."""
    for key in ("created_at", "generated_at", "timestamp"):
        raw = snapshot.get(key)
        if raw:
            result = _parse_iso(str(raw))
            if result is not None:
                return result
    return None


# ---------------------------------------------------------------------------
# Part 1 — calculate_trust_posture
# ---------------------------------------------------------------------------


def calculate_trust_posture(
    *,
    confidence_result: dict[str, Any] | None = None,
    replay_result: dict[str, Any] | None = None,
    graph_result: dict[str, Any] | None = None,
    drift_result: dict[str, Any] | None = None,
    enforcement_result: dict[str, Any] | None = None,
    evidence_authority: dict[str, Any] | None = None,
    tenant_id: str = "",
    engagement_id: str = "",
) -> dict[str, Any]:
    """Compute a weighted trust posture score from up to 5 component sources.

    All inputs are optional; sensible defaults are applied for absent inputs.
    Returns a dict containing posture level, composite score, reasoning,
    and per-component breakdown.
    """
    # --- confidence component (weight 0.50) ---
    confidence_score: int = 0
    if confidence_result is not None:
        raw = confidence_result.get("confidence_score", 0)
        try:
            confidence_score = _clamp(int(raw))
        except (TypeError, ValueError):
            confidence_score = 0

    # --- replay component (weight 0.20) — default 100 when not provided ---
    replay_score: int = 100
    if replay_result is not None:
        raw = replay_result.get("chain_replay_score", 100)
        try:
            replay_score = _clamp(int(raw))
        except (TypeError, ValueError):
            replay_score = 100

    # --- graph component (weight 0.15) ---
    graph_score: int = 100
    if graph_result is not None:
        graph_valid = graph_result.get("graph_valid")
        if graph_valid is False:
            graph_score = 0
        else:
            violations = 0
            try:
                violations = int(graph_result.get("violations", 0) or 0)
            except (TypeError, ValueError):
                violations = 0
            graph_score = _clamp(100 - violations * 10)

    # --- authority component (weight 0.10) ---
    authority_score: int = 100
    if evidence_authority is not None:
        if evidence_authority.get("valid") is False:
            authority_score = 0

    # --- enforcement component (weight 0.05) ---
    enforcement_score: int = 100
    if enforcement_result is not None:
        if enforcement_result.get("allowed") is False:
            enforcement_score = 0
        else:
            raw = enforcement_result.get("trust_score", 100)
            try:
                enforcement_score = _clamp(int(raw))
            except (TypeError, ValueError):
                enforcement_score = 100

    # --- weighted composite ---
    weighted = (
        confidence_score * _WEIGHT_CONFIDENCE
        + replay_score * _WEIGHT_REPLAY
        + graph_score * _WEIGHT_GRAPH
        + authority_score * _WEIGHT_AUTHORITY
        + enforcement_score * _WEIGHT_ENFORCEMENT
    )

    # --- drift modifier ---
    drift_direction = "stable"
    drift_modifier = _DRIFT_STABLE
    if drift_result is not None:
        drift_direction = str(drift_result.get("direction", "stable"))
        if drift_direction == "rapidly_improving":
            drift_modifier = _DRIFT_RAPIDLY_IMPROVING
        elif drift_direction == "improving":
            drift_modifier = _DRIFT_IMPROVING
        elif drift_direction == "degrading":
            drift_modifier = _DRIFT_DEGRADING
        elif drift_direction == "rapidly_degrading":
            drift_modifier = _DRIFT_RAPIDLY_DEGRADING
        else:
            drift_modifier = _DRIFT_STABLE

    final_score = _clamp(int(round(weighted)) + drift_modifier)
    posture_level = _posture_from_score(final_score)

    # --- reasoning ---
    reasoning_parts = [
        f"confidence={confidence_score}(w=0.50)",
        f"replay={replay_score}(w=0.20)",
        f"graph={graph_score}(w=0.15)",
        f"authority={authority_score}(w=0.10)",
        f"enforcement={enforcement_score}(w=0.05)",
        f"drift_modifier={drift_modifier:+d}({drift_direction})",
    ]
    reasoning = (
        "weighted_composite: "
        + " + ".join(reasoning_parts[:-1])
        + f"; {reasoning_parts[-1]}"
    )

    return {
        "trust_posture": posture_level,
        "score": final_score,
        "confidence": confidence_score,
        "reasoning": reasoning,
        "generated_from": "calculate_trust_posture",
        "tenant_id": tenant_id,
        "engagement_id": engagement_id,
        "intelligence_version": TRUST_INTELLIGENCE_VERSION,
        "component_scores": {
            "confidence_score": confidence_score,
            "replay_score": replay_score,
            "graph_score": graph_score,
            "authority_score": authority_score,
            "enforcement_score": enforcement_score,
        },
    }


# ---------------------------------------------------------------------------
# Part 2 — calculate_trust_trend
# ---------------------------------------------------------------------------


def calculate_trust_trend(
    snapshots: list[dict[str, Any]],
    *,
    window_days: int = 90,
    tenant_id: str = "",
    engagement_id: str = "",
) -> dict[str, Any]:
    """Derive trend direction and velocity from a list of trust snapshots.

    Snapshots are filtered to the requested window (validated against
    _FORECAST_WINDOWS; defaults to 90 on unknown windows), sorted by
    timestamp, and compared first-vs-last.
    """
    # Validate window
    if window_days not in _FORECAST_WINDOWS:
        window_days = 90

    now = datetime.now(tz=timezone.utc)

    # Filter snapshots to window and extract timestamp + score
    valid: list[tuple[datetime, int, int]] = []  # (ts, score, confidence)
    for item in snapshots or []:
        if not isinstance(item, dict):
            continue
        ts = _get_ts(item)
        if ts is None:
            continue
        delta_days = (now - ts).total_seconds() / 86400.0
        if delta_days > window_days:
            continue
        # score: prefer "score" then "confidence_score"
        score_raw = item.get("score", item.get("confidence_score", 0))
        try:
            score = _clamp(int(score_raw))
        except (TypeError, ValueError):
            score = 0
        # confidence: prefer "confidence" then "confidence_score" then fall back to score
        conf_raw = item.get("confidence", item.get("confidence_score", score_raw))
        try:
            confidence = _clamp(int(conf_raw))
        except (TypeError, ValueError):
            confidence = score
        valid.append((ts, score, confidence))

    if len(valid) < 2:
        return {
            "direction": "stable",
            "velocity": "minimal",
            "score_change": 0,
            "confidence_change": 0,
            "window_days": window_days,
            "data_points": len(valid),
            "trend_available": False,
            "start_score": valid[0][1] if valid else 0,
            "end_score": valid[0][1] if valid else 0,
            "tenant_id": tenant_id,
            "engagement_id": engagement_id,
            "intelligence_version": TRUST_INTELLIGENCE_VERSION,
        }

    # Sort ascending by timestamp
    valid.sort(key=lambda x: x[0])
    start_ts, start_score, start_conf = valid[0]
    end_ts, end_score, end_conf = valid[-1]

    score_change = end_score - start_score
    confidence_change = end_conf - start_conf

    direction = _trend_from_delta(score_change)
    velocity = _velocity_from_delta(score_change)

    return {
        "direction": direction,
        "velocity": velocity,
        "score_change": score_change,
        "confidence_change": confidence_change,
        "window_days": window_days,
        "data_points": len(valid),
        "trend_available": True,
        "start_score": start_score,
        "end_score": end_score,
        "tenant_id": tenant_id,
        "engagement_id": engagement_id,
        "intelligence_version": TRUST_INTELLIGENCE_VERSION,
    }


# ---------------------------------------------------------------------------
# Part 3 — generate_trust_priorities
# ---------------------------------------------------------------------------


def generate_trust_priorities(
    *,
    posture_result: dict[str, Any] | None = None,
    risk_result: dict[str, Any] | None = None,
    insights: list[dict[str, Any]] | None = None,
    hotspots: list[dict[str, Any]] | None = None,
    confidence_result: dict[str, Any] | None = None,
    replay_result: dict[str, Any] | None = None,
    drift_result: dict[str, Any] | None = None,
    tenant_id: str = "",
    engagement_id: str = "",
) -> list[dict[str, Any]]:
    """Produce a ranked remediation priority list from all available inputs.

    Candidates are sourced from replay, confidence, drift, risk, posture, and
    hotspot inputs. Sorted by trust_delta descending, deduplicated by issue key,
    then re-numbered 1..n.
    """
    candidates: list[dict[str, Any]] = []

    # --- replay ---
    chain_replay_score: int | None = None
    if replay_result is not None:
        raw = replay_result.get("chain_replay_score")
        try:
            chain_replay_score = _clamp(int(raw)) if raw is not None else None
        except (TypeError, ValueError):
            chain_replay_score = None

    if chain_replay_score is not None:
        if chain_replay_score == 0:
            candidates.append(
                {
                    "issue": "trust_chain_broken",
                    "impact": "critical",
                    "trust_delta": 30,
                    "reason": "Chain replay score is zero — trust chain is fully broken.",
                    "evidence": {"chain_replay_score": chain_replay_score},
                }
            )
        elif chain_replay_score < 75:
            candidates.append(
                {
                    "issue": "trust_chain_degraded",
                    "impact": "high",
                    "trust_delta": 20,
                    "reason": "Chain replay score below 75 — significant gaps in trust chain.",
                    "evidence": {"chain_replay_score": chain_replay_score},
                }
            )
        elif chain_replay_score < 100:
            candidates.append(
                {
                    "issue": "trust_chain_legacy_unsigned",
                    "impact": "medium",
                    "trust_delta": 10,
                    "reason": "Chain replay score below 100 — legacy unsigned evidence present.",
                    "evidence": {"chain_replay_score": chain_replay_score},
                }
            )

    # --- confidence ---
    confidence_score: int | None = None
    if confidence_result is not None:
        raw = confidence_result.get("confidence_score")
        try:
            confidence_score = _clamp(int(raw)) if raw is not None else None
        except (TypeError, ValueError):
            confidence_score = None

    if confidence_score is not None:
        if confidence_score < 25:
            candidates.append(
                {
                    "issue": "critical_confidence_deficit",
                    "impact": "critical",
                    "trust_delta": 40,
                    "reason": "Confidence score critically low — evidence base is insufficient.",
                    "evidence": {"confidence_score": confidence_score},
                }
            )
        elif confidence_score < 50:
            candidates.append(
                {
                    "issue": "low_confidence_score",
                    "impact": "high",
                    "trust_delta": 25,
                    "reason": "Confidence score below 50 — trust validation is weak.",
                    "evidence": {"confidence_score": confidence_score},
                }
            )

    # --- drift ---
    if drift_result is not None:
        drift_direction = str(drift_result.get("direction", "stable"))
        if drift_direction == "rapidly_degrading":
            candidates.append(
                {
                    "issue": "rapid_trust_decline",
                    "impact": "critical",
                    "trust_delta": 35,
                    "reason": "Trust is rapidly degrading — immediate intervention required.",
                    "evidence": {"drift_direction": drift_direction},
                }
            )
        elif drift_direction == "degrading":
            candidates.append(
                {
                    "issue": "trust_decline",
                    "impact": "high",
                    "trust_delta": 15,
                    "reason": "Trust is on a declining trajectory.",
                    "evidence": {"drift_direction": drift_direction},
                }
            )

    # --- risk ---
    if risk_result is not None:
        risk_level = str(risk_result.get("risk_level", "none"))
        if risk_level == "critical":
            candidates.append(
                {
                    "issue": "critical_risk_exposure",
                    "impact": "critical",
                    "trust_delta": 30,
                    "reason": "Overall risk assessment is critical — systemic exposure detected.",
                    "evidence": {"risk_level": risk_level},
                }
            )
        elif risk_level == "high":
            candidates.append(
                {
                    "issue": "high_risk_exposure",
                    "impact": "high",
                    "trust_delta": 18,
                    "reason": "Overall risk assessment is high.",
                    "evidence": {"risk_level": risk_level},
                }
            )

    # --- posture ---
    if posture_result is not None:
        posture_score_raw = posture_result.get("score", 100)
        try:
            posture_score = _clamp(int(posture_score_raw))
        except (TypeError, ValueError):
            posture_score = 100
        if posture_score < 25:
            candidates.append(
                {
                    "issue": "critical_posture",
                    "impact": "critical",
                    "trust_delta": 50,
                    "reason": "Trust posture score is critically low.",
                    "evidence": {"posture_score": posture_score},
                }
            )

    # --- hotspots ---
    for spot in hotspots or []:
        if not isinstance(spot, dict):
            continue
        severity = str(spot.get("severity", ""))
        area = str(spot.get("area", "unknown"))
        if severity == "critical":
            candidates.append(
                {
                    "issue": f"hotspot_{area}",
                    "impact": "critical",
                    "trust_delta": 20,
                    "reason": f"Critical hotspot detected in {area}.",
                    "evidence": {"hotspot_area": area, "severity": severity},
                }
            )
        elif severity == "high":
            candidates.append(
                {
                    "issue": f"hotspot_{area}",
                    "impact": "high",
                    "trust_delta": 12,
                    "reason": f"High-severity hotspot detected in {area}.",
                    "evidence": {"hotspot_area": area, "severity": severity},
                }
            )

    # Default if nothing found
    if not candidates:
        return [
            {
                "priority": 1,
                "issue": "maintain_trust_posture",
                "impact": "low",
                "trust_delta": 0,
                "reason": "No immediate trust concerns detected.",
                "evidence": {},
            }
        ]

    # Sort descending by trust_delta
    candidates.sort(key=lambda c: c["trust_delta"], reverse=True)

    # Deduplicate by issue (keep first occurrence = highest delta)
    seen: set[str] = set()
    deduped: list[dict[str, Any]] = []
    for c in candidates:
        if c["issue"] not in seen:
            seen.add(c["issue"])
            deduped.append(c)

    # Re-number priorities
    result = []
    for idx, c in enumerate(deduped, start=1):
        result.append(
            {
                "priority": idx,
                "issue": c["issue"],
                "impact": c["impact"],
                "trust_delta": c["trust_delta"],
                "reason": c["reason"],
                "evidence": c["evidence"],
            }
        )

    return result


# ---------------------------------------------------------------------------
# Part 4 — calculate_trust_risk
# ---------------------------------------------------------------------------


def calculate_trust_risk(
    *,
    replay_result: dict[str, Any] | None = None,
    graph_result: dict[str, Any] | None = None,
    confidence_result: dict[str, Any] | None = None,
    drift_result: dict[str, Any] | None = None,
    enforcement_result: dict[str, Any] | None = None,
    evidence_authority: dict[str, Any] | None = None,
    posture_result: dict[str, Any] | None = None,
    tenant_id: str = "",
    engagement_id: str = "",
) -> dict[str, Any]:
    """Decompose trust risk into 7 named categories.

    Overall risk = max_score * 0.70 + avg_score * 0.30, clamped to [0, 100].
    """
    category_scores: dict[str, int] = {}

    # --- authority_risk ---
    authority_risk = 0
    if evidence_authority is not None:
        if evidence_authority.get("valid") is False:
            authority_risk = 80
        elif evidence_authority.get("version_mismatch") is True:
            authority_risk = 40
    category_scores["authority_risk"] = authority_risk

    # --- replay_risk ---
    replay_risk = 0
    if replay_result is not None:
        raw = replay_result.get("chain_replay_score")
        if raw is not None:
            try:
                rrs = _clamp(int(raw))
            except (TypeError, ValueError):
                rrs = 100
            if rrs == 0:
                replay_risk = 90
            elif rrs < 50:
                replay_risk = 70
            elif rrs < 75:
                replay_risk = 45
            elif rrs < 100:
                replay_risk = 20
    category_scores["replay_risk"] = replay_risk

    # --- graph_risk ---
    graph_risk = 0
    if graph_result is not None:
        graph_valid = graph_result.get("graph_valid")
        if graph_valid is False:
            graph_risk = 80
        else:
            violations = 0
            try:
                violations = int(graph_result.get("violations", 0) or 0)
            except (TypeError, ValueError):
                violations = 0
            if violations > 0:
                graph_risk = min(70, violations * 15)
    category_scores["graph_risk"] = graph_risk

    # --- confidence_risk ---
    confidence_risk = 0
    if confidence_result is not None:
        cs_raw = confidence_result.get("confidence_score")
        level = str(confidence_result.get("level", ""))
        if cs_raw is not None:
            try:
                cs = _clamp(int(cs_raw))
            except (TypeError, ValueError):
                cs = 100
            if cs < 25 or level == "critical":
                confidence_risk = 85
            elif cs < 50 or level == "weak":
                confidence_risk = 60
            elif cs < 75 or level == "moderate":
                confidence_risk = 30
    category_scores["confidence_risk"] = confidence_risk

    # --- drift_risk ---
    drift_risk = 0
    if drift_result is not None:
        direction = str(drift_result.get("direction", "stable"))
        velocity = str(drift_result.get("velocity", "minimal"))
        velocity_bonus = 0
        if velocity == "rapid":
            velocity_bonus = 10
        elif velocity == "significant":
            velocity_bonus = 5
        if direction == "rapidly_degrading":
            drift_risk = _clamp(75 + velocity_bonus)
        elif direction == "degrading":
            drift_risk = _clamp(45 + velocity_bonus)
    category_scores["drift_risk"] = drift_risk

    # --- governance_risk ---
    governance_risk = 0
    if enforcement_result is not None:
        mode = str(enforcement_result.get("enforcement_mode", ""))
        if mode == "off":
            governance_risk = 50
        elif enforcement_result.get("allowed") is False:
            governance_risk = 70
    category_scores["governance_risk"] = governance_risk

    # --- future_autonomy_risk ---
    future_autonomy_risk = 0
    cs_for_autonomy = 100
    if confidence_result is not None:
        raw = confidence_result.get("confidence_score")
        try:
            cs_for_autonomy = _clamp(int(raw)) if raw is not None else 100
        except (TypeError, ValueError):
            cs_for_autonomy = 100

    rrs_for_autonomy = 100
    if replay_result is not None:
        raw = replay_result.get("chain_replay_score")
        try:
            rrs_for_autonomy = _clamp(int(raw)) if raw is not None else 100
        except (TypeError, ValueError):
            rrs_for_autonomy = 100

    posture_score_for_autonomy = 100
    if posture_result is not None:
        raw = posture_result.get("score")
        try:
            posture_score_for_autonomy = _clamp(int(raw)) if raw is not None else 100
        except (TypeError, ValueError):
            posture_score_for_autonomy = 100

    if cs_for_autonomy < 50 or rrs_for_autonomy < 75:
        future_autonomy_risk = 60
    elif posture_score_for_autonomy < 60:
        future_autonomy_risk = 35
    category_scores["future_autonomy_risk"] = future_autonomy_risk

    # --- overall risk ---
    scores = list(category_scores.values())
    max_score = max(scores)
    avg_score = sum(scores) / len(scores)
    overall = _clamp(int(round(max_score * 0.70 + avg_score * 0.30)))

    risk_level = _risk_from_score(overall)

    contributing_factors = sorted(
        k for k, v in category_scores.items() if v >= _RISK_MEDIUM_THRESHOLD
    )

    return {
        "risk_level": risk_level,
        "risk_score": overall,
        "contributing_factors": contributing_factors,
        "category_scores": category_scores,
        "tenant_id": tenant_id,
        "engagement_id": engagement_id,
        "intelligence_version": TRUST_INTELLIGENCE_VERSION,
    }


# ---------------------------------------------------------------------------
# Part 5 — generate_trust_insights
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def generate_trust_insights(
    *,
    posture_result: dict[str, Any] | None = None,
    trend_result: dict[str, Any] | None = None,
    risk_result: dict[str, Any] | None = None,
    hotspots: list[dict[str, Any]] | None = None,
    confidence_result: dict[str, Any] | None = None,
    drift_result: dict[str, Any] | None = None,
    tenant_id: str = "",
    engagement_id: str = "",
) -> list[dict[str, Any]]:
    """Generate explainable operational insights from all available inputs.

    Each insight has category, severity, insight text, evidence, and a
    recommended action. Sorted critical-first.
    """
    insights: list[dict[str, Any]] = []

    # --- drift insights ---
    if drift_result is not None:
        drift_dir = str(drift_result.get("direction", "stable"))
        if drift_dir == "rapidly_degrading":
            insights.append(
                {
                    "category": "drift",
                    "severity": "critical",
                    "insight": "Trust is rapidly degrading — immediate intervention required to prevent systemic failure.",
                    "evidence": {"drift_direction": drift_dir},
                    "recommended_action": "Halt all autonomous operations and convene trust review board.",
                }
            )
        elif drift_dir == "degrading":
            insights.append(
                {
                    "category": "drift",
                    "severity": "high",
                    "insight": "Trust is on a declining trajectory — action required before threshold breach.",
                    "evidence": {"drift_direction": drift_dir},
                    "recommended_action": "Initiate trust remediation plan within 72 hours.",
                }
            )
        elif drift_dir == "improving":
            insights.append(
                {
                    "category": "drift",
                    "severity": "info",
                    "insight": "Trust is improving — current practices are effective.",
                    "evidence": {"drift_direction": drift_dir},
                    "recommended_action": "Maintain current trust improvement practices.",
                }
            )
        elif drift_dir == "rapidly_improving":
            insights.append(
                {
                    "category": "drift",
                    "severity": "info",
                    "insight": "Trust is rapidly improving — significant positive trajectory detected.",
                    "evidence": {"drift_direction": drift_dir},
                    "recommended_action": "Document successful practices for replication.",
                }
            )

    # --- trend insights (independent from drift) ---
    if trend_result is not None:
        trend_dir = str(trend_result.get("direction", "stable"))
        # only emit if it differs from what drift already reported
        drift_dir_seen = (
            str(drift_result.get("direction", "stable")) if drift_result else "stable"
        )
        if trend_dir != drift_dir_seen:
            if trend_dir == "rapidly_degrading":
                insights.append(
                    {
                        "category": "authority",
                        "severity": "critical",
                        "insight": "Trend analysis shows rapid degradation independent of real-time drift signal.",
                        "evidence": {"trend_direction": trend_dir},
                        "recommended_action": "Cross-validate trend source with drift authority.",
                    }
                )
            elif trend_dir == "degrading":
                insights.append(
                    {
                        "category": "authority",
                        "severity": "high",
                        "insight": "Trend analysis indicates declining trust over the measured window.",
                        "evidence": {"trend_direction": trend_dir},
                        "recommended_action": "Review historical trust data for root cause.",
                    }
                )

    # --- confidence insights ---
    if confidence_result is not None:
        cs_raw = confidence_result.get("confidence_score")
        try:
            cs = _clamp(int(cs_raw)) if cs_raw is not None else 100
        except (TypeError, ValueError):
            cs = 100
        if cs < 25:
            insights.append(
                {
                    "category": "corroboration",
                    "severity": "critical",
                    "insight": f"Confidence score is critically low ({cs}) — insufficient corroborated evidence.",
                    "evidence": {"confidence_score": cs},
                    "recommended_action": "Collect additional corroborated evidence from independent sources.",
                }
            )
        elif cs < 50:
            insights.append(
                {
                    "category": "corroboration",
                    "severity": "high",
                    "insight": f"Confidence score is low ({cs}) — trust validation quality is weak.",
                    "evidence": {"confidence_score": cs},
                    "recommended_action": "Strengthen evidence base with cross-referenced sources.",
                }
            )

    # --- risk category insights ---
    if risk_result is not None:
        cat = risk_result.get("category_scores", {})
        replay_risk = int(cat.get("replay_risk", 0))
        governance_risk = int(cat.get("governance_risk", 0))
        autonomy_risk = int(cat.get("future_autonomy_risk", 0))

        if replay_risk >= _RISK_HIGH_THRESHOLD:
            insights.append(
                {
                    "category": "replay",
                    "severity": "high",
                    "insight": f"Replay risk is elevated ({replay_risk}) — trust chain integrity is questionable.",
                    "evidence": {"replay_risk": replay_risk},
                    "recommended_action": "Re-run full chain replay verification and resign legacy evidence.",
                }
            )

        if governance_risk >= _RISK_HIGH_THRESHOLD:
            insights.append(
                {
                    "category": "governance",
                    "severity": "high",
                    "insight": f"Governance risk is elevated ({governance_risk}) — enforcement controls are insufficient.",
                    "evidence": {"governance_risk": governance_risk},
                    "recommended_action": "Activate enforcement mode and review governance gate configuration.",
                }
            )

        if autonomy_risk >= _RISK_HIGH_THRESHOLD:
            insights.append(
                {
                    "category": "governance",
                    "severity": "high",
                    "insight": f"Future autonomy risk is elevated ({autonomy_risk}) — autonomous operations should be restricted.",
                    "evidence": {"future_autonomy_risk": autonomy_risk},
                    "recommended_action": "Require human approval for all autonomous system actions until trust is restored.",
                }
            )

    # --- hotspot insights ---
    for spot in hotspots or []:
        if not isinstance(spot, dict):
            continue
        severity = str(spot.get("severity", ""))
        area = str(spot.get("area", "unknown"))
        if severity in ("critical", "high"):
            insights.append(
                {
                    "category": "corroboration",
                    "severity": severity,
                    "insight": f"{severity.capitalize()} trust hotspot detected in '{area}' — concentrated degradation present.",
                    "evidence": {"hotspot_area": area, "hotspot_severity": severity},
                    "recommended_action": f"Prioritise remediation of the '{area}' trust component.",
                }
            )

    # --- posture insights ---
    if posture_result is not None:
        level = str(posture_result.get("trust_posture", ""))
        score = posture_result.get("score", 100)
        if level == "critical":
            insights.append(
                {
                    "category": "general",
                    "severity": "critical",
                    "insight": f"Overall trust posture is critical (score={score}) — system-wide trust has failed.",
                    "evidence": {"trust_posture": level, "score": score},
                    "recommended_action": "Initiate emergency trust recovery protocol immediately.",
                }
            )
        elif level == "degraded":
            insights.append(
                {
                    "category": "general",
                    "severity": "high",
                    "insight": f"Overall trust posture is degraded (score={score}) — significant trust deficiency.",
                    "evidence": {"trust_posture": level, "score": score},
                    "recommended_action": "Execute trust remediation plan and increase monitoring cadence.",
                }
            )

    # Default if no insights
    if not insights:
        return [
            {
                "category": "general",
                "severity": "info",
                "insight": "trust_posture_is_within_acceptable_parameters",
                "evidence": {},
                "recommended_action": "Continue standard trust monitoring practices.",
            }
        ]

    # Sort critical-first
    insights.sort(key=lambda x: _SEVERITY_ORDER.get(x.get("severity", "info"), 4))
    return insights


# ---------------------------------------------------------------------------
# Part 6 — detect_trust_hotspots
# ---------------------------------------------------------------------------


def detect_trust_hotspots(
    *,
    confidence_snapshots: list[dict[str, Any]] | None = None,
    graph_result: dict[str, Any] | None = None,
    risk_result: dict[str, Any] | None = None,
    posture_result: dict[str, Any] | None = None,
    tenant_id: str = "",
    engagement_id: str = "",
) -> list[dict[str, Any]]:
    """Identify areas of concentrated trust degradation.

    Hotspots are derived from risk category scores and confidence snapshot
    averages. Sorted by risk_score descending.
    """
    hotspots: list[dict[str, Any]] = []

    cat: dict[str, int] = {}
    if risk_result is not None:
        raw_cat = risk_result.get("category_scores", {})
        for k, v in raw_cat.items():
            try:
                cat[k] = int(v)
            except (TypeError, ValueError):
                cat[k] = 0

    # --- evidence hotspot ---
    evidence_risk = cat.get("confidence_risk", 0)
    if evidence_risk >= _RISK_HIGH_THRESHOLD:
        severity = "critical" if evidence_risk >= _RISK_CRITICAL_THRESHOLD else "high"
        hotspots.append(
            {
                "area": "evidence",
                "severity": severity,
                "reason": f"Confidence risk score {evidence_risk} indicates degraded evidence quality.",
                "risk_score": evidence_risk,
            }
        )

    # --- authority hotspot ---
    authority_risk = cat.get("authority_risk", 0)
    if authority_risk >= _RISK_HIGH_THRESHOLD:
        severity = "critical" if authority_risk >= _RISK_CRITICAL_THRESHOLD else "high"
        hotspots.append(
            {
                "area": "authority",
                "severity": severity,
                "reason": f"Authority risk score {authority_risk} indicates trust authority failure.",
                "risk_score": authority_risk,
            }
        )

    # --- replay hotspot ---
    replay_risk = cat.get("replay_risk", 0)
    if replay_risk >= _RISK_HIGH_THRESHOLD:
        severity = "critical" if replay_risk >= _RISK_CRITICAL_THRESHOLD else "high"
        hotspots.append(
            {
                "area": "replay",
                "severity": severity,
                "reason": f"Replay risk score {replay_risk} indicates chain integrity issues.",
                "risk_score": replay_risk,
            }
        )

    # --- graph hotspot ---
    graph_risk = cat.get("graph_risk", 0)
    if graph_risk >= _RISK_HIGH_THRESHOLD:
        severity = "critical" if graph_risk >= _RISK_CRITICAL_THRESHOLD else "high"
        hotspots.append(
            {
                "area": "graph",
                "severity": severity,
                "reason": f"Graph risk score {graph_risk} indicates trust graph violations.",
                "risk_score": graph_risk,
            }
        )

    # --- corroboration hotspot from snapshots ---
    corroboration_scores: list[int] = []
    for snap in confidence_snapshots or []:
        if not isinstance(snap, dict):
            continue
        raw = snap.get("corroboration_score")
        if raw is not None:
            try:
                corroboration_scores.append(_clamp(int(raw)))
            except (TypeError, ValueError):
                pass
    if corroboration_scores:
        avg_corroboration = sum(corroboration_scores) / len(corroboration_scores)
        if avg_corroboration < 30:
            hotspots.append(
                {
                    "area": "corroboration",
                    "severity": "critical",
                    "reason": f"Average corroboration score {avg_corroboration:.1f} is critically low.",
                    "risk_score": int(100 - avg_corroboration),
                }
            )
        elif avg_corroboration < 50:
            hotspots.append(
                {
                    "area": "corroboration",
                    "severity": "high",
                    "reason": f"Average corroboration score {avg_corroboration:.1f} is low.",
                    "risk_score": int(100 - avg_corroboration),
                }
            )

    # --- governance hotspot ---
    governance_risk = cat.get("governance_risk", 0)
    autonomy_risk = cat.get("future_autonomy_risk", 0)
    governance_max = max(governance_risk, autonomy_risk)
    if governance_max >= _RISK_HIGH_THRESHOLD:
        severity = "critical" if governance_max >= _RISK_CRITICAL_THRESHOLD else "high"
        hotspots.append(
            {
                "area": "governance",
                "severity": severity,
                "reason": f"Governance/autonomy risk score {governance_max} indicates enforcement gaps.",
                "risk_score": governance_max,
            }
        )

    # Sort by risk_score descending
    hotspots.sort(key=lambda h: h["risk_score"], reverse=True)
    return hotspots


# ---------------------------------------------------------------------------
# Part 7 — generate_executive_actions
# ---------------------------------------------------------------------------

_ACTION_PRIORITY_RANK = {
    "immediate": 0,
    "short_term": 1,
    "medium_term": 2,
    "long_term": 3,
}


def generate_executive_actions(
    *,
    posture_result: dict[str, Any] | None = None,
    trend_result: dict[str, Any] | None = None,
    risk_result: dict[str, Any] | None = None,
    priorities: list[dict[str, Any]] | None = None,
    insights: list[dict[str, Any]] | None = None,
    tenant_id: str = "",
    engagement_id: str = "",
) -> list[dict[str, Any]]:
    """Produce board-ready executive action items from intelligence inputs.

    Actions are sorted by priority rank (immediate first).
    """
    actions: list[dict[str, Any]] = []

    posture_level = ""
    posture_score = 100
    if posture_result is not None:
        posture_level = str(posture_result.get("trust_posture", ""))
        try:
            posture_score = _clamp(int(posture_result.get("score", 100)))
        except (TypeError, ValueError):
            posture_score = 100

    trend_direction = ""
    if trend_result is not None:
        trend_direction = str(trend_result.get("direction", ""))

    risk_level = ""
    autonomy_risk = 0
    if risk_result is not None:
        risk_level = str(risk_result.get("risk_level", ""))
        cat = risk_result.get("category_scores", {})
        try:
            autonomy_risk = int(cat.get("future_autonomy_risk", 0))
        except (TypeError, ValueError):
            autonomy_risk = 0

    # --- immediate actions ---
    if posture_level == "critical":
        actions.append(
            {
                "action": "Convene emergency trust review board and suspend non-critical operations.",
                "priority": "immediate",
                "expected_outcome": "Halt trust degradation and initiate recovery protocol.",
                "reason": "Trust posture is critical — system integrity is at risk.",
                "audience": "executive",
            }
        )

    if trend_direction == "rapidly_degrading":
        actions.append(
            {
                "action": "Activate trust incident response team and freeze autonomous decision-making.",
                "priority": "immediate",
                "expected_outcome": "Arrest rapid trust decline before system-level failure.",
                "reason": "Rapidly degrading trend detected — time-critical intervention required.",
                "audience": "operations",
            }
        )

    if risk_level == "critical":
        actions.append(
            {
                "action": "Engage governance oversight committee and implement mandatory trust gates on all critical paths.",
                "priority": "immediate",
                "expected_outcome": "Reduce critical risk exposure within 24 hours.",
                "reason": "Critical risk level detected — governance controls must be enforced immediately.",
                "audience": "governance",
            }
        )

    # --- short-term actions ---
    if posture_level in ("degraded", "watch") or trend_direction == "degrading":
        actions.append(
            {
                "action": "Execute trust remediation plan: re-sign legacy evidence, increase monitoring cadence.",
                "priority": "short_term",
                "expected_outcome": "Restore trust posture to stable within 30 days.",
                "reason": f"Posture is {posture_level or 'below target'} and/or trend is degrading.",
                "audience": "management",
            }
        )

    if risk_level in ("high", "critical"):
        actions.append(
            {
                "action": "Commission independent trust chain audit and resolve all open replay failures.",
                "priority": "short_term",
                "expected_outcome": "Reduce risk level by one tier within 14 days.",
                "reason": f"Risk level is {risk_level} — an audit chain review is required.",
                "audience": "management",
            }
        )

    # --- medium-term actions ---
    if posture_score < 75:
        actions.append(
            {
                "action": "Invest in evidence quality improvement: increase corroboration sources and signing coverage.",
                "priority": "medium_term",
                "expected_outcome": "Achieve healthy trust posture (score >= 75) within 90 days.",
                "reason": f"Posture score {posture_score} is below the healthy threshold.",
                "audience": "operations",
            }
        )

    if autonomy_risk >= _RISK_HIGH_THRESHOLD:
        actions.append(
            {
                "action": "Establish AI/Agent governance framework: define trust thresholds for autonomous operation.",
                "priority": "medium_term",
                "expected_outcome": "Enable safe expansion of autonomous operations with auditable oversight.",
                "reason": f"Future autonomy risk is elevated ({autonomy_risk}) — governance framework is required.",
                "audience": "governance",
            }
        )

    # Default
    if not actions:
        return [
            {
                "action": "maintain_current_trust_practices",
                "priority": "long_term",
                "expected_outcome": "Preserve current trust posture and prevent future degradation.",
                "reason": "No immediate trust concerns detected — maintain steady-state practices.",
                "audience": "management",
            }
        ]

    # Sort by priority rank
    actions.sort(key=lambda a: _ACTION_PRIORITY_RANK.get(a["priority"], 99))
    return actions


# ---------------------------------------------------------------------------
# Part 8 — generate_governance_recommendations
# ---------------------------------------------------------------------------


def generate_governance_recommendations(
    *,
    risk_result: dict[str, Any] | None = None,
    hotspots: list[dict[str, Any]] | None = None,
    posture_result: dict[str, Any] | None = None,
    trend_result: dict[str, Any] | None = None,
    entity_type: str = "any",
    tenant_id: str = "",
    engagement_id: str = "",
) -> list[dict[str, Any]]:
    """Generate governance recommendations appropriate for the entity type.

    entity_type values: human / agent / autonomous_system / agi / ai_system / any
    Each recommendation includes justification, trust_impact, applies_to, and
    governance_layer.
    """
    recommendations: list[dict[str, Any]] = []

    posture_score = 100
    if posture_result is not None:
        try:
            posture_score = _clamp(int(posture_result.get("score", 100)))
        except (TypeError, ValueError):
            posture_score = 100

    risk_level = ""
    autonomy_risk = 0
    if risk_result is not None:
        risk_level = str(risk_result.get("risk_level", ""))
        cat = risk_result.get("category_scores", {})
        try:
            autonomy_risk = int(cat.get("future_autonomy_risk", 0))
        except (TypeError, ValueError):
            autonomy_risk = 0

    trend_direction = ""
    if trend_result is not None:
        trend_direction = str(trend_result.get("direction", ""))

    # --- human ---
    if entity_type in ("human", "any"):
        if posture_score < 60:
            recommendations.append(
                {
                    "recommendation": "Require multi-person approval for all trust-sensitive decisions.",
                    "justification": f"Trust posture score {posture_score} is below the 60-point threshold for single-person authority.",
                    "trust_impact": "Reduces single-point-of-failure risk and enforces separation of duties.",
                    "applies_to": "human",
                    "governance_layer": "approval_workflow",
                }
            )

    # --- agent ---
    if entity_type in ("agent", "any"):
        if autonomy_risk >= _RISK_HIGH_THRESHOLD or posture_score < 60:
            recommendations.append(
                {
                    "recommendation": "Restrict agent operations to supervised mode — require human confirmation for all consequential actions.",
                    "justification": (
                        f"Autonomy risk {autonomy_risk} >= {_RISK_HIGH_THRESHOLD} or posture score {posture_score} < 60."
                    ),
                    "trust_impact": "Prevents autonomous propagation of trust errors across the system.",
                    "applies_to": "agent",
                    "governance_layer": "operational_mode",
                }
            )
        else:
            recommendations.append(
                {
                    "recommendation": "Permit agent operations with continuous trust monitoring and audit logging.",
                    "justification": "Current trust posture and autonomy risk are within acceptable bounds for supervised autonomous operation.",
                    "trust_impact": "Balances operational efficiency with governance oversight.",
                    "applies_to": "agent",
                    "governance_layer": "operational_mode",
                }
            )

    # --- autonomous_system ---
    if entity_type in ("autonomous_system", "any"):
        if posture_score < 75:
            recommendations.append(
                {
                    "recommendation": "Suspend autonomous system operations until trust posture reaches healthy threshold (>= 75).",
                    "justification": f"Trust posture score {posture_score} is below the minimum threshold for autonomous operation.",
                    "trust_impact": "Prevents autonomous execution under degraded trust conditions.",
                    "applies_to": "autonomous_system",
                    "governance_layer": "operational_control",
                }
            )

    # --- agi ---
    if entity_type in ("agi", "any"):
        recommendations.append(
            {
                "recommendation": "Mandate cryptographic verification of all AGI-generated decisions and outputs.",
                "justification": "AGI systems require the highest level of trust verification regardless of current posture.",
                "trust_impact": "Ensures every AGI action is auditable and traceable to a verified source.",
                "applies_to": "agi",
                "governance_layer": "cryptographic_control",
            }
        )
        if posture_score < 90:
            recommendations.append(
                {
                    "recommendation": "Require explicit human approval for all AGI actions until trust posture reaches excellent (>= 90).",
                    "justification": f"Trust posture score {posture_score} is below the excellent threshold required for unsupervised AGI operation.",
                    "trust_impact": "Maintains human oversight over AGI decisions in degraded trust conditions.",
                    "applies_to": "agi",
                    "governance_layer": "approval_workflow",
                }
            )

    # --- risk-based: AI trust gates ---
    if risk_level in ("high", "critical"):
        recommendations.append(
            {
                "recommendation": "Implement AI trust gates: require trust score validation before AI/agent actions are committed.",
                "justification": f"Risk level {risk_level} — automated trust gates prevent propagation of high-risk decisions.",
                "trust_impact": "Creates a deterministic checkpoint that blocks non-compliant operations.",
                "applies_to": entity_type,
                "governance_layer": "trust_gate",
            }
        )

    # --- trend-based: monitoring ---
    if trend_direction in ("degrading", "rapidly_degrading"):
        recommendations.append(
            {
                "recommendation": "Activate elevated monitoring alert cadence — reduce alert interval to hourly for trust-critical metrics.",
                "justification": f"Degrading trend ({trend_direction}) requires increased observability to detect further decline.",
                "trust_impact": "Enables earlier intervention before trust crosses critical thresholds.",
                "applies_to": entity_type,
                "governance_layer": "monitoring",
            }
        )

    # --- hotspot-based: critical governance ---
    for spot in hotspots or []:
        if not isinstance(spot, dict):
            continue
        if str(spot.get("severity", "")) == "critical":
            area = str(spot.get("area", "unknown"))
            recommendations.append(
                {
                    "recommendation": f"Address critical governance hotspot in '{area}': engage domain owner and initiate remediation sprint.",
                    "justification": f"Critical hotspot in '{area}' represents a concentrated trust failure point.",
                    "trust_impact": "Resolving critical hotspots has the highest per-action trust recovery potential.",
                    "applies_to": entity_type,
                    "governance_layer": "hotspot_remediation",
                }
            )

    # Default
    if not recommendations:
        return [
            {
                "recommendation": "Maintain current governance posture — no immediate changes required.",
                "justification": "Trust posture, risk, and trend are all within acceptable governance bounds.",
                "trust_impact": "Preserves existing trust level without additional overhead.",
                "applies_to": entity_type,
                "governance_layer": "steady_state",
            }
        ]

    return recommendations


# ---------------------------------------------------------------------------
# Part 9 — forecast_trust_posture
# ---------------------------------------------------------------------------


def forecast_trust_posture(
    *,
    trend_result: dict[str, Any] | None = None,
    posture_result: dict[str, Any] | None = None,
    window_days: int = 90,
) -> dict[str, Any]:
    """Deterministic linear extrapolation of trust posture.

    Applies dampening for long windows: 20% pull-toward-current at 180 days,
    35% at 365 days. When no trend data or score_change == 0, projects stable.
    """
    current_score = 50
    if posture_result is not None:
        raw = posture_result.get("score")
        try:
            current_score = _clamp(int(raw)) if raw is not None else 50
        except (TypeError, ValueError):
            current_score = 50

    current_posture = _posture_from_score(current_score)

    # Validate window
    if window_days not in _FORECAST_WINDOWS:
        window_days = 90

    # No trend data or no change → stable projection
    if trend_result is None or not trend_result.get("trend_available", False):
        return {
            "projected_posture": current_posture,
            "projected_score": current_score,
            "current_score": current_score,
            "current_posture": current_posture,
            "score_delta": 0,
            "days": window_days,
            "direction": "stable",
            "velocity": "minimal",
            "forecast_confidence": "low",
            "reasoning": "No trend data available — projecting stable posture.",
            "intelligence_version": TRUST_INTELLIGENCE_VERSION,
        }

    score_change = int(trend_result.get("score_change", 0))
    trend_window = int(trend_result.get("window_days", 90))
    direction = str(trend_result.get("direction", "stable"))
    velocity = str(trend_result.get("velocity", "minimal"))

    if score_change == 0 or trend_window == 0:
        return {
            "projected_posture": current_posture,
            "projected_score": current_score,
            "current_score": current_score,
            "current_posture": current_posture,
            "score_delta": 0,
            "days": window_days,
            "direction": "stable",
            "velocity": "minimal",
            "forecast_confidence": "medium" if window_days <= 90 else "low",
            "reasoning": "Score change is zero — projecting stable posture.",
            "intelligence_version": TRUST_INTELLIGENCE_VERSION,
        }

    # Linear extrapolation
    daily_rate = score_change / trend_window
    raw_delta = daily_rate * window_days

    # Dampening for long windows
    if window_days >= 365:
        raw_delta = raw_delta * (1.0 - 0.35)
    elif window_days >= 180:
        raw_delta = raw_delta * (1.0 - 0.20)

    score_delta = int(round(raw_delta))
    projected_score = _clamp(current_score + score_delta)
    projected_posture = _posture_from_score(projected_score)

    # Forecast confidence
    if window_days <= 30:
        forecast_confidence = "high"
    elif window_days <= 90:
        forecast_confidence = "medium"
    else:
        forecast_confidence = "low"

    reasoning = (
        f"Linear extrapolation: daily_rate={daily_rate:.4f} over {window_days}d "
        f"from current_score={current_score}; "
        f"dampening={'35%' if window_days >= 365 else '20%' if window_days >= 180 else 'none'}; "
        f"projected_score={projected_score}"
    )

    return {
        "projected_posture": projected_posture,
        "projected_score": projected_score,
        "current_score": current_score,
        "current_posture": current_posture,
        "score_delta": score_delta,
        "days": window_days,
        "direction": direction,
        "velocity": velocity,
        "forecast_confidence": forecast_confidence,
        "reasoning": reasoning,
        "intelligence_version": TRUST_INTELLIGENCE_VERSION,
    }


# ---------------------------------------------------------------------------
# Part 10 — generate_trust_intelligence_graph
# ---------------------------------------------------------------------------


def generate_trust_intelligence_graph(
    *,
    posture_result: dict[str, Any] | None = None,
    trend_result: dict[str, Any] | None = None,
    risk_result: dict[str, Any] | None = None,
    priorities: list[dict[str, Any]] | None = None,
    recommendations: list[dict[str, Any]] | None = None,
    forecast_result: dict[str, Any] | None = None,
    insights: list[dict[str, Any]] | None = None,
    hotspots: list[dict[str, Any]] | None = None,
    tenant_id: str = "",
    engagement_id: str = "",
) -> dict[str, Any]:
    """Produce a deterministic intelligence graph of nodes and directed edges.

    Nodes represent intelligence outputs; edges represent causal relationships.
    Node IDs follow the pattern "<type>:<index>".
    """
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []

    def _make_node(node_id: str, node_type: str, payload: Any) -> dict[str, Any]:
        return {
            "node_id": node_id,
            "node_type": node_type,
            "payload": payload,
            "tenant_id": tenant_id,
            "engagement_id": engagement_id,
        }

    def _make_edge(source_id: str, target_id: str, edge_type: str) -> dict[str, Any]:
        return {
            "source_id": source_id,
            "target_id": target_id,
            "edge_type": edge_type,
        }

    # --- core nodes ---
    posture_id = "posture:0"
    trend_id = "trend:0"
    risk_id = "risk:0"
    forecast_id = "forecast:0"

    nodes.append(_make_node(posture_id, GRAPH_NODE_POSTURE, posture_result or {}))
    nodes.append(_make_node(trend_id, GRAPH_NODE_TREND, trend_result or {}))
    nodes.append(_make_node(risk_id, GRAPH_NODE_RISK, risk_result or {}))

    if forecast_result is not None:
        nodes.append(_make_node(forecast_id, GRAPH_NODE_FORECAST, forecast_result))

    # --- priority nodes ---
    priority_ids: list[str] = []
    for idx, item in enumerate(priorities or []):
        if not isinstance(item, dict):
            continue
        pid = f"priority:{idx}"
        nodes.append(_make_node(pid, GRAPH_NODE_PRIORITY, item))
        priority_ids.append(pid)

    # --- recommendation nodes ---
    recommendation_ids: list[str] = []
    for idx, item in enumerate(recommendations or []):
        if not isinstance(item, dict):
            continue
        rid = f"recommendation:{idx}"
        nodes.append(_make_node(rid, GRAPH_NODE_RECOMMENDATION, item))
        recommendation_ids.append(rid)

    # --- insight nodes ---
    insight_ids: list[str] = []
    for idx, item in enumerate(insights or []):
        if not isinstance(item, dict):
            continue
        iid = f"insight:{idx}"
        nodes.append(_make_node(iid, GRAPH_NODE_INSIGHT, item))
        insight_ids.append(iid)

    # --- hotspot nodes ---
    hotspot_ids: list[str] = []
    for idx, item in enumerate(hotspots or []):
        if not isinstance(item, dict):
            continue
        hid = f"hotspot:{idx}"
        nodes.append(_make_node(hid, GRAPH_NODE_HOTSPOT, item))
        hotspot_ids.append(hid)

    # --- edges ---
    # posture → trend
    edges.append(_make_edge(posture_id, trend_id, "informs_trend"))

    # posture → risk
    edges.append(_make_edge(posture_id, risk_id, "informs_risk"))

    # risk → priorities
    for pid in priority_ids:
        edges.append(_make_edge(risk_id, pid, "drives_priority"))

    # priority[0] → all recommendations
    if priority_ids:
        for rid in recommendation_ids:
            edges.append(_make_edge(priority_ids[0], rid, "generates_recommendation"))

    # trend → forecast
    if forecast_result is not None:
        edges.append(_make_edge(trend_id, forecast_id, "drives_forecast"))

    # posture → insights
    for iid in insight_ids:
        edges.append(_make_edge(posture_id, iid, "generates_insight"))

    # risk → hotspots
    for hid in hotspot_ids:
        edges.append(_make_edge(risk_id, hid, "identifies_hotspot"))

    return {
        "nodes": nodes,
        "edges": edges,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "tenant_id": tenant_id,
        "engagement_id": engagement_id,
        "intelligence_version": TRUST_INTELLIGENCE_VERSION,
    }
