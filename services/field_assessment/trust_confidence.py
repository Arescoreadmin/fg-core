"""Trust Confidence & Corroboration Engine — PR 1.7.

Transforms FrostGate from proving trust relationships into quantifying trust
strength. Every score is:

  Deterministic   — identical input always produces identical output
  Explainable     — every point awarded or deducted has a named reason
  Replayable      — scores can be reconstructed at any past timestamp
  Tenant-scoped   — cross-tenant leakage is structurally impossible
  Auditor-defensible — no hidden weights, no ML, no probabilistic black boxes

Confidence range: 0–100
  0–24    → critical
  25–49   → weak
  50–74   → moderate
  75–89   → strong
  90–100  → high_assurance

Architecture:
  calculate_confidence()         master scoring function (Parts 1, 4)
  evaluate_corroboration()       independent source analysis (Part 2)
  evaluate_evidence_strength()   per-evidence quality scoring (Part 3)
  evaluate_trust_quality()       positive/negative factor analysis (Part 4)
  why_confidence()               human-readable explanation (Part 5)
  replay_confidence()            point-in-time score reconstruction (Part 6)
  calculate_confidence_decay()   age-based score degradation (Part 7)
  generate_confidence_manifest() deterministic, hashable scoring record (Part 8)

Scoring model:
  All weights are named constants visible at module level. An auditor can
  reproduce any score manually by reading _POS, _NEG, and _DECAY_TABLE and
  tracing the factor application in calculate_confidence(). No hidden logic.

Future compatibility:
  All functions operate on TrustGraphNode / TrustGraphEdge generics.
  No assessment-specific logic is hardcoded. Future node types (Identity, RBAC,
  Agent, AGI Governance, Model Registry, Autonomous System) integrate without
  changing the confidence engine. The engine scores trust relationships, not
  assessment objects.

Replay compatibility (PR 1.9):
  replay_confidence() filters the graph to nodes/edges existing at timestamp T
  and reconstructs the score that would have been assigned at that point. The
  manifest_hash in generate_confidence_manifest() excludes timestamps so
  identical scores produce identical hashes across calls.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from services.canonical import utc_iso8601_z_now
from services.field_assessment.trust_graph import (
    NodeType,
    TrustGraph,
    TrustGraphNode,
    verify_trust_graph,
)

# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------

CONFIDENCE_VERSION: str = "trust-confidence-v1"

# ---------------------------------------------------------------------------
# Confidence levels — (min_score, max_score, label)
# ---------------------------------------------------------------------------

_LEVELS: list[tuple[int, int, str]] = [
    (0, 24, "critical"),
    (25, 49, "weak"),
    (50, 74, "moderate"),
    (75, 89, "strong"),
    (90, 100, "high_assurance"),
]

# Evidence strength levels
_STRENGTH_LEVELS: list[tuple[int, int, str]] = [
    (0, 24, "very_weak"),
    (25, 49, "weak"),
    (50, 74, "moderate"),
    (75, 89, "strong"),
    (90, 100, "verified"),
]

# ---------------------------------------------------------------------------
# Decay table — (min_days_inclusive, max_days_exclusive, penalty_points)
# Applied to confidence_score and strength_score. Configurable by extending
# this table — no code changes required for new tiers.
# ---------------------------------------------------------------------------

_DECAY_TABLE: list[tuple[int, float, int]] = [
    (0, 31, 0),
    (31, 61, 5),
    (61, 91, 10),
    (91, 121, 15),
    (121, 181, 20),
    (181, float("inf"), 25),
]

# ---------------------------------------------------------------------------
# Positive factor weights (all named, all auditor-visible)
# ---------------------------------------------------------------------------

_POS: dict[str, int] = {
    "evidence_present": 10,
    "all_evidence_signed": 20,
    "some_evidence_signed": 8,
    "fresh_evidence": 10,
    "snapshot_verified": 10,
    "replay_anchor_valid": 8,
    "chain_replay_score_100": 10,
    "chain_replay_score_75": 5,
    "independent_corroboration_2": 8,
    "independent_corroboration_4": 7,
    "high_avg_trust_score": 5,
    "all_event_hashes_present": 5,
    "report_link_verified": 5,
    "authority_version_current": 3,
}

# ---------------------------------------------------------------------------
# Negative factor weights (all named, all auditor-visible)
# ---------------------------------------------------------------------------

_NEG: dict[str, int] = {
    "no_evidence": -30,
    "unsigned_evidence": -15,
    "some_unsigned_evidence": -8,
    "broken_chain": -25,
    "chain_replay_degraded": -10,
    "missing_event_hash": -8,
    "circular_dependency": -20,
    "duplicate_corroboration": -5,
    "snapshot_unverified": -5,
    "low_avg_trust_score": -5,
    "authority_version_downgraded": -10,
}

# Characters used to split evidence_id into source-family prefix
_SOURCE_SEPARATORS: tuple[str, ...] = ("-", "_", ":", "/")


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class TrustConfidenceError(ValueError):
    """Raised when a confidence operation violates a structural invariant.

    Fail closed: callers must handle this explicitly. Never silently corrects.
    """


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _confidence_level(score: int) -> str:
    for lo, hi, label in _LEVELS:
        if lo <= score <= hi:
            return label
    return "critical"


def _strength_level(score: int) -> str:
    for lo, hi, label in _STRENGTH_LEVELS:
        if lo <= score <= hi:
            return label
    return "very_weak"


def _clamp(n: int) -> int:
    return max(0, min(100, n))


def _parse_utc(ts: str) -> datetime:
    """Parse ISO-8601 UTC timestamp to timezone-aware datetime. Never raises."""
    try:
        ts = ts.replace("Z", "+00:00")
        return datetime.fromisoformat(ts).astimezone(timezone.utc)
    except Exception:  # noqa: BLE001
        return datetime.min.replace(tzinfo=timezone.utc)


def _evidence_nodes(path: list[TrustGraphNode]) -> list[TrustGraphNode]:
    return [n for n in path if n.node_type == NodeType.EVIDENCE]


def _source_family(node: TrustGraphNode) -> str:
    """Derive a source-family label for corroboration grouping.

    Priority:
      1. payload["source_type"] — explicit declaration (preferred for all future
         node types including Identity, Agent, AGI)
      2. First segment of payload["evidence_id"] split on separator
      3. node_id prefix as fallback
    """
    src = node.payload.get("source_type")
    if src and isinstance(src, str) and src.strip():
        return src.strip().lower()

    evidence_id = node.payload.get("evidence_id") or node.node_id
    for sep in _SOURCE_SEPARATORS:
        if sep in evidence_id:
            return evidence_id.split(sep)[0].lower()

    return str(evidence_id).lower()


def _now_utc() -> datetime:
    return datetime.now(tz=timezone.utc)


# ---------------------------------------------------------------------------
# Part 7 — Trust Decay Model
# ---------------------------------------------------------------------------


def calculate_confidence_decay(
    evidence_date: str | datetime,
    reference_date: str | datetime | None = None,
) -> dict[str, Any]:
    """Compute age-based confidence penalty for a piece of evidence.

    Deterministic: given the same evidence_date and reference_date, always
    returns the same result. No randomness, no ML, no adaptive learning.

    Configurable: extend _DECAY_TABLE without touching this function.
    Replayable: pass reference_date explicitly to reconstruct past scores.

    Returns:
        age_days    integer days between evidence_date and reference_date
        penalty     points to subtract from confidence score
        tier        decay tier label (fresh / mild / moderate / severe / critical)
    """
    if isinstance(evidence_date, str):
        ev_dt = _parse_utc(evidence_date)
    else:
        ev_dt = (
            evidence_date.astimezone(timezone.utc)
            if evidence_date.tzinfo
            else evidence_date.replace(tzinfo=timezone.utc)
        )

    if reference_date is None:
        ref_dt = _now_utc()
    elif isinstance(reference_date, str):
        ref_dt = _parse_utc(reference_date)
    else:
        ref_dt = (
            reference_date.astimezone(timezone.utc)
            if reference_date.tzinfo
            else reference_date.replace(tzinfo=timezone.utc)
        )

    delta = ref_dt - ev_dt
    age_days = max(0, delta.days)

    tier_labels = ["fresh", "mild", "moderate", "significant", "severe", "critical"]
    for i, (min_d, max_d, penalty) in enumerate(_DECAY_TABLE):
        if min_d <= age_days < max_d:
            return {
                "age_days": age_days,
                "penalty": penalty,
                "tier": tier_labels[min(i, len(tier_labels) - 1)],
            }

    return {"age_days": age_days, "penalty": 25, "tier": "critical"}


# ---------------------------------------------------------------------------
# Part 3 — Evidence Strength Engine
# ---------------------------------------------------------------------------


def evaluate_evidence_strength(
    node: TrustGraphNode,
    edge_authority: dict[str, Any] | None = None,
    reference_date: str | datetime | None = None,
) -> dict[str, Any]:
    """Score a single evidence node's intrinsic strength.

    Does not consider corroboration or graph-level factors — those are
    handled by evaluate_corroboration() and calculate_confidence().

    Parameters:
        node            TrustGraphNode with node_type == EVIDENCE
        edge_authority  Optional result of verify_edge_authority() for this node's edge
        reference_date  Reference point for freshness calculation (defaults to now)

    Returns:
        strength_score   0–100
        strength_level   very_weak / weak / moderate / strong / verified
        strength_factors list of {factor, points} dicts
    """
    score = 0
    strength_factors: list[dict[str, Any]] = []

    # --- Signature / authority status ---
    authority_status = node.payload.get("authority_status", "unknown")
    if authority_status == "signed":
        pts = 30
        score += pts
        strength_factors.append({"factor": "signed", "points": pts})
    elif authority_status in ("legacy_unsigned", "legacy"):
        pts = 8
        score += pts
        strength_factors.append({"factor": "legacy_unsigned", "points": pts})
    else:
        strength_factors.append({"factor": "unsigned", "points": 0})

    # --- Event hash (replay anchor fingerprint) ---
    if node.payload.get("event_hash"):
        pts = 20
        score += pts
        strength_factors.append({"factor": "event_hash_present", "points": pts})
    else:
        strength_factors.append({"factor": "event_hash_absent", "points": 0})

    # --- Trust score from node payload ---
    ts = node.payload.get("trust_score", 0)
    if ts >= 90:
        pts = 20
        score += pts
        strength_factors.append({"factor": "trust_score_very_high", "points": pts})
    elif ts >= 75:
        pts = 15
        score += pts
        strength_factors.append({"factor": "trust_score_high", "points": pts})
    elif ts >= 50:
        pts = 10
        score += pts
        strength_factors.append({"factor": "trust_score_moderate", "points": pts})
    elif ts > 0:
        pts = 5
        score += pts
        strength_factors.append({"factor": "trust_score_low", "points": pts})
    else:
        strength_factors.append({"factor": "trust_score_zero", "points": 0})

    # --- Freshness decay ---
    decay = calculate_confidence_decay(node.created_at, reference_date)
    if decay["penalty"] == 0:
        pts = 20
        score += pts
        strength_factors.append(
            {"factor": "fresh", "points": pts, "age_days": decay["age_days"]}
        )
    else:
        penalty = decay["penalty"]
        score -= penalty
        strength_factors.append(
            {
                "factor": f"stale_{decay['tier']}",
                "points": -penalty,
                "age_days": decay["age_days"],
            }
        )

    # --- Edge authority (optional cryptographic verification) ---
    if edge_authority is not None:
        if edge_authority.get("valid") is True:
            pts = 10
            score += pts
            strength_factors.append(
                {"factor": "edge_authority_verified", "points": pts}
            )
        else:
            reason = edge_authority.get("reason", "unknown")
            strength_factors.append(
                {"factor": f"edge_authority_invalid_{reason}", "points": 0}
            )

    score = _clamp(score)
    return {
        "strength_score": score,
        "strength_level": _strength_level(score),
        "strength_factors": strength_factors,
    }


# ---------------------------------------------------------------------------
# Part 2 — Corroboration Engine
# ---------------------------------------------------------------------------


def evaluate_corroboration(
    graph: TrustGraph,
    evidence_nodes: list[TrustGraphNode],
) -> dict[str, Any]:
    """Analyze whether evidence is independently supported.

    Independent corroboration means evidence comes from distinct source
    families (different connectors, systems, or observation methods).
    Duplicate evidence means the same data collected multiple times from
    the same source — it inflates count without adding confidence.

    Corroboration scoring:
        0 independent sources  →   0
        1 independent source   →  20  (single-source, unverified)
        2 independent sources  →  40
        3 independent sources  →  60
        4 independent sources  →  75
        5+ independent sources →  90+
    Minus 5 per duplicate source (up to -25 maximum).

    Returns:
        corroboration_score   0–100
        source_count          total evidence nodes evaluated
        independent_sources   distinct source families
        duplicate_sources     evidence nodes sharing source + event_hash
        source_families       sorted list of source family labels
    """
    if not evidence_nodes:
        return {
            "corroboration_score": 0,
            "source_count": 0,
            "independent_sources": 0,
            "duplicate_sources": 0,
            "source_families": [],
        }

    source_count = len(evidence_nodes)

    # Group by source family
    family_map: dict[str, list[TrustGraphNode]] = {}
    for n in evidence_nodes:
        fam = _source_family(n)
        family_map.setdefault(fam, []).append(n)

    independent_sources = len(family_map)

    # Detect duplicates: same source family AND same event_hash
    duplicate_sources = 0
    for nodes in family_map.values():
        seen_hashes: set[str] = set()
        for n in nodes:
            eh = n.payload.get("event_hash") or ""
            if eh and eh in seen_hashes:
                duplicate_sources += 1
            elif eh:
                seen_hashes.add(eh)

    # Base corroboration score
    if independent_sources == 0:
        base_score = 0
    elif independent_sources == 1:
        base_score = 20
    elif independent_sources == 2:
        base_score = 40
    elif independent_sources == 3:
        base_score = 60
    elif independent_sources == 4:
        base_score = 75
    else:
        # 5 = 90, 6 = 95, 7+ = 100
        base_score = min(100, 90 + (independent_sources - 5) * 5)

    # Duplicate penalty
    duplicate_penalty = min(25, duplicate_sources * 5)
    score = _clamp(base_score - duplicate_penalty)

    return {
        "corroboration_score": score,
        "source_count": source_count,
        "independent_sources": independent_sources,
        "duplicate_sources": duplicate_sources,
        "source_families": sorted(family_map.keys()),
    }


# ---------------------------------------------------------------------------
# Part 4 — Trust Quality Factors
# ---------------------------------------------------------------------------


def evaluate_trust_quality(
    graph: TrustGraph,
    path: list[TrustGraphNode],
    *,
    edge_authorities: dict[str, dict[str, Any]] | None = None,
    snapshot: dict[str, Any] | None = None,
    replay_result: dict[str, Any] | None = None,
    graph_integrity: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Evaluate positive and negative trust quality factors for a trust path.

    Each factor is a named string. Every string that appears in positive_factors
    or negative_factors maps directly to a weight in _POS or _NEG. Auditors can
    cross-check the score by summing the weights of all present factors.

    Returns:
        trust_quality_score   0–100
        positive_factors      sorted list of factor names that raised the score
        negative_factors      sorted list of factor names that reduced the score
    """
    positive: list[str] = []
    negative: list[str] = []
    quality_score = 0

    evidence = _evidence_nodes(path)

    # --- Evidence signature quality ---
    if evidence:
        signed_count = sum(
            1 for e in evidence if e.payload.get("authority_status") == "signed"
        )
        if signed_count == len(evidence):
            positive.append("all_evidence_signed")
            quality_score += _POS["all_evidence_signed"]
        elif signed_count > 0:
            positive.append("some_evidence_signed")
            quality_score += _POS["some_evidence_signed"]
        else:
            negative.append("unsigned_evidence")
            quality_score += _NEG["unsigned_evidence"]

    # --- Event hash completeness ---
    if evidence:
        hash_count = sum(1 for e in evidence if e.payload.get("event_hash"))
        if hash_count == len(evidence):
            positive.append("all_event_hashes_present")
            quality_score += _POS["all_event_hashes_present"]
        elif hash_count < len(evidence):
            negative.append("missing_event_hash")
            quality_score += _NEG["missing_event_hash"]

    # --- Snapshot verification ---
    if snapshot is not None:
        if snapshot.get("valid") is True:
            positive.append("snapshot_verified")
            quality_score += _POS["snapshot_verified"]
        else:
            negative.append("snapshot_unverified")
            quality_score += _NEG["snapshot_unverified"]

    # --- Chain replay ---
    if replay_result is not None:
        chain_score = replay_result.get("chain_replay_score", 0)
        if chain_score == 100:
            positive.append("chain_replay_score_100")
            quality_score += _POS["chain_replay_score_100"]
        elif chain_score >= 75:
            positive.append("chain_replay_score_75")
            quality_score += _POS["chain_replay_score_75"]
        elif chain_score == 0:
            negative.append("broken_chain")
            quality_score += _NEG["broken_chain"]
        else:
            negative.append("chain_replay_degraded")
            quality_score += _NEG["chain_replay_degraded"]

    # --- Edge authority versions ---
    if edge_authorities:
        from services.field_assessment.trust_graph_authority import (  # noqa: PLC0415
            EDGE_AUTHORITY_VERSION,
        )

        versions = [a.get("authority_version") for a in edge_authorities.values()]
        if all(v == EDGE_AUTHORITY_VERSION for v in versions if v is not None):
            positive.append("authority_version_current")
            quality_score += _POS["authority_version_current"]
        else:
            negative.append("authority_version_downgraded")
            quality_score += _NEG["authority_version_downgraded"]

    # --- Circular dependency / graph integrity ---
    integrity = graph_integrity or verify_trust_graph(graph)
    violations = integrity.get("violations", [])
    if any("cyclic" in v or "cycle" in v for v in violations):
        negative.append("circular_dependency")
        quality_score += _NEG["circular_dependency"]

    quality_score = _clamp(quality_score)
    return {
        "trust_quality_score": quality_score,
        "positive_factors": sorted(positive),
        "negative_factors": sorted(negative),
    }


# ---------------------------------------------------------------------------
# Part 1 — Confidence Engine
# ---------------------------------------------------------------------------


def calculate_confidence(
    graph: TrustGraph,
    path: list[TrustGraphNode],
    *,
    edge_authorities: dict[str, dict[str, Any]] | None = None,
    snapshot: dict[str, Any] | None = None,
    replay_result: dict[str, Any] | None = None,
    reference_date: str | datetime | None = None,
    graph_integrity: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Master confidence scoring function.

    Combines evidence strength, corroboration, trust quality, and decay into
    a single deterministic confidence score. Every contributing factor is
    named and present in confidence_factors or negative_factors.

    Parameters:
        graph            The trust graph being evaluated
        path             Ordered list of nodes in the trust path
        edge_authorities Optional {edge_id: verify_edge_authority() result}
        snapshot         Optional verify_graph_snapshot() result
        replay_result    Optional dict with chain_replay_score (0–100)
        reference_date   Reference point for freshness (defaults to now)
        graph_integrity  Pre-computed verify_trust_graph() result (avoids re-run)

    Returns:
        confidence_score    0–100
        confidence_level    critical / weak / moderate / strong / high_assurance
        confidence_factors  list of {factor, points} positive contributors
        negative_factors    list of {factor, points} negative contributors
        explanation         human-readable summary (same as why_confidence output)
        corroboration       result of evaluate_corroboration()
        quality             result of evaluate_trust_quality()
    """
    confidence_factors: list[dict[str, Any]] = []
    negative_factors: list[dict[str, Any]] = []
    score = 0

    evidence = _evidence_nodes(path)
    integrity = graph_integrity or verify_trust_graph(graph)

    # --- Factor: evidence present ---
    if evidence:
        pts = _POS["evidence_present"]
        score += pts
        confidence_factors.append({"factor": "evidence_present", "points": pts})
    else:
        pts = _NEG["no_evidence"]
        score += pts
        negative_factors.append({"factor": "no_evidence", "points": pts})

    # --- Factor: evidence signature status ---
    if evidence:
        signed = [e for e in evidence if e.payload.get("authority_status") == "signed"]
        if len(signed) == len(evidence):
            pts = _POS["all_evidence_signed"]
            score += pts
            confidence_factors.append({"factor": "all_evidence_signed", "points": pts})
        elif signed:
            pts = _POS["some_evidence_signed"]
            score += pts
            confidence_factors.append({"factor": "some_evidence_signed", "points": pts})
            pts_neg = _NEG["some_unsigned_evidence"]
            score += pts_neg
            negative_factors.append(
                {"factor": "some_unsigned_evidence", "points": pts_neg}
            )
        else:
            pts = _NEG["unsigned_evidence"]
            score += pts
            negative_factors.append({"factor": "unsigned_evidence", "points": pts})

    # --- Factor: event hash completeness ---
    if evidence:
        hashed = [e for e in evidence if e.payload.get("event_hash")]
        if len(hashed) == len(evidence):
            pts = _POS["all_event_hashes_present"]
            score += pts
            confidence_factors.append(
                {"factor": "all_event_hashes_present", "points": pts}
            )
        elif len(hashed) < len(evidence):
            pts = _NEG["missing_event_hash"]
            score += pts
            negative_factors.append({"factor": "missing_event_hash", "points": pts})

    # --- Factor: evidence freshness (worst-case decay across all evidence) ---
    if evidence:
        decays = [
            calculate_confidence_decay(e.created_at, reference_date) for e in evidence
        ]
        max_penalty = max(d["penalty"] for d in decays)
        if max_penalty == 0:
            pts = _POS["fresh_evidence"]
            score += pts
            confidence_factors.append({"factor": "fresh_evidence", "points": pts})
        else:
            score -= max_penalty
            negative_factors.append(
                {
                    "factor": f"stale_evidence_{max(d['tier'] for d in decays)}",
                    "points": -max_penalty,
                }
            )

    # --- Factor: average trust score ---
    if evidence:
        avg_trust = sum(e.payload.get("trust_score", 0) for e in evidence) / len(
            evidence
        )
        if avg_trust >= 75:
            pts = _POS["high_avg_trust_score"]
            score += pts
            confidence_factors.append(
                {
                    "factor": "high_avg_trust_score",
                    "points": pts,
                    "avg": round(avg_trust, 1),
                }
            )
        elif avg_trust < 50:
            pts = _NEG["low_avg_trust_score"]
            score += pts
            negative_factors.append(
                {
                    "factor": "low_avg_trust_score",
                    "points": pts,
                    "avg": round(avg_trust, 1),
                }
            )

    # --- Factor: corroboration ---
    corroboration = evaluate_corroboration(graph, evidence)
    ind = corroboration["independent_sources"]
    if ind >= 4:
        pts = _POS["independent_corroboration_4"]
        score += pts
        confidence_factors.append(
            {"factor": "independent_corroboration_4", "points": pts, "sources": ind}
        )
    if ind >= 2:
        pts = _POS["independent_corroboration_2"]
        score += pts
        confidence_factors.append(
            {"factor": "independent_corroboration_2", "points": pts, "sources": ind}
        )
    if corroboration["duplicate_sources"] > 0:
        pts = _NEG["duplicate_corroboration"]
        score += pts
        negative_factors.append(
            {
                "factor": "duplicate_corroboration",
                "points": pts,
                "duplicates": corroboration["duplicate_sources"],
            }
        )

    # --- Factor: snapshot ---
    if snapshot is not None:
        if snapshot.get("valid") is True:
            pts = _POS["snapshot_verified"]
            score += pts
            confidence_factors.append({"factor": "snapshot_verified", "points": pts})
        else:
            pts = _NEG["snapshot_unverified"]
            score += pts
            negative_factors.append({"factor": "snapshot_unverified", "points": pts})

    # --- Factor: chain replay ---
    if replay_result is not None:
        chain_score = replay_result.get("chain_replay_score", 0)
        if chain_score == 100:
            pts = _POS["chain_replay_score_100"]
            score += pts
            confidence_factors.append(
                {"factor": "chain_replay_score_100", "points": pts}
            )
        elif chain_score >= 75:
            pts = _POS["chain_replay_score_75"]
            score += pts
            confidence_factors.append(
                {"factor": "chain_replay_score_75", "points": pts}
            )
        elif chain_score == 0:
            pts = _NEG["broken_chain"]
            score += pts
            negative_factors.append({"factor": "broken_chain", "points": pts})
        else:
            pts = _NEG["chain_replay_degraded"]
            score += pts
            negative_factors.append({"factor": "chain_replay_degraded", "points": pts})

    # --- Factor: edge authority versions ---
    if edge_authorities:
        from services.field_assessment.trust_graph_authority import (  # noqa: PLC0415
            EDGE_AUTHORITY_VERSION,
        )

        versions = [a.get("authority_version") for a in edge_authorities.values()]
        if all(v == EDGE_AUTHORITY_VERSION for v in versions if v is not None):
            pts = _POS["authority_version_current"]
            score += pts
            confidence_factors.append(
                {"factor": "authority_version_current", "points": pts}
            )
        else:
            pts = _NEG["authority_version_downgraded"]
            score += pts
            negative_factors.append(
                {"factor": "authority_version_downgraded", "points": pts}
            )

    # --- Factor: circular dependency ---
    violations = integrity.get("violations", [])
    if any("cyclic" in v or "cycle" in v for v in violations):
        pts = _NEG["circular_dependency"]
        score += pts
        negative_factors.append({"factor": "circular_dependency", "points": pts})

    # Evaluate quality (used in manifest; does not double-count scores)
    quality = evaluate_trust_quality(
        graph,
        path,
        edge_authorities=edge_authorities,
        snapshot=snapshot,
        replay_result=replay_result,
        graph_integrity=integrity,
    )

    score = _clamp(score)
    level = _confidence_level(score)

    result: dict[str, Any] = {
        "confidence_score": score,
        "confidence_level": level,
        "confidence_factors": confidence_factors,
        "negative_factors": negative_factors,
        "corroboration": corroboration,
        "quality": quality,
        "explanation": "",  # populated below
    }
    result["explanation"] = why_confidence(result)
    return result


# ---------------------------------------------------------------------------
# Part 5 — Confidence Explainability
# ---------------------------------------------------------------------------


def why_confidence(confidence_result: dict[str, Any]) -> str:
    """Generate a deterministic, human-readable confidence explanation.

    Every score component is listed. No hidden reasoning. Same result always
    produces the same explanation. Suitable for audit logs, regulator packages,
    and client-facing trust reports.

    Example output:
        Confidence: 92 (high_assurance)

        Reasoning:
          + evidence_present (+10)
          + all_evidence_signed (+20)
          + fresh_evidence (+10)
          + snapshot_verified (+10)
          + chain_replay_score_100 (+10)
          + independent_corroboration_2 (+8)
          + independent_corroboration_4 (+7)
          + high_avg_trust_score (+5)

          - stale_evidence_mild (-5)
    """
    score = confidence_result.get("confidence_score", 0)
    level = confidence_result.get("confidence_level", "unknown")
    pos_factors = confidence_result.get("confidence_factors", [])
    neg_factors = confidence_result.get("negative_factors", [])

    lines: list[str] = [
        f"Confidence: {score} ({level})",
        "",
        "Reasoning:",
    ]

    for f in pos_factors:
        name = f.get("factor", "unknown")
        pts = f.get("points", 0)
        lines.append(f"  + {name} (+{pts})")

    if neg_factors:
        lines.append("")
    for f in neg_factors:
        name = f.get("factor", "unknown")
        pts = f.get("points", 0)
        if pts < 0:
            lines.append(f"  - {name} ({pts})")
        else:
            lines.append(f"  - {name} (0)")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Part 6 — Confidence Replay
# ---------------------------------------------------------------------------


def replay_confidence(
    graph: TrustGraph,
    tenant_id: str,
    engagement_id: str,
    at: str,
    *,
    edge_authorities: dict[str, dict[str, Any]] | None = None,
    snapshot: dict[str, Any] | None = None,
    replay_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Reconstruct the confidence score that existed at timestamp `at`.

    Filters the trust graph to nodes and edges that existed at or before `at`.
    Builds a historical sub-graph and runs calculate_confidence() on the
    historical state. Integrates with PR 1.9 replay anchors.

    Fail closed:
      - Cross-tenant replay raises TrustConfidenceError
      - Cross-engagement replay raises TrustConfidenceError
      - Future timestamps (at > now) are allowed for forward projections

    Returns the same structure as calculate_confidence(), plus:
        replayed_at       the requested timestamp
        tenant_id         echoed for audit tracing
        engagement_id     echoed for audit tracing
        historical_nodes  number of nodes that existed at `at`
        historical_edges  number of edges that existed at `at`
    """
    if graph.tenant_id != tenant_id:
        raise TrustConfidenceError(
            f"cross-tenant replay rejected: graph.tenant_id={graph.tenant_id!r} "
            f"requested={tenant_id!r}"
        )
    if graph.engagement_id != engagement_id:
        raise TrustConfidenceError(
            f"cross-engagement replay rejected: graph.engagement_id={graph.engagement_id!r} "
            f"requested={engagement_id!r}"
        )

    at_dt = _parse_utc(at)

    historical_node_ids: set[str] = set()
    historical_nodes: list[TrustGraphNode] = []
    for n in graph.nodes():
        if _parse_utc(n.created_at) <= at_dt:
            historical_node_ids.add(n.node_id)
            historical_nodes.append(n)

    if not historical_nodes:
        return {
            "confidence_score": 0,
            "confidence_level": "critical",
            "confidence_factors": [],
            "negative_factors": [
                {"factor": "no_nodes_at_timestamp", "points": _NEG["no_evidence"]}
            ],
            "corroboration": evaluate_corroboration(graph, []),
            "quality": {
                "trust_quality_score": 0,
                "positive_factors": [],
                "negative_factors": [],
            },
            "explanation": f"No graph nodes existed at {at}",
            "replayed_at": at,
            "tenant_id": tenant_id,
            "engagement_id": engagement_id,
            "historical_nodes": 0,
            "historical_edges": 0,
        }

    # Rebuild a historical sub-graph
    replay_graph = TrustGraph(tenant_id=tenant_id, engagement_id=engagement_id)
    for n in historical_nodes:
        replay_graph.add_node(n)

    historical_edge_count = 0
    # Only filter edge_authorities to edges that existed at `at`
    historical_authorities: dict[str, dict[str, Any]] | None = None
    if edge_authorities is not None:
        historical_authorities = {}

    for e in graph.edges():
        if (
            _parse_utc(e.created_at) <= at_dt
            and e.source_node_id in historical_node_ids
            and e.target_node_id in historical_node_ids
        ):
            replay_graph.add_edge(e)
            historical_edge_count += 1
            if edge_authorities is not None and e.edge_id in edge_authorities:
                historical_authorities[e.edge_id] = edge_authorities[e.edge_id]  # type: ignore[index]

    result = calculate_confidence(
        replay_graph,
        list(replay_graph.nodes()),
        edge_authorities=historical_authorities,
        snapshot=snapshot,
        replay_result=replay_result,
        reference_date=at,
    )
    result["replayed_at"] = at
    result["tenant_id"] = tenant_id
    result["engagement_id"] = engagement_id
    result["historical_nodes"] = len(historical_nodes)
    result["historical_edges"] = historical_edge_count
    return result


# ---------------------------------------------------------------------------
# Part 8 — Trust Confidence Manifest
# ---------------------------------------------------------------------------


def generate_confidence_manifest(
    confidence_result: dict[str, Any],
    corroboration_result: dict[str, Any],
    strength_result: dict[str, Any],
    quality_result: dict[str, Any],
) -> dict[str, Any]:
    """Generate a deterministic, hashable confidence scoring record.

    The manifest_hash is derived from scores only — no timestamps are included
    in the canonical bytes. Identical scores always produce identical hashes.
    This makes the manifest replay-safe and suitable for signing by PR 1.9.

    Returns:
        confidence_version   CONFIDENCE_VERSION
        confidence_score     0–100
        corroboration_score  0–100
        strength_score       0–100
        trust_quality_score  0–100
        generated_at         ISO-8601 UTC (excluded from hash)
        manifest_hash        SHA-256 of canonical scores
    """
    stable: dict[str, Any] = {
        "confidence_version": CONFIDENCE_VERSION,
        "confidence_score": confidence_result.get("confidence_score", 0),
        "corroboration_score": corroboration_result.get("corroboration_score", 0),
        "strength_score": strength_result.get("strength_score", 0),
        "trust_quality_score": quality_result.get("trust_quality_score", 0),
    }
    canonical = json.dumps(
        stable, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    manifest_hash = hashlib.sha256(canonical).hexdigest()

    return {
        "confidence_version": CONFIDENCE_VERSION,
        "confidence_score": stable["confidence_score"],
        "corroboration_score": stable["corroboration_score"],
        "strength_score": stable["strength_score"],
        "trust_quality_score": stable["trust_quality_score"],
        "generated_at": utc_iso8601_z_now(),
        "manifest_hash": manifest_hash,
    }
