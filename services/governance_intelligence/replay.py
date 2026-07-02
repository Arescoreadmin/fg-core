"""Historical Replay Engine (PR 18.5A).

Pure functions only.  No DB I/O.  Every output is labeled REPLAY with
is_production=false so it is never confusable with live production values.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from services.governance_intelligence.schemas import (
    GovernanceIntelligenceValidationError,
)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def validate_replay_request(policy_version: str, time_window: dict[str, Any]) -> None:
    """Raise GovernanceIntelligenceValidationError if inputs are invalid."""
    if not policy_version or not isinstance(policy_version, str):
        raise GovernanceIntelligenceValidationError(
            "policy_version must be a non-empty string"
        )
    if not isinstance(time_window, dict):
        raise GovernanceIntelligenceValidationError("time_window must be a dict")
    if "start" not in time_window or "end" not in time_window:
        raise GovernanceIntelligenceValidationError(
            "time_window must contain 'start' and 'end' keys"
        )


# ---------------------------------------------------------------------------
# Snapshot builder
# ---------------------------------------------------------------------------


def build_replay_snapshot(
    policy_version: str,
    evidence_snapshot: dict[str, Any],
    trust_version: str,
    transparency_snapshot: dict[str, Any],
    time_window: dict[str, Any],
) -> dict[str, Any]:
    """Build a deterministic replay snapshot from historical data.

    Returns a snapshot dict that can be passed to replay_governance().
    Same inputs always produce the same output.
    """
    validate_replay_request(policy_version, time_window)
    snapshot: dict[str, Any] = {
        "policy_version": policy_version,
        "evidence_snapshot": evidence_snapshot,
        "trust_version": trust_version,
        "transparency_snapshot": transparency_snapshot,
        "time_window": time_window,
    }
    # Compute a stable snapshot_id
    canonical = json.dumps(snapshot, sort_keys=True, ensure_ascii=False)
    snapshot["snapshot_id"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return snapshot


# ---------------------------------------------------------------------------
# Replay engine
# ---------------------------------------------------------------------------


def replay_governance(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Deterministically replay governance decisions from a snapshot.

    Output is always labeled REPLAY with is_production=False.
    snapshot_id is the SHA-256 of the canonical snapshot.
    """
    if not isinstance(snapshot, dict):
        raise GovernanceIntelligenceValidationError("snapshot must be a dict")

    canonical = json.dumps(snapshot, sort_keys=True, ensure_ascii=False)
    snapshot_id = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    policy_version = snapshot.get("policy_version", "unknown")
    evidence = snapshot.get("evidence_snapshot", {})
    trust_version = snapshot.get("trust_version", "unknown")
    transparency = snapshot.get("transparency_snapshot", {})
    time_window = snapshot.get("time_window", {})

    # Derive deterministic governance metrics from snapshot content
    evidence_count = len(evidence) if isinstance(evidence, dict) else 0
    transparency_count = len(transparency) if isinstance(transparency, dict) else 0

    # Score is deterministically derived from evidence coverage in snapshot
    score_base = min(1.0, evidence_count * 0.05 + transparency_count * 0.03)
    risk_level = (
        "LOW" if score_base >= 0.7 else "MEDIUM" if score_base >= 0.4 else "HIGH"
    )

    return {
        "snapshot_id": snapshot_id,
        "policy_evaluation": {
            "policy_version": policy_version,
            "evaluation_window": time_window,
            "score": round(score_base, 4),
            "risk_level": risk_level,
            "trust_version": trust_version,
        },
        "recommendations": [
            {
                "id": f"replay-rec-{snapshot_id[:8]}",
                "text": "Historical snapshot replay: review evidence coverage",
                "priority": "MEDIUM",
                "source": "replay_engine",
            }
        ],
        "forecasts": {
            "horizon": "REPLAY_WINDOW",
            "projected_score": round(score_base, 4),
            "confidence": "HISTORICAL",
        },
        "dashboard": {
            "governance_score": round(score_base, 4),
            "risk_level": risk_level,
            "evidence_count": evidence_count,
            "transparency_count": transparency_count,
        },
        "executive_report": {
            "summary": f"Historical governance replay for policy version {policy_version}",
            "period": time_window,
            "governance_score": round(score_base, 4),
            "risk_level": risk_level,
        },
        "replay_label": "REPLAY",
        "is_production": False,
    }


# ---------------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------------


def diff_replays(replay_a: dict[str, Any], replay_b: dict[str, Any]) -> dict[str, Any]:
    """Compute a deterministic diff between two replay results."""
    score_a = replay_a.get("policy_evaluation", {}).get("score", 0.0)
    score_b = replay_b.get("policy_evaluation", {}).get("score", 0.0)
    risk_a = replay_a.get("policy_evaluation", {}).get("risk_level", "UNKNOWN")
    risk_b = replay_b.get("policy_evaluation", {}).get("risk_level", "UNKNOWN")

    snap_a = replay_a.get("snapshot_id", "")
    snap_b = replay_b.get("snapshot_id", "")

    added: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    changed: list[dict[str, Any]] = []

    if risk_a != risk_b:
        changed.append({"field": "risk_level", "from": risk_a, "to": risk_b})
    if round(score_a, 4) != round(score_b, 4):
        changed.append(
            {
                "field": "governance_score",
                "from": round(score_a, 4),
                "to": round(score_b, 4),
            }
        )

    return {
        "snapshot_a": snap_a,
        "snapshot_b": snap_b,
        "score_delta": round(score_b - score_a, 4),
        "risk_changed": risk_a != risk_b,
        "risk_delta": {"from": risk_a, "to": risk_b},
        "added": added,
        "removed": removed,
        "changed": changed,
    }
