"""api/identity_governance/snapshots/types.py — Canonical governance snapshot types."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from api.identity_governance.models import (
    GraphEdge,
    GraphNode,
    IdentityLifecycleState,
    IdentityTimelineEvent,
    PolicyDecision,
    RiskBand,
    RiskScore,
)
from api.identity_governance.snapshots.meta import SnapshotMeta


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


def _replay_hash(*parts: object) -> str:
    """Deterministic hash of input parts for replay_version."""
    payload = json.dumps(
        [str(p) for p in parts],
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# IdentitySnapshot
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IdentitySnapshot:
    """Canonical snapshot of an identity's governance state."""

    meta: SnapshotMeta
    identity_id: str
    lifecycle_state: IdentityLifecycleState
    roles: tuple[str, ...]
    permissions: tuple[str, ...]
    capabilities: tuple[str, ...]


# ---------------------------------------------------------------------------
# RiskSnapshot
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RiskSnapshot:
    """Canonical snapshot of a risk evaluation result."""

    meta: SnapshotMeta
    subject: str
    score: float
    band: RiskBand
    factors: tuple[tuple[str, float], ...]
    evaluated_at: datetime


# ---------------------------------------------------------------------------
# GraphSnapshot
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GraphSnapshot:
    """Canonical snapshot of an identity graph."""

    meta: SnapshotMeta
    subject: str
    nodes: tuple[GraphNode, ...]
    edges: tuple[GraphEdge, ...]


# ---------------------------------------------------------------------------
# PolicySnapshot
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PolicySnapshot:
    """Canonical snapshot of a policy evaluation result."""

    meta: SnapshotMeta
    subject: str
    policies_evaluated: int
    decision: PolicyDecision
    matched_policy_id: str
    conditions_checked: tuple[str, ...]


# ---------------------------------------------------------------------------
# DigitalTwinSnapshot  (canonical version with SnapshotMeta envelope)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DigitalTwinSnapshot:
    """Canonical digital twin snapshot with SnapshotMeta envelope.

    Distinct from models.DigitalTwinSnapshot (legacy type without meta).
    Import this from api.identity_governance.snapshots for new code.
    """

    meta: SnapshotMeta
    subject: str
    identity_summary: tuple[tuple[str, str], ...]
    lifecycle_state: IdentityLifecycleState
    roles: tuple[str, ...]
    permissions: tuple[str, ...]
    capabilities: tuple[str, ...]
    device_records: tuple[tuple[tuple[str, str], ...], ...] = ()
    active_sessions_count: int = 0
    risk_score: Optional[RiskScore] = None
    active_break_glass_count: int = 0
    recent_timeline_events: tuple[IdentityTimelineEvent, ...] = ()
    assessments_count: int = 0
    evidence_count: int = 0
