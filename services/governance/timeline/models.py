"""services/governance/timeline/models.py — Canonical timeline event model.

All types are frozen dataclasses.  The payload field carries source-specific
structured data and is intentionally mutable (arbitrary JSON) — frozen only
prevents field reassignment, not deep mutation of the dict.  Callers must
not mutate the payload after construction.

SourceType enum defines the seven subsystems that produce timeline events.
event_type strings are fine-grained labels within each source type.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class SourceType(str, Enum):
    SIMULATION = "SIMULATION"
    MONITORING = "MONITORING"
    ALERT = "ALERT"
    GOVERNANCE_REPORT = "GOVERNANCE_REPORT"
    REPLAY = "REPLAY"
    EXPORT = "EXPORT"
    EVIDENCE = "EVIDENCE"
    FIELD_ASSESSMENT = "FIELD_ASSESSMENT"
    RISK_GOVERNANCE = "RISK_GOVERNANCE"
    CONTROL_REGISTRY = "CONTROL_REGISTRY"


# ---------------------------------------------------------------------------
# Display (UI convenience — computed server-side, not persisted)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TimelineEventDisplay:
    icon: str
    label: str
    summary: str
    severity: str | None  # None | "info" | "low" | "medium" | "high" | "critical"


# ---------------------------------------------------------------------------
# Canonical timeline event
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TimelineEvent:
    """Canonical, tenant-scoped, immutable timeline event.

    Invariants:
      - event_id is deterministic: SHA-256(tenant+source_type+source_id+event_type+occurred_at)[:16]
      - tenant_id always from auth context — never from request body
      - occurred_at is immutable after construction (set by producing subsystem)
      - payload must not contain PII, PHI, or raw secrets
      - replay_eligible=True means a replayable source entity exists for this event
    """

    event_id: str
    tenant_id: str
    source_type: SourceType
    source_id: str
    event_type: str
    occurred_at: str  # ISO 8601 UTC
    recorded_at: str  # ISO 8601 UTC — set at write time
    payload: dict = field(default_factory=dict)
    classification: str = "internal"  # "internal" | "confidential" | "restricted"
    manifest_hash: str | None = None
    replay_eligible: bool = False
    schema_version: str = "1.0"
    event_version: str = (
        "1.0"  # event-type contract version — evolves independently of schema_version
    )
