"""Governance event builders for simulation engine outputs.

All functions are pure Python: no I/O, no side effects.

Event contract:
  - event_id is deterministic SHA-256[:24] of (event_type, simulation_id, occurred_at_iso).
  - Events are immutable; SimulationGovernanceEvent is a frozen dataclass.
  - Severity for capability expansion events is always CRITICAL.
  - Severity for policy relaxation events is always HIGH.
  - occurred_at_iso is recorded at build time by the caller.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Optional

from .models import (
    SimulationClassification,
    SimulationEventType,
    SimulationGovernanceEvent,
    SimulationScenarioType,
    SimulationSeverity,
)


def _derive_event_id(
    event_type: str,
    simulation_id: str,
    occurred_at_iso: str,
) -> str:
    """Deterministic SHA-256[:24] event identity from (event_type, simulation_id, occurred_at_iso)."""
    raw = f"{event_type}:{simulation_id}:{occurred_at_iso}"
    return hashlib.sha256(raw.encode()).hexdigest()[:24]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_simulation_created_event(
    simulation_id: str,
    tenant_id: str,
    classification: SimulationClassification,
    scenario_type: SimulationScenarioType,
    severity: SimulationSeverity,
    actor_id: Optional[str],
) -> SimulationGovernanceEvent:
    """Build a SIMULATION_CREATED governance event."""
    occurred_at_iso = _now_iso()
    event_type = SimulationEventType.SIMULATION_CREATED
    event_id = _derive_event_id(event_type.value, simulation_id, occurred_at_iso)
    return SimulationGovernanceEvent(
        event_id=event_id,
        event_type=event_type,
        simulation_id=simulation_id,
        tenant_id=tenant_id,
        classification=classification,
        scenario_type=scenario_type,
        severity=severity,
        occurred_at_iso=occurred_at_iso,
        actor_id=actor_id,
        metadata=(),
    )


def build_simulation_replayed_event(
    simulation_id: str,
    tenant_id: str,
    classification: SimulationClassification,
    scenario_type: SimulationScenarioType,
    severity: SimulationSeverity,
    actor_id: Optional[str],
) -> SimulationGovernanceEvent:
    """Build a SIMULATION_REPLAYED governance event (idempotency hit)."""
    occurred_at_iso = _now_iso()
    event_type = SimulationEventType.SIMULATION_REPLAYED
    event_id = _derive_event_id(event_type.value, simulation_id, occurred_at_iso)
    return SimulationGovernanceEvent(
        event_id=event_id,
        event_type=event_type,
        simulation_id=simulation_id,
        tenant_id=tenant_id,
        classification=classification,
        scenario_type=scenario_type,
        severity=severity,
        occurred_at_iso=occurred_at_iso,
        actor_id=actor_id,
        metadata=(),
    )


def build_capability_expansion_event(
    simulation_id: str,
    tenant_id: str,
    classification: SimulationClassification,
    scenario_type: SimulationScenarioType,
    actor_id: Optional[str],
) -> SimulationGovernanceEvent:
    """Build a CAPABILITY_BOUNDARY_EXPANSION_PROJECTED event — severity always CRITICAL."""
    occurred_at_iso = _now_iso()
    event_type = SimulationEventType.CAPABILITY_BOUNDARY_EXPANSION_PROJECTED
    event_id = _derive_event_id(event_type.value, simulation_id, occurred_at_iso)
    return SimulationGovernanceEvent(
        event_id=event_id,
        event_type=event_type,
        simulation_id=simulation_id,
        tenant_id=tenant_id,
        classification=classification,
        scenario_type=scenario_type,
        severity=SimulationSeverity.CRITICAL,
        occurred_at_iso=occurred_at_iso,
        actor_id=actor_id,
        metadata=(),
    )


def build_policy_relaxation_event(
    simulation_id: str,
    tenant_id: str,
    classification: SimulationClassification,
    scenario_type: SimulationScenarioType,
    actor_id: Optional[str],
) -> SimulationGovernanceEvent:
    """Build a GOVERNANCE_POLICY_RELAXATION_PROJECTED event — severity always HIGH."""
    occurred_at_iso = _now_iso()
    event_type = SimulationEventType.GOVERNANCE_POLICY_RELAXATION_PROJECTED
    event_id = _derive_event_id(event_type.value, simulation_id, occurred_at_iso)
    return SimulationGovernanceEvent(
        event_id=event_id,
        event_type=event_type,
        simulation_id=simulation_id,
        tenant_id=tenant_id,
        classification=classification,
        scenario_type=scenario_type,
        severity=SimulationSeverity.HIGH,
        occurred_at_iso=occurred_at_iso,
        actor_id=actor_id,
        metadata=(),
    )


def build_replay_reconstructed_event(
    simulation_id: str,
    tenant_id: str,
    classification: SimulationClassification,
    scenario_type: SimulationScenarioType,
    actor_id: Optional[str],
) -> SimulationGovernanceEvent:
    """Build a SIMULATION_REPLAY_RECONSTRUCTED event (replay endpoint accessed)."""
    occurred_at_iso = _now_iso()
    event_type = SimulationEventType.SIMULATION_REPLAY_RECONSTRUCTED
    event_id = _derive_event_id(event_type.value, simulation_id, occurred_at_iso)
    return SimulationGovernanceEvent(
        event_id=event_id,
        event_type=event_type,
        simulation_id=simulation_id,
        tenant_id=tenant_id,
        classification=classification,
        scenario_type=scenario_type,
        severity=SimulationSeverity.INFORMATIONAL,
        occurred_at_iso=occurred_at_iso,
        actor_id=actor_id,
        metadata=(),
    )
