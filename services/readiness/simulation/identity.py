"""Deterministic simulation identity derivation.

All functions are pure Python: no I/O, no side effects, no randomness.

Identity contract:
  - Replay-equivalent inputs MUST produce replay-equivalent identities.
  - Identities are SHA-256 digests of sorted, canonical JSON representations.
  - No timestamp-only identities (timestamps break replay equivalence).
  - No random UUIDs.
  - No insertion-order-dependent serialization.

Simulation identity:
  Derived from: tenant_id, assessment_id (or ""), framework_id (or ""),
  scenario_type, scenario_parameters_json, simulation_contract_version.
  → Two simulations with identical governance scope and parameters produce
    identical simulation_ids (idempotent submission).

Snapshot identity:
  Derived from: simulation_id, simulated_at_iso.
  → Stable within a single simulation across replay.

Impact identity (for deduplication):
  Derived from: simulation_id, impact_domain, affected_scope.
  → Identical impact domain + scope within one simulation share an ID.

Diff identity (for deduplication):
  Derived from: simulation_id, diff_type, before_value, after_value.
  → Identical diffs within one simulation share an ID.

Warning identity:
  Derived from: simulation_id, warning_type, affected_scope.
  → Identical warnings within one simulation share an ID.
"""

from __future__ import annotations

import hashlib
import json


def derive_simulation_id(
    tenant_id: str,
    assessment_id: str,
    framework_id: str,
    scenario_type: str,
    scenario_parameters_json: str,
    simulation_contract_version: str,
) -> str:
    """Derive a deterministic simulation ID from canonical governance inputs.

    Two simulations with identical inputs produce the same simulation_id —
    enabling idempotent submission: submitting the same simulation twice is safe.

    # distributed_lock_seam: simulation_id is the natural distributed lock key.
    # Under HA or multi-region deployments, a distributed lock acquired on
    # simulation_id before execution prevents duplicate concurrent simulations.
    # The winner proceeds; all others resolve via the idempotent GET path.
    """
    payload = json.dumps(
        {
            "tenant_id": tenant_id,
            "assessment_id": assessment_id,
            "framework_id": framework_id,
            "scenario_type": scenario_type,
            "scenario_parameters_json": scenario_parameters_json,
            "simulation_contract_version": simulation_contract_version,
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()[:32]


def derive_simulation_snapshot_id(
    simulation_id: str,
    simulated_at_iso: str,
) -> str:
    """Derive a deterministic snapshot ID from the simulation and timestamp."""
    payload = json.dumps(
        {
            "simulation_id": simulation_id,
            "simulated_at_iso": simulated_at_iso,
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()[:32]


def derive_impact_id(
    simulation_id: str,
    impact_domain: str,
    affected_scope: str,
) -> str:
    """Derive a deterministic impact record ID.

    Impacts with identical domain + scope within one simulation share an ID.
    """
    payload = json.dumps(
        {
            "simulation_id": simulation_id,
            "impact_domain": impact_domain,
            "affected_scope": affected_scope,
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()[:24]


def derive_diff_id(
    simulation_id: str,
    diff_type: str,
    before_value: str,
    after_value: str,
) -> str:
    """Derive a deterministic diff record ID."""
    payload = json.dumps(
        {
            "simulation_id": simulation_id,
            "diff_type": diff_type,
            "before_value": before_value,
            "after_value": after_value,
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()[:24]


def derive_warning_id(
    simulation_id: str,
    warning_type: str,
    affected_scope: str,
) -> str:
    """Derive a deterministic warning ID."""
    payload = json.dumps(
        {
            "simulation_id": simulation_id,
            "warning_type": warning_type,
            "affected_scope": affected_scope,
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()[:24]
