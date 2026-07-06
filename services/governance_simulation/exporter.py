"""Replay-safe export for simulation ReplayPackage."""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping
from typing import Any

from services.governance_digital_twin.immutability import deep_freeze
from services.governance_simulation.models import ReplayPackage

_FORBIDDEN_KEYS = frozenset({
    "secret",
    "token",
    "password",
    "api_key",
    "auth_header",
    "authorization",
    "raw_prompt",
    "raw_vector",
    "embedding",
    "provider_payload",
    "private_key",
    "session",
    "cookie",
})


def _scrub_forbidden(payload: Any) -> Any:
    """Recursively remove forbidden keys from dicts."""
    if isinstance(payload, dict):
        return {
            k: _scrub_forbidden(v)
            for k, v in payload.items()
            if k.lower() not in _FORBIDDEN_KEYS
        }
    if isinstance(payload, (list, tuple)):
        scrubbed = [_scrub_forbidden(item) for item in payload]
        return type(payload)(scrubbed) if isinstance(payload, tuple) else scrubbed
    return payload


def export_replay_package(package: ReplayPackage) -> Mapping[str, Any]:
    """Convert a ReplayPackage to a deep-frozen replay-safe export dict.

    No secrets. No forbidden keys. Includes replay_instructions sub-dict.
    """
    raw = dataclasses.asdict(package)
    scrubbed = _scrub_forbidden(raw)

    scrubbed["replay_instructions"] = {
        "schema_version": package.schema_version,
        "replay_version": package.replay_version,
        "how_to_replay": (
            "To replay: obtain the source snapshot with fingerprint "
            f"'{package.source_snapshot_fingerprint}', then call "
            "GovernanceSimulationService.simulate(snapshot, package.scenario). "
            "The result fingerprint must match package.fingerprint."
        ),
        "required_inputs": [
            "source GovernanceDigitalTwinSnapshot (fingerprint must match source_snapshot_fingerprint)",
            "package.scenario (embedded SimulationScenario)",
        ],
        "determinism_guarantee": (
            "Identical snapshot + scenario inputs ALWAYS produce identical outputs. "
            "Fingerprint is SHA-256 over canonical JSON of all hashes."
        ),
    }

    return deep_freeze(scrubbed)
