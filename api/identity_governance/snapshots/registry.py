"""api/identity_governance/snapshots/registry.py — Snapshot type registry."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class SnapshotRegistration:
    snapshot_type: type
    schema_version: str        # e.g. "identity/1.0"
    source_version: str        # e.g. "identity/1.0.0"
    fingerprint_algorithm: str = "sha256"


class SnapshotRegistryError(Exception):
    pass


class SnapshotRegistry:
    """Maps snapshot types to their registration metadata."""

    def __init__(self) -> None:
        self._registrations: dict[type, SnapshotRegistration] = {}

    def register(self, registration: SnapshotRegistration) -> None:
        self._registrations[registration.snapshot_type] = registration

    def lookup(self, snapshot_type: type) -> SnapshotRegistration:
        if snapshot_type not in self._registrations:
            raise SnapshotRegistryError(
                f"No registration for {snapshot_type.__name__}"
            )
        return self._registrations[snapshot_type]

    def get_schema_version(self, snapshot_type: type) -> str:
        return self.lookup(snapshot_type).schema_version

    def registered_types(self) -> list[type]:
        return list(self._registrations.keys())


# ---------------------------------------------------------------------------
# Module singleton pre-registered with the 5 canonical types
# ---------------------------------------------------------------------------

_default_registry: Optional[SnapshotRegistry] = None


def get_snapshot_registry() -> SnapshotRegistry:
    global _default_registry
    if _default_registry is None:
        _default_registry = _build_default_registry()
    return _default_registry


def _build_default_registry() -> SnapshotRegistry:
    from api.identity_governance.snapshots.types import (
        DigitalTwinSnapshot,
        GraphSnapshot,
        IdentitySnapshot,
        PolicySnapshot,
        RiskSnapshot,
    )

    reg = SnapshotRegistry()
    reg.register(SnapshotRegistration(IdentitySnapshot, "identity/1.0", "identity/1.0.0"))
    reg.register(SnapshotRegistration(RiskSnapshot, "risk/1.0", "risk/1.0.0"))
    reg.register(SnapshotRegistration(GraphSnapshot, "graph/1.0", "graph/1.0.0"))
    reg.register(SnapshotRegistration(PolicySnapshot, "policy/1.0", "policy/1.0.0"))
    reg.register(
        SnapshotRegistration(DigitalTwinSnapshot, "digital_twin/1.0", "digital_twin/1.0.0")
    )
    return reg
