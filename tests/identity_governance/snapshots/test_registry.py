"""tests/identity_governance/snapshots/test_registry.py — SnapshotRegistry tests."""

from __future__ import annotations

import pytest

from api.identity_governance.snapshots.registry import (
    SnapshotRegistration,
    SnapshotRegistry,
    SnapshotRegistryError,
    get_snapshot_registry,
)
from api.identity_governance.snapshots.types import (
    DigitalTwinSnapshot,
    GraphSnapshot,
    IdentitySnapshot,
    PolicySnapshot,
    RiskSnapshot,
)


class TestGetSnapshotRegistry:
    def test_returns_registry(self) -> None:
        reg = get_snapshot_registry()
        assert isinstance(reg, SnapshotRegistry)

    def test_singleton(self) -> None:
        a = get_snapshot_registry()
        b = get_snapshot_registry()
        assert a is b

    def test_all_five_canonical_types_registered(self) -> None:
        reg = get_snapshot_registry()
        types = reg.registered_types()
        assert IdentitySnapshot in types
        assert RiskSnapshot in types
        assert GraphSnapshot in types
        assert PolicySnapshot in types
        assert DigitalTwinSnapshot in types

    def test_registered_types_count_at_least_five(self) -> None:
        reg = get_snapshot_registry()
        assert len(reg.registered_types()) >= 5


class TestLookup:
    def test_lookup_identity_snapshot(self) -> None:
        reg = get_snapshot_registry()
        reg_entry = reg.lookup(IdentitySnapshot)
        assert reg_entry.snapshot_type is IdentitySnapshot
        assert reg_entry.schema_version == "identity/1.0"
        assert reg_entry.source_version == "identity/1.0.0"

    def test_lookup_risk_snapshot(self) -> None:
        reg = get_snapshot_registry()
        reg_entry = reg.lookup(RiskSnapshot)
        assert reg_entry.schema_version == "risk/1.0"

    def test_lookup_graph_snapshot(self) -> None:
        reg = get_snapshot_registry()
        reg_entry = reg.lookup(GraphSnapshot)
        assert reg_entry.schema_version == "graph/1.0"

    def test_lookup_policy_snapshot(self) -> None:
        reg = get_snapshot_registry()
        reg_entry = reg.lookup(PolicySnapshot)
        assert reg_entry.schema_version == "policy/1.0"

    def test_lookup_digital_twin_snapshot(self) -> None:
        reg = get_snapshot_registry()
        reg_entry = reg.lookup(DigitalTwinSnapshot)
        assert reg_entry.schema_version == "digital_twin/1.0"

    def test_lookup_unknown_raises(self) -> None:
        reg = get_snapshot_registry()
        with pytest.raises(SnapshotRegistryError, match="No registration"):
            reg.lookup(str)  # type: ignore[arg-type]


class TestGetSchemaVersion:
    def test_identity_schema_version(self) -> None:
        reg = get_snapshot_registry()
        assert reg.get_schema_version(IdentitySnapshot) == "identity/1.0"

    def test_risk_schema_version(self) -> None:
        reg = get_snapshot_registry()
        assert reg.get_schema_version(RiskSnapshot) == "risk/1.0"

    def test_graph_schema_version(self) -> None:
        reg = get_snapshot_registry()
        assert reg.get_schema_version(GraphSnapshot) == "graph/1.0"

    def test_policy_schema_version(self) -> None:
        reg = get_snapshot_registry()
        assert reg.get_schema_version(PolicySnapshot) == "policy/1.0"

    def test_digital_twin_schema_version(self) -> None:
        reg = get_snapshot_registry()
        assert reg.get_schema_version(DigitalTwinSnapshot) == "digital_twin/1.0"


class TestCustomRegistration:
    def test_register_custom_type(self) -> None:
        from dataclasses import dataclass

        @dataclass(frozen=True)
        class CustomSnapshot:
            meta: object
            data: str

        reg = SnapshotRegistry()
        reg.register(SnapshotRegistration(CustomSnapshot, "custom/1.0", "custom/1.0.0"))
        entry = reg.lookup(CustomSnapshot)
        assert entry.schema_version == "custom/1.0"

    def test_custom_registry_independent_from_default(self) -> None:
        """Custom registries do not affect the global default."""
        custom_reg = SnapshotRegistry()
        default_reg = get_snapshot_registry()
        # Custom is empty
        assert len(custom_reg.registered_types()) == 0
        # Default still has all types
        assert IdentitySnapshot in default_reg.registered_types()

    def test_fingerprint_algorithm_default(self) -> None:
        reg = get_snapshot_registry()
        entry = reg.lookup(IdentitySnapshot)
        assert entry.fingerprint_algorithm == "sha256"


class TestRegisteredTypes:
    def test_returns_list(self) -> None:
        reg = get_snapshot_registry()
        types = reg.registered_types()
        assert isinstance(types, list)

    def test_returns_all_types(self) -> None:
        reg = get_snapshot_registry()
        types = reg.registered_types()
        for cls in [
            IdentitySnapshot,
            RiskSnapshot,
            GraphSnapshot,
            PolicySnapshot,
            DigitalTwinSnapshot,
        ]:
            assert cls in types
