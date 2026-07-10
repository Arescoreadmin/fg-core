"""tests/identity_governance/snapshots/test_comparison.py — Comparison engine tests."""
from __future__ import annotations

import warnings
from datetime import datetime, timezone

import pytest

from api.identity_governance.models import (
    IdentityLifecycleState,
    RiskBand,
)
from api.identity_governance.snapshots.comparison import (
    SnapshotComparisonEngine,
    SnapshotSourceVersionWarning,
    SnapshotVersionError,
)
from api.identity_governance.snapshots.meta import SnapshotMeta
from api.identity_governance.snapshots.types import (
    IdentitySnapshot,
    RiskSnapshot,
)


_TS = datetime(2026, 7, 10, 12, 0, 0, tzinfo=timezone.utc)
_FP = "a" * 64


def _meta(
    schema: str = "identity/1.0",
    source: str = "identity/1.0.0",
) -> SnapshotMeta:
    return SnapshotMeta(
        tenant_id="tenant-a",
        generated_at=_TS,
        fingerprint=_FP,
        schema_version=schema,
        replay_version="deadbeef12345678",
        source_version=source,
    )


def _identity(
    identity_id: str = "user-1",
    lifecycle_state: IdentityLifecycleState = IdentityLifecycleState.ACTIVE,
    roles: tuple[str, ...] = ("admin",),
    schema: str = "identity/1.0",
    source: str = "identity/1.0.0",
) -> IdentitySnapshot:
    return IdentitySnapshot(
        meta=_meta(schema, source),
        identity_id=identity_id,
        lifecycle_state=lifecycle_state,
        roles=roles,
        permissions=("read:all",),
        capabilities=(),
    )


@pytest.fixture
def engine() -> SnapshotComparisonEngine:
    return SnapshotComparisonEngine()


class TestIdenticalSnapshots:
    def test_no_changes(self, engine: SnapshotComparisonEngine) -> None:
        a = _identity()
        b = _identity()
        diff = engine.compare(a, b)
        assert diff.fields_added == ()
        assert diff.fields_removed == ()
        assert diff.fields_changed == ()

    def test_is_compatible_true(self, engine: SnapshotComparisonEngine) -> None:
        a = _identity()
        b = _identity()
        diff = engine.compare(a, b)
        assert diff.is_compatible is True

    def test_same_source_version_true(self, engine: SnapshotComparisonEngine) -> None:
        a = _identity()
        b = _identity()
        diff = engine.compare(a, b)
        assert diff.same_source_version is True

    def test_snapshot_type_in_diff(self, engine: SnapshotComparisonEngine) -> None:
        a = _identity()
        b = _identity()
        diff = engine.compare(a, b)
        assert diff.snapshot_type == "IdentitySnapshot"

    def test_schema_version_in_diff(self, engine: SnapshotComparisonEngine) -> None:
        a = _identity()
        b = _identity()
        diff = engine.compare(a, b)
        assert diff.schema_version == "identity/1.0"


class TestChangedFields:
    def test_changed_role_appears_in_fields_changed(
        self, engine: SnapshotComparisonEngine
    ) -> None:
        a = _identity(roles=("admin",))
        b = _identity(roles=("viewer",))
        diff = engine.compare(a, b)
        changed_fields = {c.field for c in diff.fields_changed}
        assert "roles" in changed_fields

    def test_changed_lifecycle_appears_in_fields_changed(
        self, engine: SnapshotComparisonEngine
    ) -> None:
        a = _identity(lifecycle_state=IdentityLifecycleState.ACTIVE)
        b = _identity(lifecycle_state=IdentityLifecycleState.SUSPENDED)
        diff = engine.compare(a, b)
        changed_fields = {c.field for c in diff.fields_changed}
        assert "lifecycle_state" in changed_fields

    def test_field_change_records_old_and_new(
        self, engine: SnapshotComparisonEngine
    ) -> None:
        a = _identity(identity_id="user-1")
        b = _identity(identity_id="user-2")
        diff = engine.compare(a, b)
        id_changes = [c for c in diff.fields_changed if c.field == "identity_id"]
        assert len(id_changes) == 1
        change = id_changes[0]
        assert "user-1" in change.old_value
        assert "user-2" in change.new_value

    def test_fields_changed_sorted(self, engine: SnapshotComparisonEngine) -> None:
        a = _identity(identity_id="user-1", roles=("admin",))
        b = _identity(identity_id="user-2", roles=("viewer",))
        diff = engine.compare(a, b)
        field_names = [c.field for c in diff.fields_changed]
        assert field_names == sorted(field_names)


class TestVersionErrors:
    def test_different_schema_versions_raise(
        self, engine: SnapshotComparisonEngine
    ) -> None:
        a = _identity(schema="identity/1.0")
        b = _identity(schema="identity/2.0")
        with pytest.raises(SnapshotVersionError, match="Incompatible schema"):
            engine.compare(a, b)

    def test_different_types_raise(self, engine: SnapshotComparisonEngine) -> None:
        a = _identity()
        b = RiskSnapshot(
            meta=_meta("risk/1.0", "risk/1.0.0"),
            subject="user-1",
            score=0.5,
            band=RiskBand.MEDIUM,
            factors=(),
            evaluated_at=_TS,
        )
        with pytest.raises(TypeError):
            engine.compare(a, b)  # type: ignore[arg-type]


class TestSourceVersionWarning:
    def test_different_source_versions_warn(
        self, engine: SnapshotComparisonEngine
    ) -> None:
        a = _identity(source="identity/1.0.0")
        b = _identity(source="identity/1.0.1")
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            engine.compare(a, b)
        warning_types = [w.category for w in caught]
        assert SnapshotSourceVersionWarning in warning_types

    def test_same_source_version_no_warning(
        self, engine: SnapshotComparisonEngine
    ) -> None:
        a = _identity(source="identity/1.0.0")
        b = _identity(source="identity/1.0.0")
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            engine.compare(a, b)
        warning_types = [w.category for w in caught]
        assert SnapshotSourceVersionWarning not in warning_types

    def test_same_source_version_flag_true(
        self, engine: SnapshotComparisonEngine
    ) -> None:
        a = _identity(source="identity/1.0.0")
        b = _identity(source="identity/1.0.0")
        diff = engine.compare(a, b)
        assert diff.same_source_version is True

    def test_different_source_version_flag_false(
        self, engine: SnapshotComparisonEngine
    ) -> None:
        a = _identity(source="identity/1.0.0")
        b = _identity(source="identity/1.0.1")
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            diff = engine.compare(a, b)
        assert diff.same_source_version is False
