"""tests/identity_governance/snapshots/test_meta.py — SnapshotMeta tests."""
from __future__ import annotations

import dataclasses
from datetime import datetime, timezone

import pytest

from api.identity_governance.snapshots.meta import SnapshotMeta


def _meta(**kwargs: object) -> SnapshotMeta:
    defaults = dict(
        tenant_id="t1",
        generated_at=datetime(2026, 7, 10, 12, 0, 0, tzinfo=timezone.utc),
        fingerprint="a" * 64,
        schema_version="identity/1.0",
        replay_version="deadbeef12345678",
        source_version="identity/1.0.0",
    )
    defaults.update(kwargs)  # type: ignore[arg-type]
    return SnapshotMeta(**defaults)  # type: ignore[arg-type]


class TestSnapshotMetaImmutability:
    def test_is_frozen(self) -> None:
        meta = _meta()
        with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
            meta.tenant_id = "other"  # type: ignore[misc]

    def test_is_dataclass(self) -> None:
        assert dataclasses.is_dataclass(SnapshotMeta)


class TestSnapshotMetaRequiredFields:
    def test_missing_tenant_id_raises(self) -> None:
        with pytest.raises(TypeError):
            SnapshotMeta(  # type: ignore[call-arg]
                generated_at=datetime(2026, 7, 10, tzinfo=timezone.utc),
                fingerprint="a" * 64,
                schema_version="identity/1.0",
                replay_version="abc",
                source_version="identity/1.0.0",
            )

    def test_missing_fingerprint_raises(self) -> None:
        with pytest.raises(TypeError):
            SnapshotMeta(  # type: ignore[call-arg]
                tenant_id="t1",
                generated_at=datetime(2026, 7, 10, tzinfo=timezone.utc),
                schema_version="identity/1.0",
                replay_version="abc",
                source_version="identity/1.0.0",
            )

    def test_missing_generated_at_raises(self) -> None:
        with pytest.raises(TypeError):
            SnapshotMeta(  # type: ignore[call-arg]
                tenant_id="t1",
                fingerprint="a" * 64,
                schema_version="identity/1.0",
                replay_version="abc",
                source_version="identity/1.0.0",
            )


class TestSnapshotMetaDefaults:
    def test_snapshot_id_default(self) -> None:
        meta = _meta()
        assert meta.snapshot_id == ""

    def test_generated_by_default(self) -> None:
        meta = _meta()
        assert meta.generated_by == ""

    def test_correlation_id_default(self) -> None:
        meta = _meta()
        assert meta.correlation_id == ""

    def test_classification_default(self) -> None:
        meta = _meta()
        assert meta.classification == "internal"

    def test_retention_class_default(self) -> None:
        meta = _meta()
        assert meta.retention_class == "standard"

    def test_integrity_algorithm_default(self) -> None:
        meta = _meta()
        assert meta.integrity_algorithm == "sha256"


class TestSnapshotMetaEquality:
    def test_equal_with_same_args(self) -> None:
        ts = datetime(2026, 7, 10, 12, 0, 0, tzinfo=timezone.utc)
        a = SnapshotMeta(
            tenant_id="t1",
            generated_at=ts,
            fingerprint="a" * 64,
            schema_version="identity/1.0",
            replay_version="deadbeef12345678",
            source_version="identity/1.0.0",
        )
        b = SnapshotMeta(
            tenant_id="t1",
            generated_at=ts,
            fingerprint="a" * 64,
            schema_version="identity/1.0",
            replay_version="deadbeef12345678",
            source_version="identity/1.0.0",
        )
        assert a == b

    def test_not_equal_with_different_tenant(self) -> None:
        a = _meta(tenant_id="t1")
        b = _meta(tenant_id="t2")
        assert a != b
