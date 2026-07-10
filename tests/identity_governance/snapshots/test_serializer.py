"""tests/identity_governance/snapshots/test_serializer.py — Serializer tests."""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from api.identity_governance.models import (
    IdentityLifecycleState,
    PolicyDecision,
    RiskBand,
)
from api.identity_governance.snapshots.meta import SnapshotMeta
from api.identity_governance.snapshots.serializer import (
    compute_replay_version,
    deserialize_snapshot,
    fingerprint_snapshot,
    serialize_snapshot,
)
from api.identity_governance.snapshots.types import (
    IdentitySnapshot,
    PolicySnapshot,
    RiskSnapshot,
)


_TS = datetime(2026, 7, 10, 12, 0, 0, 123456, tzinfo=timezone.utc)
_FP = "a" * 64


def _meta(schema: str = "identity/1.0", source: str = "identity/1.0.0") -> SnapshotMeta:
    return SnapshotMeta(
        tenant_id="tenant-a",
        generated_at=_TS,
        fingerprint=_FP,
        schema_version=schema,
        replay_version="deadbeef12345678",
        source_version=source,
    )


def _identity_snap(
    identity_id: str = "user-1",
    roles: tuple[str, ...] = ("admin",),
    ts: datetime | None = None,
) -> IdentitySnapshot:
    meta = _meta() if ts is None else SnapshotMeta(
        tenant_id="tenant-a",
        generated_at=ts,
        fingerprint=_FP,
        schema_version="identity/1.0",
        replay_version="deadbeef12345678",
        source_version="identity/1.0.0",
    )
    return IdentitySnapshot(
        meta=meta,
        identity_id=identity_id,
        lifecycle_state=IdentityLifecycleState.ACTIVE,
        roles=roles,
        permissions=("read:all",),
        capabilities=("write",),
    )


class TestSerializeSnapshot:
    def test_produces_valid_json(self) -> None:
        snap = _identity_snap()
        raw = serialize_snapshot(snap)
        parsed = json.loads(raw)
        assert isinstance(parsed, dict)

    def test_produces_sorted_keys(self) -> None:
        snap = _identity_snap()
        raw = serialize_snapshot(snap)
        parsed = json.loads(raw)
        keys = list(parsed.keys())
        assert keys == sorted(keys), "Top-level keys must be sorted"

    def test_canonical_datetime_z_suffix(self) -> None:
        snap = _identity_snap()
        raw = serialize_snapshot(snap)
        # generated_at is inside "meta"
        parsed = json.loads(raw)
        assert parsed["meta"]["generated_at"].endswith("Z")

    def test_canonical_datetime_microseconds(self) -> None:
        snap = _identity_snap()
        raw = serialize_snapshot(snap)
        parsed = json.loads(raw)
        # Format: 2026-07-10T12:00:00.123456Z
        assert "." in parsed["meta"]["generated_at"]

    def test_enum_serialized_as_value(self) -> None:
        snap = _identity_snap()
        raw = serialize_snapshot(snap)
        parsed = json.loads(raw)
        assert parsed["lifecycle_state"] == "ACTIVE"  # not "IdentityLifecycleState.ACTIVE"

    def test_no_extra_whitespace(self) -> None:
        snap = _identity_snap()
        raw = serialize_snapshot(snap)
        assert " " not in raw or raw.count(" ") == 0

    def test_deterministic_double_call(self) -> None:
        snap = _identity_snap()
        assert serialize_snapshot(snap) == serialize_snapshot(snap)

    def test_raises_for_non_dataclass(self) -> None:
        with pytest.raises(TypeError):
            serialize_snapshot({"not": "a snapshot"})  # type: ignore[arg-type]


class TestRoundTrip:
    def test_identity_snapshot_round_trip(self) -> None:
        snap = _identity_snap()
        raw = serialize_snapshot(snap)
        restored = deserialize_snapshot(raw, IdentitySnapshot)
        assert restored == snap

    def test_risk_snapshot_round_trip(self) -> None:
        snap = RiskSnapshot(
            meta=_meta("risk/1.0", "risk/1.0.0"),
            subject="user-1",
            score=0.75,
            band=RiskBand.HIGH,
            factors=(("no_mfa", 0.5), ("break_glass", 0.25)),
            evaluated_at=_TS,
        )
        raw = serialize_snapshot(snap)
        restored = deserialize_snapshot(raw, RiskSnapshot)
        assert restored == snap

    def test_policy_snapshot_round_trip(self) -> None:
        snap = PolicySnapshot(
            meta=_meta("policy/1.0", "policy/1.0.0"),
            subject="user-1",
            policies_evaluated=3,
            decision=PolicyDecision.ALLOW,
            matched_policy_id="p-1",
            conditions_checked=("mfa", "device"),
        )
        raw = serialize_snapshot(snap)
        restored = deserialize_snapshot(raw, PolicySnapshot)
        assert restored == snap

    def test_factors_tuple_round_trip(self) -> None:
        """tuple[tuple[str, float], ...] must survive JSON round-trip."""
        snap = RiskSnapshot(
            meta=_meta("risk/1.0", "risk/1.0.0"),
            subject="user-1",
            score=0.1,
            band=RiskBand.LOW,
            factors=(("factor_a", 0.05), ("factor_b", 0.05)),
            evaluated_at=_TS,
        )
        raw = serialize_snapshot(snap)
        restored = deserialize_snapshot(raw, RiskSnapshot)
        assert restored.factors == (("factor_a", 0.05), ("factor_b", 0.05))
        assert all(isinstance(f, tuple) for f in restored.factors)


class TestFingerprintSnapshot:
    def test_returns_64_char_hex(self) -> None:
        snap = _identity_snap()
        fp = fingerprint_snapshot(snap)
        assert len(fp) == 64
        assert all(c in "0123456789abcdef" for c in fp)

    def test_deterministic(self) -> None:
        snap = _identity_snap()
        assert fingerprint_snapshot(snap) == fingerprint_snapshot(snap)

    def test_identical_data_same_fingerprint(self) -> None:
        a = _identity_snap()
        b = _identity_snap()
        assert fingerprint_snapshot(a) == fingerprint_snapshot(b)

    def test_changed_role_changes_fingerprint(self) -> None:
        a = _identity_snap(roles=("admin",))
        b = _identity_snap(roles=("viewer",))
        assert fingerprint_snapshot(a) != fingerprint_snapshot(b)

    def test_changed_identity_id_changes_fingerprint(self) -> None:
        a = _identity_snap(identity_id="user-1")
        b = _identity_snap(identity_id="user-2")
        assert fingerprint_snapshot(a) != fingerprint_snapshot(b)

    def test_generated_at_does_not_affect_fingerprint(self) -> None:
        ts1 = datetime(2026, 7, 10, 12, 0, 0, tzinfo=timezone.utc)
        ts2 = datetime(2026, 7, 11, 9, 0, 0, tzinfo=timezone.utc)
        a = _identity_snap(ts=ts1)
        b = _identity_snap(ts=ts2)
        # Same data fields, only generated_at (in meta) differs → same fingerprint
        assert fingerprint_snapshot(a) == fingerprint_snapshot(b)

    def test_excludes_meta_fields(self) -> None:
        """Fingerprint must NOT change when only meta (non-data) changes."""
        base = _identity_snap()
        meta_different = SnapshotMeta(
            tenant_id="tenant-a",
            generated_at=datetime(2030, 1, 1, tzinfo=timezone.utc),  # different
            fingerprint="b" * 64,  # different
            schema_version="identity/1.0",
            replay_version="different_replay",  # different
            source_version="identity/1.0.0",
            snapshot_id="some-id",  # different
        )
        snap_different_meta = IdentitySnapshot(
            meta=meta_different,
            identity_id=base.identity_id,
            lifecycle_state=base.lifecycle_state,
            roles=base.roles,
            permissions=base.permissions,
            capabilities=base.capabilities,
        )
        assert fingerprint_snapshot(base) == fingerprint_snapshot(snap_different_meta)


class TestComputeReplayVersion:
    def test_returns_hex_string(self) -> None:
        rv = compute_replay_version("user-1", "tenant-a")
        assert isinstance(rv, str)
        assert all(c in "0123456789abcdef" for c in rv)

    def test_returns_16_char_string(self) -> None:
        rv = compute_replay_version("user-1", "tenant-a")
        assert len(rv) == 16

    def test_deterministic(self) -> None:
        a = compute_replay_version("user-1", "tenant-a", "2026-07-10")
        b = compute_replay_version("user-1", "tenant-a", "2026-07-10")
        assert a == b

    def test_different_inputs_different_output(self) -> None:
        a = compute_replay_version("user-1")
        b = compute_replay_version("user-2")
        assert a != b
