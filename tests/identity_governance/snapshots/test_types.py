"""tests/identity_governance/snapshots/test_types.py — Canonical snapshot type tests."""

from __future__ import annotations

import dataclasses
from datetime import datetime, timezone

import pytest

from api.identity_governance.models import (
    GraphEdge,
    GraphNode,
    IdentityLifecycleState,
    PolicyDecision,
    RiskBand,
)
from api.identity_governance.snapshots.meta import SnapshotMeta
from api.identity_governance.snapshots.types import (
    DigitalTwinSnapshot,
    GraphSnapshot,
    IdentitySnapshot,
    PolicySnapshot,
    RiskSnapshot,
)


_TS = datetime(2026, 7, 10, 12, 0, 0, tzinfo=timezone.utc)

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


class TestTypesAreFrozen:
    def test_identity_snapshot_frozen(self) -> None:
        snap = IdentitySnapshot(
            meta=_meta(),
            identity_id="user-1",
            lifecycle_state=IdentityLifecycleState.ACTIVE,
            roles=("admin",),
            permissions=("read:all",),
            capabilities=("write",),
        )
        with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
            snap.identity_id = "other"  # type: ignore[misc]

    def test_risk_snapshot_frozen(self) -> None:
        snap = RiskSnapshot(
            meta=_meta("risk/1.0", "risk/1.0.0"),
            subject="user-1",
            score=0.5,
            band=RiskBand.MEDIUM,
            factors=(("mfa_missing", 0.3),),
            evaluated_at=_TS,
        )
        with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
            snap.score = 0.9  # type: ignore[misc]

    def test_graph_snapshot_frozen(self) -> None:
        snap = GraphSnapshot(
            meta=_meta("graph/1.0", "graph/1.0.0"),
            subject="user-1",
            nodes=(),
            edges=(),
        )
        with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
            snap.subject = "other"  # type: ignore[misc]

    def test_policy_snapshot_frozen(self) -> None:
        snap = PolicySnapshot(
            meta=_meta("policy/1.0", "policy/1.0.0"),
            subject="user-1",
            policies_evaluated=3,
            decision=PolicyDecision.ALLOW,
            matched_policy_id="p-1",
            conditions_checked=("mfa", "device"),
        )
        with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
            snap.policies_evaluated = 99  # type: ignore[misc]

    def test_digital_twin_snapshot_frozen(self) -> None:
        snap = DigitalTwinSnapshot(
            meta=_meta("digital_twin/1.0", "digital_twin/1.0.0"),
            subject="user-1",
            identity_summary=(("key", "value"),),
            lifecycle_state=IdentityLifecycleState.ACTIVE,
            roles=(),
            permissions=(),
            capabilities=(),
        )
        with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
            snap.subject = "other"  # type: ignore[misc]


class TestMetaIsFirstField:
    def test_identity_meta_first(self) -> None:
        fields = dataclasses.fields(IdentitySnapshot)
        assert fields[0].name == "meta"

    def test_risk_meta_first(self) -> None:
        fields = dataclasses.fields(RiskSnapshot)
        assert fields[0].name == "meta"

    def test_graph_meta_first(self) -> None:
        fields = dataclasses.fields(GraphSnapshot)
        assert fields[0].name == "meta"

    def test_policy_meta_first(self) -> None:
        fields = dataclasses.fields(PolicySnapshot)
        assert fields[0].name == "meta"

    def test_digital_twin_meta_first(self) -> None:
        fields = dataclasses.fields(DigitalTwinSnapshot)
        assert fields[0].name == "meta"


class TestAllTypesInstantiate:
    def test_identity_snapshot(self) -> None:
        snap = IdentitySnapshot(
            meta=_meta(),
            identity_id="user-1",
            lifecycle_state=IdentityLifecycleState.ACTIVE,
            roles=("admin", "viewer"),
            permissions=("read:all",),
            capabilities=(),
        )
        assert snap.identity_id == "user-1"
        assert snap.roles == ("admin", "viewer")

    def test_risk_snapshot(self) -> None:
        snap = RiskSnapshot(
            meta=_meta("risk/1.0", "risk/1.0.0"),
            subject="user-1",
            score=0.75,
            band=RiskBand.HIGH,
            factors=(("no_mfa", 0.5), ("break_glass", 0.25)),
            evaluated_at=_TS,
        )
        assert snap.score == 0.75
        assert snap.band == RiskBand.HIGH

    def test_graph_snapshot(self) -> None:
        node = GraphNode(node_id="n1", node_type="identity", label="user-1")
        edge = GraphEdge(edge_id="e1", source="n1", target="n2", edge_type="has_role")
        snap = GraphSnapshot(
            meta=_meta("graph/1.0", "graph/1.0.0"),
            subject="user-1",
            nodes=(node,),
            edges=(edge,),
        )
        assert len(snap.nodes) == 1
        assert len(snap.edges) == 1

    def test_policy_snapshot(self) -> None:
        snap = PolicySnapshot(
            meta=_meta("policy/1.0", "policy/1.0.0"),
            subject="user-1",
            policies_evaluated=5,
            decision=PolicyDecision.DENY,
            matched_policy_id="policy-deny-1",
            conditions_checked=("mfa", "lifecycle", "device"),
        )
        assert snap.decision == PolicyDecision.DENY
        assert snap.policies_evaluated == 5

    def test_digital_twin_snapshot(self) -> None:
        snap = DigitalTwinSnapshot(
            meta=_meta("digital_twin/1.0", "digital_twin/1.0.0"),
            subject="user-1",
            identity_summary=(("email", "user@example.com"),),
            lifecycle_state=IdentityLifecycleState.ACTIVE,
            roles=("admin",),
            permissions=("read:all",),
            capabilities=("write",),
        )
        assert snap.subject == "user-1"
        assert snap.active_sessions_count == 0  # default
        assert snap.risk_score is None  # default
        assert snap.device_records == ()  # default


class TestOptionalFieldDefaults:
    def test_digital_twin_all_defaults(self) -> None:
        snap = DigitalTwinSnapshot(
            meta=_meta("digital_twin/1.0", "digital_twin/1.0.0"),
            subject="user-1",
            identity_summary=(),
            lifecycle_state=IdentityLifecycleState.ACTIVE,
            roles=(),
            permissions=(),
            capabilities=(),
        )
        assert snap.device_records == ()
        assert snap.active_sessions_count == 0
        assert snap.risk_score is None
        assert snap.active_break_glass_count == 0
        assert snap.recent_timeline_events == ()
        assert snap.assessments_count == 0
        assert snap.evidence_count == 0
