"""tests/identity_governance/test_graph.py — Identity graph exporter tests."""

from __future__ import annotations

from typing import Any

import pytest

from api.identity_governance.devices import DeviceTrustRegistry
from api.identity_governance.graph import IdentityGraphExporter


@pytest.fixture
def exporter() -> IdentityGraphExporter:
    return IdentityGraphExporter()


def test_export_basic(exporter: IdentityGraphExporter) -> None:
    snap = exporter.export_snapshot(
        subject="user-1",
        tenant_id="tenant-a",
        roles=["assessor"],
        permissions=["read:evidence"],
    )
    node_ids = [n.node_id for n in snap.nodes]
    assert "identity:user-1" in node_ids
    assert "tenant:tenant-a" in node_ids
    assert "role:assessor" in node_ids
    assert "permission:read:evidence" in node_ids


def test_edges_deterministic_order(exporter: IdentityGraphExporter) -> None:
    snap = exporter.export_snapshot(
        subject="u",
        tenant_id="t",
        roles=["r1", "r2", "r3"],
    )
    edge_ids = [e.edge_id for e in snap.edges]
    assert edge_ids == sorted(edge_ids)


def test_fingerprint_deterministic(exporter: IdentityGraphExporter) -> None:
    kwargs: dict[str, Any] = dict(
        subject="u",
        tenant_id="t",
        roles=["assessor", "manager"],
        permissions=["read", "write"],
    )
    s1 = exporter.export_snapshot(**kwargs)
    s2 = exporter.export_snapshot(**kwargs)
    assert s1.fingerprint == s2.fingerprint


def test_fingerprint_changes_when_roles_change(
    exporter: IdentityGraphExporter,
) -> None:
    a = exporter.export_snapshot(subject="u", tenant_id="t", roles=["r1"])
    b = exporter.export_snapshot(subject="u", tenant_id="t", roles=["r2"])
    assert a.fingerprint != b.fingerprint


def test_cross_tenant_device_filtered(exporter: IdentityGraphExporter) -> None:
    registry = DeviceTrustRegistry()
    d_a = registry.register_device(
        subject="u",
        tenant_id="tenant-a",
        fingerprint_hash="h",
        user_agent_hash="u",
        ip_metadata="i",
    )
    d_b = registry.register_device(
        subject="u",
        tenant_id="tenant-b",
        fingerprint_hash="h",
        user_agent_hash="u",
        ip_metadata="i",
    )
    snap = exporter.export_snapshot(
        subject="u",
        tenant_id="tenant-a",
        devices=[d_a, d_b],
    )
    node_ids = [n.node_id for n in snap.nodes]
    assert f"device:{d_a.device_id}" in node_ids
    assert f"device:{d_b.device_id}" not in node_ids


def test_no_secrets_in_snapshot(exporter: IdentityGraphExporter) -> None:
    snap = exporter.export_snapshot(
        subject="u",
        tenant_id="t",
        roles=["r"],
        identity_summary={
            "email": "u@example.com",
            "password": "hunter2",
            "token": "abc",
        },
    )
    identity_node = next(n for n in snap.nodes if n.node_id == "identity:u")
    attrs = dict(identity_node.attributes)
    assert "password" not in attrs
    assert "token" not in attrs
    assert attrs.get("email") == "u@example.com"


def test_no_raw_fingerprint_in_nodes(exporter: IdentityGraphExporter) -> None:
    registry = DeviceTrustRegistry()
    d = registry.register_device(
        subject="u",
        tenant_id="t",
        fingerprint_hash="hashed-value-only",
        user_agent_hash="u",
        ip_metadata="i",
    )
    snap = exporter.export_snapshot(subject="u", tenant_id="t", devices=[d])
    device_node = next(n for n in snap.nodes if n.node_type == "device")
    attrs = dict(device_node.attributes)
    assert "fingerprint" not in attrs


def test_subject_required(exporter: IdentityGraphExporter) -> None:
    with pytest.raises(ValueError, match="subject is required"):
        exporter.export_snapshot(subject="", tenant_id="t")


def test_tenant_required(exporter: IdentityGraphExporter) -> None:
    with pytest.raises(ValueError, match="tenant_id is required"):
        exporter.export_snapshot(subject="u", tenant_id="")


def test_nodes_sorted_by_id(exporter: IdentityGraphExporter) -> None:
    snap = exporter.export_snapshot(
        subject="u",
        tenant_id="t",
        roles=["z-role", "a-role"],
    )
    node_ids = [n.node_id for n in snap.nodes]
    assert node_ids == sorted(node_ids)
