"""api/identity_governance/graph.py — Deterministic identity graph exporter.

Builds a snapshot of the identity graph for a subject inside a tenant:
subject node, role nodes, permission nodes, device nodes, tenant node,
and their directed relationships. No secrets are placed on nodes or
edges. Ordering is deterministic (sorted by ``node_id`` and ``edge_id``)
so the SHA-256 ``fingerprint`` is stable across identical inputs.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Iterable, Optional

from api.identity_governance.models import (
    DeviceRecord,
    GraphEdge,
    GraphNode,
    IdentityGraphSnapshot,
)

_SECRET_KEYS = frozenset(
    {
        "token",
        "secret",
        "password",
        "key",
        "access_token",
        "refresh_token",
        "id_token",
        "client_secret",
        "authorization",
        "cookie",
        "fingerprint",  # raw fingerprint is never emitted
    }
)


def _safe_attrs(attrs: dict[str, object]) -> tuple[tuple[str, str], ...]:
    """Sort attributes; drop any secret-like keys."""
    out: list[tuple[str, str]] = []
    for k in sorted(attrs.keys()):
        if k.lower() in _SECRET_KEYS:
            continue
        out.append((k, str(attrs[k])))
    return tuple(out)


class IdentityGraphExporter:
    """Exports a deterministic identity-graph snapshot."""

    def export_snapshot(
        self,
        subject: str,
        tenant_id: str,
        roles: Optional[Iterable[str]] = None,
        permissions: Optional[Iterable[str]] = None,
        devices: Optional[Iterable[DeviceRecord]] = None,
        identity_summary: Optional[dict[str, object]] = None,
    ) -> IdentityGraphSnapshot:
        """Build a deterministic graph snapshot for the subject/tenant."""
        if not subject:
            raise ValueError("subject is required")
        if not tenant_id:
            raise ValueError("tenant_id is required")

        roles_list = sorted(set(roles or []))
        perms_list = sorted(set(permissions or []))
        devices_list = list(devices or [])
        # Guarantee tenant + subject isolation for devices.
        devices_list = [
            d for d in devices_list if d.tenant_id == tenant_id and d.subject == subject
        ]

        nodes = self._build_nodes(
            subject=subject,
            tenant_id=tenant_id,
            roles=roles_list,
            permissions=perms_list,
            devices=devices_list,
            identity_summary=identity_summary or {},
        )
        edges = self._build_edges(
            subject=subject,
            tenant_id=tenant_id,
            roles=roles_list,
            permissions=perms_list,
            devices=devices_list,
        )

        # Deterministic ordering by id.
        nodes_sorted = tuple(sorted(nodes, key=lambda n: n.node_id))
        edges_sorted = tuple(sorted(edges, key=lambda e: e.edge_id))

        snapshot = IdentityGraphSnapshot(
            subject=subject,
            tenant_id=tenant_id,
            generated_at=datetime.now(tz=timezone.utc),
            nodes=nodes_sorted,
            edges=edges_sorted,
            fingerprint="",
        )
        fingerprint = self._fingerprint(snapshot)
        return IdentityGraphSnapshot(
            subject=snapshot.subject,
            tenant_id=snapshot.tenant_id,
            generated_at=snapshot.generated_at,
            nodes=snapshot.nodes,
            edges=snapshot.edges,
            fingerprint=fingerprint,
        )

    # ------------------------------------------------------------------
    # Builders
    # ------------------------------------------------------------------

    def _build_nodes(
        self,
        *,
        subject: str,
        tenant_id: str,
        roles: list[str],
        permissions: list[str],
        devices: list[DeviceRecord],
        identity_summary: dict[str, object],
    ) -> list[GraphNode]:
        nodes: list[GraphNode] = []
        nodes.append(
            GraphNode(
                node_id=f"tenant:{tenant_id}",
                node_type="tenant",
                label=tenant_id,
                attributes=(),
            )
        )
        nodes.append(
            GraphNode(
                node_id=f"identity:{subject}",
                node_type="identity",
                label=subject,
                attributes=_safe_attrs(identity_summary),
            )
        )
        for role in roles:
            nodes.append(
                GraphNode(
                    node_id=f"role:{role}",
                    node_type="role",
                    label=role,
                )
            )
        for perm in permissions:
            nodes.append(
                GraphNode(
                    node_id=f"permission:{perm}",
                    node_type="permission",
                    label=perm,
                )
            )
        for device in devices:
            nodes.append(
                GraphNode(
                    node_id=f"device:{device.device_id}",
                    node_type="device",
                    label=f"device[{device.trust_state.value}]",
                    attributes=(
                        ("trust_state", device.trust_state.value),
                        ("risk_score", f"{device.risk_score:.4f}"),
                    ),
                )
            )
        return nodes

    def _build_edges(
        self,
        *,
        subject: str,
        tenant_id: str,
        roles: list[str],
        permissions: list[str],
        devices: list[DeviceRecord],
    ) -> list[GraphEdge]:
        edges: list[GraphEdge] = []
        identity_node = f"identity:{subject}"
        tenant_node = f"tenant:{tenant_id}"

        edges.append(
            GraphEdge(
                edge_id=f"edge:{identity_node}->belongs_to->{tenant_node}",
                source=identity_node,
                target=tenant_node,
                edge_type="belongs_to",
            )
        )
        for role in roles:
            role_node = f"role:{role}"
            edges.append(
                GraphEdge(
                    edge_id=f"edge:{identity_node}->has_role->{role_node}",
                    source=identity_node,
                    target=role_node,
                    edge_type="has_role",
                )
            )
        for perm in permissions:
            perm_node = f"permission:{perm}"
            edges.append(
                GraphEdge(
                    edge_id=f"edge:{identity_node}->has_permission->{perm_node}",
                    source=identity_node,
                    target=perm_node,
                    edge_type="has_permission",
                )
            )
        for device in devices:
            device_node = f"device:{device.device_id}"
            edges.append(
                GraphEdge(
                    edge_id=f"edge:{identity_node}->uses_device->{device_node}",
                    source=identity_node,
                    target=device_node,
                    edge_type="uses_device",
                )
            )
        return edges

    def _fingerprint(self, snapshot: IdentityGraphSnapshot) -> str:
        """Deterministic SHA-256 fingerprint of the snapshot content.

        Does NOT include ``generated_at`` so identical structural content
        produces identical fingerprints across snapshots.
        """
        h = hashlib.sha256()
        h.update(snapshot.subject.encode())
        h.update(b"|")
        h.update(snapshot.tenant_id.encode())
        h.update(b"|")
        for node in snapshot.nodes:
            h.update(node.node_id.encode())
            h.update(b":")
            h.update(node.node_type.encode())
            h.update(b":")
            h.update(node.label.encode())
            for k, v in node.attributes:
                h.update(k.encode())
                h.update(b"=")
                h.update(v.encode())
                h.update(b";")
            h.update(b"|")
        h.update(b"~")
        for edge in snapshot.edges:
            h.update(edge.edge_id.encode())
            h.update(b":")
            h.update(edge.source.encode())
            h.update(b"->")
            h.update(edge.target.encode())
            h.update(b":")
            h.update(edge.edge_type.encode())
            h.update(b"|")
        return h.hexdigest()
