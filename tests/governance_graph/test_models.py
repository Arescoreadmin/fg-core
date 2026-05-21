"""Tests for governance graph pure data models."""

from __future__ import annotations

import pytest

from services.governance_graph.models import (
    EdgeDirection,
    EdgeType,
    GraphBuildResult,
    GraphNode,
    NodeType,
)


class TestNodeTypeEnum:
    def test_has_governance_asset(self) -> None:
        assert NodeType.governance_asset == "governance_asset"

    def test_has_ai_system(self) -> None:
        assert NodeType.ai_system == "ai_system"

    def test_has_identity(self) -> None:
        assert NodeType.identity == "identity"

    def test_has_finding(self) -> None:
        assert NodeType.finding == "finding"

    def test_has_control(self) -> None:
        assert NodeType.control == "control"

    def test_has_scan(self) -> None:
        assert NodeType.scan == "scan"

    def test_has_engagement(self) -> None:
        assert NodeType.engagement == "engagement"

    def test_expected_count(self) -> None:
        assert len(NodeType) == 12


class TestEdgeTypeEnum:
    def test_has_owns(self) -> None:
        assert EdgeType.OWNS == "OWNS"

    def test_has_governed_by(self) -> None:
        assert EdgeType.GOVERNED_BY == "GOVERNED_BY"

    def test_has_uses(self) -> None:
        assert EdgeType.USES == "USES"

    def test_has_impacts(self) -> None:
        assert EdgeType.IMPACTS == "IMPACTS"

    def test_has_promoted_from(self) -> None:
        assert EdgeType.PROMOTED_FROM == "PROMOTED_FROM"

    def test_expected_count(self) -> None:
        assert len(EdgeType) == 12


class TestEdgeDirectionEnum:
    def test_values(self) -> None:
        assert EdgeDirection.outbound == "outbound"
        assert EdgeDirection.inbound == "inbound"
        assert EdgeDirection.both == "both"


class TestGraphNodeFrozen:
    def _make_node(self) -> GraphNode:
        return GraphNode(
            node_id="node-001",
            tenant_id="tenant-a",
            node_type="governance_asset",
            entity_id="asset-001",
            entity_type="governance_assets",
            label="My Asset",
            properties={"risk_tier": "high"},
            tags=["ai"],
            trust_score=100,
            degree_centrality=3,
            centrality_rank=1,
            confidence=100,
            source_ref="governance_assets:asset-001",
            engagement_id=None,
            snapshot_id="snap-001",
            derived_at="2026-05-20T00:00:00Z",
        )

    def test_is_frozen(self) -> None:
        node = self._make_node()
        with pytest.raises(Exception):
            node.label = "mutated"  # type: ignore[misc]

    def test_fields_accessible(self) -> None:
        node = self._make_node()
        assert node.node_id == "node-001"
        assert node.trust_score == 100
        assert node.properties["risk_tier"] == "high"

    def test_nullable_fields(self) -> None:
        node = self._make_node()
        assert node.engagement_id is None


class TestGraphBuildResultFields:
    def test_all_fields_present(self) -> None:
        result = GraphBuildResult(
            snapshot_id="snap-001",
            snapshot_seq=1,
            tenant_id="tenant-a",
            nodes_upserted=5,
            edges_upserted=3,
            nodes_deleted=0,
            edges_deleted=0,
            anomalies_detected=1,
            triggered_by="rebuild_api",
            built_at="2026-05-20T00:00:00Z",
        )
        assert result.snapshot_id == "snap-001"
        assert result.nodes_upserted == 5
        assert result.anomalies_detected == 1

    def test_is_mutable(self) -> None:
        result = GraphBuildResult(
            snapshot_id="snap-001",
            snapshot_seq=1,
            tenant_id="tenant-a",
            nodes_upserted=0,
            edges_upserted=0,
            nodes_deleted=0,
            edges_deleted=0,
            anomalies_detected=0,
            triggered_by="rebuild_api",
            built_at="2026-05-20T00:00:00Z",
        )
        result.nodes_upserted = 99
        assert result.nodes_upserted == 99
