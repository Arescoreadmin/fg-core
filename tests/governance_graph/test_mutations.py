"""Tests for governance graph mutation helpers (upsert_node, upsert_edge, etc.)."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from api.db_models import Base
import api.db_models_governance_graph  # noqa: F401 — registers models

from api.db_models_governance_graph import GovernanceGraphNode
from services.governance_graph.mutations import (
    _edge_id,
    _node_id,
    delete_stale,
    update_centrality,
    upsert_edge,
    upsert_node,
)

_TENANT = "tenant-mut-test"
_TENANT_B = "tenant-mut-test-b"


@pytest.fixture()
def engine():
    eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(eng)
    yield eng
    eng.dispose()


@pytest.fixture()
def db(engine):
    with Session(engine) as session:
        yield session


def _make_node(
    db: Session,
    *,
    entity_id: str = "asset-001",
    node_type: str = "governance_asset",
    tenant_id: str = _TENANT,
    derived_at: str = "2026-05-20T00:00:00Z",
) -> GovernanceGraphNode:
    return upsert_node(
        db,
        tenant_id=tenant_id,
        node_type=node_type,
        entity_id=entity_id,
        entity_type="governance_assets",
        label=f"Asset {entity_id}",
        properties={"risk_tier": "high"},
        tags=["ai"],
        trust_score=100,
        confidence=100,
        source_ref=f"governance_assets:{entity_id}",
        snapshot_id="snap-001",
        derived_at=derived_at,
    )


class TestUpsertNode:
    def test_creates_new_node(self, db: Session) -> None:
        node = _make_node(db)
        assert node.node_id == _node_id(_TENANT, "governance_asset", "asset-001")
        assert node.label == "Asset asset-001"

    def test_idempotent_upsert(self, db: Session) -> None:
        node1 = _make_node(db)
        node2 = upsert_node(
            db,
            tenant_id=_TENANT,
            node_type="governance_asset",
            entity_id="asset-001",
            entity_type="governance_assets",
            label="Updated Label",
            properties={"risk_tier": "critical"},
            tags=[],
            trust_score=80,
            confidence=90,
            source_ref="governance_assets:asset-001",
            snapshot_id="snap-002",
            derived_at="2026-05-20T01:00:00Z",
        )
        assert node1.node_id == node2.node_id
        assert node2.label == "Updated Label"
        assert node2.trust_score == 80

    def test_node_id_deterministic(self, db: Session) -> None:
        node = _make_node(db)
        expected = _node_id(_TENANT, "governance_asset", "asset-001")
        assert node.node_id == expected

    def test_different_tenants_different_ids(self) -> None:
        id1 = _node_id("tenant-a", "governance_asset", "asset-001")
        id2 = _node_id("tenant-b", "governance_asset", "asset-001")
        assert id1 != id2

    def test_default_trust_score(self, db: Session) -> None:
        node = _make_node(db)
        assert node.trust_score == 100

    def test_default_degree_centrality(self, db: Session) -> None:
        node = _make_node(db)
        assert node.degree_centrality == 0


class TestUpsertEdge:
    def test_creates_new_edge(self, db: Session) -> None:
        src = _make_node(db, entity_id="identity-001", node_type="identity")
        tgt = _make_node(db, entity_id="asset-001", node_type="governance_asset")
        edge = upsert_edge(
            db,
            tenant_id=_TENANT,
            edge_type="OWNS",
            source_node_id=src.node_id,
            target_node_id=tgt.node_id,
            confidence=100,
            properties={},
            source_ref="governance_asset_owners:owner-001",
            snapshot_id="snap-001",
            derived_at="2026-05-20T00:00:00Z",
        )
        assert edge.edge_type == "OWNS"
        assert edge.source_node_id == src.node_id
        assert edge.target_node_id == tgt.node_id

    def test_idempotent_upsert(self, db: Session) -> None:
        src = _make_node(db, entity_id="identity-001", node_type="identity")
        tgt = _make_node(db, entity_id="asset-001", node_type="governance_asset")
        edge1 = upsert_edge(
            db,
            tenant_id=_TENANT,
            edge_type="OWNS",
            source_node_id=src.node_id,
            target_node_id=tgt.node_id,
            confidence=100,
            properties={},
            source_ref="governance_asset_owners:owner-001",
            snapshot_id="snap-001",
            derived_at="2026-05-20T00:00:00Z",
        )
        edge2 = upsert_edge(
            db,
            tenant_id=_TENANT,
            edge_type="OWNS",
            source_node_id=src.node_id,
            target_node_id=tgt.node_id,
            confidence=90,
            properties={"note": "updated"},
            source_ref="governance_asset_owners:owner-001",
            snapshot_id="snap-002",
            derived_at="2026-05-20T01:00:00Z",
        )
        assert edge1.edge_id == edge2.edge_id
        assert edge2.confidence == 90

    def test_edge_id_deterministic(self, db: Session) -> None:
        src = _make_node(db, entity_id="identity-001", node_type="identity")
        tgt = _make_node(db, entity_id="asset-001", node_type="governance_asset")
        edge = upsert_edge(
            db,
            tenant_id=_TENANT,
            edge_type="OWNS",
            source_node_id=src.node_id,
            target_node_id=tgt.node_id,
            confidence=100,
            properties={},
            source_ref="ref",
            snapshot_id="snap-001",
            derived_at="2026-05-20T00:00:00Z",
        )
        expected = _edge_id(_TENANT, "OWNS", src.node_id, tgt.node_id)
        assert edge.edge_id == expected


class TestDeleteStale:
    def test_deletes_old_nodes_and_edges(self, db: Session) -> None:
        n1 = _make_node(db, entity_id="old-001", derived_at="2026-05-01T00:00:00Z")
        n2 = _make_node(db, entity_id="new-001", derived_at="2026-05-20T00:00:00Z")
        nodes_del, edges_del = delete_stale(
            db, tenant_id=_TENANT, older_than="2026-05-10T00:00:00Z"
        )
        assert nodes_del == 1
        assert edges_del == 0
        assert db.get(GovernanceGraphNode, n1.node_id) is None
        assert db.get(GovernanceGraphNode, n2.node_id) is not None

    def test_returns_zero_for_empty_graph(self, db: Session) -> None:
        nodes_del, edges_del = delete_stale(
            db, tenant_id=_TENANT, older_than="2026-05-20T00:00:00Z"
        )
        assert nodes_del == 0
        assert edges_del == 0


class TestUpdateCentrality:
    def test_computes_degree(self, db: Session) -> None:
        hub = _make_node(db, entity_id="hub", node_type="governance_asset")
        leaf1 = _make_node(db, entity_id="leaf1", node_type="identity")
        leaf2 = _make_node(db, entity_id="leaf2", node_type="identity")

        upsert_edge(
            db,
            tenant_id=_TENANT,
            edge_type="OWNS",
            source_node_id=leaf1.node_id,
            target_node_id=hub.node_id,
            confidence=100,
            properties={},
            source_ref="ref",
            snapshot_id="snap-001",
            derived_at="2026-05-20T00:00:00Z",
        )
        upsert_edge(
            db,
            tenant_id=_TENANT,
            edge_type="OWNS",
            source_node_id=leaf2.node_id,
            target_node_id=hub.node_id,
            confidence=100,
            properties={},
            source_ref="ref",
            snapshot_id="snap-001",
            derived_at="2026-05-20T00:00:00Z",
        )

        count = update_centrality(db, tenant_id=_TENANT, snapshot_id="snap-001")
        assert count == 3

        db.refresh(hub)
        assert hub.degree_centrality == 2  # 2 inbound edges

        db.refresh(leaf1)
        assert leaf1.degree_centrality == 1  # 1 outbound

    def test_centrality_rank_ordering(self, db: Session) -> None:
        hub = _make_node(db, entity_id="hub2", node_type="governance_asset")
        leaf = _make_node(db, entity_id="leaf2b", node_type="identity")

        upsert_edge(
            db,
            tenant_id=_TENANT,
            edge_type="OWNS",
            source_node_id=leaf.node_id,
            target_node_id=hub.node_id,
            confidence=100,
            properties={},
            source_ref="ref",
            snapshot_id="snap-001",
            derived_at="2026-05-20T00:00:00Z",
        )

        update_centrality(db, tenant_id=_TENANT, snapshot_id="snap-001")
        db.refresh(hub)
        db.refresh(leaf)

        # hub has degree=1, leaf has degree=1 — ranks assigned
        assert hub.centrality_rank is not None
        assert leaf.centrality_rank is not None
        # The node with higher (or equal) degree gets rank=1
        assert min(hub.centrality_rank, leaf.centrality_rank) == 1
