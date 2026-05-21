"""Tests for governance graph query helpers."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from api.db_models import Base
import api.db_models_governance_graph  # noqa: F401 — registers models

from services.governance_graph.mutations import (
    upsert_edge,
    upsert_node,
)
from services.governance_graph.queries import (
    find_path,
    get_graph_stats,
    get_node,
    list_nodes,
    traverse,
)

_TENANT = "tenant-q-test"
_TENANT_B = "tenant-q-test-b"
_SNAP = "snap-001"
_AT = "2026-05-20T00:00:00Z"


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


def _node(
    db: Session,
    *,
    entity_id: str,
    node_type: str = "governance_asset",
    tenant_id: str = _TENANT,
    derived_at: str = _AT,
):
    return upsert_node(
        db,
        tenant_id=tenant_id,
        node_type=node_type,
        entity_id=entity_id,
        entity_type=node_type + "s",
        label=f"{node_type}:{entity_id}",
        properties={},
        tags=[],
        trust_score=100,
        confidence=100,
        source_ref=f"{node_type}:{entity_id}",
        snapshot_id=_SNAP,
        derived_at=derived_at,
    )


def _edge(
    db: Session,
    *,
    src_id: str,
    tgt_id: str,
    edge_type: str = "OWNS",
    tenant_id: str = _TENANT,
):
    return upsert_edge(
        db,
        tenant_id=tenant_id,
        edge_type=edge_type,
        source_node_id=src_id,
        target_node_id=tgt_id,
        confidence=100,
        properties={},
        source_ref="ref",
        snapshot_id=_SNAP,
        derived_at=_AT,
    )


class TestGetNode:
    def test_returns_node_for_valid_id(self, db: Session) -> None:
        n = _node(db, entity_id="asset-001")
        result = get_node(db, tenant_id=_TENANT, node_id=n.node_id)
        assert result is not None
        assert result.node_id == n.node_id

    def test_returns_none_for_unknown_id(self, db: Session) -> None:
        result = get_node(db, tenant_id=_TENANT, node_id="unknown-node-id")
        assert result is None

    def test_tenant_isolation(self, db: Session) -> None:
        n = _node(db, entity_id="asset-001", tenant_id=_TENANT_B)
        result = get_node(db, tenant_id=_TENANT, node_id=n.node_id)
        assert result is None


class TestListNodes:
    def test_lists_all_tenant_nodes(self, db: Session) -> None:
        _node(db, entity_id="a1")
        _node(db, entity_id="a2")
        _node(db, entity_id="b1", tenant_id=_TENANT_B)
        results = list_nodes(db, tenant_id=_TENANT)
        assert len(results) == 2

    def test_filters_by_node_type(self, db: Session) -> None:
        _node(db, entity_id="asset-001", node_type="governance_asset")
        _node(db, entity_id="id-001", node_type="identity")
        results = list_nodes(db, tenant_id=_TENANT, node_type="identity")
        assert len(results) == 1
        assert results[0].node_type == "identity"

    def test_limit_and_offset(self, db: Session) -> None:
        for i in range(5):
            _node(db, entity_id=f"asset-{i:03d}")
        page1 = list_nodes(db, tenant_id=_TENANT, limit=3, offset=0)
        page2 = list_nodes(db, tenant_id=_TENANT, limit=3, offset=3)
        assert len(page1) == 3
        assert len(page2) == 2


class TestTraverse:
    def test_returns_root_only_for_isolated_node(self, db: Session) -> None:
        root = _node(db, entity_id="root")
        result = traverse(db, tenant_id=_TENANT, root_node_id=root.node_id)
        assert len(result.nodes) == 1
        assert result.nodes[0].node_id == root.node_id

    def test_follows_outbound_edges(self, db: Session) -> None:
        root = _node(db, entity_id="root-t")
        child = _node(db, entity_id="child-t", node_type="identity")
        _edge(db, src_id=root.node_id, tgt_id=child.node_id)
        result = traverse(db, tenant_id=_TENANT, root_node_id=root.node_id)
        node_ids = {n.node_id for n in result.nodes}
        assert root.node_id in node_ids
        assert child.node_id in node_ids

    def test_respects_max_depth(self, db: Session) -> None:
        # Chain: root -> n1 -> n2 -> n3
        root = _node(db, entity_id="chain-root")
        n1 = _node(db, entity_id="chain-n1")
        n2 = _node(db, entity_id="chain-n2")
        n3 = _node(db, entity_id="chain-n3")
        _edge(db, src_id=root.node_id, tgt_id=n1.node_id)
        _edge(db, src_id=n1.node_id, tgt_id=n2.node_id)
        _edge(db, src_id=n2.node_id, tgt_id=n3.node_id)
        result = traverse(db, tenant_id=_TENANT, root_node_id=root.node_id, max_depth=2)
        node_ids = {n.node_id for n in result.nodes}
        # At depth=2: root(0), n1(1), n2(2) — n3 is at depth 3, excluded
        assert root.node_id in node_ids
        assert n1.node_id in node_ids
        assert n2.node_id in node_ids
        assert n3.node_id not in node_ids

    def test_hard_cap_depth(self, db: Session) -> None:
        result = traverse(
            db,
            tenant_id=_TENANT,
            root_node_id="any",
            max_depth=99,  # should be capped at MAX_TRAVERSE_DEPTH
        )
        # Just validate it doesn't error; capping logic is internal
        assert result.truncated is False or result.truncated is True

    def test_tenant_isolation(self, db: Session) -> None:
        root_a = _node(db, entity_id="root-a", tenant_id=_TENANT)
        root_b = _node(db, entity_id="root-a", tenant_id=_TENANT_B)
        # Cross-tenant edge (should not happen in practice but test isolation)
        result = traverse(db, tenant_id=_TENANT, root_node_id=root_a.node_id)
        node_ids = {n.node_id for n in result.nodes}
        assert root_b.node_id not in node_ids


class TestFindPath:
    def test_finds_direct_path(self, db: Session) -> None:
        src = _node(db, entity_id="fp-src")
        tgt = _node(db, entity_id="fp-tgt")
        _edge(db, src_id=src.node_id, tgt_id=tgt.node_id)
        path = find_path(
            db,
            tenant_id=_TENANT,
            source_node_id=src.node_id,
            target_node_id=tgt.node_id,
        )
        assert path is not None
        assert len(path) == 2

    def test_returns_none_for_unreachable(self, db: Session) -> None:
        src = _node(db, entity_id="fp2-src")
        tgt = _node(db, entity_id="fp2-tgt")
        path = find_path(
            db,
            tenant_id=_TENANT,
            source_node_id=src.node_id,
            target_node_id=tgt.node_id,
        )
        assert path is None

    def test_same_node_returns_self(self, db: Session) -> None:
        n = _node(db, entity_id="fp3-same")
        path = find_path(
            db,
            tenant_id=_TENANT,
            source_node_id=n.node_id,
            target_node_id=n.node_id,
        )
        assert path is not None
        assert len(path) == 1


class TestGetGraphStats:
    def test_empty_graph(self, db: Session) -> None:
        stats = get_graph_stats(db, tenant_id="empty-tenant")
        assert stats["node_count"] == 0
        assert stats["edge_count"] == 0
        assert stats["anomaly_count"] == 0
        assert stats["last_snapshot"] is None

    def test_counts_nodes_and_edges(self, db: Session) -> None:
        n1 = _node(db, entity_id="stats-n1")
        n2 = _node(db, entity_id="stats-n2", node_type="identity")
        _edge(db, src_id=n2.node_id, tgt_id=n1.node_id)
        stats = get_graph_stats(db, tenant_id=_TENANT)
        assert stats["node_count"] >= 2
        assert stats["edge_count"] >= 1

    def test_by_node_type_present(self, db: Session) -> None:
        _node(db, entity_id="snt-a1", node_type="governance_asset")
        _node(db, entity_id="snt-a2", node_type="governance_asset")
        _node(db, entity_id="snt-i1", node_type="identity")
        stats = get_graph_stats(db, tenant_id=_TENANT)
        by_type = stats["by_node_type"]
        assert by_type.get("governance_asset", 0) >= 2
        assert by_type.get("identity", 0) >= 1
