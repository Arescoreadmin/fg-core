"""Tests for graph integrity checks."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from api.db_models import Base
import api.db_models_governance_graph  # noqa: F401 — registers models

from api.db_models_governance_graph import GovernanceGraphEdge
from services.governance_graph.mutations import (
    upsert_edge,
    upsert_node,
)
from services.governance_graph.integrity import (
    detect_orphan_edges,
    validate_graph_invariants,
)

_TENANT = "tenant-integrity-test"
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


def _node(db: Session, *, entity_id: str, node_type: str = "governance_asset"):
    return upsert_node(
        db,
        tenant_id=_TENANT,
        node_type=node_type,
        entity_id=entity_id,
        entity_type=node_type,
        label=f"{node_type}:{entity_id}",
        properties={},
        tags=[],
        trust_score=100,
        confidence=100,
        source_ref=f"{node_type}:{entity_id}",
        snapshot_id=_SNAP,
        derived_at=_AT,
    )


def _edge(db: Session, *, src_id: str, tgt_id: str, edge_type: str = "OWNS"):
    return upsert_edge(
        db,
        tenant_id=_TENANT,
        edge_type=edge_type,
        source_node_id=src_id,
        target_node_id=tgt_id,
        confidence=100,
        properties={},
        source_ref="ref",
        snapshot_id=_SNAP,
        derived_at=_AT,
    )


class TestDetectOrphanEdges:
    def test_finds_dangling_edge(self, db: Session) -> None:
        src = _node(db, entity_id="orphan-src")
        # Insert a dangling edge directly without a real target node
        dangling = GovernanceGraphEdge(
            edge_id="dangling-edge-001",
            tenant_id=_TENANT,
            edge_type="OWNS",
            source_node_id=src.node_id,
            target_node_id="ghost-node-does-not-exist",
            weight=1,
            confidence=100,
            properties={},
            source_ref="ref",
            snapshot_id=_SNAP,
            derived_at=_AT,
            schema_version="1.0",
        )
        db.add(dangling)
        db.flush()
        orphans = detect_orphan_edges(db, tenant_id=_TENANT)
        assert "dangling-edge-001" in orphans

    def test_returns_empty_for_clean_graph(self, db: Session) -> None:
        n1 = _node(db, entity_id="clean-n1")
        n2 = _node(db, entity_id="clean-n2", node_type="identity")
        _edge(db, src_id=n2.node_id, tgt_id=n1.node_id)
        orphans = detect_orphan_edges(db, tenant_id=_TENANT)
        assert orphans == []


class TestValidateGraphInvariants:
    def test_catches_self_loops(self, db: Session) -> None:
        n = _node(db, entity_id="loop-node")
        self_loop = GovernanceGraphEdge(
            edge_id="self-loop-edge-001",
            tenant_id=_TENANT,
            edge_type="RELATED_TO",
            source_node_id=n.node_id,
            target_node_id=n.node_id,
            weight=1,
            confidence=100,
            properties={},
            source_ref="ref",
            snapshot_id=_SNAP,
            derived_at=_AT,
            schema_version="1.0",
        )
        db.add(self_loop)
        db.flush()
        violations = validate_graph_invariants(db, tenant_id=_TENANT)
        self_loop_violations = [v for v in violations if "self_loop" in v]
        assert len(self_loop_violations) >= 1

    def test_returns_empty_for_valid_graph(self, db: Session) -> None:
        n1 = _node(db, entity_id="valid-n1")
        n2 = _node(db, entity_id="valid-n2", node_type="identity")
        _edge(db, src_id=n2.node_id, tgt_id=n1.node_id)
        violations = validate_graph_invariants(db, tenant_id=_TENANT)
        assert violations == []

    def test_catches_invalid_node_type(self, db: Session) -> None:
        from api.db_models_governance_graph import GovernanceGraphNode
        # Insert node with invalid type directly
        bad_node = GovernanceGraphNode(
            node_id="bad-node-type-001",
            tenant_id=_TENANT,
            node_type="totally_invalid_type",
            entity_id="bad-entity",
            entity_type="unknown",
            label="Bad Node",
            properties={},
            tags=[],
            trust_score=100,
            degree_centrality=0,
            centrality_rank=None,
            confidence=100,
            source_ref="unknown:bad-entity",
            snapshot_id=_SNAP,
            derived_at=_AT,
            schema_version="1.0",
        )
        db.add(bad_node)
        db.flush()
        violations = validate_graph_invariants(db, tenant_id=_TENANT)
        type_violations = [v for v in violations if "invalid_node_type" in v]
        assert len(type_violations) >= 1

    def test_empty_tenant_returns_no_violations(self, db: Session) -> None:
        violations = validate_graph_invariants(db, tenant_id="empty-tenant-integrity")
        assert violations == []
