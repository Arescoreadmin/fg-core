"""Tests for drift root-cause graph correlation."""

from __future__ import annotations

import os

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_ACKNOWLEDGMENT_KEY", "test-key-32-bytes-exactly-padded!!")

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from api.db_models import Base
import api.db_models_field_assessment  # noqa: F401
import api.db_models_governance_graph  # noqa: F401

from api.db_models_governance_graph import GovernanceGraphEdge, GovernanceGraphNode
from services.canonical import utc_iso8601_z_now
from services.connectors.drift.correlation import find_root_cause_candidates

_TENANT = "tenant-corr-test"
_FINDING = "finding-001"
_BASELINE = "2026-01-01T00:00:00Z"
_CURRENT = "2026-02-01T00:00:00Z"
_OUTSIDE = "2025-01-01T00:00:00Z"


@pytest.fixture()
def engine():
    import api.signed_artifacts  # noqa: F401

    os.environ.setdefault("FG_DEVICE_KEY_KEK_CURRENT_VERSION", "v1")
    os.environ.setdefault(
        "FG_DEVICE_KEY_KEK_V1", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
    )
    eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(eng)
    yield eng
    eng.dispose()


@pytest.fixture()
def db(engine):
    with Session(engine) as session:
        yield session


def _make_node(db: Session, node_id: str, entity_id: str) -> GovernanceGraphNode:
    now = utc_iso8601_z_now()
    row = GovernanceGraphNode(
        node_id=node_id,
        tenant_id=_TENANT,
        node_type="finding",
        entity_id=entity_id,
        entity_type="FaNormalizedFinding",
        label=f"Node {entity_id}",
        properties={},
        tags=[],
        trust_score=100,
        degree_centrality=0,
        confidence=100,
        source_ref=f"finding:{entity_id}",
        derived_at=now,
        schema_version="1.0",
    )
    db.add(row)
    db.flush()
    return row


def _make_edge(
    db: Session,
    edge_id: str,
    source_node_id: str,
    target_node_id: str,
    derived_at: str,
    source_ref: str = "test",
) -> GovernanceGraphEdge:
    row = GovernanceGraphEdge(
        edge_id=edge_id,
        tenant_id=_TENANT,
        edge_type="FINDING_LINKED_TO",
        source_node_id=source_node_id,
        target_node_id=target_node_id,
        weight=1,
        confidence=100,
        properties={},
        source_ref=source_ref,
        derived_at=derived_at,
        schema_version="1.0",
    )
    db.add(row)
    db.flush()
    return row


class TestFindRootCauseCandidates:
    def test_returns_empty_when_no_graph_nodes(self, db: Session) -> None:
        result = find_root_cause_candidates(
            db,
            tenant_id=_TENANT,
            finding_id=_FINDING,
            baseline_collected_at=_BASELINE,
            current_collected_at=_CURRENT,
        )
        assert result == []

    def test_returns_empty_when_no_edges_in_window(self, db: Session) -> None:
        node = _make_node(db, "n-001", _FINDING)
        other = _make_node(db, "n-002", "other-asset")
        _make_edge(db, "e-001", node.node_id, other.node_id, derived_at=_OUTSIDE)
        result = find_root_cause_candidates(
            db,
            tenant_id=_TENANT,
            finding_id=_FINDING,
            baseline_collected_at=_BASELINE,
            current_collected_at=_CURRENT,
        )
        assert result == []

    def test_finds_edge_in_drift_window(self, db: Session) -> None:
        node = _make_node(db, "n-003", _FINDING)
        other = _make_node(db, "n-004", "asset-x")
        _make_edge(
            db, "e-002", node.node_id, other.node_id, derived_at="2026-01-15T00:00:00Z"
        )
        result = find_root_cause_candidates(
            db,
            tenant_id=_TENANT,
            finding_id=_FINDING,
            baseline_collected_at=_BASELINE,
            current_collected_at=_CURRENT,
        )
        assert len(result) == 1
        assert result[0].edge_id == "e-002"

    def test_source_and_target_both_match(self, db: Session) -> None:
        node = _make_node(db, "n-005", _FINDING)
        a = _make_node(db, "n-006", "asset-a")
        b = _make_node(db, "n-007", "asset-b")
        mid = "2026-01-20T00:00:00Z"
        _make_edge(db, "e-003", node.node_id, a.node_id, derived_at=mid)
        _make_edge(db, "e-004", b.node_id, node.node_id, derived_at=mid)
        result = find_root_cause_candidates(
            db,
            tenant_id=_TENANT,
            finding_id=_FINDING,
            baseline_collected_at=_BASELINE,
            current_collected_at=_CURRENT,
        )
        edge_ids = {r.edge_id for r in result}
        assert "e-003" in edge_ids
        assert "e-004" in edge_ids

    def test_rationale_included(self, db: Session) -> None:
        node = _make_node(db, "n-008", _FINDING)
        other = _make_node(db, "n-009", "asset-y")
        _make_edge(
            db, "e-005", node.node_id, other.node_id, derived_at="2026-01-10T00:00:00Z"
        )
        result = find_root_cause_candidates(
            db,
            tenant_id=_TENANT,
            finding_id=_FINDING,
            baseline_collected_at=_BASELINE,
            current_collected_at=_CURRENT,
        )
        assert result[0].rationale != ""

    def test_broad_source_ref_match(self, db: Session) -> None:
        a = _make_node(db, "n-010", "asset-z")
        b = _make_node(db, "n-011", "asset-w")
        _make_edge(
            db,
            "e-006",
            a.node_id,
            b.node_id,
            derived_at="2026-01-25T00:00:00Z",
            source_ref=f"finding:{_FINDING}:extra",
        )
        result = find_root_cause_candidates(
            db,
            tenant_id=_TENANT,
            finding_id=_FINDING,
            baseline_collected_at=_BASELINE,
            current_collected_at=_CURRENT,
        )
        assert any(r.edge_id == "e-006" for r in result)
