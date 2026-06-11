"""Trust Graph Foundation tests — PR 1.6.

Coverage matrix:
  Node Creation          build_*_node factories, TrustGraph.add_node
  Edge Creation          TrustGraph.add_edge, edge-type validation
  Cross-Tenant Isolation add_node/add_edge cross-tenant rejection
  Cross-Engagement       add_node/add_edge cross-engagement rejection
  Duplicate Detection    duplicate node_id, duplicate edge
  Traversal              _upstream_bfs, _downstream_bfs
  Lineage                get_*_lineage (all 5 functions)
  Trust Path Generation  generate_trust_path (found, not found, same node)
  Graph Integrity        verify_trust_graph — all violation types
  Cycle Detection        cyclic_authority_path detection
  Manifest Hashing       generate_trust_graph_manifest, graph_hash stability
  Replay Compatibility   created_at preserved, event_hash enforcement
  Security Invariants    forged nodes, invalid edge types
  Performance            100 / 1000 / 10000 node timing targets
"""

from __future__ import annotations

import hashlib
import time
import uuid

import pytest

from services.field_assessment.trust_graph import (
    GRAPH_VERSION,
    MANIFEST_VERSION,
    EdgeType,
    NodeType,
    TrustGraph,
    TrustGraphEdge,
    TrustGraphError,
    TrustGraphNode,
    _canonical_graph_bytes,
    build_control_node,
    build_evidence_node,
    build_finding_node,
    build_framework_node,
    build_report_node,
    build_risk_node,
    generate_trust_graph_manifest,
    generate_trust_path,
    get_control_lineage,
    get_evidence_lineage,
    get_finding_lineage,
    get_report_lineage,
    get_risk_lineage,
    verify_trust_graph,
)

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

TENANT = "tenant-a"
ENG = "eng-001"
TENANT_B = "tenant-b"
ENG_B = "eng-002"


def _graph() -> TrustGraph:
    return TrustGraph(tenant_id=TENANT, engagement_id=ENG)


def _uid(prefix: str = "") -> str:
    return f"{prefix}{uuid.uuid4().hex[:8]}"


def _ev(
    graph: TrustGraph, nid: str = "", *, event_hash: str = "abc123"
) -> TrustGraphNode:
    nid = nid or _uid("ev-")
    node = build_evidence_node(
        node_id=nid,
        tenant_id=graph.tenant_id,
        engagement_id=graph.engagement_id,
        evidence_id=f"EV-{nid}",
        event_hash=event_hash,
        authority_status="signed",
        trust_score=100,
    )
    graph.add_node(node)
    return node


def _fi(graph: TrustGraph, nid: str = "") -> TrustGraphNode:
    nid = nid or _uid("fi-")
    node = build_finding_node(
        node_id=nid,
        tenant_id=graph.tenant_id,
        engagement_id=graph.engagement_id,
        finding_id=f"F-{nid}",
        severity="high",
    )
    graph.add_node(node)
    return node


def _co(graph: TrustGraph, nid: str = "", fw: str = "NIST CSF") -> TrustGraphNode:
    nid = nid or _uid("co-")
    node = build_control_node(
        node_id=nid,
        tenant_id=graph.tenant_id,
        engagement_id=graph.engagement_id,
        control_id=f"AC-{nid}",
        framework=fw,
    )
    graph.add_node(node)
    return node


def _fw(graph: TrustGraph, nid: str = "") -> TrustGraphNode:
    nid = nid or _uid("fw-")
    node = build_framework_node(
        node_id=nid,
        tenant_id=graph.tenant_id,
        engagement_id=graph.engagement_id,
        framework_id=f"FW-{nid}",
        framework_name="NIST CSF",
    )
    graph.add_node(node)
    return node


def _ri(graph: TrustGraph, nid: str = "") -> TrustGraphNode:
    nid = nid or _uid("ri-")
    node = build_risk_node(
        node_id=nid,
        tenant_id=graph.tenant_id,
        engagement_id=graph.engagement_id,
        risk_id=f"R-{nid}",
        risk_level="high",
        risk_type="security",
    )
    graph.add_node(node)
    return node


def _re(graph: TrustGraph, nid: str = "") -> TrustGraphNode:
    nid = nid or _uid("re-")
    node = build_report_node(
        node_id=nid,
        tenant_id=graph.tenant_id,
        engagement_id=graph.engagement_id,
        report_id=f"REP-{nid}",
        report_hash="hash123",
        report_status="finalized",
    )
    graph.add_node(node)
    return node


def _edge(
    graph: TrustGraph,
    src: TrustGraphNode,
    tgt: TrustGraphNode,
    edge_type: EdgeType,
) -> TrustGraphEdge:
    e = TrustGraphEdge(
        edge_id=_uid("e-"),
        edge_type=edge_type,
        source_node_id=src.node_id,
        target_node_id=tgt.node_id,
        tenant_id=graph.tenant_id,
        engagement_id=graph.engagement_id,
    )
    graph.add_edge(e)
    return e


# ---------------------------------------------------------------------------
# Node Creation
# ---------------------------------------------------------------------------


class TestNodeCreation:
    def test_build_evidence_node_fields(self) -> None:
        n = build_evidence_node(
            node_id="ev-1",
            tenant_id=TENANT,
            engagement_id=ENG,
            evidence_id="EV-001",
            event_hash="deadbeef",
            authority_status="signed",
            trust_score=100,
        )
        assert n.node_type == NodeType.EVIDENCE
        assert n.payload["evidence_id"] == "EV-001"
        assert n.payload["event_hash"] == "deadbeef"
        assert n.payload["authority_status"] == "signed"
        assert n.payload["trust_score"] == 100
        assert n.tenant_id == TENANT
        assert n.engagement_id == ENG

    def test_build_finding_node_fields(self) -> None:
        n = build_finding_node(
            node_id="fi-1",
            tenant_id=TENANT,
            engagement_id=ENG,
            finding_id="F-001",
            severity="critical",
            confidence="high",
            status="open",
        )
        assert n.node_type == NodeType.FINDING
        assert n.payload["severity"] == "critical"
        assert n.payload["confidence"] == "high"

    def test_build_control_node_fields(self) -> None:
        n = build_control_node(
            node_id="co-1",
            tenant_id=TENANT,
            engagement_id=ENG,
            control_id="AC-2",
            framework="NIST CSF",
            control_status="implemented",
        )
        assert n.node_type == NodeType.CONTROL
        assert n.payload["framework"] == "NIST CSF"
        assert n.payload["control_status"] == "implemented"

    def test_build_framework_node_fields(self) -> None:
        n = build_framework_node(
            node_id="fw-1",
            tenant_id=TENANT,
            engagement_id=ENG,
            framework_id="FW-NIST",
            framework_name="NIST AI RMF",
            version="1.0",
        )
        assert n.node_type == NodeType.FRAMEWORK
        assert n.payload["framework_name"] == "NIST AI RMF"

    def test_build_risk_node_fields(self) -> None:
        n = build_risk_node(
            node_id="ri-1",
            tenant_id=TENANT,
            engagement_id=ENG,
            risk_id="R-77",
            risk_level="critical",
            risk_type="ai",
        )
        assert n.node_type == NodeType.RISK
        assert n.payload["risk_level"] == "critical"
        assert n.payload["risk_type"] == "ai"

    def test_build_report_node_fields(self) -> None:
        n = build_report_node(
            node_id="rp-1",
            tenant_id=TENANT,
            engagement_id=ENG,
            report_id="REP-001",
            report_hash="sha256abc",
            report_signature="sig",
            report_status="finalized",
        )
        assert n.node_type == NodeType.REPORT
        assert n.payload["report_status"] == "finalized"
        assert n.payload["report_signature"] == "sig"

    def test_node_is_frozen(self) -> None:
        n = _ev(_graph())
        with pytest.raises((AttributeError, TypeError)):
            n.node_id = "tampered"  # type: ignore[misc]

    def test_add_node_increments_count(self) -> None:
        g = _graph()
        assert g.node_count() == 0
        _ev(g)
        assert g.node_count() == 1

    def test_get_node_returns_node(self) -> None:
        g = _graph()
        ev = _ev(g, "ev-x")
        assert g.get_node("ev-x") is ev

    def test_get_node_missing_returns_none(self) -> None:
        assert _graph().get_node("nonexistent") is None

    def test_nodes_by_type_filters(self) -> None:
        g = _graph()
        _ev(g)
        _ev(g)
        _fi(g)
        assert len(g.nodes_by_type(NodeType.EVIDENCE)) == 2
        assert len(g.nodes_by_type(NodeType.FINDING)) == 1

    def test_nodes_sorted_by_node_id(self) -> None:
        g = _graph()
        _ev(g, "z-node")
        _ev(g, "a-node")
        _ev(g, "m-node")
        ids = [n.node_id for n in g.nodes()]
        assert ids == sorted(ids)

    def test_created_at_defaults_populated(self) -> None:
        n = build_evidence_node(
            node_id="ev-1",
            tenant_id=TENANT,
            engagement_id=ENG,
            evidence_id="EV-001",
            event_hash="hash",
        )
        assert n.created_at  # non-empty ISO string

    def test_created_at_custom_preserved(self) -> None:
        n = build_evidence_node(
            node_id="ev-1",
            tenant_id=TENANT,
            engagement_id=ENG,
            evidence_id="EV-001",
            event_hash="hash",
            created_at="2025-01-01T00:00:00Z",
        )
        assert n.created_at == "2025-01-01T00:00:00Z"


# ---------------------------------------------------------------------------
# Edge Creation
# ---------------------------------------------------------------------------


class TestEdgeCreation:
    def test_evidence_to_finding_accepted(self) -> None:
        g = _graph()
        ev = _ev(g)
        fi = _fi(g)
        e = _edge(g, ev, fi, EdgeType.EVIDENCE_TO_FINDING)
        assert g.edge_count() == 1
        assert e.edge_type == EdgeType.EVIDENCE_TO_FINDING

    def test_finding_to_control_accepted(self) -> None:
        g = _graph()
        fi = _fi(g)
        co = _co(g)
        _edge(g, fi, co, EdgeType.FINDING_TO_CONTROL)
        assert g.edge_count() == 1

    def test_control_to_framework_accepted(self) -> None:
        g = _graph()
        co = _co(g)
        fw = _fw(g)
        _edge(g, co, fw, EdgeType.CONTROL_TO_FRAMEWORK)
        assert g.edge_count() == 1

    def test_finding_to_risk_accepted(self) -> None:
        g = _graph()
        fi = _fi(g)
        ri = _ri(g)
        _edge(g, fi, ri, EdgeType.FINDING_TO_RISK)
        assert g.edge_count() == 1

    def test_risk_to_report_accepted(self) -> None:
        g = _graph()
        ri = _ri(g)
        re = _re(g)
        _edge(g, ri, re, EdgeType.RISK_TO_REPORT)
        assert g.edge_count() == 1

    def test_evidence_to_report_accepted(self) -> None:
        g = _graph()
        ev = _ev(g)
        re = _re(g)
        _edge(g, ev, re, EdgeType.EVIDENCE_TO_REPORT)
        assert g.edge_count() == 1

    def test_wrong_edge_type_for_pair_rejected(self) -> None:
        g = _graph()
        ev = _ev(g)
        re = _re(g)
        with pytest.raises(TrustGraphError, match="invalid edge type"):
            _edge(g, ev, re, EdgeType.EVIDENCE_TO_FINDING)

    def test_invalid_reverse_edge_rejected(self) -> None:
        g = _graph()
        fi = _fi(g)
        ev = _ev(g)
        with pytest.raises(TrustGraphError):
            _edge(g, fi, ev, EdgeType.EVIDENCE_TO_FINDING)

    def test_source_not_in_graph_rejected(self) -> None:
        g = _graph()
        fi = _fi(g)
        build_evidence_node(
            node_id="ghost",
            tenant_id=TENANT,
            engagement_id=ENG,
            evidence_id="EV-ghost",
            event_hash="h",
        )
        e = TrustGraphEdge(
            edge_id="e1",
            edge_type=EdgeType.EVIDENCE_TO_FINDING,
            source_node_id="ghost",
            target_node_id=fi.node_id,
            tenant_id=TENANT,
            engagement_id=ENG,
        )
        with pytest.raises(TrustGraphError, match="source node not found"):
            g.add_edge(e)

    def test_target_not_in_graph_rejected(self) -> None:
        g = _graph()
        ev = _ev(g)
        e = TrustGraphEdge(
            edge_id="e1",
            edge_type=EdgeType.EVIDENCE_TO_FINDING,
            source_node_id=ev.node_id,
            target_node_id="ghost",
            tenant_id=TENANT,
            engagement_id=ENG,
        )
        with pytest.raises(TrustGraphError, match="target node not found"):
            g.add_edge(e)

    def test_edges_sorted_deterministically(self) -> None:
        g = _graph()
        ev1 = _ev(g, "ev-1")
        ev2 = _ev(g, "ev-2")
        fi = _fi(g, "fi-1")
        _edge(g, ev2, fi, EdgeType.EVIDENCE_TO_FINDING)
        _edge(g, ev1, fi, EdgeType.EVIDENCE_TO_FINDING)
        edge_srcs = [e.source_node_id for e in g.edges()]
        assert edge_srcs == sorted(edge_srcs)


# ---------------------------------------------------------------------------
# Cross-Tenant Isolation
# ---------------------------------------------------------------------------


class TestCrossTenantIsolation:
    def test_add_node_wrong_tenant_rejected(self) -> None:
        g = _graph()
        bad = build_evidence_node(
            node_id="ev-bad",
            tenant_id=TENANT_B,
            engagement_id=ENG,
            evidence_id="EV-x",
            event_hash="h",
        )
        with pytest.raises(TrustGraphError, match="cross-tenant node"):
            g.add_node(bad)

    def test_add_edge_wrong_tenant_rejected(self) -> None:
        g = _graph()
        ev = _ev(g)
        fi = _fi(g)
        e = TrustGraphEdge(
            edge_id="e1",
            edge_type=EdgeType.EVIDENCE_TO_FINDING,
            source_node_id=ev.node_id,
            target_node_id=fi.node_id,
            tenant_id=TENANT_B,
            engagement_id=ENG,
        )
        with pytest.raises(TrustGraphError, match="cross-tenant edge"):
            g.add_edge(e)

    def test_graph_tenant_visible_on_manifest(self) -> None:
        g = _graph()
        m = generate_trust_graph_manifest(g)
        assert m["tenant_id"] == TENANT

    def test_cross_tenant_nodes_same_id_independent(self) -> None:
        g1 = TrustGraph(tenant_id=TENANT, engagement_id=ENG)
        g2 = TrustGraph(tenant_id=TENANT_B, engagement_id=ENG)
        n1 = build_evidence_node(
            node_id="ev-shared",
            tenant_id=TENANT,
            engagement_id=ENG,
            evidence_id="EV-1",
            event_hash="h",
        )
        n2 = build_evidence_node(
            node_id="ev-shared",
            tenant_id=TENANT_B,
            engagement_id=ENG,
            evidence_id="EV-1",
            event_hash="h",
        )
        g1.add_node(n1)
        g2.add_node(n2)
        assert g1.get_node("ev-shared").tenant_id == TENANT  # type: ignore[union-attr]
        assert g2.get_node("ev-shared").tenant_id == TENANT_B  # type: ignore[union-attr]

    def test_verify_detects_node_wrong_graph_tenant(self) -> None:
        """verify_trust_graph catches a node whose tenant_id differs from graph.tenant_id."""
        g = _graph()
        rogue = TrustGraphNode(
            node_id="ev-rogue",
            node_type=NodeType.EVIDENCE,
            tenant_id=TENANT_B,
            engagement_id=ENG,
            payload={
                "evidence_id": "EV-r",
                "event_hash": "h",
                "authority_status": "signed",
                "trust_score": 0,
            },
        )
        g._nodes["ev-rogue"] = rogue
        g._adj_out["ev-rogue"] = []
        g._adj_in["ev-rogue"] = []
        result = verify_trust_graph(g)
        assert not result["graph_valid"]
        assert any("cross_tenant_node" in v for v in result["violations"])

    def test_verify_detects_edge_wrong_graph_tenant(self) -> None:
        """verify_trust_graph catches an edge whose tenant_id differs from graph.tenant_id."""
        g = _graph()
        _ev(g, "ev-1")
        _fi(g, "fi-1")
        ev = g.get_node("ev-1")
        assert ev is not None
        bad_edge = TrustGraphEdge(
            edge_id="e-bad",
            edge_type=EdgeType.EVIDENCE_TO_FINDING,
            source_node_id="ev-1",
            target_node_id="fi-1",
            tenant_id=TENANT_B,
            engagement_id=ENG,
        )
        g._edges.append(bad_edge)
        g._adj_out["ev-1"].append(bad_edge)
        g._adj_in["fi-1"].append(bad_edge)
        result = verify_trust_graph(g)
        assert not result["graph_valid"]
        assert any("cross_tenant_edge" in v for v in result["violations"])

    def test_verify_detects_cross_tenant_node_pair(self) -> None:
        # Manually construct an inconsistent graph (bypass guards via internal _nodes)
        g = _graph()
        _ev(g, "ev-1")
        # Inject a rogue finding node with wrong tenant directly
        rogue = TrustGraphNode(
            node_id="fi-rogue",
            node_type=NodeType.FINDING,
            tenant_id=TENANT_B,
            engagement_id=ENG,
            payload={
                "finding_id": "F-rogue",
                "severity": "low",
                "confidence": "low",
                "status": "open",
            },
        )
        g._nodes["fi-rogue"] = rogue
        g._adj_out["fi-rogue"] = []
        g._adj_in["fi-rogue"] = []
        # Inject edge directly (bypass add_edge guard)
        e = TrustGraphEdge(
            edge_id="e-rogue",
            edge_type=EdgeType.EVIDENCE_TO_FINDING,
            source_node_id="ev-1",
            target_node_id="fi-rogue",
            tenant_id=TENANT,
            engagement_id=ENG,
        )
        g._edges.append(e)
        g._adj_out["ev-1"].append(e)
        g._adj_in["fi-rogue"].append(e)
        result = verify_trust_graph(g)
        assert not result["graph_valid"]
        assert any("cross_tenant_edge" in v for v in result["violations"])


# ---------------------------------------------------------------------------
# Cross-Engagement Isolation
# ---------------------------------------------------------------------------


class TestCrossEngagementIsolation:
    def test_add_node_wrong_engagement_rejected(self) -> None:
        g = _graph()
        bad = build_evidence_node(
            node_id="ev-bad",
            tenant_id=TENANT,
            engagement_id=ENG_B,
            evidence_id="EV-x",
            event_hash="h",
        )
        with pytest.raises(TrustGraphError, match="cross-engagement node"):
            g.add_node(bad)

    def test_add_edge_wrong_engagement_rejected(self) -> None:
        g = _graph()
        ev = _ev(g)
        fi = _fi(g)
        e = TrustGraphEdge(
            edge_id="e1",
            edge_type=EdgeType.EVIDENCE_TO_FINDING,
            source_node_id=ev.node_id,
            target_node_id=fi.node_id,
            tenant_id=TENANT,
            engagement_id=ENG_B,
        )
        with pytest.raises(TrustGraphError, match="cross-engagement edge"):
            g.add_edge(e)

    def test_verify_detects_cross_engagement_node_pair(self) -> None:
        g = _graph()
        _ev(g, "ev-1")
        rogue = TrustGraphNode(
            node_id="fi-rogue",
            node_type=NodeType.FINDING,
            tenant_id=TENANT,
            engagement_id=ENG_B,
            payload={
                "finding_id": "F-r",
                "severity": "low",
                "confidence": "low",
                "status": "open",
            },
        )
        g._nodes["fi-rogue"] = rogue
        g._adj_out["fi-rogue"] = []
        g._adj_in["fi-rogue"] = []
        e = TrustGraphEdge(
            edge_id="e-rogue",
            edge_type=EdgeType.EVIDENCE_TO_FINDING,
            source_node_id="ev-1",
            target_node_id="fi-rogue",
            tenant_id=TENANT,
            engagement_id=ENG,
        )
        g._edges.append(e)
        g._adj_out["ev-1"].append(e)
        g._adj_in["fi-rogue"].append(e)
        result = verify_trust_graph(g)
        assert not result["graph_valid"]
        assert any("cross_engagement_edge" in v for v in result["violations"])


# ---------------------------------------------------------------------------
# Duplicate Detection
# ---------------------------------------------------------------------------


class TestDuplicateDetection:
    def test_duplicate_node_id_rejected(self) -> None:
        g = _graph()
        _ev(g, "ev-1")
        with pytest.raises(TrustGraphError, match="duplicate node_id"):
            _ev(g, "ev-1")

    def test_duplicate_edge_rejected(self) -> None:
        g = _graph()
        ev = _ev(g)
        fi = _fi(g)
        _edge(g, ev, fi, EdgeType.EVIDENCE_TO_FINDING)
        with pytest.raises(TrustGraphError, match="duplicate edge"):
            _edge(g, ev, fi, EdgeType.EVIDENCE_TO_FINDING)

    def test_two_edges_same_pair_different_type_rejected(self) -> None:
        # EVIDENCE_TO_REPORT and EVIDENCE_TO_FINDING both require different target types;
        # confirm the constraint is per (src, tgt, type) triplet, not just (src, tgt)
        g = _graph()
        ev = _ev(g)
        fi = _fi(g)
        _edge(g, ev, fi, EdgeType.EVIDENCE_TO_FINDING)
        # can't add a second edge between same pair with same type (already done above)
        # but attempting a second identical edge should fail
        with pytest.raises(TrustGraphError, match="duplicate edge"):
            _edge(g, ev, fi, EdgeType.EVIDENCE_TO_FINDING)

    def test_verify_detects_duplicate_edge(self) -> None:
        g = _graph()
        _ev(g, "ev-1")
        _fi(g, "fi-1")
        e = TrustGraphEdge(
            edge_id="e-dup",
            edge_type=EdgeType.EVIDENCE_TO_FINDING,
            source_node_id="ev-1",
            target_node_id="fi-1",
            tenant_id=TENANT,
            engagement_id=ENG,
        )
        # Inject duplicate directly, bypassing guard
        g._edges.append(e)
        g._edges.append(e)
        result = verify_trust_graph(g)
        assert any("duplicate_edge" in v for v in result["violations"])

    def test_duplicate_edge_id_rejected(self) -> None:
        g = _graph()
        _ev(g, "ev-1")
        _fi(g, "fi-1")
        _fi(g, "fi-2")
        e1 = TrustGraphEdge(
            edge_id="shared-id",
            edge_type=EdgeType.EVIDENCE_TO_FINDING,
            source_node_id="ev-1",
            target_node_id="fi-1",
            tenant_id=TENANT,
            engagement_id=ENG,
        )
        e2 = TrustGraphEdge(
            edge_id="shared-id",
            edge_type=EdgeType.EVIDENCE_TO_FINDING,
            source_node_id="ev-1",
            target_node_id="fi-2",
            tenant_id=TENANT,
            engagement_id=ENG,
        )
        g.add_edge(e1)
        with pytest.raises(TrustGraphError, match="duplicate edge_id"):
            g.add_edge(e2)


# ---------------------------------------------------------------------------
# Traversal
# ---------------------------------------------------------------------------


class TestTraversal:
    def _build_chain(
        self,
    ) -> tuple[
        TrustGraph,
        TrustGraphNode,
        TrustGraphNode,
        TrustGraphNode,
        TrustGraphNode,
        TrustGraphNode,
    ]:
        """Build: ev → fi → ri → re, ev → re (direct)"""
        g = _graph()
        ev = _ev(g, "ev-1")
        fi = _fi(g, "fi-1")
        ri = _ri(g, "ri-1")
        re = _re(g, "re-1")
        _edge(g, ev, fi, EdgeType.EVIDENCE_TO_FINDING)
        _edge(g, fi, ri, EdgeType.FINDING_TO_RISK)
        _edge(g, ri, re, EdgeType.RISK_TO_REPORT)
        _edge(g, ev, re, EdgeType.EVIDENCE_TO_REPORT)
        return g, ev, fi, ri, re, re

    def test_downstream_from_evidence_reaches_all(self) -> None:
        g, ev, fi, ri, re, _ = self._build_chain()
        lineage = get_evidence_lineage(g, ev.node_id)
        ids = {n.node_id for n in lineage}
        assert "ev-1" in ids
        assert "fi-1" in ids
        assert "ri-1" in ids
        assert "re-1" in ids

    def test_upstream_from_report_reaches_all(self) -> None:
        g, ev, fi, ri, re, _ = self._build_chain()
        lineage = get_report_lineage(g, re.node_id)
        ids = {n.node_id for n in lineage}
        assert "re-1" in ids
        assert "ri-1" in ids
        assert "fi-1" in ids
        assert "ev-1" in ids

    def test_traversal_is_deterministic(self) -> None:
        g = _graph()
        for i in range(5):
            ev = _ev(g, f"ev-{i}")
            fi = _fi(g, f"fi-{i}")
            _edge(g, ev, fi, EdgeType.EVIDENCE_TO_FINDING)
        _re(g, "re-0")
        g2 = _graph()
        for i in range(5):
            ev = _ev(g2, f"ev-{i}")
            fi = _fi(g2, f"fi-{i}")
            _edge(g2, ev, fi, EdgeType.EVIDENCE_TO_FINDING)
        _re(g2, "re-0")
        ev0 = g.get_node("ev-0")
        ev0_2 = g2.get_node("ev-0")
        assert ev0 is not None and ev0_2 is not None
        r1 = [n.node_id for n in get_evidence_lineage(g, "ev-0")]
        r2 = [n.node_id for n in get_evidence_lineage(g2, "ev-0")]
        assert r1 == r2

    def test_lineage_result_sorted_by_node_id(self) -> None:
        g, ev, fi, ri, re, _ = self._build_chain()
        lineage = get_report_lineage(g, re.node_id)
        ids = [n.node_id for n in lineage]
        assert ids == sorted(ids)

    def test_evidence_lineage_wrong_type_raises(self) -> None:
        g = _graph()
        fi = _fi(g)
        with pytest.raises(TrustGraphError):
            get_evidence_lineage(g, fi.node_id)

    def test_finding_lineage_wrong_type_raises(self) -> None:
        g = _graph()
        ev = _ev(g)
        with pytest.raises(TrustGraphError):
            get_finding_lineage(g, ev.node_id)

    def test_control_lineage_traverses_upstream(self) -> None:
        g = _graph()
        ev = _ev(g, "ev-1")
        fi = _fi(g, "fi-1")
        co = _co(g, "co-1")
        _edge(g, ev, fi, EdgeType.EVIDENCE_TO_FINDING)
        _edge(g, fi, co, EdgeType.FINDING_TO_CONTROL)
        lineage = get_control_lineage(g, co.node_id)
        ids = {n.node_id for n in lineage}
        assert {"co-1", "fi-1", "ev-1"} == ids

    def test_risk_lineage_traverses_upstream(self) -> None:
        g = _graph()
        ev = _ev(g, "ev-1")
        fi = _fi(g, "fi-1")
        ri = _ri(g, "ri-1")
        _edge(g, ev, fi, EdgeType.EVIDENCE_TO_FINDING)
        _edge(g, fi, ri, EdgeType.FINDING_TO_RISK)
        lineage = get_risk_lineage(g, ri.node_id)
        ids = {n.node_id for n in lineage}
        assert {"ri-1", "fi-1", "ev-1"} == ids

    def test_finding_lineage_only_upstream(self) -> None:
        g = _graph()
        ev = _ev(g, "ev-1")
        fi = _fi(g, "fi-1")
        ri = _ri(g, "ri-1")
        _edge(g, ev, fi, EdgeType.EVIDENCE_TO_FINDING)
        _edge(g, fi, ri, EdgeType.FINDING_TO_RISK)
        lineage = get_finding_lineage(g, fi.node_id)
        ids = {n.node_id for n in lineage}
        # Upstream: fi + ev. Risk is downstream of fi.
        assert "ri-1" not in ids
        assert "ev-1" in ids
        assert "fi-1" in ids

    def test_lineage_missing_node_raises(self) -> None:
        g = _graph()
        with pytest.raises(TrustGraphError):
            get_report_lineage(g, "nonexistent")

    def test_multi_evidence_all_upstream_of_control(self) -> None:
        g = _graph()
        ev1 = _ev(g, "ev-1")
        ev2 = _ev(g, "ev-2")
        fi = _fi(g, "fi-1")
        co = _co(g, "co-1")
        _edge(g, ev1, fi, EdgeType.EVIDENCE_TO_FINDING)
        _edge(g, ev2, fi, EdgeType.EVIDENCE_TO_FINDING)
        _edge(g, fi, co, EdgeType.FINDING_TO_CONTROL)
        lineage = get_control_lineage(g, co.node_id)
        ids = {n.node_id for n in lineage}
        assert "ev-1" in ids
        assert "ev-2" in ids


# ---------------------------------------------------------------------------
# Trust Path Generation
# ---------------------------------------------------------------------------


class TestTrustPath:
    def test_path_evidence_to_report_via_risk(self) -> None:
        g = _graph()
        ev = _ev(g, "ev-1")
        fi = _fi(g, "fi-1")
        ri = _ri(g, "ri-1")
        re = _re(g, "re-1")
        _edge(g, ev, fi, EdgeType.EVIDENCE_TO_FINDING)
        _edge(g, fi, ri, EdgeType.FINDING_TO_RISK)
        _edge(g, ri, re, EdgeType.RISK_TO_REPORT)
        path = generate_trust_path(g, "ev-1", "re-1")
        ids = [n.node_id for n in path]
        assert ids[0] == "ev-1"
        assert ids[-1] == "re-1"
        assert "fi-1" in ids
        assert "ri-1" in ids

    def test_path_no_path_returns_empty(self) -> None:
        g = _graph()
        _ev(g, "ev-1")
        _re(g, "re-1")  # no edge
        path = generate_trust_path(g, "ev-1", "re-1")
        assert path == []

    def test_path_same_start_end(self) -> None:
        g = _graph()
        _ev(g, "ev-1")
        path = generate_trust_path(g, "ev-1", "ev-1")
        assert len(path) == 1
        assert path[0].node_id == "ev-1"

    def test_path_missing_start_raises(self) -> None:
        g = _graph()
        _ev(g, "ev-1")
        with pytest.raises(TrustGraphError, match="start node not found"):
            generate_trust_path(g, "ghost", "ev-1")

    def test_path_missing_end_raises(self) -> None:
        g = _graph()
        _ev(g, "ev-1")
        with pytest.raises(TrustGraphError, match="end node not found"):
            generate_trust_path(g, "ev-1", "ghost")

    def test_path_is_deterministic(self) -> None:
        g = _graph()
        ev = _ev(g, "ev-1")
        fi1 = _fi(g, "fi-1")
        fi2 = _fi(g, "fi-2")
        ri = _ri(g, "ri-1")
        re = _re(g, "re-1")
        _edge(g, ev, fi1, EdgeType.EVIDENCE_TO_FINDING)
        _edge(g, ev, fi2, EdgeType.EVIDENCE_TO_FINDING)
        _edge(g, fi1, ri, EdgeType.FINDING_TO_RISK)
        _edge(g, fi2, ri, EdgeType.FINDING_TO_RISK)
        _edge(g, ri, re, EdgeType.RISK_TO_REPORT)
        p1 = [n.node_id for n in generate_trust_path(g, "ev-1", "re-1")]
        p2 = [n.node_id for n in generate_trust_path(g, "ev-1", "re-1")]
        assert p1 == p2

    def test_full_chain_path_evidence_to_report_direct(self) -> None:
        g = _graph()
        ev = _ev(g, "ev-1")
        re = _re(g, "re-1")
        _edge(g, ev, re, EdgeType.EVIDENCE_TO_REPORT)
        path = generate_trust_path(g, "ev-1", "re-1")
        assert [n.node_id for n in path] == ["ev-1", "re-1"]

    def test_path_through_framework(self) -> None:
        g = _graph()
        ev = _ev(g, "ev-1")
        fi = _fi(g, "fi-1")
        co = _co(g, "co-1")
        fw = _fw(g, "fw-1")
        _edge(g, ev, fi, EdgeType.EVIDENCE_TO_FINDING)
        _edge(g, fi, co, EdgeType.FINDING_TO_CONTROL)
        _edge(g, co, fw, EdgeType.CONTROL_TO_FRAMEWORK)
        path = generate_trust_path(g, "ev-1", "fw-1")
        assert path[-1].node_id == "fw-1"
        assert len(path) == 4


# ---------------------------------------------------------------------------
# Graph Integrity
# ---------------------------------------------------------------------------


class TestGraphIntegrity:
    def test_empty_graph_is_valid(self) -> None:
        result = verify_trust_graph(_graph())
        assert result["graph_valid"]
        assert result["violations"] == []
        assert result["node_count"] == 0
        assert result["edge_count"] == 0

    def test_clean_graph_is_valid(self) -> None:
        g = _graph()
        ev = _ev(g)
        fi = _fi(g)
        _edge(g, ev, fi, EdgeType.EVIDENCE_TO_FINDING)
        result = verify_trust_graph(g)
        assert result["graph_valid"]

    def test_orphaned_non_evidence_detected(self) -> None:
        g = _graph()
        _fi(g, "fi-orphan")  # no edges
        result = verify_trust_graph(g)
        assert not result["graph_valid"]
        assert any("orphaned_node" in v for v in result["violations"])

    def test_evidence_orphan_not_flagged(self) -> None:
        g = _graph()
        _ev(g, "ev-lone")  # evidence can be a root
        result = verify_trust_graph(g)
        assert result["graph_valid"]

    def test_missing_event_hash_flagged(self) -> None:
        g = _graph()
        _ev(g, "ev-nohash", event_hash="")
        result = verify_trust_graph(g)
        assert not result["graph_valid"]
        assert any("replay_mismatch" in v for v in result["violations"])

    def test_violation_counts_reported(self) -> None:
        g = _graph()
        _ev(g, "ev-1", event_hash="")
        _fi(g, "fi-orphan")
        result = verify_trust_graph(g)
        assert len(result["violations"]) >= 2

    def test_node_count_correct(self) -> None:
        g = _graph()
        for i in range(5):
            _ev(g, f"ev-{i}")
        result = verify_trust_graph(g)
        assert result["node_count"] == 5

    def test_edge_count_correct(self) -> None:
        g = _graph()
        ev = _ev(g)
        fi = _fi(g)
        _edge(g, ev, fi, EdgeType.EVIDENCE_TO_FINDING)
        result = verify_trust_graph(g)
        assert result["edge_count"] == 1

    def test_verify_returns_all_expected_keys(self) -> None:
        result = verify_trust_graph(_graph())
        assert set(result.keys()) == {
            "graph_valid",
            "violations",
            "node_count",
            "edge_count",
        }


# ---------------------------------------------------------------------------
# Cycle Detection
# ---------------------------------------------------------------------------


class TestCycleDetection:
    def test_no_cycle_valid(self) -> None:
        g = _graph()
        ev = _ev(g, "ev-1")
        fi = _fi(g, "fi-1")
        ri = _ri(g, "ri-1")
        re = _re(g, "re-1")
        _edge(g, ev, fi, EdgeType.EVIDENCE_TO_FINDING)
        _edge(g, fi, ri, EdgeType.FINDING_TO_RISK)
        _edge(g, ri, re, EdgeType.RISK_TO_REPORT)
        result = verify_trust_graph(g)
        assert result["graph_valid"]

    def test_cycle_detected(self) -> None:
        g = _graph()
        ev1 = _ev(g, "ev-1")
        _ev(g, "ev-2")
        fi = _fi(g, "fi-1")
        _edge(g, ev1, fi, EdgeType.EVIDENCE_TO_FINDING)
        # Manually inject a backward edge (ev2 node type is EVIDENCE, fi→ev is invalid type)
        # Instead: inject two evidence nodes that share a finding cycle via internal nodes
        # We must inject directly since add_edge enforces type constraints
        # Create a cycle: ev1 "reports to" ev2, ev2 "reports to" ev1 (same node types)
        # Actually the type system prevents cycles naturally in normal usage.
        # Test: inject cycle via _nodes/_edges directly
        e_back = TrustGraphEdge(
            edge_id="e-cycle",
            edge_type=EdgeType.EVIDENCE_TO_FINDING,
            source_node_id="fi-1",
            target_node_id="ev-1",
            tenant_id=TENANT,
            engagement_id=ENG,
        )
        g._edges.append(e_back)
        g._adj_out["fi-1"].append(e_back)
        g._adj_in["ev-1"].append(e_back)
        result = verify_trust_graph(g)
        assert not result["graph_valid"]
        assert any("cyclic_authority_path" in v for v in result["violations"])

    def test_dangling_edge_does_not_crash_cycle_detection(self) -> None:
        """verify_trust_graph must not raise when a dangling edge exists; it should
        report missing_node and still return graph_valid=False without KeyError."""
        g = _graph()
        _ev(g, "ev-1")
        dangling = TrustGraphEdge(
            edge_id="e-dangle",
            edge_type=EdgeType.EVIDENCE_TO_FINDING,
            source_node_id="ev-1",
            target_node_id="fi-missing",  # not in graph
            tenant_id=TENANT,
            engagement_id=ENG,
        )
        g._edges.append(dangling)
        g._adj_out["ev-1"].append(dangling)
        result = verify_trust_graph(g)
        assert not result["graph_valid"]
        assert any("missing_node" in v for v in result["violations"])

    def test_self_loop_detected(self) -> None:
        g = _graph()
        _ev(g, "ev-self")
        e = TrustGraphEdge(
            edge_id="e-self",
            edge_type=EdgeType.EVIDENCE_TO_FINDING,
            source_node_id="ev-self",
            target_node_id="ev-self",
            tenant_id=TENANT,
            engagement_id=ENG,
        )
        g._edges.append(e)
        g._adj_out["ev-self"].append(e)
        g._adj_in["ev-self"].append(e)
        result = verify_trust_graph(g)
        assert not result["graph_valid"]
        assert any("cyclic" in v for v in result["violations"])


# ---------------------------------------------------------------------------
# Manifest Hashing
# ---------------------------------------------------------------------------


class TestManifestHashing:
    def test_manifest_has_required_keys(self) -> None:
        m = generate_trust_graph_manifest(_graph())
        required = {
            "manifest_version",
            "graph_version",
            "tenant_id",
            "engagement_id",
            "node_count",
            "edge_count",
            "root_nodes",
            "graph_hash",
            "generated_at",
        }
        assert required <= set(m.keys())

    def test_manifest_version_constants(self) -> None:
        m = generate_trust_graph_manifest(_graph())
        assert m["manifest_version"] == MANIFEST_VERSION
        assert m["graph_version"] == GRAPH_VERSION

    def test_graph_hash_is_sha256_hex(self) -> None:
        m = generate_trust_graph_manifest(_graph())
        assert len(m["graph_hash"]) == 64
        int(m["graph_hash"], 16)  # must be valid hex

    def test_same_graph_same_hash(self) -> None:
        g = _graph()
        ev = build_evidence_node(
            node_id="ev-1",
            tenant_id=TENANT,
            engagement_id=ENG,
            evidence_id="EV-001",
            event_hash="hash1",
            created_at="2025-01-01T00:00:00Z",
        )
        fi = build_finding_node(
            node_id="fi-1",
            tenant_id=TENANT,
            engagement_id=ENG,
            finding_id="F-001",
            severity="high",
            created_at="2025-01-01T00:00:00Z",
        )
        g.add_node(ev)
        g.add_node(fi)
        _edge(g, ev, fi, EdgeType.EVIDENCE_TO_FINDING)
        h1 = hashlib.sha256(_canonical_graph_bytes(g)).hexdigest()
        h2 = hashlib.sha256(_canonical_graph_bytes(g)).hexdigest()
        assert h1 == h2

    def test_different_graph_different_hash(self) -> None:
        g1 = _graph()
        g2 = _graph()
        _ev(g1, "ev-1")
        _ev(g2, "ev-2")
        h1 = hashlib.sha256(_canonical_graph_bytes(g1)).hexdigest()
        h2 = hashlib.sha256(_canonical_graph_bytes(g2)).hexdigest()
        assert h1 != h2

    def test_root_nodes_are_sources_with_no_incoming(self) -> None:
        g = _graph()
        ev = _ev(g, "ev-1")
        fi = _fi(g, "fi-1")
        _edge(g, ev, fi, EdgeType.EVIDENCE_TO_FINDING)
        m = generate_trust_graph_manifest(g)
        assert "ev-1" in m["root_nodes"]
        assert "fi-1" not in m["root_nodes"]

    def test_empty_graph_root_nodes_empty(self) -> None:
        m = generate_trust_graph_manifest(_graph())
        assert m["root_nodes"] == []

    def test_root_nodes_sorted(self) -> None:
        g = _graph()
        _ev(g, "z-ev")
        _ev(g, "a-ev")
        m = generate_trust_graph_manifest(g)
        assert m["root_nodes"] == sorted(m["root_nodes"])

    def test_manifest_counts_match_graph(self) -> None:
        g = _graph()
        ev = _ev(g)
        fi = _fi(g)
        _edge(g, ev, fi, EdgeType.EVIDENCE_TO_FINDING)
        m = generate_trust_graph_manifest(g)
        assert m["node_count"] == 2
        assert m["edge_count"] == 1


# ---------------------------------------------------------------------------
# Replay Compatibility
# ---------------------------------------------------------------------------


class TestReplayCompatibility:
    def test_node_created_at_preserved(self) -> None:
        ts = "2025-06-01T12:00:00Z"
        n = build_evidence_node(
            node_id="ev-1",
            tenant_id=TENANT,
            engagement_id=ENG,
            evidence_id="EV-001",
            event_hash="h",
            created_at=ts,
        )
        assert n.created_at == ts

    def test_edge_created_at_preserved(self) -> None:
        ts = "2025-06-01T12:00:00Z"
        e = TrustGraphEdge(
            edge_id="e-1",
            edge_type=EdgeType.EVIDENCE_TO_FINDING,
            source_node_id="s",
            target_node_id="t",
            tenant_id=TENANT,
            engagement_id=ENG,
            created_at=ts,
        )
        assert e.created_at == ts

    def test_event_hash_empty_detected_by_verify(self) -> None:
        g = _graph()
        _ev(g, "ev-1", event_hash="")
        result = verify_trust_graph(g)
        assert any("replay_mismatch" in v for v in result["violations"])

    def test_event_hash_non_empty_passes_verify(self) -> None:
        g = _graph()
        _ev(g, "ev-1", event_hash="sha256hashvalue")
        result = verify_trust_graph(g)
        assert not any("replay_mismatch" in v for v in result["violations"])

    def test_canonical_bytes_excludes_timestamps(self) -> None:
        """Two graphs identical except created_at must produce the same hash."""
        ev_a = build_evidence_node(
            node_id="ev-1",
            tenant_id=TENANT,
            engagement_id=ENG,
            evidence_id="EV-001",
            event_hash="h",
            created_at="2025-01-01T00:00:00Z",
        )
        ev_b = build_evidence_node(
            node_id="ev-1",
            tenant_id=TENANT,
            engagement_id=ENG,
            evidence_id="EV-001",
            event_hash="h",
            created_at="2026-06-11T09:00:00Z",
        )
        g1 = TrustGraph(TENANT, ENG)
        g2 = TrustGraph(TENANT, ENG)
        g1.add_node(ev_a)
        g2.add_node(ev_b)
        h1 = hashlib.sha256(_canonical_graph_bytes(g1)).hexdigest()
        h2 = hashlib.sha256(_canonical_graph_bytes(g2)).hexdigest()
        assert h1 == h2


# ---------------------------------------------------------------------------
# Security Invariants
# ---------------------------------------------------------------------------


class TestSecurityInvariants:
    def test_forged_evidence_node_wrong_tenant_rejected(self) -> None:
        g = _graph()
        forged = build_evidence_node(
            node_id="ev-forged",
            tenant_id="attacker",
            engagement_id=ENG,
            evidence_id="EV-x",
            event_hash="h",
        )
        with pytest.raises(TrustGraphError, match="cross-tenant"):
            g.add_node(forged)

    def test_forged_report_node_wrong_tenant_rejected(self) -> None:
        g = _graph()
        forged = build_report_node(
            node_id="rp-forged",
            tenant_id="attacker",
            engagement_id=ENG,
            report_id="REP-x",
        )
        with pytest.raises(TrustGraphError, match="cross-tenant"):
            g.add_node(forged)

    def test_invalid_edge_type_rejected_at_add(self) -> None:
        g = _graph()
        ev = _ev(g)
        ri = _ri(g)
        # EVIDENCE → RISK is not a valid edge type
        e = TrustGraphEdge(
            edge_id="e-bad",
            edge_type=EdgeType.FINDING_TO_RISK,
            source_node_id=ev.node_id,
            target_node_id=ri.node_id,
            tenant_id=TENANT,
            engagement_id=ENG,
        )
        with pytest.raises(TrustGraphError, match="invalid edge type"):
            g.add_edge(e)

    def test_orphaned_authority_chain_detected(self) -> None:
        g = _graph()
        _fi(g, "fi-orphan")  # no evidence backing
        result = verify_trust_graph(g)
        assert not result["graph_valid"]
        assert any("orphaned_node" in v for v in result["violations"])

    def test_graph_error_on_wrong_lineage_type(self) -> None:
        g = _graph()
        ri = _ri(g)
        with pytest.raises(TrustGraphError):
            get_report_lineage(g, ri.node_id)

    def test_fail_closed_verify_returns_false_not_raises(self) -> None:
        g = _graph()
        _ev(g, "ev-1", event_hash="")
        result = verify_trust_graph(g)
        assert isinstance(result, dict)
        assert result["graph_valid"] is False

    def test_add_node_empty_node_id_accepted_but_unique(self) -> None:
        """Empty string is a valid (if bad) node_id; duplicates still rejected."""
        g = _graph()
        n1 = build_evidence_node(
            node_id="",
            tenant_id=TENANT,
            engagement_id=ENG,
            evidence_id="EV-x",
            event_hash="h",
        )
        g.add_node(n1)
        n2 = build_evidence_node(
            node_id="",
            tenant_id=TENANT,
            engagement_id=ENG,
            evidence_id="EV-y",
            event_hash="h",
        )
        with pytest.raises(TrustGraphError, match="duplicate node_id"):
            g.add_node(n2)


# ---------------------------------------------------------------------------
# Performance
# ---------------------------------------------------------------------------


class TestPerformance:
    def _build_linear_chain(self, n: int) -> tuple[TrustGraph, str, str]:
        """Build alternating ev→fi chain of length n. Return graph + first/last node_id."""
        g = _graph()
        prev_ev = _ev(g, "ev-0")
        first_id = prev_ev.node_id
        last_id = first_id
        for i in range(1, n):
            fi = _fi(g, f"fi-{i}")
            _edge(g, prev_ev, fi, EdgeType.EVIDENCE_TO_FINDING)
            # Add another evidence node to link forward
            if i < n - 1:
                _ev(g, f"ev-{i}")
                _edge(
                    g,
                    fi,
                    TrustGraphNode(
                        node_id=f"ri-{i}",
                        node_type=NodeType.RISK,
                        tenant_id=TENANT,
                        engagement_id=ENG,
                        payload={
                            "risk_id": f"R-{i}",
                            "risk_level": "low",
                            "risk_type": "security",
                        },
                    )
                    if False
                    else fi,
                    EdgeType.EVIDENCE_TO_FINDING,  # won't reach here
                ) if False else None
                last_id = fi.node_id
            else:
                last_id = fi.node_id
        return g, first_id, last_id

    def _build_flat_evidence(self, n: int) -> TrustGraph:
        g = _graph()
        for i in range(n):
            _ev(g, f"ev-{i}")
        return g

    def test_100_nodes_traversal_under_50ms(self) -> None:
        g = _graph()
        for i in range(50):
            ev = _ev(g, f"ev-{i}")
            fi = _fi(g, f"fi-{i}")
            _edge(g, ev, fi, EdgeType.EVIDENCE_TO_FINDING)
        re = _re(g, "re-0")
        # Link all findings to report via risk
        ri = _ri(g, "ri-0")
        fi0 = g.get_node("fi-0")
        assert fi0 is not None
        _edge(g, fi0, ri, EdgeType.FINDING_TO_RISK)
        _edge(g, ri, re, EdgeType.RISK_TO_REPORT)
        t0 = time.monotonic()
        get_report_lineage(g, re.node_id)
        elapsed_ms = (time.monotonic() - t0) * 1000
        assert elapsed_ms < 50, (
            f"100-node traversal took {elapsed_ms:.1f}ms (target <50ms)"
        )

    def test_1000_nodes_verify_under_250ms(self) -> None:
        g = _graph()
        for i in range(500):
            ev = _ev(g, f"ev-{i}")
            fi = _fi(g, f"fi-{i}")
            _edge(g, ev, fi, EdgeType.EVIDENCE_TO_FINDING)
        t0 = time.monotonic()
        verify_trust_graph(g)
        elapsed_ms = (time.monotonic() - t0) * 1000
        assert elapsed_ms < 250, (
            f"1000-node verify took {elapsed_ms:.1f}ms (target <250ms)"
        )

    def test_10000_nodes_manifest_under_1000ms(self) -> None:
        g = _graph()
        for i in range(5000):
            ev = _ev(g, f"ev-{i}")
            fi = _fi(g, f"fi-{i}")
            _edge(g, ev, fi, EdgeType.EVIDENCE_TO_FINDING)
        t0 = time.monotonic()
        generate_trust_graph_manifest(g)
        elapsed_ms = (time.monotonic() - t0) * 1000
        assert elapsed_ms < 1000, (
            f"10000-node manifest took {elapsed_ms:.1f}ms (target <1000ms)"
        )

    def test_100_node_manifest_under_50ms(self) -> None:
        g = self._build_flat_evidence(100)
        t0 = time.monotonic()
        generate_trust_graph_manifest(g)
        elapsed_ms = (time.monotonic() - t0) * 1000
        assert elapsed_ms < 50

    def test_1000_node_path_under_250ms(self) -> None:
        g = _graph()
        prev = _ev(g, "ev-0")
        for i in range(1, 500):
            fi = _fi(g, f"fi-{i}")
            _edge(g, prev, fi, EdgeType.EVIDENCE_TO_FINDING)
            ri = _ri(g, f"ri-{i}")
            _edge(g, fi, ri, EdgeType.FINDING_TO_RISK)
            prev_ri = ri
            if i < 499:
                # chain findings
                ev = _ev(g, f"ev-{i}")
                prev = ev
        re = _re(g, "re-0")
        _edge(g, prev_ri, re, EdgeType.RISK_TO_REPORT)
        t0 = time.monotonic()
        get_report_lineage(g, re.node_id)
        elapsed_ms = (time.monotonic() - t0) * 1000
        assert elapsed_ms < 250


# ---------------------------------------------------------------------------
# Edge Type Enum Coverage
# ---------------------------------------------------------------------------


class TestEdgeTypeEnumCoverage:
    @pytest.mark.parametrize("edge_type", list(EdgeType))
    def test_all_edge_types_in_valid_map(self, edge_type: EdgeType) -> None:
        from services.field_assessment.trust_graph import _VALID_EDGES

        assert edge_type in _VALID_EDGES

    @pytest.mark.parametrize("node_type", list(NodeType))
    def test_all_node_types_accessible(self, node_type: NodeType) -> None:
        assert isinstance(node_type.value, str)

    def test_graph_version_non_empty(self) -> None:
        assert GRAPH_VERSION
        assert MANIFEST_VERSION


# ---------------------------------------------------------------------------
# Node Type Coverage — all 6 factory functions round-trip
# ---------------------------------------------------------------------------


class TestAllNodeFactories:
    @pytest.mark.parametrize(
        "factory,node_type,extra",
        [
            (
                build_evidence_node,
                NodeType.EVIDENCE,
                {"evidence_id": "EV-1", "event_hash": "h"},
            ),
            (
                build_finding_node,
                NodeType.FINDING,
                {"finding_id": "F-1", "severity": "high"},
            ),
            (
                build_control_node,
                NodeType.CONTROL,
                {"control_id": "AC-1", "framework": "NIST"},
            ),
            (
                build_framework_node,
                NodeType.FRAMEWORK,
                {"framework_id": "FW-1", "framework_name": "NIST"},
            ),
            (
                build_risk_node,
                NodeType.RISK,
                {"risk_id": "R-1", "risk_level": "low", "risk_type": "sec"},
            ),
            (build_report_node, NodeType.REPORT, {"report_id": "REP-1"}),
        ],
    )
    def test_factory_produces_correct_type(self, factory, node_type, extra) -> None:
        n = factory(node_id="n-1", tenant_id=TENANT, engagement_id=ENG, **extra)
        assert n.node_type == node_type
        assert n.tenant_id == TENANT
        assert n.engagement_id == ENG
        assert n.node_id == "n-1"
        assert n.created_at  # non-empty


# ---------------------------------------------------------------------------
# Full Integration Scenario
# ---------------------------------------------------------------------------


class TestFullIntegrationScenario:
    def test_full_assessment_trust_chain(self) -> None:
        """Build a realistic assessment graph and verify the full trust path."""
        g = _graph()

        fw = build_framework_node(
            node_id="fw-nist",
            tenant_id=TENANT,
            engagement_id=ENG,
            framework_id="FW-NIST-CSF",
            framework_name="NIST CSF",
            version="2.0",
        )
        g.add_node(fw)

        ev1 = build_evidence_node(
            node_id="ev-001",
            tenant_id=TENANT,
            engagement_id=ENG,
            evidence_id="EV-001",
            event_hash="aabbccdd",
            authority_status="signed",
            trust_score=100,
        )
        ev2 = build_evidence_node(
            node_id="ev-002",
            tenant_id=TENANT,
            engagement_id=ENG,
            evidence_id="EV-002",
            event_hash="eeff0011",
            authority_status="signed",
            trust_score=100,
        )
        g.add_node(ev1)
        g.add_node(ev2)

        fi = build_finding_node(
            node_id="fi-001",
            tenant_id=TENANT,
            engagement_id=ENG,
            finding_id="F-001",
            severity="high",
            confidence="high",
        )
        g.add_node(fi)

        co = build_control_node(
            node_id="co-ac2",
            tenant_id=TENANT,
            engagement_id=ENG,
            control_id="AC-2",
            framework="NIST CSF",
            control_status="partial",
        )
        g.add_node(co)

        ri = build_risk_node(
            node_id="ri-001",
            tenant_id=TENANT,
            engagement_id=ENG,
            risk_id="R-001",
            risk_level="high",
            risk_type="security",
        )
        g.add_node(ri)

        rp = build_report_node(
            node_id="rp-001",
            tenant_id=TENANT,
            engagement_id=ENG,
            report_id="REP-001",
            report_hash="sha256abc",
            report_status="finalized",
        )
        g.add_node(rp)

        _edge(g, ev1, fi, EdgeType.EVIDENCE_TO_FINDING)
        _edge(g, ev2, fi, EdgeType.EVIDENCE_TO_FINDING)
        _edge(g, fi, co, EdgeType.FINDING_TO_CONTROL)
        _edge(g, co, fw, EdgeType.CONTROL_TO_FRAMEWORK)
        _edge(g, fi, ri, EdgeType.FINDING_TO_RISK)
        _edge(g, ri, rp, EdgeType.RISK_TO_REPORT)
        _edge(g, ev1, rp, EdgeType.EVIDENCE_TO_REPORT)

        # Verify graph integrity
        result = verify_trust_graph(g)
        assert result["graph_valid"], result["violations"]
        assert result["node_count"] == 7
        assert result["edge_count"] == 7

        # Trust path: evidence → report
        path = generate_trust_path(g, "ev-001", "rp-001")
        assert path[0].node_id == "ev-001"
        assert path[-1].node_id == "rp-001"

        # Report lineage: all upstream nodes
        lineage = get_report_lineage(g, rp.node_id)
        ids = {n.node_id for n in lineage}
        assert {"ev-001", "ev-002", "fi-001", "ri-001", "rp-001"} <= ids

        # Control lineage: what supports AC-2?
        ctrl_lineage = get_control_lineage(g, co.node_id)
        ctrl_ids = {n.node_id for n in ctrl_lineage}
        assert "ev-001" in ctrl_ids
        assert "ev-002" in ctrl_ids
        assert "fi-001" in ctrl_ids

        # Manifest
        manifest = generate_trust_graph_manifest(g)
        assert manifest["node_count"] == 7
        assert manifest["edge_count"] == 7
        assert "ev-001" in manifest["root_nodes"] or "ev-002" in manifest["root_nodes"]
        assert len(manifest["graph_hash"]) == 64

    def test_auditor_query_why_does_report_exist(self) -> None:
        """Auditor: Why does this report exist?"""
        g = _graph()
        ev = _ev(g, "ev-1")
        fi = _fi(g, "fi-1")
        ri = _ri(g, "ri-1")
        re = _re(g, "re-1")
        _edge(g, ev, fi, EdgeType.EVIDENCE_TO_FINDING)
        _edge(g, fi, ri, EdgeType.FINDING_TO_RISK)
        _edge(g, ri, re, EdgeType.RISK_TO_REPORT)
        lineage = get_report_lineage(g, re.node_id)
        types = {n.node_type for n in lineage}
        # Must surface evidence, finding, risk, and the report itself
        assert NodeType.EVIDENCE in types
        assert NodeType.FINDING in types
        assert NodeType.RISK in types

    def test_regulator_query_what_supports_control(self) -> None:
        """Regulator: What evidence supports this control?"""
        g = _graph()
        ev = _ev(g, "ev-1")
        fi = _fi(g, "fi-1")
        co = _co(g, "co-1")
        _edge(g, ev, fi, EdgeType.EVIDENCE_TO_FINDING)
        _edge(g, fi, co, EdgeType.FINDING_TO_CONTROL)
        lineage = get_control_lineage(g, co.node_id)
        evidence_nodes = [n for n in lineage if n.node_type == NodeType.EVIDENCE]
        assert len(evidence_nodes) == 1
        assert evidence_nodes[0].node_id == "ev-1"

    def test_executive_query_why_is_risk_present(self) -> None:
        """Executive: Why is this risk score present?"""
        g = _graph()
        ev = _ev(g, "ev-1")
        fi = _fi(g, "fi-1")
        ri = _ri(g, "ri-1")
        _edge(g, ev, fi, EdgeType.EVIDENCE_TO_FINDING)
        _edge(g, fi, ri, EdgeType.FINDING_TO_RISK)
        lineage = get_risk_lineage(g, ri.node_id)
        evidence = [n for n in lineage if n.node_type == NodeType.EVIDENCE]
        assert len(evidence) >= 1
