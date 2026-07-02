"""Tests for PR 18.5A — ProvenanceGraph, build_node, compute_node_digest.

Pure-function tests. No DB required.
"""

from __future__ import annotations

import hashlib
import json

from services.governance_intelligence.provenance import (
    ALL_NODE_TYPES,
    ASSESSMENT,
    BENCHMARK,
    CONTROL,
    DASHBOARD_WIDGET,
    EVIDENCE,
    EXECUTIVE_INSIGHT,
    FINDING,
    FORECAST,
    FRAMEWORK,
    ORCHESTRATION,
    POLICY,
    RECOMMENDATION,
    REMEDIATION,
    REPORT,
    SIMULATION,
    TRANSPARENCY_ENTRY,
    TRUST_RECORD,
    VERIFICATION,
    ProvenanceGraph,
    ProvenanceNode,
    build_node,
    compute_node_digest,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_node(
    node_type: str = EVIDENCE,
    authority: str = "test_auth",
    source_id: str = "obj-1",
    data: dict | None = None,
    parent_ids: list[str] | None = None,
    timestamp: str = "2026-01-01T00:00:00Z",
) -> ProvenanceNode:
    return build_node(
        node_type,
        authority,
        source_id,
        data or {},
        parent_ids or [],
        timestamp=timestamp,
    )


# ---------------------------------------------------------------------------
# NODE_TYPE constants
# ---------------------------------------------------------------------------


class TestNodeTypeConstants:
    def test_assessment_constant(self):
        assert ASSESSMENT == "ASSESSMENT"

    def test_finding_constant(self):
        assert FINDING == "FINDING"

    def test_evidence_constant(self):
        assert EVIDENCE == "EVIDENCE"

    def test_verification_constant(self):
        assert VERIFICATION == "VERIFICATION"

    def test_control_constant(self):
        assert CONTROL == "CONTROL"

    def test_framework_constant(self):
        assert FRAMEWORK == "FRAMEWORK"

    def test_remediation_constant(self):
        assert REMEDIATION == "REMEDIATION"

    def test_policy_constant(self):
        assert POLICY == "POLICY"

    def test_orchestration_constant(self):
        assert ORCHESTRATION == "ORCHESTRATION"

    def test_simulation_constant(self):
        assert SIMULATION == "SIMULATION"

    def test_benchmark_constant(self):
        assert BENCHMARK == "BENCHMARK"

    def test_forecast_constant(self):
        assert FORECAST == "FORECAST"

    def test_recommendation_constant(self):
        assert RECOMMENDATION == "RECOMMENDATION"

    def test_executive_insight_constant(self):
        assert EXECUTIVE_INSIGHT == "EXECUTIVE_INSIGHT"

    def test_dashboard_widget_constant(self):
        assert DASHBOARD_WIDGET == "DASHBOARD_WIDGET"

    def test_report_constant(self):
        assert REPORT == "REPORT"

    def test_trust_record_constant(self):
        assert TRUST_RECORD == "TRUST_RECORD"

    def test_transparency_entry_constant(self):
        assert TRANSPARENCY_ENTRY == "TRANSPARENCY_ENTRY"

    def test_all_node_types_is_frozenset(self):
        assert isinstance(ALL_NODE_TYPES, frozenset)

    def test_all_node_types_contains_18_entries(self):
        assert len(ALL_NODE_TYPES) == 18

    def test_all_node_types_contains_evidence(self):
        assert EVIDENCE in ALL_NODE_TYPES

    def test_all_node_types_contains_verification(self):
        assert VERIFICATION in ALL_NODE_TYPES

    def test_all_node_types_contains_assessment(self):
        assert ASSESSMENT in ALL_NODE_TYPES

    def test_all_node_types_contains_policy(self):
        assert POLICY in ALL_NODE_TYPES


# ---------------------------------------------------------------------------
# compute_node_digest
# ---------------------------------------------------------------------------


class TestComputeNodeDigest:
    def test_returns_64_char_hex(self):
        digest = compute_node_digest({"a": 1})
        assert len(digest) == 64
        assert all(c in "0123456789abcdef" for c in digest)

    def test_deterministic_same_input(self):
        d1 = compute_node_digest({"x": 1, "y": 2})
        d2 = compute_node_digest({"x": 1, "y": 2})
        assert d1 == d2

    def test_key_order_independent(self):
        d1 = compute_node_digest({"a": 1, "b": 2})
        d2 = compute_node_digest({"b": 2, "a": 1})
        assert d1 == d2

    def test_different_values_different_digest(self):
        d1 = compute_node_digest({"a": 1})
        d2 = compute_node_digest({"a": 2})
        assert d1 != d2

    def test_empty_dict(self):
        digest = compute_node_digest({})
        expected = hashlib.sha256(
            json.dumps({}, sort_keys=True).encode("utf-8")
        ).hexdigest()
        assert digest == expected

    def test_nested_dict(self):
        digest = compute_node_digest({"nested": {"key": "val"}})
        assert len(digest) == 64

    def test_unicode_data(self):
        digest = compute_node_digest({"text": "日本語"})
        assert len(digest) == 64

    def test_list_value(self):
        digest = compute_node_digest({"items": [1, 2, 3]})
        assert len(digest) == 64


# ---------------------------------------------------------------------------
# build_node
# ---------------------------------------------------------------------------


class TestBuildNode:
    def test_returns_provenance_node(self):
        node = _make_node()
        assert isinstance(node, ProvenanceNode)

    def test_node_type_set_correctly(self):
        node = _make_node(node_type=FINDING)
        assert node.node_type == FINDING

    def test_authority_set_correctly(self):
        node = _make_node(authority="my_auth")
        assert node.authority == "my_auth"

    def test_source_object_id_set_correctly(self):
        node = _make_node(source_id="src-42")
        assert node.source_object_id == "src-42"

    def test_id_is_sha256_digest(self):
        node = _make_node()
        assert len(node.id) == 64

    def test_id_equals_sha256_digest(self):
        node = _make_node()
        assert node.id == node.sha256_digest

    def test_parent_ids_empty_by_default(self):
        node = _make_node()
        assert node.parent_ids == []

    def test_parent_ids_stored(self):
        node = _make_node(parent_ids=["parent-1"])
        assert "parent-1" in node.parent_ids

    def test_child_ids_empty_after_build(self):
        node = _make_node()
        assert node.child_ids == []

    def test_deterministic_same_inputs(self):
        n1 = _make_node(timestamp="2026-01-01T00:00:00Z")
        n2 = _make_node(timestamp="2026-01-01T00:00:00Z")
        assert n1.id == n2.id

    def test_different_data_different_id(self):
        n1 = _make_node(data={"a": 1}, timestamp="2026-01-01T00:00:00Z")
        n2 = _make_node(data={"a": 2}, timestamp="2026-01-01T00:00:00Z")
        assert n1.id != n2.id

    def test_optional_refs_default_none(self):
        node = _make_node()
        assert node.trust_ref is None
        assert node.transparency_ref is None
        assert node.confidence_ref is None
        assert node.simulation_ref is None
        assert node.replay_ref is None

    def test_optional_refs_set_via_kwargs(self):
        node = build_node(
            EVIDENCE,
            "auth",
            "obj",
            {},
            [],
            timestamp="2026-01-01T00:00:00Z",
            trust_ref="tr-1",
            transparency_ref="tx-1",
            confidence_ref="cf-1",
            simulation_ref="sim-1",
            replay_ref="rep-1",
        )
        assert node.trust_ref == "tr-1"
        assert node.transparency_ref == "tx-1"
        assert node.confidence_ref == "cf-1"
        assert node.simulation_ref == "sim-1"
        assert node.replay_ref == "rep-1"

    def test_authority_version_default(self):
        node = _make_node()
        assert node.authority_version == "1.0"

    def test_authority_version_custom(self):
        node = build_node(
            EVIDENCE,
            "auth",
            "obj",
            {},
            [],
            timestamp="2026-01-01T00:00:00Z",
            authority_version="2.0",
        )
        assert node.authority_version == "2.0"

    def test_to_dict_has_all_fields(self):
        node = _make_node()
        d = node.to_dict()
        assert "id" in d
        assert "node_type" in d
        assert "authority" in d
        assert "sha256_digest" in d
        assert "parent_ids" in d
        assert "child_ids" in d


# ---------------------------------------------------------------------------
# ProvenanceGraph — add / get
# ---------------------------------------------------------------------------


class TestProvenanceGraphAddGet:
    def test_add_and_get_node(self):
        g = ProvenanceGraph()
        n = _make_node()
        g.add_node(n)
        assert g.get_node(n.id) is n

    def test_get_missing_returns_none(self):
        g = ProvenanceGraph()
        assert g.get_node("nonexistent") is None

    def test_add_updates_parent_child_link(self):
        g = ProvenanceGraph()
        parent = _make_node(source_id="p1", timestamp="2026-01-01T00:00:00Z")
        child = _make_node(
            source_id="c1", parent_ids=[parent.id], timestamp="2026-01-02T00:00:00Z"
        )
        g.add_node(parent)
        g.add_node(child)
        assert child.id in g.get_node(parent.id).child_ids

    def test_add_multiple_nodes(self):
        g = ProvenanceGraph()
        n1 = _make_node(source_id="s1", timestamp="2026-01-01T00:00:00Z")
        n2 = _make_node(source_id="s2", timestamp="2026-01-02T00:00:00Z")
        g.add_node(n1)
        g.add_node(n2)
        assert g.get_node(n1.id) is not None
        assert g.get_node(n2.id) is not None

    def test_replace_existing_node(self):
        g = ProvenanceGraph()
        n = _make_node()
        g.add_node(n)
        g.add_node(n)
        assert g.get_node(n.id) is n


# ---------------------------------------------------------------------------
# ProvenanceGraph — ancestors
# ---------------------------------------------------------------------------


class TestProvenanceGraphAncestors:
    def test_no_ancestors_for_root(self):
        g = ProvenanceGraph()
        root = _make_node(source_id="root", timestamp="2026-01-01T00:00:00Z")
        g.add_node(root)
        assert g.get_ancestors(root.id) == []

    def test_one_ancestor(self):
        g = ProvenanceGraph()
        parent = _make_node(source_id="p", timestamp="2026-01-01T00:00:00Z")
        child = _make_node(
            source_id="c", parent_ids=[parent.id], timestamp="2026-01-02T00:00:00Z"
        )
        g.add_node(parent)
        g.add_node(child)
        ancestors = g.get_ancestors(child.id)
        assert len(ancestors) == 1
        assert ancestors[0].id == parent.id

    def test_two_levels_of_ancestors(self):
        g = ProvenanceGraph()
        gp = _make_node(source_id="gp", timestamp="2026-01-01T00:00:00Z")
        parent = _make_node(
            source_id="p", parent_ids=[gp.id], timestamp="2026-01-02T00:00:00Z"
        )
        child = _make_node(
            source_id="c", parent_ids=[parent.id], timestamp="2026-01-03T00:00:00Z"
        )
        g.add_node(gp)
        g.add_node(parent)
        g.add_node(child)
        ancestors = g.get_ancestors(child.id)
        ancestor_ids = {a.id for a in ancestors}
        assert parent.id in ancestor_ids
        assert gp.id in ancestor_ids

    def test_missing_node_returns_empty(self):
        g = ProvenanceGraph()
        assert g.get_ancestors("no-such-node") == []


# ---------------------------------------------------------------------------
# ProvenanceGraph — descendants
# ---------------------------------------------------------------------------


class TestProvenanceGraphDescendants:
    def test_no_descendants_for_leaf(self):
        g = ProvenanceGraph()
        leaf = _make_node()
        g.add_node(leaf)
        assert g.get_descendants(leaf.id) == []

    def test_one_descendant(self):
        g = ProvenanceGraph()
        parent = _make_node(source_id="p", timestamp="2026-01-01T00:00:00Z")
        child = _make_node(
            source_id="c", parent_ids=[parent.id], timestamp="2026-01-02T00:00:00Z"
        )
        g.add_node(parent)
        g.add_node(child)
        descendants = g.get_descendants(parent.id)
        assert len(descendants) == 1
        assert descendants[0].id == child.id

    def test_two_levels_of_descendants(self):
        g = ProvenanceGraph()
        root = _make_node(source_id="r", timestamp="2026-01-01T00:00:00Z")
        child = _make_node(
            source_id="c", parent_ids=[root.id], timestamp="2026-01-02T00:00:00Z"
        )
        grandchild = _make_node(
            source_id="gc", parent_ids=[child.id], timestamp="2026-01-03T00:00:00Z"
        )
        g.add_node(root)
        g.add_node(child)
        g.add_node(grandchild)
        desc = g.get_descendants(root.id)
        desc_ids = {d.id for d in desc}
        assert child.id in desc_ids
        assert grandchild.id in desc_ids

    def test_missing_node_returns_empty(self):
        g = ProvenanceGraph()
        assert g.get_descendants("no-such-node") == []


# ---------------------------------------------------------------------------
# ProvenanceGraph — cycle detection
# ---------------------------------------------------------------------------


class TestProvenanceGraphCycleDetection:
    def test_acyclic_graph_returns_empty(self):
        g = ProvenanceGraph()
        n1 = _make_node(source_id="s1", timestamp="2026-01-01T00:00:00Z")
        n2 = _make_node(
            source_id="s2", parent_ids=[n1.id], timestamp="2026-01-02T00:00:00Z"
        )
        g.add_node(n1)
        g.add_node(n2)
        assert g.detect_cycles() == []

    def test_empty_graph_no_cycles(self):
        g = ProvenanceGraph()
        assert g.detect_cycles() == []

    def test_single_node_no_cycles(self):
        g = ProvenanceGraph()
        n = _make_node()
        g.add_node(n)
        assert g.detect_cycles() == []

    def test_manual_cycle_detected(self):
        g = ProvenanceGraph()
        n1 = ProvenanceNode(
            id="node-a",
            node_type=EVIDENCE,
            authority="auth",
            authority_version="1.0",
            source_object_id="s1",
            sha256_digest="node-a",
            timestamp="2026-01-01T00:00:00Z",
            parent_ids=[],
            child_ids=["node-b"],
        )
        n2 = ProvenanceNode(
            id="node-b",
            node_type=EVIDENCE,
            authority="auth",
            authority_version="1.0",
            source_object_id="s2",
            sha256_digest="node-b",
            timestamp="2026-01-01T00:00:00Z",
            parent_ids=["node-a"],
            child_ids=["node-a"],  # creates cycle
        )
        g.add_node(n1)
        g.add_node(n2)
        cycles = g.detect_cycles()
        assert cycles != []
        assert len(cycles) >= 1


# ---------------------------------------------------------------------------
# ProvenanceGraph — export_graph determinism
# ---------------------------------------------------------------------------


class TestProvenanceGraphExport:
    def test_export_graph_returns_dict(self):
        g = ProvenanceGraph()
        n = _make_node()
        g.add_node(n)
        result = g.export_graph()
        assert isinstance(result, dict)

    def test_export_graph_has_nodes(self):
        g = ProvenanceGraph()
        n = _make_node()
        g.add_node(n)
        result = g.export_graph()
        assert "nodes" in result
        assert len(result["nodes"]) == 1

    def test_export_graph_has_edges(self):
        g = ProvenanceGraph()
        p = _make_node(source_id="p", timestamp="2026-01-01T00:00:00Z")
        c = _make_node(
            source_id="c", parent_ids=[p.id], timestamp="2026-01-02T00:00:00Z"
        )
        g.add_node(p)
        g.add_node(c)
        result = g.export_graph()
        assert len(result["edges"]) >= 1

    def test_export_graph_node_count(self):
        g = ProvenanceGraph()
        for i in range(5):
            g.add_node(
                _make_node(source_id=f"s{i}", timestamp=f"2026-01-0{i + 1}T00:00:00Z")
            )
        result = g.export_graph()
        assert result["node_count"] == 5

    def test_export_graph_determinism(self):
        g = ProvenanceGraph()
        n1 = _make_node(source_id="a", timestamp="2026-01-01T00:00:00Z")
        n2 = _make_node(source_id="b", timestamp="2026-01-02T00:00:00Z")
        g.add_node(n1)
        g.add_node(n2)
        r1 = g.export_graph()
        r2 = g.export_graph()
        assert json.dumps(r1, sort_keys=True) == json.dumps(r2, sort_keys=True)

    def test_export_graph_cycle_detected_flag(self):
        g = ProvenanceGraph()
        n = _make_node()
        g.add_node(n)
        result = g.export_graph()
        assert isinstance(result["cycle_detected"], bool)

    def test_export_empty_graph(self):
        g = ProvenanceGraph()
        result = g.export_graph()
        assert result["node_count"] == 0
        assert result["nodes"] == []
        assert result["edges"] == []

    def test_to_sorted_list_returns_sorted(self):
        g = ProvenanceGraph()
        n1 = _make_node(source_id="zzz", timestamp="2026-01-01T00:00:00Z")
        n2 = _make_node(source_id="aaa", timestamp="2026-01-02T00:00:00Z")
        g.add_node(n1)
        g.add_node(n2)
        lst = g.to_sorted_list()
        ids = [item["id"] for item in lst]
        assert ids == sorted(ids)
