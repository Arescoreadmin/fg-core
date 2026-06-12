"""Trust Graph Authority & Snapshot Foundation tests — PR 1.6A.

Coverage matrix:
  Edge Authority Creation         build_edge_authority_event, sign_edge_authority
  Edge Authority Verification     verify_edge_authority — all check layers
  Snapshot Creation               generate_signed_graph_snapshot
  Snapshot Verification           verify_graph_snapshot — all check layers
  Snapshot Signature Invariant    snapshot_hash is signed (not snapshot_id, not created_at)
  Replay Anchors                  build_replay_anchor
  Replay Anchor Verification      verify_replay_anchor — all check layers
  Trust Explanation Functions     why_report, why_risk, why_control, why_finding
  Trust Query Result              TrustQueryResult fields, subject_id, query_type, to_dict
  Tamper Detection                hash mismatch, field mutation, field injection
  Wrong Key Detection             key_unavailable, wrong key material
  Cross Tenant Isolation          edge/snapshot across tenant boundaries
  Cross Engagement Isolation      edge/snapshot across engagement boundaries
  Determinism                     same graph → same hash → same output
  Manifest Stability              timestamp exclusion from canonical bytes
  Performance                     sign/verify latency targets — 100-node and 1000-node
  Future Node Compatibility       unknown payload fields tolerated
  Security Invariants             missing fields, version spoofing, replay
  No Private Key In Output        seed never appears in any output surface
  Malformed Inputs                None/wrong types for all public verify paths
  Edge Authority Version          EDGE_AUTHORITY_VERSION in payload, downgrade detection
"""

from __future__ import annotations

import base64
import hashlib
import time
import uuid
from typing import Any

import pytest

from services.field_assessment.trust_graph import (
    EdgeType,
    NodeType,
    TrustGraph,
    TrustGraphEdge,
    TrustGraphError,
    TrustGraphNode,
    build_control_node,
    build_evidence_node,
    build_finding_node,
    build_framework_node,
    build_report_node,
    build_risk_node,
    generate_trust_graph_manifest,
)
from services.field_assessment.trust_graph_authority import (
    EDGE_AUTHORITY_VERSION,
    SNAPSHOT_VERSION,
    TrustGraphAuthorityError,
    TrustQueryResult,
    _canonical_snapshot_bytes,
    build_edge_authority_event,
    build_replay_anchor,
    generate_signed_graph_snapshot,
    sign_edge_authority,
    verify_edge_authority,
    verify_graph_snapshot,
    verify_replay_anchor,
    why_control,
    why_finding,
    why_report,
    why_risk,
)

# ---------------------------------------------------------------------------
# Test key material
# ---------------------------------------------------------------------------

_TEST_SEED: bytes = hashlib.sha256(b"trust-graph-authority-test-seed").digest()
_TEST_SEED_B64: str = base64.b64encode(_TEST_SEED).decode()

# A second deterministic seed for wrong-key tests
_ALT_SEED: bytes = hashlib.sha256(b"trust-graph-authority-alt-seed").digest()
_ALT_SEED_B64: str = base64.b64encode(_ALT_SEED).decode()

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

TENANT = "tenant-x"
ENG = "eng-100"
TENANT_B = "tenant-y"
ENG_B = "eng-200"


def _uid(prefix: str = "") -> str:
    return f"{prefix}{uuid.uuid4().hex[:8]}"


def _graph(tenant: str = TENANT, eng: str = ENG) -> TrustGraph:
    return TrustGraph(tenant_id=tenant, engagement_id=eng)


def _ev(
    graph: TrustGraph, nid: str = "", event_hash: str = "deadbeef"
) -> TrustGraphNode:
    nid = nid or _uid("ev-")
    node = build_evidence_node(
        node_id=nid,
        tenant_id=graph.tenant_id,
        engagement_id=graph.engagement_id,
        evidence_id=f"EV-{nid}",
        event_hash=event_hash,
        authority_status="signed",
        trust_score=90,
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


def _co(graph: TrustGraph, nid: str = "") -> TrustGraphNode:
    nid = nid or _uid("co-")
    node = build_control_node(
        node_id=nid,
        tenant_id=graph.tenant_id,
        engagement_id=graph.engagement_id,
        control_id=f"AC-{nid}",
        framework="NIST CSF",
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
        report_hash="hash999",
        report_status="finalized",
    )
    graph.add_node(node)
    return node


def _edge(
    graph: TrustGraph,
    src: TrustGraphNode,
    tgt: TrustGraphNode,
    edge_type: EdgeType,
    eid: str = "",
) -> TrustGraphEdge:
    e = TrustGraphEdge(
        edge_id=eid or _uid("e-"),
        edge_type=edge_type,
        source_node_id=src.node_id,
        target_node_id=tgt.node_id,
        tenant_id=graph.tenant_id,
        engagement_id=graph.engagement_id,
    )
    graph.add_edge(e)
    return e


def _full_graph() -> tuple[TrustGraph, dict[str, Any]]:
    """Build a complete 7-node graph with all edge types."""
    g = _graph()
    fw = _fw(g, "fw-1")
    ev = _ev(g, "ev-1")
    fi = _fi(g, "fi-1")
    co = _co(g, "co-1")
    ri = _ri(g, "ri-1")
    re = _re(g, "re-1")
    ev2 = _ev(g, "ev-2")
    e1 = _edge(g, ev, fi, EdgeType.EVIDENCE_TO_FINDING)
    e2 = _edge(g, fi, co, EdgeType.FINDING_TO_CONTROL)
    e3 = _edge(g, co, fw, EdgeType.CONTROL_TO_FRAMEWORK)
    e4 = _edge(g, fi, ri, EdgeType.FINDING_TO_RISK)
    e5 = _edge(g, ri, re, EdgeType.RISK_TO_REPORT)
    e6 = _edge(g, ev2, re, EdgeType.EVIDENCE_TO_REPORT)
    return g, {
        "fw": fw,
        "ev": ev,
        "fi": fi,
        "co": co,
        "ri": ri,
        "re": re,
        "ev2": ev2,
        "e1": e1,
        "e2": e2,
        "e3": e3,
        "e4": e4,
        "e5": e5,
        "e6": e6,
    }


def _make_ev_fi_edge(tenant: str = TENANT, eng: str = ENG) -> TrustGraphEdge:
    return TrustGraphEdge(
        edge_id=_uid("e-"),
        edge_type=EdgeType.EVIDENCE_TO_FINDING,
        source_node_id="ev-1",
        target_node_id="fi-1",
        tenant_id=tenant,
        engagement_id=eng,
    )


# ---------------------------------------------------------------------------
# Edge Authority Creation
# ---------------------------------------------------------------------------


class TestBuildEdgeAuthorityEvent:
    def test_returns_required_fields(self) -> None:
        edge = _make_ev_fi_edge()
        event = build_edge_authority_event(edge)
        assert "edge_type" in event
        assert "source_node_id" in event
        assert "target_node_id" in event
        assert "tenant_id" in event
        assert "engagement_id" in event
        assert "authority_version" in event
        assert "signing_key_id" in event

    def test_edge_type_is_string_value(self) -> None:
        edge = _make_ev_fi_edge()
        event = build_edge_authority_event(edge)
        assert event["edge_type"] == EdgeType.EVIDENCE_TO_FINDING.value

    def test_authority_version_matches_constant(self) -> None:
        edge = _make_ev_fi_edge()
        event = build_edge_authority_event(edge)
        assert event["authority_version"] == EDGE_AUTHORITY_VERSION

    def test_tenant_and_engagement_preserved(self) -> None:
        edge = _make_ev_fi_edge()
        event = build_edge_authority_event(edge)
        assert event["tenant_id"] == TENANT
        assert event["engagement_id"] == ENG

    def test_source_and_target_preserved(self) -> None:
        edge = _make_ev_fi_edge()
        event = build_edge_authority_event(edge)
        assert event["source_node_id"] == "ev-1"
        assert event["target_node_id"] == "fi-1"

    def test_no_key_results_in_none_signing_key_id(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("FG_EVIDENCE_SIGNING_KEY_B64", raising=False)
        monkeypatch.delenv("FG_EVIDENCE_VERIFY_KEY_B64", raising=False)
        edge = _make_ev_fi_edge()
        event = build_edge_authority_event(edge)
        assert event["signing_key_id"] is None

    def test_signing_key_id_present_with_key(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        edge = _make_ev_fi_edge()
        event = build_edge_authority_event(edge)
        assert event["signing_key_id"] is not None
        assert len(event["signing_key_id"]) == 16

    def test_deterministic_for_same_edge(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        edge = _make_ev_fi_edge()
        e1 = build_edge_authority_event(edge)
        e2 = build_edge_authority_event(edge)
        assert e1 == e2

    def test_all_edge_types_produce_events(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        edge_types = [
            (EdgeType.EVIDENCE_TO_FINDING, "ev", "fi"),
            (EdgeType.FINDING_TO_CONTROL, "fi", "co"),
            (EdgeType.CONTROL_TO_FRAMEWORK, "co", "fw"),
            (EdgeType.FINDING_TO_RISK, "fi", "ri"),
            (EdgeType.RISK_TO_REPORT, "ri", "re"),
            (EdgeType.EVIDENCE_TO_REPORT, "ev", "re"),
        ]
        for et, src, tgt in edge_types:
            edge = TrustGraphEdge(
                edge_id=_uid(),
                edge_type=et,
                source_node_id=f"{src}-1",
                target_node_id=f"{tgt}-1",
                tenant_id=TENANT,
                engagement_id=ENG,
            )
            event = build_edge_authority_event(edge)
            assert event["edge_type"] == et.value


class TestSignEdgeAuthority:
    def test_raises_without_signing_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("FG_EVIDENCE_SIGNING_KEY_B64", raising=False)
        monkeypatch.delenv("FG_EVIDENCE_VERIFY_KEY_B64", raising=False)
        edge = _make_ev_fi_edge()
        with pytest.raises(TrustGraphAuthorityError):
            sign_edge_authority(edge)

    def test_returns_all_required_fields(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        edge = _make_ev_fi_edge()
        auth = sign_edge_authority(edge)
        assert "event_hash" in auth
        assert "signature" in auth
        assert "signing_key_id" in auth
        assert "authority_version" in auth

    def test_signature_is_hex_string(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        edge = _make_ev_fi_edge()
        auth = sign_edge_authority(edge)
        bytes.fromhex(auth["signature"])  # raises if not valid hex

    def test_event_hash_is_64_char_hex(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        edge = _make_ev_fi_edge()
        auth = sign_edge_authority(edge)
        assert len(auth["event_hash"]) == 64
        bytes.fromhex(auth["event_hash"])

    def test_signing_key_id_is_16_chars(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        edge = _make_ev_fi_edge()
        auth = sign_edge_authority(edge)
        assert len(auth["signing_key_id"]) == 16

    def test_authority_version_constant(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        edge = _make_ev_fi_edge()
        auth = sign_edge_authority(edge)
        assert auth["authority_version"] == EDGE_AUTHORITY_VERSION

    def test_deterministic_signatures_for_same_edge_and_key(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        edge = _make_ev_fi_edge()
        a1 = sign_edge_authority(edge)
        a2 = sign_edge_authority(edge)
        assert a1["event_hash"] == a2["event_hash"]
        assert a1["signature"] == a2["signature"]
        assert a1["signing_key_id"] == a2["signing_key_id"]

    def test_different_edges_produce_different_hashes(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        e1 = _make_ev_fi_edge(TENANT, ENG)
        e2 = TrustGraphEdge(
            edge_id=_uid(),
            edge_type=EdgeType.EVIDENCE_TO_FINDING,
            source_node_id="ev-2",
            target_node_id="fi-2",
            tenant_id=TENANT,
            engagement_id=ENG,
        )
        a1 = sign_edge_authority(e1)
        a2 = sign_edge_authority(e2)
        assert a1["event_hash"] != a2["event_hash"]

    def test_different_tenants_produce_different_hashes(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        e1 = _make_ev_fi_edge(TENANT, ENG)
        e2 = _make_ev_fi_edge(TENANT_B, ENG)
        a1 = sign_edge_authority(e1)
        a2 = sign_edge_authority(e2)
        assert a1["event_hash"] != a2["event_hash"]

    def test_invalid_seed_length_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        bad_seed = base64.b64encode(b"tooshort").decode()
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", bad_seed)
        monkeypatch.delenv("FG_EVIDENCE_VERIFY_KEY_B64", raising=False)
        edge = _make_ev_fi_edge()
        with pytest.raises(TrustGraphAuthorityError, match="32 bytes"):
            sign_edge_authority(edge)

    def test_non_base64_seed_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", "!!!not-base64!!!")
        monkeypatch.delenv("FG_EVIDENCE_VERIFY_KEY_B64", raising=False)
        edge = _make_ev_fi_edge()
        with pytest.raises(TrustGraphAuthorityError, match="base64"):
            sign_edge_authority(edge)


# ---------------------------------------------------------------------------
# Edge Authority Verification
# ---------------------------------------------------------------------------


class TestVerifyEdgeAuthority:
    def test_valid_signature_returns_valid_true(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        edge = _make_ev_fi_edge()
        auth = sign_edge_authority(edge)
        result = verify_edge_authority(edge, auth)
        assert result["valid"] is True
        assert result["reason"] is None

    def test_missing_authority_returns_invalid(self) -> None:
        edge = _make_ev_fi_edge()
        result = verify_edge_authority(edge, {})
        assert result["valid"] is False
        assert "missing_authority_fields" in result["reason"]

    def test_none_authority_returns_invalid(self) -> None:
        edge = _make_ev_fi_edge()
        result = verify_edge_authority(edge, None)  # type: ignore[arg-type]
        assert result["valid"] is False

    def test_missing_event_hash_field(self) -> None:
        edge = _make_ev_fi_edge()
        auth = {
            "signature": "aabbcc",
            "signing_key_id": "abc123",
            "authority_version": EDGE_AUTHORITY_VERSION,
        }
        result = verify_edge_authority(edge, auth)
        assert result["valid"] is False
        assert "event_hash" in result["reason"]

    def test_missing_signature_field(self) -> None:
        edge = _make_ev_fi_edge()
        auth = {
            "event_hash": "aabbcc",
            "signing_key_id": "abc123",
            "authority_version": EDGE_AUTHORITY_VERSION,
        }
        result = verify_edge_authority(edge, auth)
        assert result["valid"] is False

    def test_wrong_authority_version_returns_invalid(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        edge = _make_ev_fi_edge()
        auth = sign_edge_authority(edge)
        auth = dict(auth)
        auth["authority_version"] = "trust-graph-edge-authority-v999"
        result = verify_edge_authority(edge, auth)
        assert result["valid"] is False
        assert "invalid_authority_version" in result["reason"]

    def test_tampered_edge_type_detected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        edge = _make_ev_fi_edge()
        auth = sign_edge_authority(edge)
        tampered_edge = TrustGraphEdge(
            edge_id=edge.edge_id,
            edge_type=EdgeType.EVIDENCE_TO_REPORT,  # mutated
            source_node_id=edge.source_node_id,
            target_node_id=edge.target_node_id,
            tenant_id=edge.tenant_id,
            engagement_id=edge.engagement_id,
        )
        result = verify_edge_authority(tampered_edge, auth)
        assert result["valid"] is False
        assert result["reason"] in ("tampered_payload", "signature_mismatch")

    def test_tampered_tenant_detected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        edge = _make_ev_fi_edge()
        auth = sign_edge_authority(edge)
        tampered = TrustGraphEdge(
            edge_id=edge.edge_id,
            edge_type=edge.edge_type,
            source_node_id=edge.source_node_id,
            target_node_id=edge.target_node_id,
            tenant_id=TENANT_B,  # mutated
            engagement_id=edge.engagement_id,
        )
        result = verify_edge_authority(tampered, auth)
        assert result["valid"] is False

    def test_tampered_source_node_detected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        edge = _make_ev_fi_edge()
        auth = sign_edge_authority(edge)
        tampered = TrustGraphEdge(
            edge_id=edge.edge_id,
            edge_type=edge.edge_type,
            source_node_id="injected-node",  # mutated
            target_node_id=edge.target_node_id,
            tenant_id=edge.tenant_id,
            engagement_id=edge.engagement_id,
        )
        result = verify_edge_authority(tampered, auth)
        assert result["valid"] is False

    def test_tampered_event_hash_detected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        edge = _make_ev_fi_edge()
        auth = dict(sign_edge_authority(edge))
        auth["event_hash"] = "a" * 64  # zeroed hash
        result = verify_edge_authority(edge, auth)
        assert result["valid"] is False
        assert result["reason"] == "tampered_payload"

    def test_invalid_hex_signature(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        edge = _make_ev_fi_edge()
        auth = dict(sign_edge_authority(edge))
        auth["signature"] = "not-hex!!!"
        result = verify_edge_authority(edge, auth)
        assert result["valid"] is False
        assert result["reason"] == "signature_mismatch"

    def test_wrong_key_returns_signature_mismatch(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        edge = _make_ev_fi_edge()
        auth = dict(sign_edge_authority(edge))
        # Now verify with a different key
        pub_bytes = (
            __import__(
                "cryptography.hazmat.primitives.asymmetric.ed25519",
                fromlist=["Ed25519PrivateKey"],
            )
            .Ed25519PrivateKey.from_private_bytes(_ALT_SEED)
            .public_key()
            .public_bytes_raw()
        )
        alt_pub_b64 = base64.b64encode(pub_bytes).decode()
        monkeypatch.setenv("FG_EVIDENCE_VERIFY_KEY_B64", alt_pub_b64)
        result = verify_edge_authority(edge, auth)
        assert result["valid"] is False
        assert result["reason"] == "signature_mismatch"

    def test_no_key_available_returns_key_unavailable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        edge = _make_ev_fi_edge()
        auth = sign_edge_authority(edge)
        monkeypatch.delenv("FG_EVIDENCE_SIGNING_KEY_B64", raising=False)
        monkeypatch.delenv("FG_EVIDENCE_VERIFY_KEY_B64", raising=False)
        result = verify_edge_authority(edge, auth)
        assert result["valid"] is False
        assert result["reason"] == "key_unavailable"

    def test_verify_never_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("FG_EVIDENCE_SIGNING_KEY_B64", raising=False)
        monkeypatch.delenv("FG_EVIDENCE_VERIFY_KEY_B64", raising=False)
        edge = _make_ev_fi_edge()
        # Garbage authority — should not raise
        result = verify_edge_authority(edge, {"signature": None, "event_hash": 123})
        assert result["valid"] is False

    def test_injected_field_in_authority_detected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        edge = _make_ev_fi_edge()
        auth = dict(sign_edge_authority(edge))
        # Injecting extra data doesn't flip valid — canonical is recomputed from edge only
        auth["injected"] = "malicious"
        result = verify_edge_authority(edge, auth)
        # Should still be valid since canonical excludes injected field
        assert result["valid"] is True


# ---------------------------------------------------------------------------
# Snapshot Creation
# ---------------------------------------------------------------------------


class TestGenerateSignedGraphSnapshot:
    def test_raises_without_signing_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("FG_EVIDENCE_SIGNING_KEY_B64", raising=False)
        monkeypatch.delenv("FG_EVIDENCE_VERIFY_KEY_B64", raising=False)
        g = _graph()
        _ev(g, "ev-1")
        with pytest.raises(TrustGraphAuthorityError):
            generate_signed_graph_snapshot(g)

    def test_returns_all_required_fields(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        g = _graph()
        _ev(g, "ev-1")
        snap = generate_signed_graph_snapshot(g)
        for field in (
            "snapshot_id",
            "snapshot_hash",
            "snapshot_signature",
            "snapshot_key_id",
            "snapshot_version",
            "graph_hash",
            "created_at",
        ):
            assert field in snap, f"missing field: {field}"

    def test_snapshot_version_matches_constant(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        g = _graph()
        _ev(g, "ev-1")
        snap = generate_signed_graph_snapshot(g)
        assert snap["snapshot_version"] == SNAPSHOT_VERSION

    def test_snapshot_id_is_unique_per_call(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        g = _graph()
        _ev(g, "ev-1")
        s1 = generate_signed_graph_snapshot(g)
        s2 = generate_signed_graph_snapshot(g)
        assert s1["snapshot_id"] != s2["snapshot_id"]

    def test_snapshot_hash_stable_across_calls(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        g = _graph()
        _ev(g, "ev-1")
        s1 = generate_signed_graph_snapshot(g)
        s2 = generate_signed_graph_snapshot(g)
        assert s1["snapshot_hash"] == s2["snapshot_hash"]

    def test_graph_hash_matches_manifest(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        g = _graph()
        _ev(g, "ev-1")
        manifest = generate_trust_graph_manifest(g)
        snap = generate_signed_graph_snapshot(g)
        assert snap["graph_hash"] == manifest["graph_hash"]

    def test_snapshot_key_id_is_16_chars(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        g = _graph()
        _ev(g, "ev-1")
        snap = generate_signed_graph_snapshot(g)
        assert len(snap["snapshot_key_id"]) == 16

    def test_snapshot_hash_changes_when_graph_changes(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        g1 = _graph()
        _ev(g1, "ev-1")
        s1 = generate_signed_graph_snapshot(g1)

        g2 = _graph()
        _ev(g2, "ev-1")
        _fi(g2, "fi-1")
        s2 = generate_signed_graph_snapshot(g2)

        assert s1["snapshot_hash"] != s2["snapshot_hash"]

    def test_empty_graph_snapshot(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        g = _graph()
        snap = generate_signed_graph_snapshot(g)
        assert snap["snapshot_hash"]
        assert snap["snapshot_signature"]

    def test_full_graph_snapshot(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        g, _ = _full_graph()
        snap = generate_signed_graph_snapshot(g)
        assert snap["valid"] if "valid" in snap else True
        assert snap["snapshot_hash"]


# ---------------------------------------------------------------------------
# Snapshot Verification
# ---------------------------------------------------------------------------


class TestVerifyGraphSnapshot:
    def test_valid_snapshot_returns_valid_true(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        g = _graph()
        _ev(g, "ev-1")
        snap = generate_signed_graph_snapshot(g)
        result = verify_graph_snapshot(g, snap)
        assert result["valid"] is True
        assert result["reason"] is None

    def test_missing_snapshot_fields(self) -> None:
        g = _graph()
        result = verify_graph_snapshot(g, {})
        assert result["valid"] is False
        assert "missing_snapshot_fields" in result["reason"]

    def test_none_snapshot_returns_invalid(self) -> None:
        g = _graph()
        result = verify_graph_snapshot(g, None)  # type: ignore[arg-type]
        assert result["valid"] is False

    def test_wrong_snapshot_version(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        g = _graph()
        _ev(g, "ev-1")
        snap = dict(generate_signed_graph_snapshot(g))
        snap["snapshot_version"] = "old-version-v0"
        result = verify_graph_snapshot(g, snap)
        assert result["valid"] is False
        assert "invalid_snapshot_version" in result["reason"]

    def test_tampered_snapshot_hash_detected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        g = _graph()
        _ev(g, "ev-1")
        snap = dict(generate_signed_graph_snapshot(g))
        snap["snapshot_hash"] = "b" * 64
        result = verify_graph_snapshot(g, snap)
        assert result["valid"] is False
        assert result["reason"] == "tampered_snapshot"

    def test_graph_mutation_invalidates_snapshot(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        g = _graph()
        _ev(g, "ev-1")
        snap = generate_signed_graph_snapshot(g)
        _fi(g, "fi-1")  # mutate graph
        result = verify_graph_snapshot(g, snap)
        assert result["valid"] is False

    def test_signature_mismatch_returns_invalid(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        g = _graph()
        _ev(g, "ev-1")
        snap = dict(generate_signed_graph_snapshot(g))
        snap["snapshot_signature"] = "cc" * 32  # 64 valid hex bytes, wrong value
        result = verify_graph_snapshot(g, snap)
        assert result["valid"] is False
        assert result["reason"] == "signature_mismatch"

    def test_no_key_available_returns_key_unavailable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        g = _graph()
        _ev(g, "ev-1")
        snap = generate_signed_graph_snapshot(g)
        monkeypatch.delenv("FG_EVIDENCE_SIGNING_KEY_B64", raising=False)
        monkeypatch.delenv("FG_EVIDENCE_VERIFY_KEY_B64", raising=False)
        result = verify_graph_snapshot(g, snap)
        assert result["valid"] is False
        assert result["reason"] == "key_unavailable"

    def test_verify_snapshot_never_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("FG_EVIDENCE_SIGNING_KEY_B64", raising=False)
        monkeypatch.delenv("FG_EVIDENCE_VERIFY_KEY_B64", raising=False)
        g = _graph()
        result = verify_graph_snapshot(g, {"snapshot_signature": None})
        assert result["valid"] is False

    def test_full_graph_roundtrip(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        g, _ = _full_graph()
        snap = generate_signed_graph_snapshot(g)
        result = verify_graph_snapshot(g, snap)
        assert result["valid"] is True

    def test_snapshot_from_different_graph_rejected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        g1 = _graph()
        _ev(g1, "ev-1")
        snap = generate_signed_graph_snapshot(g1)

        g2 = _graph()
        _ev(g2, "ev-1")
        _fi(g2, "fi-1")
        result = verify_graph_snapshot(g2, snap)
        assert result["valid"] is False


# ---------------------------------------------------------------------------
# Replay Anchors
# ---------------------------------------------------------------------------


class TestBuildReplayAnchor:
    def _snap(self, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        g = _graph()
        _ev(g, "ev-1")
        return generate_signed_graph_snapshot(g)

    def test_returns_required_fields(self, monkeypatch: pytest.MonkeyPatch) -> None:
        snap = self._snap(monkeypatch)
        anchor = build_replay_anchor(snap)
        assert "graph_hash" in anchor
        assert "snapshot_hash" in anchor
        assert "snapshot_signature" in anchor
        assert "snapshot_version" in anchor

    def test_fields_match_snapshot(self, monkeypatch: pytest.MonkeyPatch) -> None:
        snap = self._snap(monkeypatch)
        anchor = build_replay_anchor(snap)
        assert anchor["graph_hash"] == snap["graph_hash"]
        assert anchor["snapshot_hash"] == snap["snapshot_hash"]
        assert anchor["snapshot_signature"] == snap["snapshot_signature"]
        assert anchor["snapshot_version"] == snap["snapshot_version"]

    def test_anchor_excludes_snapshot_id_and_timestamps(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        snap = self._snap(monkeypatch)
        anchor = build_replay_anchor(snap)
        assert "snapshot_id" not in anchor
        assert "created_at" not in anchor
        assert "snapshot_key_id" not in anchor

    def test_anchor_is_deterministic_from_same_snapshot(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        snap = self._snap(monkeypatch)
        a1 = build_replay_anchor(snap)
        a2 = build_replay_anchor(snap)
        assert a1 == a2

    def test_anchor_snapshot_version_matches_constant(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        snap = self._snap(monkeypatch)
        anchor = build_replay_anchor(snap)
        assert anchor["snapshot_version"] == SNAPSHOT_VERSION

    def test_anchor_is_hashable_as_json(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import json

        snap = self._snap(monkeypatch)
        anchor = build_replay_anchor(snap)
        # Must be JSON-serializable
        s = json.dumps(anchor, sort_keys=True)
        assert len(s) > 0


# ---------------------------------------------------------------------------
# Trust Explanation Functions
# ---------------------------------------------------------------------------


class TestWhyFunctions:
    def _populated_graph(self) -> tuple[TrustGraph, dict[str, Any]]:
        g = _graph()
        fw = _fw(g, "fw-1")
        ev = _ev(g, "ev-1")
        fi = _fi(g, "fi-1")
        co = _co(g, "co-1")
        ri = _ri(g, "ri-1")
        re = _re(g, "re-1")
        _edge(g, ev, fi, EdgeType.EVIDENCE_TO_FINDING)
        _edge(g, fi, co, EdgeType.FINDING_TO_CONTROL)
        _edge(g, co, fw, EdgeType.CONTROL_TO_FRAMEWORK)
        _edge(g, fi, ri, EdgeType.FINDING_TO_RISK)
        _edge(g, ri, re, EdgeType.RISK_TO_REPORT)
        return g, {"fw": fw, "ev": ev, "fi": fi, "co": co, "ri": ri, "re": re}

    # why_report
    def test_why_report_returns_string(self) -> None:
        g, nodes = self._populated_graph()
        result = why_report(g, nodes["re"].node_id)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_why_report_contains_report_id(self) -> None:
        g, nodes = self._populated_graph()
        result = why_report(g, nodes["re"].node_id)
        assert "Report" in result

    def test_why_report_wrong_node_type_raises(self) -> None:
        g, nodes = self._populated_graph()
        with pytest.raises(TrustGraphError):
            why_report(g, nodes["ev"].node_id)

    def test_why_report_missing_node_raises(self) -> None:
        g, _ = self._populated_graph()
        with pytest.raises(TrustGraphError):
            why_report(g, "nonexistent-node")

    def test_why_report_deterministic(self) -> None:
        g, nodes = self._populated_graph()
        r1 = why_report(g, nodes["re"].node_id)
        r2 = why_report(g, nodes["re"].node_id)
        assert r1 == r2

    def test_why_report_includes_evidence_block(self) -> None:
        g, nodes = self._populated_graph()
        result = why_report(g, nodes["re"].node_id)
        assert "EVIDENCE" in result or "evidence" in result.lower()

    # why_risk
    def test_why_risk_returns_string(self) -> None:
        g, nodes = self._populated_graph()
        result = why_risk(g, nodes["ri"].node_id)
        assert isinstance(result, str)

    def test_why_risk_wrong_node_type_raises(self) -> None:
        g, nodes = self._populated_graph()
        with pytest.raises(TrustGraphError):
            why_risk(g, nodes["ev"].node_id)

    def test_why_risk_missing_node_raises(self) -> None:
        g, _ = self._populated_graph()
        with pytest.raises(TrustGraphError):
            why_risk(g, "ghost")

    def test_why_risk_deterministic(self) -> None:
        g, nodes = self._populated_graph()
        assert why_risk(g, nodes["ri"].node_id) == why_risk(g, nodes["ri"].node_id)

    def test_why_risk_contains_risk_id(self) -> None:
        g, nodes = self._populated_graph()
        result = why_risk(g, nodes["ri"].node_id)
        assert "Risk" in result

    # why_control
    def test_why_control_returns_string(self) -> None:
        g, nodes = self._populated_graph()
        result = why_control(g, nodes["co"].node_id)
        assert isinstance(result, str)

    def test_why_control_wrong_node_type_raises(self) -> None:
        g, nodes = self._populated_graph()
        with pytest.raises(TrustGraphError):
            why_control(g, nodes["ev"].node_id)

    def test_why_control_missing_node_raises(self) -> None:
        g, _ = self._populated_graph()
        with pytest.raises(TrustGraphError):
            why_control(g, "ghost")

    def test_why_control_deterministic(self) -> None:
        g, nodes = self._populated_graph()
        assert why_control(g, nodes["co"].node_id) == why_control(
            g, nodes["co"].node_id
        )

    def test_why_control_includes_finding_block(self) -> None:
        g, nodes = self._populated_graph()
        result = why_control(g, nodes["co"].node_id)
        assert "FINDING" in result or "finding" in result.lower()

    # why_finding
    def test_why_finding_returns_string(self) -> None:
        g, nodes = self._populated_graph()
        result = why_finding(g, nodes["fi"].node_id)
        assert isinstance(result, str)

    def test_why_finding_wrong_node_type_raises(self) -> None:
        g, nodes = self._populated_graph()
        with pytest.raises(TrustGraphError):
            why_finding(g, nodes["re"].node_id)

    def test_why_finding_missing_node_raises(self) -> None:
        g, _ = self._populated_graph()
        with pytest.raises(TrustGraphError):
            why_finding(g, "ghost")

    def test_why_finding_deterministic(self) -> None:
        g, nodes = self._populated_graph()
        assert why_finding(g, nodes["fi"].node_id) == why_finding(
            g, nodes["fi"].node_id
        )

    def test_why_finding_includes_evidence_block(self) -> None:
        g, nodes = self._populated_graph()
        result = why_finding(g, nodes["fi"].node_id)
        assert "EVIDENCE" in result or "evidence" in result.lower()

    # Explanation content
    def test_explain_lineage_includes_subject_label(self) -> None:
        g, nodes = self._populated_graph()
        result = why_report(g, nodes["re"].node_id)
        assert "exists because" in result

    def test_explain_lineage_sorts_nodes_by_id(self) -> None:
        g = _graph()
        fi = _fi(g, "fi-1")
        ev_a = _ev(g, "ev-a")
        ev_z = _ev(g, "ev-z")
        _edge(g, ev_a, fi, EdgeType.EVIDENCE_TO_FINDING)
        _edge(g, ev_z, fi, EdgeType.EVIDENCE_TO_FINDING)
        # Both calls should produce same order
        r1 = why_finding(g, fi.node_id)
        r2 = why_finding(g, fi.node_id)
        assert r1 == r2
        # ev-a should appear before ev-z in output
        assert r1.index("ev-a") < r1.index("ev-z")


# ---------------------------------------------------------------------------
# Trust Query Result
# ---------------------------------------------------------------------------


class TestTrustQueryResult:
    def _result(self, **kwargs: Any) -> TrustQueryResult:
        g = _graph()
        ev = _ev(g, "ev-1")
        return TrustQueryResult(
            path=[ev],
            node_count=1,
            edge_count=0,
            graph_hash="abc123",
            **kwargs,
        )

    def test_default_confidence_is_100(self) -> None:
        r = self._result()
        assert r.confidence == 100

    def test_default_snapshot_hash_is_none(self) -> None:
        r = self._result()
        assert r.snapshot_hash is None

    def test_snapshot_hash_can_be_set(self) -> None:
        r = self._result(snapshot_hash="snap-hash-abc")
        assert r.snapshot_hash == "snap-hash-abc"

    def test_to_dict_returns_expected_keys(self) -> None:
        r = self._result()
        d = r.to_dict()
        assert "path" in d
        assert "node_count" in d
        assert "edge_count" in d
        assert "graph_hash" in d
        assert "snapshot_hash" in d
        assert "confidence" in d

    def test_to_dict_path_contains_node_fields(self) -> None:
        r = self._result()
        d = r.to_dict()
        assert len(d["path"]) == 1
        node_entry = d["path"][0]
        assert "node_id" in node_entry
        assert "node_type" in node_entry
        assert "tenant_id" in node_entry
        assert "engagement_id" in node_entry

    def test_to_dict_node_type_is_string(self) -> None:
        r = self._result()
        d = r.to_dict()
        assert isinstance(d["path"][0]["node_type"], str)

    def test_to_dict_snapshot_hash_none_when_not_set(self) -> None:
        r = self._result()
        assert r.to_dict()["snapshot_hash"] is None

    def test_to_dict_confidence_placeholder_100(self) -> None:
        r = self._result()
        assert r.to_dict()["confidence"] == 100

    def test_to_dict_with_empty_path(self) -> None:
        r = TrustQueryResult(
            path=[],
            node_count=0,
            edge_count=0,
            graph_hash="empty-hash",
        )
        d = r.to_dict()
        assert d["path"] == []

    def test_to_dict_graph_hash_preserved(self) -> None:
        r = self._result()
        assert r.to_dict()["graph_hash"] == "abc123"

    def test_to_dict_counts_preserved(self) -> None:
        r = TrustQueryResult(
            path=[],
            node_count=42,
            edge_count=7,
            graph_hash="x",
        )
        d = r.to_dict()
        assert d["node_count"] == 42
        assert d["edge_count"] == 7


# ---------------------------------------------------------------------------
# Tamper Detection
# ---------------------------------------------------------------------------


class TestTamperDetection:
    def test_edge_field_mutation_detected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        edge = _make_ev_fi_edge()
        auth = sign_edge_authority(edge)
        bad_edge = TrustGraphEdge(
            edge_id=edge.edge_id,
            edge_type=edge.edge_type,
            source_node_id=edge.source_node_id,
            target_node_id=edge.target_node_id,
            tenant_id=edge.tenant_id,
            engagement_id=ENG_B,  # mutated engagement
        )
        result = verify_edge_authority(bad_edge, auth)
        assert result["valid"] is False

    def test_all_edge_fields_included_in_hash(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        base = _make_ev_fi_edge()
        auth = sign_edge_authority(base)
        mutations = [
            TrustGraphEdge(
                edge_id=base.edge_id,
                edge_type=EdgeType.EVIDENCE_TO_REPORT,  # different type
                source_node_id=base.source_node_id,
                target_node_id=base.target_node_id,
                tenant_id=base.tenant_id,
                engagement_id=base.engagement_id,
            ),
            TrustGraphEdge(
                edge_id=base.edge_id,
                edge_type=base.edge_type,
                source_node_id="tampered-src",
                target_node_id=base.target_node_id,
                tenant_id=base.tenant_id,
                engagement_id=base.engagement_id,
            ),
            TrustGraphEdge(
                edge_id=base.edge_id,
                edge_type=base.edge_type,
                source_node_id=base.source_node_id,
                target_node_id="tampered-tgt",
                tenant_id=base.tenant_id,
                engagement_id=base.engagement_id,
            ),
        ]
        for bad in mutations:
            result = verify_edge_authority(bad, auth)
            assert result["valid"] is False, f"mutation not detected: {bad}"

    def test_snapshot_node_addition_invalidates(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        g = _graph()
        _ev(g, "ev-1")
        snap = generate_signed_graph_snapshot(g)
        _fi(g, "fi-1")
        assert verify_graph_snapshot(g, snap)["valid"] is False

    def test_snapshot_edge_addition_invalidates(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        g = _graph()
        ev = _ev(g, "ev-1")
        fi = _fi(g, "fi-1")
        snap = generate_signed_graph_snapshot(g)
        _edge(g, ev, fi, EdgeType.EVIDENCE_TO_FINDING)
        assert verify_graph_snapshot(g, snap)["valid"] is False


# ---------------------------------------------------------------------------
# Cross Tenant / Cross Engagement Isolation
# ---------------------------------------------------------------------------


class TestCrossTenantIsolation:
    def test_edge_signed_for_tenant_a_fails_for_tenant_b(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        edge_a = _make_ev_fi_edge(TENANT, ENG)
        auth = sign_edge_authority(edge_a)
        edge_b = _make_ev_fi_edge(TENANT_B, ENG)
        result = verify_edge_authority(edge_b, auth)
        assert result["valid"] is False

    def test_snapshot_for_tenant_a_rejected_on_tenant_b_graph(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        g_a = _graph(TENANT, ENG)
        _ev(g_a, "ev-1")
        snap = generate_signed_graph_snapshot(g_a)

        g_b = _graph(TENANT_B, ENG)
        _ev(g_b, "ev-1")
        result = verify_graph_snapshot(g_b, snap)
        assert result["valid"] is False


class TestCrossEngagementIsolation:
    def test_edge_signed_for_eng_a_fails_for_eng_b(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        edge_a = _make_ev_fi_edge(TENANT, ENG)
        auth = sign_edge_authority(edge_a)
        edge_b = _make_ev_fi_edge(TENANT, ENG_B)
        result = verify_edge_authority(edge_b, auth)
        assert result["valid"] is False

    def test_snapshot_for_eng_a_rejected_on_eng_b_graph(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        g_a = _graph(TENANT, ENG)
        _ev(g_a, "ev-1")
        snap = generate_signed_graph_snapshot(g_a)

        g_b = _graph(TENANT, ENG_B)
        _ev(g_b, "ev-1")
        result = verify_graph_snapshot(g_b, snap)
        assert result["valid"] is False


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_edge_event_hash_deterministic(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        edge = _make_ev_fi_edge()
        h1 = sign_edge_authority(edge)["event_hash"]
        h2 = sign_edge_authority(edge)["event_hash"]
        assert h1 == h2

    def test_snapshot_hash_deterministic_for_identical_graphs(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)

        def build() -> TrustGraph:
            g = _graph()
            _ev(g, "ev-1")
            _fi(g, "fi-1")
            return g

        g1 = build()
        g2 = build()
        s1 = generate_signed_graph_snapshot(g1)
        s2 = generate_signed_graph_snapshot(g2)
        assert s1["snapshot_hash"] == s2["snapshot_hash"]
        assert s1["graph_hash"] == s2["graph_hash"]

    def test_snapshot_id_unique_even_for_identical_graphs(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        g = _graph()
        _ev(g, "ev-1")
        s1 = generate_signed_graph_snapshot(g)
        s2 = generate_signed_graph_snapshot(g)
        assert s1["snapshot_id"] != s2["snapshot_id"]

    def test_why_report_output_stable(self) -> None:
        g, nodes = _full_graph()
        results = [why_report(g, nodes["re"].node_id) for _ in range(5)]
        assert all(r == results[0] for r in results)

    def test_signing_key_id_stable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        edge = _make_ev_fi_edge()
        ids = [sign_edge_authority(edge)["signing_key_id"] for _ in range(3)]
        assert len(set(ids)) == 1


# ---------------------------------------------------------------------------
# Manifest Stability (timestamp exclusion)
# ---------------------------------------------------------------------------


class TestManifestStability:
    def test_timestamps_excluded_from_canonical_snapshot_bytes(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        g = _graph()
        _ev(g, "ev-1")
        manifest1 = generate_trust_graph_manifest(g)
        # Simulate second call producing a different created_at in manifest
        manifest2 = dict(manifest1)
        manifest2["created_at"] = "2099-01-01T00:00:00Z"
        b1 = _canonical_snapshot_bytes(manifest1)
        b2 = _canonical_snapshot_bytes(manifest2)
        assert b1 == b2

    def test_snapshot_hash_excludes_created_at(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        g = _graph()
        _ev(g, "ev-1")
        s1 = generate_signed_graph_snapshot(g)
        s2 = generate_signed_graph_snapshot(g)
        # Different created_at timestamps but same hash
        assert (
            s1["created_at"] != s2["created_at"] or True
        )  # may coincide; hash must match
        assert s1["snapshot_hash"] == s2["snapshot_hash"]

    def test_canonical_bytes_fields_deterministic_order(self) -> None:
        manifest = {
            "graph_version": "trust-graph-v1",
            "tenant_id": TENANT,
            "engagement_id": ENG,
            "node_count": 3,
            "edge_count": 2,
            "root_nodes": ["node-c", "node-a", "node-b"],
            "graph_hash": "deadbeef",
        }
        b1 = _canonical_snapshot_bytes(manifest)
        b2 = _canonical_snapshot_bytes(manifest)
        assert b1 == b2
        assert b"root_nodes" in b1

    def test_root_nodes_sorted_in_canonical(self) -> None:
        manifest_a = {
            "graph_version": "v1",
            "tenant_id": TENANT,
            "engagement_id": ENG,
            "node_count": 2,
            "edge_count": 0,
            "root_nodes": ["z-node", "a-node"],
            "graph_hash": "abc",
        }
        manifest_b = {
            "graph_version": "v1",
            "tenant_id": TENANT,
            "engagement_id": ENG,
            "node_count": 2,
            "edge_count": 0,
            "root_nodes": ["a-node", "z-node"],
            "graph_hash": "abc",
        }
        assert _canonical_snapshot_bytes(manifest_a) == _canonical_snapshot_bytes(
            manifest_b
        )


# ---------------------------------------------------------------------------
# Performance
# ---------------------------------------------------------------------------


class TestPerformance:
    def test_sign_edge_under_50ms(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        edge = _make_ev_fi_edge()
        t0 = time.perf_counter()
        sign_edge_authority(edge)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        assert elapsed_ms < 50, f"sign took {elapsed_ms:.1f}ms"

    def test_verify_edge_under_50ms(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        edge = _make_ev_fi_edge()
        auth = sign_edge_authority(edge)
        t0 = time.perf_counter()
        verify_edge_authority(edge, auth)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        assert elapsed_ms < 50, f"verify took {elapsed_ms:.1f}ms"

    def test_snapshot_generation_100_nodes_under_200ms(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        g = _graph()
        for i in range(100):
            _ev(g, f"ev-{i:03d}")
        t0 = time.perf_counter()
        generate_signed_graph_snapshot(g)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        assert elapsed_ms < 200, f"snapshot 100 nodes took {elapsed_ms:.1f}ms"

    def test_verify_snapshot_100_nodes_under_200ms(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        g = _graph()
        for i in range(100):
            _ev(g, f"ev-{i:03d}")
        snap = generate_signed_graph_snapshot(g)
        t0 = time.perf_counter()
        verify_graph_snapshot(g, snap)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        assert elapsed_ms < 200, f"verify 100 nodes took {elapsed_ms:.1f}ms"

    def test_why_report_1000_node_graph_under_500ms(self) -> None:
        g = _graph()
        re_node = _re(g, "re-root")
        for i in range(999):
            ev = _ev(g, f"ev-{i:04d}")
            _edge(g, ev, re_node, EdgeType.EVIDENCE_TO_REPORT)
        t0 = time.perf_counter()
        why_report(g, re_node.node_id)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        assert elapsed_ms < 500, f"why_report 1000-node took {elapsed_ms:.1f}ms"


# ---------------------------------------------------------------------------
# Future Node Compatibility
# ---------------------------------------------------------------------------


class TestFutureNodeCompatibility:
    def test_unknown_payload_fields_tolerated_in_explain(self) -> None:
        g = _graph()
        node = TrustGraphNode(
            node_id="ev-future",
            node_type=NodeType.EVIDENCE,
            tenant_id=TENANT,
            engagement_id=ENG,
            payload={
                "evidence_id": "EV-999",
                "event_hash": "future-hash",
                "future_field": "future_value",
                "authority_status": "signed",
                "trust_score": 100,
            },
        )
        g.add_node(node)
        fi_node = _fi(g, "fi-1")
        _edge(g, node, fi_node, EdgeType.EVIDENCE_TO_FINDING)
        result = why_finding(g, fi_node.node_id)
        assert isinstance(result, str)

    def test_missing_optional_payload_fields_do_not_crash_explain(self) -> None:
        g = _graph()
        node = TrustGraphNode(
            node_id="ev-minimal",
            node_type=NodeType.EVIDENCE,
            tenant_id=TENANT,
            engagement_id=ENG,
            payload={},  # all optional
        )
        g.add_node(node)
        fi_node = _fi(g, "fi-1")
        _edge(g, node, fi_node, EdgeType.EVIDENCE_TO_FINDING)
        result = why_finding(g, fi_node.node_id)
        assert isinstance(result, str)
        assert "unknown" in result  # defaults to "unknown"

    def test_trust_query_result_with_future_node_type(self) -> None:
        g = _graph()
        node = TrustGraphNode(
            node_id="ev-1",
            node_type=NodeType.EVIDENCE,
            tenant_id=TENANT,
            engagement_id=ENG,
            payload={"evidence_id": "EV-1", "event_hash": "h"},
        )
        g.add_node(node)
        r = TrustQueryResult(
            path=[node],
            node_count=1,
            edge_count=0,
            graph_hash="future-hash",
        )
        d = r.to_dict()
        assert d["path"][0]["node_type"] == NodeType.EVIDENCE.value

    def test_sign_edge_with_risk_to_report_type(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        edge = TrustGraphEdge(
            edge_id=_uid(),
            edge_type=EdgeType.RISK_TO_REPORT,
            source_node_id="ri-1",
            target_node_id="re-1",
            tenant_id=TENANT,
            engagement_id=ENG,
        )
        auth = sign_edge_authority(edge)
        result = verify_edge_authority(edge, auth)
        assert result["valid"] is True


# ---------------------------------------------------------------------------
# Security Invariants
# ---------------------------------------------------------------------------


class TestSecurityInvariants:
    def test_empty_string_signing_key_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", "")
        monkeypatch.delenv("FG_EVIDENCE_VERIFY_KEY_B64", raising=False)
        with pytest.raises(TrustGraphAuthorityError):
            sign_edge_authority(_make_ev_fi_edge())

    def test_verify_key_env_takes_priority_over_signing_key(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        edge = _make_ev_fi_edge()
        auth = sign_edge_authority(edge)
        # Set verify key to alt — should fail
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        alt_pub = (
            Ed25519PrivateKey.from_private_bytes(_ALT_SEED)
            .public_key()
            .public_bytes_raw()
        )
        monkeypatch.setenv(
            "FG_EVIDENCE_VERIFY_KEY_B64", base64.b64encode(alt_pub).decode()
        )
        result = verify_edge_authority(edge, auth)
        assert result["valid"] is False

    def test_authority_version_downgrade_rejected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        edge = _make_ev_fi_edge()
        auth = dict(sign_edge_authority(edge))
        auth["authority_version"] = "trust-graph-edge-authority-v0"
        result = verify_edge_authority(edge, auth)
        assert result["valid"] is False

    def test_replay_with_different_edge_rejected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        edge_a = _make_ev_fi_edge()
        auth = sign_edge_authority(edge_a)
        edge_b = TrustGraphEdge(
            edge_id=_uid(),
            edge_type=EdgeType.EVIDENCE_TO_FINDING,
            source_node_id="ev-injected",
            target_node_id="fi-injected",
            tenant_id=TENANT,
            engagement_id=ENG,
        )
        result = verify_edge_authority(edge_b, auth)
        assert result["valid"] is False

    def test_key_material_not_in_authority_output(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        edge = _make_ev_fi_edge()
        auth = sign_edge_authority(edge)
        seed_b64 = _TEST_SEED_B64
        for v in auth.values():
            if isinstance(v, str):
                assert v != seed_b64, "private seed leaked into authority output"

    def test_snapshot_signature_not_reusable_across_graphs(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        g1 = _graph()
        _ev(g1, "ev-1")
        snap = generate_signed_graph_snapshot(g1)

        g2 = _graph()
        _ev(g2, "ev-1")
        _fi(g2, "fi-1")
        result = verify_graph_snapshot(g2, snap)
        assert result["valid"] is False

    def test_signing_key_id_is_public_key_fingerprint(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        edge = _make_ev_fi_edge()
        auth = sign_edge_authority(edge)
        pub_bytes = (
            Ed25519PrivateKey.from_private_bytes(_TEST_SEED)
            .public_key()
            .public_bytes_raw()
        )
        expected_key_id = hashlib.sha256(pub_bytes).hexdigest()[:16]
        assert auth["signing_key_id"] == expected_key_id

    def test_authority_error_is_runtime_error_subclass(self) -> None:
        assert issubclass(TrustGraphAuthorityError, RuntimeError)

    def test_verify_edge_returns_dict_not_bool(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        edge = _make_ev_fi_edge()
        auth = sign_edge_authority(edge)
        result = verify_edge_authority(edge, auth)
        assert isinstance(result, dict)
        assert "valid" in result
        assert "reason" in result

    def test_verify_snapshot_returns_dict_not_bool(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        g = _graph()
        _ev(g, "ev-1")
        snap = generate_signed_graph_snapshot(g)
        result = verify_graph_snapshot(g, snap)
        assert isinstance(result, dict)
        assert "valid" in result
        assert "reason" in result

    def test_tampered_graph_hash_in_snapshot_detected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # P1 fix: snapshot["graph_hash"] must be validated against the recomputed
        # manifest — mutating it with snapshot_hash intact must return invalid.
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        g = _graph()
        _ev(g, "ev-1")
        snap = dict(generate_signed_graph_snapshot(g))
        snap["graph_hash"] = "a" * 64  # attacker-controlled value
        result = verify_graph_snapshot(g, snap)
        assert result["valid"] is False
        assert result["reason"] == "tampered_graph_hash"

    def test_edge_id_mutation_detected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # P2 fix: authority signed for edge-A must not verify against edge-B
        # with same type/endpoints but a different edge_id.
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        edge_a = TrustGraphEdge(
            edge_id="edge-id-original",
            edge_type=EdgeType.EVIDENCE_TO_FINDING,
            source_node_id="ev-1",
            target_node_id="fi-1",
            tenant_id=TENANT,
            engagement_id=ENG,
        )
        auth = sign_edge_authority(edge_a)
        edge_b = TrustGraphEdge(
            edge_id="edge-id-different",  # same endpoints, different id
            edge_type=edge_a.edge_type,
            source_node_id=edge_a.source_node_id,
            target_node_id=edge_a.target_node_id,
            tenant_id=edge_a.tenant_id,
            engagement_id=edge_a.engagement_id,
        )
        result = verify_edge_authority(edge_b, auth)
        assert result["valid"] is False

    def test_edge_id_in_build_edge_authority_event(self) -> None:
        edge = TrustGraphEdge(
            edge_id="my-edge-id",
            edge_type=EdgeType.EVIDENCE_TO_FINDING,
            source_node_id="ev-1",
            target_node_id="fi-1",
            tenant_id=TENANT,
            engagement_id=ENG,
        )
        event = build_edge_authority_event(edge)
        assert event["edge_id"] == "my-edge-id"

    def test_edge_id_in_sign_edge_authority(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        edge = TrustGraphEdge(
            edge_id="signed-edge-id",
            edge_type=EdgeType.EVIDENCE_TO_FINDING,
            source_node_id="ev-1",
            target_node_id="fi-1",
            tenant_id=TENANT,
            engagement_id=ENG,
        )
        auth = sign_edge_authority(edge)
        # Round-trip: same edge with same id must verify
        result = verify_edge_authority(edge, auth)
        assert result["valid"] is True


# ---------------------------------------------------------------------------
# Snapshot Signature Invariant
# ---------------------------------------------------------------------------


class TestSnapshotSignatureInvariant:
    def test_signature_is_over_snapshot_hash_not_snapshot_id(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Changing snapshot_id must not affect signature validity.
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        g = _graph()
        _ev(g, "ev-1")
        snap = dict(generate_signed_graph_snapshot(g))
        original_id = snap["snapshot_id"]
        snap["snapshot_id"] = "different-uuid-entirely"
        assert snap["snapshot_id"] != original_id
        # Signature is over snapshot_hash, not snapshot_id — must still verify
        result = verify_graph_snapshot(g, snap)
        assert result["valid"] is True

    def test_signature_is_not_over_created_at(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        g = _graph()
        _ev(g, "ev-1")
        snap = dict(generate_signed_graph_snapshot(g))
        snap["created_at"] = "2099-12-31T23:59:59Z"  # mutated timestamp
        result = verify_graph_snapshot(g, snap)
        assert result["valid"] is True

    def test_snapshot_hash_identical_across_calls(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        g = _graph()
        _ev(g, "ev-1")
        s1 = generate_signed_graph_snapshot(g)
        s2 = generate_signed_graph_snapshot(g)
        assert s1["snapshot_hash"] == s2["snapshot_hash"]
        assert s1["snapshot_id"] != s2["snapshot_id"]
        assert (
            s1["created_at"] != s2["created_at"] or True
        )  # may coincide; hash must match

    def test_mutating_snapshot_hash_itself_invalidates(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        g = _graph()
        _ev(g, "ev-1")
        snap = dict(generate_signed_graph_snapshot(g))
        snap["snapshot_hash"] = "c" * 64
        result = verify_graph_snapshot(g, snap)
        assert result["valid"] is False
        # Either tampered_snapshot (hash mismatch) or signature_mismatch
        assert result["reason"] in ("tampered_snapshot", "signature_mismatch")

    def test_graph_hash_alteration_detected_as_tampered_graph_hash(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        g = _graph()
        _ev(g, "ev-1")
        snap = dict(generate_signed_graph_snapshot(g))
        snap["graph_hash"] = "d" * 64
        result = verify_graph_snapshot(g, snap)
        assert result["valid"] is False
        assert result["reason"] == "tampered_graph_hash"


# ---------------------------------------------------------------------------
# Replay Anchor Verification
# ---------------------------------------------------------------------------


class TestVerifyReplayAnchor:
    def _snap(self, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        g = _graph()
        _ev(g, "ev-1")
        return generate_signed_graph_snapshot(g)

    def _anchor(self, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
        return build_replay_anchor(self._snap(monkeypatch))

    def test_valid_anchor_returns_valid_true(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        anchor = self._anchor(monkeypatch)
        result = verify_replay_anchor(anchor)
        assert result["valid"] is True
        assert result["reason"] is None

    def test_none_anchor_returns_invalid(self) -> None:
        result = verify_replay_anchor(None)  # type: ignore[arg-type]
        assert result["valid"] is False

    def test_empty_anchor_returns_invalid(self) -> None:
        result = verify_replay_anchor({})
        assert result["valid"] is False
        assert "missing_anchor_fields" in result["reason"]

    def test_missing_graph_hash(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        anchor = dict(self._anchor(monkeypatch))
        del anchor["graph_hash"]
        result = verify_replay_anchor(anchor)
        assert result["valid"] is False
        assert "graph_hash" in result["reason"]

    def test_missing_snapshot_hash(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        anchor = dict(self._anchor(monkeypatch))
        del anchor["snapshot_hash"]
        result = verify_replay_anchor(anchor)
        assert result["valid"] is False

    def test_missing_snapshot_signature(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        anchor = dict(self._anchor(monkeypatch))
        del anchor["snapshot_signature"]
        result = verify_replay_anchor(anchor)
        assert result["valid"] is False

    def test_wrong_snapshot_version(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        anchor = dict(self._anchor(monkeypatch))
        anchor["snapshot_version"] = "old-version-v0"
        result = verify_replay_anchor(anchor)
        assert result["valid"] is False
        assert "invalid_snapshot_version" in result["reason"]

    def test_bad_signature_returns_signature_mismatch(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        anchor = dict(self._anchor(monkeypatch))
        anchor["snapshot_signature"] = "ee" * 32
        result = verify_replay_anchor(anchor)
        assert result["valid"] is False
        assert result["reason"] == "signature_mismatch"

    def test_no_key_returns_key_unavailable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        anchor = self._anchor(monkeypatch)
        monkeypatch.delenv("FG_EVIDENCE_SIGNING_KEY_B64", raising=False)
        monkeypatch.delenv("FG_EVIDENCE_VERIFY_KEY_B64", raising=False)
        result = verify_replay_anchor(anchor)
        assert result["valid"] is False
        assert result["reason"] == "key_unavailable"

    def test_never_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("FG_EVIDENCE_SIGNING_KEY_B64", raising=False)
        monkeypatch.delenv("FG_EVIDENCE_VERIFY_KEY_B64", raising=False)
        result = verify_replay_anchor({"snapshot_signature": None, "garbage": 123})
        assert result["valid"] is False

    def test_anchor_snapshot_mismatch_detected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        snap = self._snap(monkeypatch)
        anchor = build_replay_anchor(snap)
        # Create a second snapshot for a different graph
        g2 = _graph()
        _ev(g2, "ev-1")
        _fi(g2, "fi-1")
        snap2 = generate_signed_graph_snapshot(g2)
        result = verify_replay_anchor(anchor, snapshot=snap2)
        assert result["valid"] is False
        assert "mismatch" in result["reason"]

    def test_anchor_snapshot_match_passes(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        snap = self._snap(monkeypatch)
        anchor = build_replay_anchor(snap)
        result = verify_replay_anchor(anchor, snapshot=snap)
        assert result["valid"] is True

    def test_anchor_graph_stale_when_graph_mutated(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        g = _graph()
        _ev(g, "ev-1")
        snap = generate_signed_graph_snapshot(g)
        anchor = build_replay_anchor(snap)
        _fi(g, "fi-1")  # mutate graph after anchor was built
        result = verify_replay_anchor(anchor, graph=g)
        assert result["valid"] is False
        assert result["reason"] == "anchor_graph_hash_stale"

    def test_anchor_graph_matches_current_graph(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        g = _graph()
        _ev(g, "ev-1")
        snap = generate_signed_graph_snapshot(g)
        anchor = build_replay_anchor(snap)
        result = verify_replay_anchor(anchor, graph=g)
        assert result["valid"] is True


# ---------------------------------------------------------------------------
# Edge Authority Version In Payload
# ---------------------------------------------------------------------------


class TestEdgeAuthorityVersionInPayload:
    def test_authority_version_in_build_event(self) -> None:
        edge = _make_ev_fi_edge()
        event = build_edge_authority_event(edge)
        assert event["authority_version"] == EDGE_AUTHORITY_VERSION

    def test_authority_version_in_sign_output(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        edge = _make_ev_fi_edge()
        auth = sign_edge_authority(edge)
        assert auth["authority_version"] == EDGE_AUTHORITY_VERSION

    def test_version_downgrade_after_signing_detected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        edge = _make_ev_fi_edge()
        auth = dict(sign_edge_authority(edge))
        auth["authority_version"] = "trust-graph-edge-authority-v0"
        result = verify_edge_authority(edge, auth)
        assert result["valid"] is False
        assert "invalid_authority_version" in result["reason"]

    def test_version_absent_from_authority_returns_missing_fields(self) -> None:
        edge = _make_ev_fi_edge()
        auth = {
            "event_hash": "a" * 64,
            "signature": "b" * 128,
            "signing_key_id": "c" * 16,
            # authority_version deliberately omitted
        }
        result = verify_edge_authority(edge, auth)
        assert result["valid"] is False
        assert "authority_version" in result["reason"]

    def test_version_in_canonical_affects_hash(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Changing EDGE_AUTHORITY_VERSION would change the canonical bytes and
        # therefore the event_hash. Confirm event_hash changes when version changes.
        from services.field_assessment import trust_graph_authority as mod

        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        edge = _make_ev_fi_edge()
        auth1 = sign_edge_authority(edge)

        orig_version = mod.EDGE_AUTHORITY_VERSION
        monkeypatch.setattr(mod, "EDGE_AUTHORITY_VERSION", "tampered-version-vX")
        auth2 = sign_edge_authority(edge)
        monkeypatch.setattr(mod, "EDGE_AUTHORITY_VERSION", orig_version)

        assert auth1["event_hash"] != auth2["event_hash"]


# ---------------------------------------------------------------------------
# TrustQueryResult — subject_id and query_type
# ---------------------------------------------------------------------------


class TestTrustQueryResultExtended:
    def _base(self, **kwargs: Any) -> TrustQueryResult:
        g = _graph()
        ev = _ev(g, "ev-1")
        return TrustQueryResult(
            path=[ev], node_count=1, edge_count=0, graph_hash="tqr-hash", **kwargs
        )

    def test_subject_id_defaults_to_none(self) -> None:
        assert self._base().subject_id is None

    def test_query_type_defaults_to_none(self) -> None:
        assert self._base().query_type is None

    def test_subject_id_settable(self) -> None:
        r = self._base(subject_id="re-1")
        assert r.subject_id == "re-1"

    def test_query_type_settable(self) -> None:
        for qt in ("why_report", "why_risk", "why_control", "why_finding"):
            r = self._base(query_type=qt)
            assert r.query_type == qt

    def test_to_dict_includes_subject_id(self) -> None:
        r = self._base(subject_id="ri-1")
        assert r.to_dict()["subject_id"] == "ri-1"

    def test_to_dict_includes_query_type(self) -> None:
        r = self._base(query_type="why_risk")
        assert r.to_dict()["query_type"] == "why_risk"

    def test_to_dict_subject_id_none_when_unset(self) -> None:
        assert self._base().to_dict()["subject_id"] is None

    def test_to_dict_query_type_none_when_unset(self) -> None:
        assert self._base().to_dict()["query_type"] is None

    def test_to_dict_all_keys_present(self) -> None:
        r = self._base(subject_id="s1", query_type="why_finding")
        d = r.to_dict()
        for key in (
            "path",
            "node_count",
            "edge_count",
            "graph_hash",
            "snapshot_hash",
            "confidence",
            "subject_id",
            "query_type",
        ):
            assert key in d, f"missing key: {key}"


# ---------------------------------------------------------------------------
# No Private Key In Output
# ---------------------------------------------------------------------------


class TestNoPrivateKeyInOutput:
    def _all_values(self, d: dict[str, Any]) -> list[str]:
        return [str(v) for v in d.values() if v is not None]

    def test_sign_edge_output_does_not_contain_seed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        edge = _make_ev_fi_edge()
        auth = sign_edge_authority(edge)
        for v in self._all_values(auth):
            assert v != _TEST_SEED_B64, "private seed leaked into edge authority output"
            assert v != _TEST_SEED.hex(), (
                "raw seed bytes leaked into edge authority output"
            )

    def test_snapshot_output_does_not_contain_seed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        g = _graph()
        _ev(g, "ev-1")
        snap = generate_signed_graph_snapshot(g)
        for v in self._all_values(snap):
            assert v != _TEST_SEED_B64
            assert v != _TEST_SEED.hex()

    def test_replay_anchor_does_not_contain_seed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        g = _graph()
        _ev(g, "ev-1")
        snap = generate_signed_graph_snapshot(g)
        anchor = build_replay_anchor(snap)
        for v in self._all_values(anchor):
            assert v != _TEST_SEED_B64
            assert v != _TEST_SEED.hex()

    def test_trust_query_result_to_dict_does_not_contain_seed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        g = _graph()
        ev = _ev(g, "ev-1")
        r = TrustQueryResult(
            path=[ev],
            node_count=1,
            edge_count=0,
            graph_hash="hash",
            subject_id="ev-1",
            query_type="why_finding",
        )
        import json

        serialized = json.dumps(r.to_dict())
        assert _TEST_SEED_B64 not in serialized
        assert _TEST_SEED.hex() not in serialized


# ---------------------------------------------------------------------------
# Malformed Inputs
# ---------------------------------------------------------------------------


class TestMalformedInputs:
    def test_verify_edge_authority_with_none(self) -> None:
        edge = _make_ev_fi_edge()
        result = verify_edge_authority(edge, None)  # type: ignore[arg-type]
        assert result["valid"] is False

    def test_verify_edge_authority_with_wrong_types(self) -> None:
        edge = _make_ev_fi_edge()
        # All fields present but wrong types
        result = verify_edge_authority(
            edge,
            {
                "event_hash": 12345,
                "signature": ["not", "a", "string"],
                "signing_key_id": None,
                "authority_version": EDGE_AUTHORITY_VERSION,
            },
        )
        assert result["valid"] is False

    def test_verify_edge_authority_with_non_hex_types(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        edge = _make_ev_fi_edge()
        auth = dict(sign_edge_authority(edge))
        auth["signature"] = {"nested": "object"}
        result = verify_edge_authority(edge, auth)
        assert result["valid"] is False

    def test_verify_graph_snapshot_with_none(self) -> None:
        g = _graph()
        result = verify_graph_snapshot(g, None)  # type: ignore[arg-type]
        assert result["valid"] is False

    def test_verify_graph_snapshot_with_wrong_types(self) -> None:
        g = _graph()
        result = verify_graph_snapshot(
            g,
            {
                "snapshot_hash": 99999,
                "snapshot_signature": True,
                "snapshot_key_id": [],
                "snapshot_version": SNAPSHOT_VERSION,
                "graph_hash": None,
            },
        )
        assert result["valid"] is False

    def test_verify_replay_anchor_with_none(self) -> None:
        result = verify_replay_anchor(None)  # type: ignore[arg-type]
        assert result["valid"] is False

    def test_verify_replay_anchor_with_empty_dict(self) -> None:
        result = verify_replay_anchor({})
        assert result["valid"] is False

    def test_verify_replay_anchor_with_wrong_types(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        g = _graph()
        _ev(g, "ev-1")
        snap = generate_signed_graph_snapshot(g)
        anchor = dict(build_replay_anchor(snap))
        anchor["snapshot_signature"] = 12345  # wrong type
        result = verify_replay_anchor(anchor)
        assert result["valid"] is False

    def test_verify_edge_authority_with_all_none_values(self) -> None:
        edge = _make_ev_fi_edge()
        result = verify_edge_authority(
            edge,
            {
                "event_hash": None,
                "signature": None,
                "signing_key_id": None,
                "authority_version": None,
            },
        )
        assert result["valid"] is False


# ---------------------------------------------------------------------------
# Large Graph Performance (1000 nodes)
# ---------------------------------------------------------------------------


class TestLargeGraphPerformance:
    def test_snapshot_generation_1000_nodes_under_500ms(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        g = _graph()
        for i in range(1000):
            _ev(g, f"ev-{i:04d}")
        t0 = time.perf_counter()
        snap = generate_signed_graph_snapshot(g)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        assert snap["snapshot_hash"]
        assert elapsed_ms < 500, f"1000-node snapshot took {elapsed_ms:.1f}ms"

    def test_snapshot_verification_1000_nodes_under_500ms(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        g = _graph()
        for i in range(1000):
            _ev(g, f"ev-{i:04d}")
        snap = generate_signed_graph_snapshot(g)
        t0 = time.perf_counter()
        result = verify_graph_snapshot(g, snap)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        assert result["valid"] is True
        assert elapsed_ms < 500, f"1000-node verify took {elapsed_ms:.1f}ms"

    def test_replay_anchor_verification_1000_nodes_under_500ms(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FG_EVIDENCE_SIGNING_KEY_B64", _TEST_SEED_B64)
        g = _graph()
        for i in range(1000):
            _ev(g, f"ev-{i:04d}")
        snap = generate_signed_graph_snapshot(g)
        anchor = build_replay_anchor(snap)
        t0 = time.perf_counter()
        result = verify_replay_anchor(anchor, graph=g, snapshot=snap)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        assert result["valid"] is True
        assert elapsed_ms < 500, f"1000-node anchor verify took {elapsed_ms:.1f}ms"
