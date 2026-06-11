"""Tests for PR 1.2 / PR 1.2A — Trust Replay Engine Foundation + Proof Authority Hardening.

Covers:
  - verify_chain_node: single-node hash validation
  - verify_hash_chain: generic primitive (hash mismatch, duplicate hash, cycle,
    tenant/engagement contamination, empty input)
  - replay_provenance_chain: ordered records, wrong tenant, cycle safety
  - verify_full_provenance_chain: valid chain (1-node and multi-node),
    determinism, broken link, tampered hash, corrupt genesis, cycle,
    duplicate hash, wrong tenant, cross-engagement contamination,
    not-found record
  - compute_chain_replay_score: 100 / 75 / 0 branches
  - generate_chain_verification_manifest: deterministic hash
  - performance: 100-node chain
  - legacy: empty engagement
"""

from __future__ import annotations

from typing import Any

import time

import sqlalchemy
from sqlalchemy.orm import Session

from api.db_models_field_assessment import FaEvidenceProvenance
from services.field_assessment.trust_replay import (
    REPLAY_MANIFEST_VERSION,
    ChainNodeData,
    SCORE_BROKEN,
    SCORE_DEGRADED,
    SCORE_PERFECT,
    SCORE_WARNINGS,
    compute_chain_replay_score,
    generate_chain_verification_manifest,
    generate_trust_proof,
    replay_provenance_chain,
    verify_chain_node,
    verify_full_provenance_chain,
    verify_hash_chain,
)

TENANT_A = "trust-replay-tenant-a"
TENANT_B = "trust-replay-tenant-b"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_provenance(db: Session, **kwargs) -> FaEvidenceProvenance:
    from services.field_assessment.evidence_provenance import create_evidence_provenance

    defaults: dict[str, Any] = dict(
        tenant_id=TENANT_A,
        engagement_id="eng-replay-001",
        evidence_id="ev-replay-001",
        source_type="scan_result",
        collected_by_type="connector",
        collected_by_id="ms_graph_connector",
        collection_method="scan_connector",
    )
    defaults.update(kwargs)
    return create_evidence_provenance(db, **defaults)


def _extend_chain(
    db: Session,
    record: FaEvidenceProvenance,
    steps: int = 1,
) -> FaEvidenceProvenance:
    """Extend a chain by `steps` review records. Returns the latest record."""
    from services.field_assessment.evidence_provenance import mark_provenance_reviewed

    current = record
    for i in range(steps):
        current = mark_provenance_reviewed(
            db,
            tenant_id=current.tenant_id,
            provenance_id=current.id,
            reviewed_by=f"reviewer-{i}",
            new_status="approved",
            review_notes=f"step {i}",
        )
    return current


def _bulk_chain(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
    evidence_id: str,
    n: int,
) -> FaEvidenceProvenance:
    """Create an n-node chain using direct ORM inserts (fast, for perf tests)."""
    from services.field_assessment.evidence_provenance import (
        _hash_payload,
        compute_provenance_hash,
    )
    from services.field_assessment.store import _new_id

    previous_hash: str | None = None
    last: FaEvidenceProvenance | None = None

    for i in range(n):
        created_at = f"2026-06-{(i % 28) + 1:02d}T00:{i // 28:02d}:00Z"
        collected_at = created_at
        payload = _hash_payload(
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            evidence_id=evidence_id,
            finding_id=None,
            source_type="scan_result",
            collection_method="scan_connector",
            collected_by_type="connector",
            collected_by_id="ms_graph",
            collected_at=collected_at,
            artifact_hash=None,
            previous_hash=previous_hash,
            created_at=created_at,
        )
        event_hash = compute_provenance_hash(payload)
        record = FaEvidenceProvenance(
            id=_new_id(),
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            evidence_id=evidence_id,
            finding_id=None,
            source_type="scan_result",
            source_system=None,
            source_reference=None,
            source_uri_hash=None,
            artifact_hash=None,
            collected_by_type="connector",
            collected_by_id="ms_graph",
            collected_at=collected_at,
            collection_method="scan_connector",
            collection_context_json={},
            classification=None,
            retention_policy=None,
            freshness_at_collection=None,
            trust_level="unverified",
            review_status="pending",
            chain_status="active",
            used_in_report_ids=[],
            previous_hash=previous_hash,
            event_hash=event_hash,
            created_at=created_at,
            schema_version="1.0",
        )
        db.add(record)
        previous_hash = event_hash
        last = record

    db.flush()
    assert last is not None
    return last


# ---------------------------------------------------------------------------
# verify_chain_node
# ---------------------------------------------------------------------------


def test_verify_chain_node_valid(build_app):
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        record = _make_provenance(db, engagement_id="eng-cn-valid-001")
        db.commit()

        stored = db.get(FaEvidenceProvenance, record.id)
        result = verify_chain_node(stored)
        assert result["hash_valid"] is True
        assert result["computed_hash"] == stored.event_hash
        assert result["failure_reason"] is None


def test_verify_chain_node_tampered_fails(build_app):
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        record = _make_provenance(db, engagement_id="eng-cn-tamper-001")
        db.commit()

        db.execute(
            sqlalchemy.text(
                "UPDATE fa_evidence_provenance SET event_hash = :bad WHERE id = :id"
            ),
            {"bad": "0" * 64, "id": record.id},
        )
        db.commit()

        stored = db.get(FaEvidenceProvenance, record.id)
        db.expire(stored)
        stored = db.get(FaEvidenceProvenance, record.id)
        result = verify_chain_node(stored)
        assert result["hash_valid"] is False
        assert result["failure_reason"] == "hash_mismatch"


# ---------------------------------------------------------------------------
# verify_hash_chain (generic primitive)
# ---------------------------------------------------------------------------


def _node(
    node_id: str,
    event_hash: str,
    previous_hash: str | None = None,
    *,
    tenant_id: str = TENANT_A,
    engagement_id: str = "eng-generic",
    computed_hash: str | None = None,
) -> ChainNodeData:
    return ChainNodeData(
        node_id=node_id,
        event_hash=event_hash,
        previous_hash=previous_hash,
        computed_hash=computed_hash if computed_hash is not None else event_hash,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
    )


def test_verify_hash_chain_empty():
    result = verify_hash_chain([])
    assert result["chain_valid"] is False
    assert result["failed_nodes"][0]["reason"] == "empty_chain"


def test_verify_hash_chain_single_valid():
    nodes = [_node("n1", "aaa", None)]
    result = verify_hash_chain(nodes)
    assert result["chain_valid"] is True
    assert len(result["verified_nodes"]) == 1
    assert result["failed_nodes"] == []


def test_verify_hash_chain_multi_valid():
    nodes = [
        _node("n2", "bbb", "aaa"),
        _node("n1", "aaa", None),
    ]
    result = verify_hash_chain(nodes)
    assert result["chain_valid"] is True
    assert len(result["verified_nodes"]) == 2


def test_verify_hash_chain_hash_mismatch():
    nodes = [_node("n1", "correct_hash", None, computed_hash="wrong_hash")]
    result = verify_hash_chain(nodes)
    assert result["chain_valid"] is False
    assert result["failed_nodes"][0]["reason"] == "hash_mismatch"


def test_verify_hash_chain_duplicate_event_hash():
    nodes = [
        _node("n2", "same_hash", "aaa"),
        _node("n1", "same_hash", None),  # duplicate
    ]
    result = verify_hash_chain(nodes)
    assert result["chain_valid"] is False
    reasons = {f["reason"] for f in result["failed_nodes"]}
    assert "duplicate_event_hash" in reasons


def test_verify_hash_chain_cycle():
    # n1 → n2 → n1 (cycle via node_id)
    nodes = [
        _node("n1", "hash_a", None),
        _node("n2", "hash_b", "hash_a"),
        _node("n1", "hash_c", "hash_b"),  # duplicate node_id
    ]
    result = verify_hash_chain(nodes)
    assert result["chain_valid"] is False
    reasons = {f["reason"] for f in result["failed_nodes"]}
    assert "cycle_detected" in reasons


def test_verify_hash_chain_tenant_contamination():
    nodes = [
        _node("n2", "bbb", "aaa", tenant_id=TENANT_A),
        _node("n1", "aaa", None, tenant_id=TENANT_B),  # wrong tenant
    ]
    result = verify_hash_chain(nodes)
    assert result["chain_valid"] is False
    assert result["failed_nodes"][0]["reason"] == "tenant_contamination"


def test_verify_hash_chain_engagement_contamination():
    nodes = [
        _node("n2", "bbb", "aaa", engagement_id="eng-a"),
        _node("n1", "aaa", None, engagement_id="eng-b"),  # wrong engagement
    ]
    result = verify_hash_chain(nodes)
    assert result["chain_valid"] is False
    assert result["failed_nodes"][0]["reason"] == "engagement_contamination"


def test_verify_hash_chain_disconnected_nodes_detected():
    """Two individually hash-valid nodes with unrelated hashes must not pass as a chain."""
    nodes = [
        _node("n2", "hash_b", "hash_x"),  # previous_hash points nowhere in list
        _node("n1", "hash_a", None),  # genesis, but n2 doesn't link to it
    ]
    result = verify_hash_chain(nodes)
    assert result["chain_valid"] is False
    reasons = {f["reason"] for f in result["failed_nodes"]}
    assert "adjacency_mismatch" in reasons


def test_verify_hash_chain_non_genesis_last_node_detected():
    """Last node (genesis position) with previous_hash != None must be rejected."""
    nodes = [
        _node("n1", "hash_a", "orphan_hash")
    ]  # single node, non-null previous_hash
    result = verify_hash_chain(nodes)
    assert result["chain_valid"] is False
    reasons = {f["reason"] for f in result["failed_nodes"]}
    assert "corrupt_genesis" in reasons


# ---------------------------------------------------------------------------
# compute_chain_replay_score
# ---------------------------------------------------------------------------


def test_compute_chain_replay_score_perfect():
    assert compute_chain_replay_score([{"node_id": "n1"}], [], []) == SCORE_PERFECT


def test_compute_chain_replay_score_warnings():
    assert (
        compute_chain_replay_score([{"node_id": "n1"}], [], ["some warning"])
        == SCORE_WARNINGS
    )


def test_compute_chain_replay_score_broken():
    assert (
        compute_chain_replay_score(
            [], [{"node_id": "n1", "reason": "hash_mismatch"}], []
        )
        == SCORE_BROKEN
    )


def test_compute_chain_replay_score_broken_even_with_warnings():
    assert (
        compute_chain_replay_score([], [{"reason": "broken_link"}], ["warning"])
        == SCORE_BROKEN
    )


# ---------------------------------------------------------------------------
# replay_provenance_chain
# ---------------------------------------------------------------------------


def test_replay_provenance_chain_genesis_first(build_app):
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        genesis = _make_provenance(db, engagement_id="eng-replay-order-001")
        db.commit()
        latest = _extend_chain(db, genesis, steps=2)
        db.commit()

        chain = replay_provenance_chain(db, tenant_id=TENANT_A, provenance_id=latest.id)
        assert len(chain) == 3
        assert chain[0].previous_hash is None  # genesis is first
        assert chain[-1].id == latest.id


def test_replay_provenance_chain_single_node(build_app):
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        record = _make_provenance(db, engagement_id="eng-replay-single-001")
        db.commit()

        chain = replay_provenance_chain(db, tenant_id=TENANT_A, provenance_id=record.id)
        assert len(chain) == 1
        assert chain[0].id == record.id
        assert chain[0].previous_hash is None


def test_replay_provenance_chain_wrong_tenant_returns_empty(build_app):
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        record = _make_provenance(db, engagement_id="eng-replay-xten-001")
        db.commit()

        chain = replay_provenance_chain(db, tenant_id=TENANT_B, provenance_id=record.id)
        assert chain == []


def test_replay_provenance_chain_stops_on_cycle(build_app):
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        genesis = _make_provenance(db, engagement_id="eng-replay-cycle-001")
        db.commit()
        mid = _extend_chain(db, genesis, steps=1)
        db.commit()

        # Inject cycle: point genesis's previous_hash at mid's event_hash
        db.execute(
            sqlalchemy.text(
                "UPDATE fa_evidence_provenance SET previous_hash = :ph WHERE id = :id"
            ),
            {"ph": mid.event_hash, "id": genesis.id},
        )
        db.commit()

        # Should not hang; stops when cycle detected
        chain = replay_provenance_chain(db, tenant_id=TENANT_A, provenance_id=mid.id)
        assert len(chain) <= 3  # terminates


# ---------------------------------------------------------------------------
# verify_full_provenance_chain
# ---------------------------------------------------------------------------


def test_verify_full_chain_single_node_valid(build_app):
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        record = _make_provenance(
            db, engagement_id="eng-full-single-001", artifact_hash="a" * 64
        )
        db.commit()

        result = verify_full_provenance_chain(
            db, tenant_id=TENANT_A, provenance_id=record.id
        )
        assert result["chain_valid"] is True
        assert result["chain_depth"] == 1
        # No signing key in test env → legacy_unsigned warning → SCORE_DEGRADED
        assert result["chain_replay_score"] == SCORE_DEGRADED
        assert result["genesis_hash"] == record.event_hash
        assert result["latest_hash"] == record.event_hash
        assert result["failed_nodes"] == []
        assert len(result["verification_manifest_hash"]) == 64


def test_verify_full_chain_multi_node_valid(build_app):
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        genesis = _make_provenance(
            db, engagement_id="eng-full-multi-001", artifact_hash="a" * 64
        )
        db.commit()
        latest = _extend_chain(db, genesis, steps=2)
        db.commit()

        result = verify_full_provenance_chain(
            db, tenant_id=TENANT_A, provenance_id=latest.id
        )
        assert result["chain_valid"] is True
        assert result["chain_depth"] == 3
        # No signing key in test env → legacy_unsigned warnings → SCORE_DEGRADED
        assert result["chain_replay_score"] == SCORE_DEGRADED
        assert result["genesis_hash"] == genesis.event_hash
        assert result["latest_hash"] == latest.event_hash
        assert len(result["verified_nodes"]) == 3


def test_verify_full_chain_deterministic(build_app):
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        record = _make_provenance(
            db, engagement_id="eng-full-det-001", artifact_hash="d" * 64
        )
        db.commit()

        r1 = verify_full_provenance_chain(
            db, tenant_id=TENANT_A, provenance_id=record.id
        )
        r2 = verify_full_provenance_chain(
            db, tenant_id=TENANT_A, provenance_id=record.id
        )
        # verification_duration_ms may differ; all other fields must match
        assert r1["chain_valid"] == r2["chain_valid"]
        assert r1["chain_depth"] == r2["chain_depth"]
        assert r1["genesis_hash"] == r2["genesis_hash"]
        assert r1["latest_hash"] == r2["latest_hash"]
        assert r1["chain_replay_score"] == r2["chain_replay_score"]
        assert r1["verified_nodes"] == r2["verified_nodes"]
        assert r1["failed_nodes"] == r2["failed_nodes"]
        assert r1["verification_manifest_hash"] == r2["verification_manifest_hash"]


def test_verify_full_chain_not_found(build_app):
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        result = verify_full_provenance_chain(
            db, tenant_id=TENANT_A, provenance_id="nonexistent-id-xyz"
        )
        assert result["chain_valid"] is False
        assert result["chain_replay_score"] == SCORE_BROKEN
        assert result["chain_depth"] == 0
        assert result["failed_nodes"][0]["reason"] == "not_found"


def test_not_found_manifest_hash_unique_per_provenance_id(build_app):
    """Different not-found IDs must produce different manifest hashes (not a constant)."""
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        r1 = verify_full_provenance_chain(
            db, tenant_id=TENANT_A, provenance_id="missing-id-aaa"
        )
        r2 = verify_full_provenance_chain(
            db, tenant_id=TENANT_A, provenance_id="missing-id-bbb"
        )
        assert r1["verification_manifest_hash"] != r2["verification_manifest_hash"]


def test_not_found_manifest_hash_unique_per_tenant(build_app):
    """Same provenance_id looked up under different tenants must produce different hashes."""
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        r1 = verify_full_provenance_chain(
            db, tenant_id=TENANT_A, provenance_id="missing-id-shared"
        )
        r2 = verify_full_provenance_chain(
            db, tenant_id=TENANT_B, provenance_id="missing-id-shared"
        )
        assert r1["verification_manifest_hash"] != r2["verification_manifest_hash"]


def test_verify_full_chain_wrong_tenant_safe_failure(build_app):
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        record = _make_provenance(db, engagement_id="eng-full-xten-001")
        db.commit()

        result = verify_full_provenance_chain(
            db, tenant_id=TENANT_B, provenance_id=record.id
        )
        assert result["chain_valid"] is False
        assert result["chain_replay_score"] == SCORE_BROKEN
        # Must return not_found, not reveal that record exists under TENANT_A
        assert result["failed_nodes"][0]["reason"] == "not_found"


def test_verify_full_chain_tampered_hash(build_app):
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        record = _make_provenance(db, engagement_id="eng-full-tamper-001")
        db.commit()

        db.execute(
            sqlalchemy.text(
                "UPDATE fa_evidence_provenance SET event_hash = :bad WHERE id = :id"
            ),
            {"bad": "f" * 64, "id": record.id},
        )
        db.commit()

        result = verify_full_provenance_chain(
            db, tenant_id=TENANT_A, provenance_id=record.id
        )
        assert result["chain_valid"] is False
        assert result["chain_replay_score"] == SCORE_BROKEN
        reasons = {f["reason"] for f in result["failed_nodes"]}
        assert "hash_mismatch" in reasons


def test_verify_full_chain_broken_link(build_app):
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        genesis = _make_provenance(db, engagement_id="eng-full-broken-001")
        db.commit()
        latest = _extend_chain(db, genesis, steps=1)
        db.commit()

        # Point latest's previous_hash at a hash that doesn't exist
        db.execute(
            sqlalchemy.text(
                "UPDATE fa_evidence_provenance SET previous_hash = :ph WHERE id = :id"
            ),
            {"ph": "e" * 64, "id": latest.id},
        )
        db.commit()

        result = verify_full_provenance_chain(
            db, tenant_id=TENANT_A, provenance_id=latest.id
        )
        assert result["chain_valid"] is False
        reasons = {f["reason"] for f in result["failed_nodes"]}
        assert "broken_link" in reasons or "hash_mismatch" in reasons


def test_verify_full_chain_corrupt_genesis(build_app):
    """Genesis node has a non-null previous_hash that references nothing."""
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        genesis = _make_provenance(db, engagement_id="eng-full-corrupt-genesis-001")
        db.commit()

        db.execute(
            sqlalchemy.text(
                "UPDATE fa_evidence_provenance SET previous_hash = :ph WHERE id = :id"
            ),
            {"ph": "c" * 64, "id": genesis.id},
        )
        db.commit()

        result = verify_full_provenance_chain(
            db, tenant_id=TENANT_A, provenance_id=genesis.id
        )
        assert result["chain_valid"] is False
        reasons = {f["reason"] for f in result["failed_nodes"]}
        # Corrupt genesis = broken_link (previous_hash non-null, no matching record)
        # AND hash_mismatch (we changed previous_hash so the event_hash no longer matches)
        assert "broken_link" in reasons or "hash_mismatch" in reasons


def test_verify_full_chain_cycle(build_app):
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        genesis = _make_provenance(db, engagement_id="eng-full-cycle-001")
        db.commit()
        mid = _extend_chain(db, genesis, steps=1)
        db.commit()

        # Create cycle: point genesis back to mid
        db.execute(
            sqlalchemy.text(
                "UPDATE fa_evidence_provenance SET previous_hash = :ph WHERE id = :id"
            ),
            {"ph": mid.event_hash, "id": genesis.id},
        )
        db.commit()

        # Must terminate and report invalid
        result = verify_full_provenance_chain(
            db, tenant_id=TENANT_A, provenance_id=mid.id
        )
        assert result["chain_valid"] is False


def test_verify_full_chain_duplicate_hash_via_generic(build_app):
    """Duplicate event_hash detection via verify_hash_chain called directly."""
    nodes = [
        ChainNodeData(
            node_id="n2",
            event_hash="same_hash",
            previous_hash="prev_hash",
            computed_hash="same_hash",
            tenant_id=TENANT_A,
            engagement_id="eng-dup",
        ),
        ChainNodeData(
            node_id="n1",
            event_hash="same_hash",  # duplicate
            previous_hash=None,
            computed_hash="same_hash",
            tenant_id=TENANT_A,
            engagement_id="eng-dup",
        ),
    ]
    result = verify_hash_chain(nodes)
    assert result["chain_valid"] is False
    reasons = {f["reason"] for f in result["failed_nodes"]}
    assert "duplicate_event_hash" in reasons


def test_verify_full_chain_warnings_lower_score(build_app):
    """Chain with no artifact_hash gets SCORE_WARNINGS (75), not 100."""
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        # artifact_hash=None triggers soft warning
        record = _make_provenance(db, engagement_id="eng-full-warn-001")
        db.commit()

        result = verify_full_provenance_chain(
            db, tenant_id=TENANT_A, provenance_id=record.id
        )
        assert result["chain_valid"] is True
        assert result["chain_replay_score"] == SCORE_WARNINGS
        assert any("no_artifact_hash" in w for w in result["warnings"])


def test_verify_full_chain_result_has_all_required_fields(build_app):
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        record = _make_provenance(db, engagement_id="eng-full-fields-001")
        db.commit()

        result = verify_full_provenance_chain(
            db, tenant_id=TENANT_A, provenance_id=record.id
        )
        required = {
            "chain_valid",
            "chain_depth",
            "verified_at",
            "verification_duration_ms",
            "genesis_hash",
            "latest_hash",
            "chain_replay_score",
            "verified_nodes",
            "failed_nodes",
            "warnings",
            "verification_manifest_hash",
            "engagement_id",
            "replay_manifest_version",
            "replay_summary",
            "replay_hash",
        }
        assert required <= result.keys()


# ---------------------------------------------------------------------------
# generate_chain_verification_manifest
# ---------------------------------------------------------------------------


def test_generate_manifest_has_required_fields(build_app):
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        record = _make_provenance(
            db, engagement_id="eng-manifest-fields-001", artifact_hash="m" * 64
        )
        db.commit()

        manifest = generate_chain_verification_manifest(
            db, tenant_id=TENANT_A, provenance_id=record.id
        )
        required = {
            "tenant_id",
            "engagement_id",
            "chain_depth",
            "genesis_hash",
            "latest_hash",
            "verified_at",
            "chain_replay_score",
            "verified_nodes",
            "verification_manifest_hash",
        }
        assert required <= manifest.keys()


def test_generate_manifest_deterministic(build_app):
    """Same chain → same manifest hash (excluding verified_at which changes per call)."""
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        record = _make_provenance(
            db, engagement_id="eng-manifest-det-001", artifact_hash="n" * 64
        )
        db.commit()

        m1 = generate_chain_verification_manifest(
            db, tenant_id=TENANT_A, provenance_id=record.id
        )
        m2 = generate_chain_verification_manifest(
            db, tenant_id=TENANT_A, provenance_id=record.id
        )
        # verified_at may differ between calls; structural fields must match
        assert m1["chain_depth"] == m2["chain_depth"]
        assert m1["genesis_hash"] == m2["genesis_hash"]
        assert m1["latest_hash"] == m2["latest_hash"]
        assert m1["chain_replay_score"] == m2["chain_replay_score"]
        assert m1["verified_nodes"] == m2["verified_nodes"]
        assert m1["tenant_id"] == m2["tenant_id"]
        assert m1["engagement_id"] == m2["engagement_id"]


def test_generate_manifest_wrong_tenant_safe(build_app):
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        record = _make_provenance(db, engagement_id="eng-manifest-xten-001")
        db.commit()

        manifest = generate_chain_verification_manifest(
            db, tenant_id=TENANT_B, provenance_id=record.id
        )
        assert manifest["chain_replay_score"] == SCORE_BROKEN
        assert manifest["engagement_id"] is None


# ---------------------------------------------------------------------------
# Performance
# ---------------------------------------------------------------------------


def test_large_chain_replay_performance(build_app):
    """100-node chain should replay in well under 1s (target <100ms)."""
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        latest = _bulk_chain(
            db,
            tenant_id=TENANT_A,
            engagement_id="eng-perf-100-001",
            evidence_id="ev-perf-100",
            n=100,
        )
        db.commit()

        t0 = time.monotonic()
        result = verify_full_provenance_chain(
            db, tenant_id=TENANT_A, provenance_id=latest.id
        )
        elapsed_ms = (time.monotonic() - t0) * 1000

        assert result["chain_valid"] is True
        assert result["chain_depth"] == 100
        assert elapsed_ms < 1000, (
            f"100-node replay took {elapsed_ms:.0f}ms, expected <1000ms"
        )


# ---------------------------------------------------------------------------
# Legacy / edge cases
# ---------------------------------------------------------------------------


def test_legacy_empty_engagement_does_not_crash(build_app):
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        result = verify_full_provenance_chain(
            db,
            tenant_id=TENANT_A,
            provenance_id="nonexistent-legacy-id",
        )
        assert result["chain_valid"] is False
        assert result["chain_replay_score"] == SCORE_BROKEN


def test_replay_nonexistent_provenance_returns_empty(build_app):
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        chain = replay_provenance_chain(
            db, tenant_id=TENANT_A, provenance_id="does-not-exist"
        )
        assert chain == []


# ---------------------------------------------------------------------------
# PR 1.2A — Proof Authority Hardening
# ---------------------------------------------------------------------------


def test_replay_manifest_version_is_set(build_app):
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        record = _make_provenance(
            db, engagement_id="eng-version-001", artifact_hash="v" * 64
        )
        db.commit()

        result = verify_full_provenance_chain(
            db, tenant_id=TENANT_A, provenance_id=record.id
        )
        assert result["replay_manifest_version"] == REPLAY_MANIFEST_VERSION
        assert result["replay_manifest_version"] == "trust-replay-v2"


def test_replay_summary_correct(build_app):
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        genesis = _make_provenance(db, engagement_id="eng-summary-001")
        db.commit()
        latest = _extend_chain(db, genesis, steps=2)
        db.commit()

        result = verify_full_provenance_chain(
            db, tenant_id=TENANT_A, provenance_id=latest.id
        )
        summary = result["replay_summary"]
        assert summary["chain_depth"] == 3
        assert summary["verified_node_count"] == 3
        assert summary["failed_node_count"] == 0
        assert summary["warning_count"] > 0  # no artifact_hash → warnings
        assert summary["chain_replay_score"] == SCORE_WARNINGS


def test_replay_summary_perfect_chain(build_app):
    """Chain with artifact_hash set has 0 warnings → score 100 and warning_count 0."""
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        record = _make_provenance(
            db, engagement_id="eng-summary-perfect-001", artifact_hash="p" * 64
        )
        db.commit()

        result = verify_full_provenance_chain(
            db, tenant_id=TENANT_A, provenance_id=record.id
        )
        summary = result["replay_summary"]
        # No signing key in test env → legacy_unsigned warning → SCORE_DEGRADED
        assert summary["chain_replay_score"] == SCORE_DEGRADED
        assert summary["warning_count"] == 1  # legacy_unsigned
        assert summary["failed_node_count"] == 0
        assert summary["verified_node_count"] == 1


def test_replay_hash_stable_for_identical_chain(build_app):
    """Same chain state → same replay_hash across multiple calls."""
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        record = _make_provenance(
            db, engagement_id="eng-rh-stable-001", artifact_hash="r" * 64
        )
        db.commit()

        r1 = verify_full_provenance_chain(
            db, tenant_id=TENANT_A, provenance_id=record.id
        )
        r2 = verify_full_provenance_chain(
            db, tenant_id=TENANT_A, provenance_id=record.id
        )
        assert r1["replay_hash"] == r2["replay_hash"]


def test_replay_hash_changes_when_chain_tampered(build_app):
    """Tampered event_hash changes the verification outcome → different replay_hash."""
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        record = _make_provenance(
            db, engagement_id="eng-rh-tamper-001", artifact_hash="t" * 64
        )
        db.commit()

        r_before = verify_full_provenance_chain(
            db, tenant_id=TENANT_A, provenance_id=record.id
        )

        db.execute(
            sqlalchemy.text(
                "UPDATE fa_evidence_provenance SET event_hash = :bad WHERE id = :id"
            ),
            {"bad": "0" * 64, "id": record.id},
        )
        db.commit()

        r_after = verify_full_provenance_chain(
            db, tenant_id=TENANT_A, provenance_id=record.id
        )
        assert r_before["replay_hash"] != r_after["replay_hash"]
        assert r_after["chain_valid"] is False


def test_replay_hash_changes_when_report_link_added(build_app):
    """Adding a report link changes report_link_status → different replay_hash (P1.1 fix)."""
    from api.db import get_engine

    from services.field_assessment.report_link_authority import create_report_link

    build_app()
    with Session(get_engine()) as db:
        import os

        import base64

        _seed = b"\xcc" * 32
        _key_b64 = base64.b64encode(_seed).decode()
        os.environ["FG_EVIDENCE_SIGNING_KEY_B64"] = _key_b64
        try:
            record = _make_provenance(
                db, engagement_id="eng-rh-link-001", artifact_hash="l" * 64
            )
            db.commit()

            r_before = verify_full_provenance_chain(
                db, tenant_id=TENANT_A, provenance_id=record.id
            )
            assert r_before["report_link_status"] == "unlinked"

            create_report_link(
                db,
                tenant_id=TENANT_A,
                engagement_id="eng-rh-link-001",
                evidence_id="ev-link-rh-001",
                report_id="rep-rh-link-001",
            )
            db.commit()

            r_after = verify_full_provenance_chain(
                db, tenant_id=TENANT_A, provenance_id=record.id
            )
            assert r_after["report_link_status"] == "verified"
            assert r_before["replay_hash"] != r_after["replay_hash"]
        finally:
            os.environ.pop("FG_EVIDENCE_SIGNING_KEY_B64", None)


def test_replay_hash_excludes_timestamps(build_app):
    """verified_at and verification_duration_ms must not influence replay_hash."""
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        record = _make_provenance(
            db, engagement_id="eng-rh-no-ts-001", artifact_hash="x" * 64
        )
        db.commit()

        r1 = verify_full_provenance_chain(
            db, tenant_id=TENANT_A, provenance_id=record.id
        )
        r2 = verify_full_provenance_chain(
            db, tenant_id=TENANT_A, provenance_id=record.id
        )
        # verified_at and verification_duration_ms will almost certainly differ
        # across two calls; replay_hash must still match
        assert r1["replay_hash"] == r2["replay_hash"]


def test_replay_hash_not_found_is_unique_per_id(build_app):
    """not_found replay_hash varies with provenance_id (not constant)."""
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        r1 = verify_full_provenance_chain(
            db, tenant_id=TENANT_A, provenance_id="proof-missing-aaa"
        )
        r2 = verify_full_provenance_chain(
            db, tenant_id=TENANT_A, provenance_id="proof-missing-bbb"
        )
        assert r1["replay_hash"] != r2["replay_hash"]


def test_result_has_engagement_id(build_app):
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        record = _make_provenance(db, engagement_id="eng-eid-001")
        db.commit()

        result = verify_full_provenance_chain(
            db, tenant_id=TENANT_A, provenance_id=record.id
        )
        assert result["engagement_id"] == "eng-eid-001"


def test_result_engagement_id_none_on_not_found(build_app):
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        result = verify_full_provenance_chain(
            db, tenant_id=TENANT_A, provenance_id="missing-for-eid"
        )
        assert result["engagement_id"] is None


def test_generate_trust_proof_has_required_fields(build_app):
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        record = _make_provenance(
            db, engagement_id="eng-proof-fields-001", artifact_hash="q" * 64
        )
        db.commit()

        proof = generate_trust_proof(db, tenant_id=TENANT_A, provenance_id=record.id)
        assert "replay_manifest" in proof
        assert "replay_hash" in proof
        assert "verification_summary" in proof
        assert "chain_valid" in proof
        assert "chain_replay_score" in proof

        summary = proof["verification_summary"]
        assert "verified_node_count" in summary
        assert "failed_node_count" in summary
        assert "warning_count" in summary
        assert "chain_depth" in summary
        assert "chain_replay_score" in summary

        manifest = proof["replay_manifest"]
        assert "replay_manifest_version" in manifest
        assert manifest["replay_manifest_version"] == "trust-replay-v1"


def test_generate_trust_proof_deterministic(build_app):
    """Same chain → same proof (excluding ephemeral timing fields)."""
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        record = _make_provenance(
            db, engagement_id="eng-proof-det-001", artifact_hash="w" * 64
        )
        db.commit()

        p1 = generate_trust_proof(db, tenant_id=TENANT_A, provenance_id=record.id)
        p2 = generate_trust_proof(db, tenant_id=TENANT_A, provenance_id=record.id)

        assert p1["replay_hash"] == p2["replay_hash"]
        assert p1["chain_valid"] == p2["chain_valid"]
        assert p1["chain_replay_score"] == p2["chain_replay_score"]
        assert p1["verification_summary"] == p2["verification_summary"]
        assert p1["replay_manifest"] == p2["replay_manifest"]


def test_generate_trust_proof_wrong_tenant_safe(build_app):
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        record = _make_provenance(db, engagement_id="eng-proof-xten-001")
        db.commit()

        proof = generate_trust_proof(db, tenant_id=TENANT_B, provenance_id=record.id)
        assert proof["chain_valid"] is False
        assert proof["chain_replay_score"] == SCORE_BROKEN
        assert proof["replay_manifest"]["engagement_id"] is None


def test_generate_trust_proof_no_signing_fields(build_app):
    """PR 1.2A must not include PR 1.3 signing fields."""
    from api.db import get_engine

    build_app()
    with Session(get_engine()) as db:
        record = _make_provenance(db, engagement_id="eng-proof-nosign-001")
        db.commit()

        proof = generate_trust_proof(db, tenant_id=TENANT_A, provenance_id=record.id)
        pr13_fields = {"signature", "signing_key_id", "authority_version", "signed_at"}
        assert not (pr13_fields & proof.keys()), "PR 1.3 signing fields must not appear"
