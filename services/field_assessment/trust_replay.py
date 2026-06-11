"""Trust Replay Engine — chain verification and replay for FA evidence provenance.

This module is a trust infrastructure primitive designed for:
  - Determinism: identical inputs produce identical verification results
  - Iterative traversal: O(n), no recursion, safe for arbitrarily long chains
  - Tenant safety: wrong-tenant returns safe failure with no existence leakage
  - Generality: verify_hash_chain() is chain-type-agnostic; reuse it for report,
    identity, RBAC, governance, and future AGI governance chains

PR 1.3 compatibility: ChainNodeData has a reserved `signature_meta` dict so
signed nodes (signature, signing_key_id, signed_at, authority_version) can be
verified in the replay pipeline without redesign.

Performance targets: 100-node chain <100ms, 1000-node chain <1s.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db_models_field_assessment import FaEvidenceProvenance
from services.canonical import canonical_json_bytes, utc_iso8601_z_now
from services.field_assessment.evidence_provenance import (
    _hash_payload,
    compute_provenance_hash,
)

# ---------------------------------------------------------------------------
# Score constants
# ---------------------------------------------------------------------------

SCORE_PERFECT: int = 100  # all nodes valid, no warnings
SCORE_WARNINGS: int = 75  # all nodes valid, soft warnings present
SCORE_DEGRADED: int = 50  # reserved for PR 1.3 (valid chain, unsigned nodes)
SCORE_BROKEN: int = 0  # any hard integrity failure


# ---------------------------------------------------------------------------
# Generic chain node — reusable across chain types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ChainNodeData:
    """Generic chain node for verify_hash_chain.

    Caller supplies computed_hash (from a chain-type-specific hash function).
    verify_hash_chain checks correctness — it does not know HOW to compute hashes.

    signature_meta: reserved for PR 1.3 Evidence Authority. Pass {} for now.
    """

    node_id: str
    event_hash: str
    previous_hash: str | None
    computed_hash: str
    tenant_id: str
    engagement_id: str
    signature_meta: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _elapsed_ms(t_start: float) -> int:
    return int((time.monotonic() - t_start) * 1000)


def _canonical_hash(obj: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(obj)).hexdigest()


# ---------------------------------------------------------------------------
# Generic chain verifier (reusable primitive)
# ---------------------------------------------------------------------------


def verify_hash_chain(nodes: list[ChainNodeData]) -> dict[str, Any]:
    """Verify structural and hash integrity of an ordered chain of nodes.

    Generic — no DB access, no knowledge of node semantics. Caller loads and
    converts nodes. Nodes should be ordered latest-first (traversal order).

    Detects:
      hash_mismatch          — computed_hash != event_hash
      duplicate_event_hash   — same hash appears twice in the chain
      cycle_detected         — same node_id appears twice
      tenant_contamination   — node.tenant_id != head node's tenant_id
      engagement_contamination — node.engagement_id != head node's engagement_id

    Returns:
      chain_valid    bool
      verified_nodes list[{node_id, event_hash, previous_hash}]
      failed_nodes   list[{node_id, event_hash, previous_hash, reason}]
      warnings       list[str]
    """
    if not nodes:
        return {
            "chain_valid": False,
            "verified_nodes": [],
            "failed_nodes": [{"node_id": None, "reason": "empty_chain"}],
            "warnings": [],
        }

    seen_hashes: set[str] = set()
    seen_ids: set[str] = set()
    verified: list[dict] = []
    failed: list[dict] = []
    warnings: list[str] = []

    ref_tenant = nodes[0].tenant_id
    ref_engagement = nodes[0].engagement_id

    for node in nodes:
        failure: str | None = None
        summary = {
            "node_id": node.node_id,
            "event_hash": node.event_hash,
            "previous_hash": node.previous_hash,
        }

        if node.node_id in seen_ids:
            failure = "cycle_detected"
        seen_ids.add(node.node_id)

        if not failure and node.event_hash in seen_hashes:
            failure = "duplicate_event_hash"
        seen_hashes.add(node.event_hash)

        if not failure and node.computed_hash != node.event_hash:
            failure = "hash_mismatch"

        if not failure and node.tenant_id != ref_tenant:
            failure = "tenant_contamination"

        if not failure and node.engagement_id != ref_engagement:
            failure = "engagement_contamination"

        if failure:
            failed.append({**summary, "reason": failure})
        else:
            verified.append(summary)

    return {
        "chain_valid": len(failed) == 0,
        "verified_nodes": verified,
        "failed_nodes": failed,
        "warnings": warnings,
    }


# ---------------------------------------------------------------------------
# Single-node verifier
# ---------------------------------------------------------------------------


def verify_chain_node(record: FaEvidenceProvenance) -> dict[str, Any]:
    """Recompute event_hash for one provenance record and compare to stored value.

    Returns hash_valid bool, computed_hash, and failure_reason (None if valid).
    """
    payload = _hash_payload(
        tenant_id=record.tenant_id,
        engagement_id=record.engagement_id,
        evidence_id=record.evidence_id,
        finding_id=record.finding_id,
        source_type=record.source_type,
        collection_method=record.collection_method,
        collected_by_type=record.collected_by_type,
        collected_by_id=record.collected_by_id,
        collected_at=record.collected_at,
        artifact_hash=record.artifact_hash,
        previous_hash=record.previous_hash,
        created_at=record.created_at,
    )
    computed = compute_provenance_hash(payload)
    valid = computed == record.event_hash
    return {
        "node_id": record.id,
        "event_hash": record.event_hash,
        "computed_hash": computed,
        "hash_valid": valid,
        "failure_reason": None if valid else "hash_mismatch",
    }


# ---------------------------------------------------------------------------
# Internal: load engagement records indexed by event_hash
# ---------------------------------------------------------------------------


def _load_engagement_records(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
) -> dict[str, FaEvidenceProvenance]:
    stmt = select(FaEvidenceProvenance).where(
        FaEvidenceProvenance.tenant_id == tenant_id,
        FaEvidenceProvenance.engagement_id == engagement_id,
    )
    return {r.event_hash: r for r in db.execute(stmt).scalars().all()}


# ---------------------------------------------------------------------------
# Chain replay (returns ordered records, genesis first)
# ---------------------------------------------------------------------------


def replay_provenance_chain(
    db: Session,
    *,
    tenant_id: str,
    provenance_id: str,
) -> list[FaEvidenceProvenance]:
    """Return the full provenance chain as ordered records (genesis first).

    Iterative — safe for arbitrarily long chains. Stops on cycle or broken link.
    Returns [] if the record is not found or belongs to a different tenant.
    """
    from services.field_assessment.evidence_provenance import get_evidence_provenance

    start = get_evidence_provenance(
        db, provenance_id=provenance_id, tenant_id=tenant_id
    )
    if start is None:
        return []

    by_hash = _load_engagement_records(
        db, tenant_id=tenant_id, engagement_id=start.engagement_id
    )

    chain: list[FaEvidenceProvenance] = []
    seen_ids: set[str] = set()
    current: FaEvidenceProvenance | None = start

    while current is not None:
        if current.id in seen_ids:
            break  # cycle — stop
        seen_ids.add(current.id)
        chain.append(current)
        if current.previous_hash is None:
            break  # genesis
        current = by_hash.get(current.previous_hash)

    chain.reverse()
    return chain


# ---------------------------------------------------------------------------
# Score computation
# ---------------------------------------------------------------------------


def compute_chain_replay_score(
    verified_nodes: list[dict],
    failed_nodes: list[dict],
    warnings: list[str],
) -> int:
    """Deterministic replay score.

    100 — perfect: all nodes valid, no warnings
     75 — warnings: all nodes valid, soft warnings present
     50 — reserved: PR 1.3 will use for valid-chain-but-unsigned-nodes
      0 — broken: any hard integrity failure
    """
    if failed_nodes:
        return SCORE_BROKEN
    if warnings:
        return SCORE_WARNINGS
    return SCORE_PERFECT


# ---------------------------------------------------------------------------
# Full chain verification
# ---------------------------------------------------------------------------


def verify_full_provenance_chain(
    db: Session,
    *,
    tenant_id: str,
    provenance_id: str,
) -> dict[str, Any]:
    """Walk and verify the complete provenance chain from a given record.

    Traverses latest → previous_hash → … → genesis iteratively.

    Detects: hash_mismatch, broken_link, cycle_detected, duplicate_event_hash,
             tenant_contamination, engagement_contamination, corrupt_genesis.

    Tenant-safe: wrong-tenant or missing record returns a safe 'not_found' failure
    without revealing whether another tenant's chain exists.

    Result fields (all deterministic):
      chain_valid             bool
      chain_depth             int
      verified_at             str (ISO8601)
      verification_duration_ms int
      genesis_hash            str | None
      latest_hash             str | None
      chain_replay_score      int  (100/75/50/0)
      verified_nodes          list[{node_id, event_hash, previous_hash}]
      failed_nodes            list[{node_id, ..., reason}]
      warnings                list[str]
      verification_manifest_hash str (SHA-256 of canonical manifest payload)
    """
    from services.field_assessment.evidence_provenance import get_evidence_provenance

    t_start = time.monotonic()
    now = utc_iso8601_z_now()

    start = get_evidence_provenance(
        db, provenance_id=provenance_id, tenant_id=tenant_id
    )
    if start is None:
        return {
            "chain_valid": False,
            "chain_depth": 0,
            "verified_at": now,
            "verification_duration_ms": _elapsed_ms(t_start),
            "genesis_hash": None,
            "latest_hash": None,
            "chain_replay_score": SCORE_BROKEN,
            "verified_nodes": [],
            "failed_nodes": [{"node_id": None, "reason": "not_found"}],
            "warnings": [],
            "verification_manifest_hash": _canonical_hash({}),
        }

    by_hash = _load_engagement_records(
        db, tenant_id=tenant_id, engagement_id=start.engagement_id
    )

    # --- Iterative chain walk: collect traversal records and structural failures ---
    traversal: list[FaEvidenceProvenance] = []
    structural_failures: list[dict] = []
    seen_ids: set[str] = set()

    current: FaEvidenceProvenance | None = start

    while current is not None:
        if current.id in seen_ids:
            structural_failures.append(
                {
                    "node_id": current.id,
                    "event_hash": current.event_hash,
                    "previous_hash": current.previous_hash,
                    "reason": "cycle_detected",
                }
            )
            break
        seen_ids.add(current.id)
        traversal.append(current)

        if current.previous_hash is None:
            break  # true genesis

        parent = by_hash.get(current.previous_hash)
        if parent is None:
            # broken_link covers corrupt_genesis (non-null previous_hash, no matching record)
            structural_failures.append(
                {
                    "node_id": current.id,
                    "event_hash": current.event_hash,
                    "previous_hash": current.previous_hash,
                    "reason": "broken_link",
                }
            )
            break
        current = parent

    # --- Build ChainNodeData list and run generic verifier ---
    nodes: list[ChainNodeData] = []
    soft_warnings: list[str] = []

    for record in traversal:
        payload = _hash_payload(
            tenant_id=record.tenant_id,
            engagement_id=record.engagement_id,
            evidence_id=record.evidence_id,
            finding_id=record.finding_id,
            source_type=record.source_type,
            collection_method=record.collection_method,
            collected_by_type=record.collected_by_type,
            collected_by_id=record.collected_by_id,
            collected_at=record.collected_at,
            artifact_hash=record.artifact_hash,
            previous_hash=record.previous_hash,
            created_at=record.created_at,
        )
        computed = compute_provenance_hash(payload)
        nodes.append(
            ChainNodeData(
                node_id=record.id,
                event_hash=record.event_hash,
                previous_hash=record.previous_hash,
                computed_hash=computed,
                tenant_id=record.tenant_id,
                engagement_id=record.engagement_id,
            )
        )
        if record.artifact_hash is None:
            soft_warnings.append(f"node:{record.id}:no_artifact_hash")

    base = verify_hash_chain(nodes)

    all_failed = base["failed_nodes"] + structural_failures
    all_warnings = base["warnings"] + soft_warnings

    chain_valid = len(all_failed) == 0
    score = compute_chain_replay_score(base["verified_nodes"], all_failed, all_warnings)

    genesis_hash = traversal[-1].event_hash if traversal else None
    latest_hash = traversal[0].event_hash if traversal else None
    depth = len(traversal)

    # Manifest hash is over stable chain data only — excludes verified_at (ephemeral)
    # so the hash is identical for the same chain regardless of when verification runs.
    manifest_payload: dict[str, Any] = {
        "tenant_id": tenant_id,
        "engagement_id": start.engagement_id,
        "chain_depth": depth,
        "genesis_hash": genesis_hash,
        "latest_hash": latest_hash,
        "chain_replay_score": score,
        "verified_nodes": sorted(base["verified_nodes"], key=lambda n: n["node_id"]),
    }
    manifest_hash = _canonical_hash(manifest_payload)

    return {
        "chain_valid": chain_valid,
        "chain_depth": depth,
        "verified_at": now,
        "verification_duration_ms": _elapsed_ms(t_start),
        "genesis_hash": genesis_hash,
        "latest_hash": latest_hash,
        "chain_replay_score": score,
        "verified_nodes": base["verified_nodes"],
        "failed_nodes": all_failed,
        "warnings": all_warnings,
        "verification_manifest_hash": manifest_hash,
    }


# ---------------------------------------------------------------------------
# Verification manifest
# ---------------------------------------------------------------------------


def generate_chain_verification_manifest(
    db: Session,
    *,
    tenant_id: str,
    provenance_id: str,
) -> dict[str, Any]:
    """Generate a deterministic, hashable manifest for a provenance chain.

    Suitable for export to auditors and regulators. The manifest_hash is
    deterministic: canonical JSON, sorted keys, stable encoding.

    Returns the same fields as the verify result manifest_payload plus
    verification_manifest_hash. Safe for wrong-tenant calls.
    """
    from services.field_assessment.evidence_provenance import get_evidence_provenance

    result = verify_full_provenance_chain(
        db, tenant_id=tenant_id, provenance_id=provenance_id
    )

    # Recover engagement_id from DB if chain was found
    start = get_evidence_provenance(
        db, provenance_id=provenance_id, tenant_id=tenant_id
    )
    engagement_id = start.engagement_id if start is not None else None

    return {
        "tenant_id": tenant_id,
        "engagement_id": engagement_id,
        "chain_depth": result["chain_depth"],
        "genesis_hash": result["genesis_hash"],
        "latest_hash": result["latest_hash"],
        "verified_at": result["verified_at"],
        "chain_replay_score": result["chain_replay_score"],
        "verified_nodes": sorted(result["verified_nodes"], key=lambda n: n["node_id"]),
        "verification_manifest_hash": result["verification_manifest_hash"],
    }
