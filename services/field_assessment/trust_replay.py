"""Trust Replay Engine — chain verification and replay for FA evidence provenance.

This module is a trust infrastructure primitive designed for:
  - Determinism: identical inputs produce identical verification results
  - Iterative traversal: O(n), no recursion, safe for arbitrarily long chains
  - Tenant safety: wrong-tenant returns safe failure with no existence leakage
  - Generality: verify_hash_chain() is chain-type-agnostic; reuse it for report,
    identity, RBAC, governance, and future AGI governance chains

PR 1.3 integration:
  - ChainNodeData.signature_meta now populated from evidence_authority.py
  - verify_full_provenance_chain() verifies both hash chain AND signature chain
  - Legacy unsigned records: warning (legacy_unsigned), not failure
  - Signed records with invalid signature: hard failure (invalid_signature)
  - SCORE_DEGRADED (50) activates when all nodes are hash-valid but some unsigned

Performance targets: 100-node chain <150ms, 1000-node chain <2s.
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
# Constants
# ---------------------------------------------------------------------------

SCORE_PERFECT: int = 100  # all nodes valid, signed, no warnings
SCORE_WARNINGS: int = 75  # all nodes valid, signed (or legacy), non-signature warnings
SCORE_DEGRADED: int = 50  # all nodes hash-valid; only legacy_unsigned warnings
SCORE_BROKEN: int = 0  # any hard integrity failure (hash or signature)

REPLAY_MANIFEST_VERSION: str = "trust-replay-v1"
# Increment to "trust-replay-v2" etc. when the replay schema changes.
# Consumers must check this field before interpreting replay results.


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


def _build_replay_summary(
    verified_nodes: list[dict],
    failed_nodes: list[dict],
    warnings: list[str],
    chain_depth: int,
    chain_replay_score: int,
) -> dict[str, Any]:
    """Deterministic summary of verification outcome for dashboards and reporting."""
    return {
        "verified_node_count": len(verified_nodes),
        "failed_node_count": len(failed_nodes),
        "warning_count": len(warnings),
        "chain_depth": chain_depth,
        "chain_replay_score": chain_replay_score,
    }


def _build_replay_hash(
    *,
    chain_valid: bool,
    chain_depth: int,
    genesis_hash: str | None,
    latest_hash: str | None,
    chain_replay_score: int,
    verified_nodes: list[dict],
    failed_nodes: list[dict],
    warnings: list[str],
    verification_manifest_hash: str,
    replay_summary: dict[str, Any],
    replay_manifest_version: str,
) -> str:
    """SHA-256 of the deterministic verification outcome.

    Covers the replay result — not the underlying chain. The underlying chain
    already has verification_manifest_hash. This hash covers scores, failures,
    warnings, and summary so any change in the verification outcome changes
    the replay_hash.

    Explicitly excluded: verified_at, verification_duration_ms (ephemeral).
    Nodes and failures sorted by node_id for stable ordering.
    """
    payload: dict[str, Any] = {
        "replay_manifest_version": replay_manifest_version,
        "chain_valid": chain_valid,
        "chain_depth": chain_depth,
        "genesis_hash": genesis_hash,
        "latest_hash": latest_hash,
        "chain_replay_score": chain_replay_score,
        "verified_nodes": sorted(verified_nodes, key=lambda n: n.get("node_id") or ""),
        "failed_nodes": sorted(
            failed_nodes,
            key=lambda n: (n.get("node_id") or "", n.get("reason", "")),
        ),
        "warnings": sorted(warnings),
        "verification_manifest_hash": verification_manifest_hash,
        "replay_summary": replay_summary,
    }
    return _canonical_hash(payload)


# ---------------------------------------------------------------------------
# Generic chain verifier (reusable primitive)
# ---------------------------------------------------------------------------


def verify_hash_chain(nodes: list[ChainNodeData]) -> dict[str, Any]:
    """Verify structural and hash integrity of an ordered chain of nodes.

    Generic — no DB access, no knowledge of node semantics. Caller loads and
    converts nodes. Nodes must be ordered latest-first (traversal order).

    Detects:
      hash_mismatch          — computed_hash != event_hash
      duplicate_event_hash   — same hash appears twice in the chain
      cycle_detected         — same node_id appears twice
      tenant_contamination   — node.tenant_id != head node's tenant_id
      engagement_contamination — node.engagement_id != head node's engagement_id
      adjacency_mismatch     — nodes[i].previous_hash != nodes[i+1].event_hash
      corrupt_genesis        — last node (genesis) has a non-null previous_hash

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

    # Adjacency: each node's previous_hash must equal the next node's event_hash.
    # This catches disconnected or reordered lists that pass per-node hash checks.
    for i in range(len(nodes) - 1):
        curr, nxt = nodes[i], nodes[i + 1]
        if curr.previous_hash != nxt.event_hash:
            failed.append(
                {
                    "node_id": curr.node_id,
                    "event_hash": curr.event_hash,
                    "previous_hash": curr.previous_hash,
                    "reason": "adjacency_mismatch",
                }
            )

    # Genesis node (last in latest-first order) must have no previous_hash.
    if nodes[-1].previous_hash is not None:
        last = nodes[-1]
        failed.append(
            {
                "node_id": last.node_id,
                "event_hash": last.event_hash,
                "previous_hash": last.previous_hash,
                "reason": "corrupt_genesis",
            }
        )

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
    """Recompute event_hash and verify Ed25519 authority signature for one record.

    Returns hash_valid bool, computed_hash, failure_reason, and signature fields.
    signature_valid=None means legacy_unsigned (warning, not failure).
    """
    from services.field_assessment.evidence_authority import verify_provenance_signature

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
    hash_valid = computed == record.event_hash

    sig_result = verify_provenance_signature(record)

    return {
        "node_id": record.id,
        "event_hash": record.event_hash,
        "computed_hash": computed,
        "hash_valid": hash_valid,
        "failure_reason": None if hash_valid else "hash_mismatch",
        "signature_valid": sig_result["valid"],
        "signature_status": sig_result["status"],
        "authority_version": sig_result.get("authority_version"),
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

    100 — perfect: all nodes hash-valid AND signature-valid, no warnings
     75 — warnings: all nodes valid, but non-legacy soft warnings present
     50 — degraded: all nodes hash-valid; only legacy_unsigned signature warnings
      0 — broken: any hard integrity failure (hash mismatch or invalid signature)
    """
    if failed_nodes:
        return SCORE_BROKEN
    if not warnings:
        return SCORE_PERFECT
    # SCORE_DEGRADED activates when all warnings are legacy_unsigned — no other issues
    if all(w.endswith(":legacy_unsigned") for w in warnings):
        return SCORE_DEGRADED
    return SCORE_WARNINGS


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

    Result fields (all deterministic except verified_at and verification_duration_ms):
      chain_valid               bool
      chain_depth               int
      verified_at               str (ISO8601) — ephemeral, excluded from replay_hash
      verification_duration_ms  int — ephemeral, excluded from replay_hash
      genesis_hash              str | None
      latest_hash               str | None
      chain_replay_score        int  (100/75/50/0)
      verified_nodes            list[{node_id, event_hash, previous_hash}]
      failed_nodes              list[{node_id, ..., reason}]
      warnings                  list[str]
      verification_manifest_hash str
      engagement_id             str | None
      replay_manifest_version   str  ("trust-replay-v1")
      replay_summary            dict  (verified_node_count, failed_node_count, …)
      replay_hash               str  (SHA-256 of deterministic outcome fields)
    """
    from services.field_assessment.evidence_provenance import get_evidence_provenance

    t_start = time.monotonic()
    now = utc_iso8601_z_now()

    start = get_evidence_provenance(
        db, provenance_id=provenance_id, tenant_id=tenant_id
    )
    if start is None:
        # Hash over (tenant_id, provenance_id) so each failed lookup gets a
        # unique, recomputable fingerprint — not a constant shared across all failures.
        not_found_manifest_hash = _canonical_hash(
            {
                "tenant_id": tenant_id,
                "provenance_id": provenance_id,
                "chain_valid": False,
            }
        )
        nf_failed = [{"node_id": None, "reason": "not_found"}]
        nf_summary = _build_replay_summary([], nf_failed, [], 0, SCORE_BROKEN)
        nf_replay_hash = _build_replay_hash(
            chain_valid=False,
            chain_depth=0,
            genesis_hash=None,
            latest_hash=None,
            chain_replay_score=SCORE_BROKEN,
            verified_nodes=[],
            failed_nodes=nf_failed,
            warnings=[],
            verification_manifest_hash=not_found_manifest_hash,
            replay_summary=nf_summary,
            replay_manifest_version=REPLAY_MANIFEST_VERSION,
        )
        return {
            "chain_valid": False,
            "chain_depth": 0,
            "verified_at": now,
            "verification_duration_ms": _elapsed_ms(t_start),
            "genesis_hash": None,
            "latest_hash": None,
            "chain_replay_score": SCORE_BROKEN,
            "verified_nodes": [],
            "failed_nodes": nf_failed,
            "warnings": [],
            "verification_manifest_hash": not_found_manifest_hash,
            "engagement_id": None,
            "replay_manifest_version": REPLAY_MANIFEST_VERSION,
            "replay_summary": nf_summary,
            "replay_hash": nf_replay_hash,
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

    # --- Build ChainNodeData list, run generic hash verifier, verify signatures ---
    from services.field_assessment.evidence_authority import verify_provenance_signature

    nodes: list[ChainNodeData] = []
    soft_warnings: list[str] = []
    # Map node_id → signature verification result for post-hash-chain enrichment
    sig_results: dict[str, dict] = {}

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
        sig_result = verify_provenance_signature(record)
        sig_results[record.id] = sig_result

        nodes.append(
            ChainNodeData(
                node_id=record.id,
                event_hash=record.event_hash,
                previous_hash=record.previous_hash,
                computed_hash=computed,
                tenant_id=record.tenant_id,
                engagement_id=record.engagement_id,
                signature_meta={
                    "signature_valid": sig_result["valid"],
                    "signature_status": sig_result["status"],
                    "authority_version": sig_result.get("authority_version"),
                    "signing_key_id": sig_result.get("signing_key_id"),
                },
            )
        )
        if record.artifact_hash is None:
            soft_warnings.append(f"node:{record.id}:no_artifact_hash")

    base = verify_hash_chain(nodes)

    # Enrich hash-verified nodes with signature data; move sig-invalid to failed
    enriched_verified: list[dict] = []
    sig_failures: list[dict] = []
    sig_warnings: list[str] = []

    for node_dict in base["verified_nodes"]:
        nid = node_dict["node_id"]
        sr = sig_results.get(nid, {})
        enriched = {
            **node_dict,
            "signature_valid": sr.get("valid"),
            "signature_status": sr.get("status"),
            "authority_version": sr.get("authority_version"),
        }
        if sr.get("valid") is False:
            # Invalid signature on an otherwise hash-valid node → hard failure
            sig_failures.append(
                {
                    "node_id": nid,
                    "event_hash": node_dict["event_hash"],
                    "reason": "invalid_signature",
                }
            )
        else:
            enriched_verified.append(enriched)
            if sr.get("status") == "legacy_unsigned":
                sig_warnings.append(f"node:{nid}:legacy_unsigned")

    all_failed = base["failed_nodes"] + structural_failures + sig_failures
    all_warnings = base["warnings"] + soft_warnings + sig_warnings

    chain_valid = len(all_failed) == 0
    score = compute_chain_replay_score(enriched_verified, all_failed, all_warnings)

    genesis_hash = traversal[-1].event_hash if traversal else None
    latest_hash = traversal[0].event_hash if traversal else None
    depth = len(traversal)

    # Manifest hash covers stable chain data only (no ephemeral timestamps).
    manifest_payload: dict[str, Any] = {
        "tenant_id": tenant_id,
        "engagement_id": start.engagement_id,
        "chain_depth": depth,
        "genesis_hash": genesis_hash,
        "latest_hash": latest_hash,
        "chain_replay_score": score,
        "verified_nodes": sorted(enriched_verified, key=lambda n: n["node_id"]),
    }
    manifest_hash = _canonical_hash(manifest_payload)

    replay_summary = _build_replay_summary(
        enriched_verified, all_failed, all_warnings, depth, score
    )
    replay_hash = _build_replay_hash(
        chain_valid=chain_valid,
        chain_depth=depth,
        genesis_hash=genesis_hash,
        latest_hash=latest_hash,
        chain_replay_score=score,
        verified_nodes=enriched_verified,
        failed_nodes=all_failed,
        warnings=all_warnings,
        verification_manifest_hash=manifest_hash,
        replay_summary=replay_summary,
        replay_manifest_version=REPLAY_MANIFEST_VERSION,
    )

    return {
        "chain_valid": chain_valid,
        "chain_depth": depth,
        "verified_at": now,
        "verification_duration_ms": _elapsed_ms(t_start),
        "genesis_hash": genesis_hash,
        "latest_hash": latest_hash,
        "chain_replay_score": score,
        "verified_nodes": enriched_verified,
        "failed_nodes": all_failed,
        "warnings": all_warnings,
        "verification_manifest_hash": manifest_hash,
        "engagement_id": start.engagement_id,
        "replay_manifest_version": REPLAY_MANIFEST_VERSION,
        "replay_summary": replay_summary,
        "replay_hash": replay_hash,
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

    Suitable for export to auditors and regulators. Safe for wrong-tenant calls.
    engagement_id is taken from the verify result — no extra DB query.
    """
    result = verify_full_provenance_chain(
        db, tenant_id=tenant_id, provenance_id=provenance_id
    )
    return {
        "tenant_id": tenant_id,
        "engagement_id": result["engagement_id"],
        "chain_depth": result["chain_depth"],
        "genesis_hash": result["genesis_hash"],
        "latest_hash": result["latest_hash"],
        "verified_at": result["verified_at"],
        "chain_replay_score": result["chain_replay_score"],
        "replay_manifest_version": result["replay_manifest_version"],
        "verified_nodes": sorted(result["verified_nodes"], key=lambda n: n["node_id"]),
        "verification_manifest_hash": result["verification_manifest_hash"],
    }


# ---------------------------------------------------------------------------
# Trust proof
# ---------------------------------------------------------------------------


def generate_trust_proof(
    db: Session,
    *,
    tenant_id: str,
    provenance_id: str,
) -> dict[str, Any]:
    """Generate a deterministic trust proof package for a provenance chain.

    Includes both hash chain and signature chain verification results.
    Self-describing: a consumer with the chain data and public key can
    independently recompute replay_hash and verify all signatures.

    Returns:
      replay_manifest        dict — chain verification manifest (stable, no timestamps)
      replay_hash            str  — deterministic fingerprint of the outcome
      verification_summary   dict — executive/dashboard metrics
      chain_valid            bool — True only if hash AND signature chain valid
      chain_replay_score     int  — 100/75/50/0
    """
    result = verify_full_provenance_chain(
        db, tenant_id=tenant_id, provenance_id=provenance_id
    )
    manifest = {
        "tenant_id": tenant_id,
        "engagement_id": result["engagement_id"],
        "chain_depth": result["chain_depth"],
        "genesis_hash": result["genesis_hash"],
        "latest_hash": result["latest_hash"],
        "chain_replay_score": result["chain_replay_score"],
        "replay_manifest_version": result["replay_manifest_version"],
        "verified_nodes": sorted(result["verified_nodes"], key=lambda n: n["node_id"]),
        "verification_manifest_hash": result["verification_manifest_hash"],
    }
    return {
        "replay_manifest": manifest,
        "replay_hash": result["replay_hash"],
        "verification_summary": result["replay_summary"],
        "chain_valid": result["chain_valid"],
        "chain_replay_score": result["chain_replay_score"],
    }
