"""Trust Graph Authority & Snapshot Foundation — PR 1.6A.

Elevates the Trust Graph from a graph engine into a cryptographically
provable trust substrate.

Provides:
  - Edge authority: signed, verifiable trust relationship assertions
  - Graph snapshot authority: signed, immutable graph state records
  - Replay anchors: deterministic anchors for PR 1.9 time-travel reconstruction
  - Trust explainability: deterministic, traversal-based natural language explanations
  - TrustQueryResult: query result container with confidence placeholder for PR 1.7

Cryptographic design:
  - Ed25519 over SHA-256 digest of canonical JSON (same algorithm as evidence_authority)
  - Key material from FG_EVIDENCE_SIGNING_KEY_B64 (base64-encoded 32-byte seed)
  - Verification-only mode via FG_EVIDENCE_VERIFY_KEY_B64
  - signing_key_id = SHA256(pub_bytes)[:16] for key rotation queries
  - No private key material ever leaves this module

Replay compatibility (PR 1.9):
  - Edge authority events carry authority_version for forward compatibility
  - Snapshot hashes exclude runtime state (timestamps excluded from canonical input)
  - Replay anchors are self-contained — consumed by PR 1.9 without redesign

Extensibility:
  - No assessment-specific assumptions in the authority or snapshot layers
  - Future node types (Identity, RBAC, Agent, AGI Governance) sign through the
    same sign_edge_authority() / verify_edge_authority() interface
"""

from __future__ import annotations

import base64
import hashlib
import json
import uuid
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from services.canonical import canonical_json_bytes, utc_iso8601_z_now
from services.field_assessment.trust_graph import (
    NodeType,
    TrustGraph,
    TrustGraphEdge,
    TrustGraphNode,
    generate_trust_graph_manifest,
    get_control_lineage,
    get_finding_lineage,
    get_report_lineage,
    get_risk_lineage,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

EDGE_AUTHORITY_VERSION: str = "trust-graph-edge-authority-v1"
SNAPSHOT_VERSION: str = "trust-graph-snapshot-v1"

_ENV_SIGNING_KEY = "FG_EVIDENCE_SIGNING_KEY_B64"
_ENV_VERIFY_KEY = "FG_EVIDENCE_VERIFY_KEY_B64"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class TrustGraphAuthorityError(RuntimeError):
    """Raised when signing key material is missing or invalid.

    Fail closed: callers must handle this explicitly in production paths.
    In dev/test, callers should catch and skip signing (same pattern as
    evidence_authority.py _try_sign_new_event()).
    """


# ---------------------------------------------------------------------------
# Key management (private — key material must never leave this module)
# ---------------------------------------------------------------------------


def _load_private_key_seed() -> bytes:
    """Load 32-byte Ed25519 seed from FG_EVIDENCE_SIGNING_KEY_B64."""
    raw = (
        __import__("os").getenv(_ENV_SIGNING_KEY) or ""  # noqa: PLC0415
    ).strip()
    if not raw:
        raise TrustGraphAuthorityError(
            f"{_ENV_SIGNING_KEY} is required for trust graph authority signing"
        )
    try:
        seed = base64.b64decode(raw)
    except Exception as exc:
        raise TrustGraphAuthorityError(
            f"{_ENV_SIGNING_KEY} must be valid base64"
        ) from exc
    if len(seed) != 32:
        raise TrustGraphAuthorityError(
            f"{_ENV_SIGNING_KEY} must decode to 32 bytes (got {len(seed)})"
        )
    return seed


def _derive_public_key_bytes(seed: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()


def _derive_key_id(pub_bytes: bytes) -> str:
    """SHA256(public_key_bytes)[:16] — stable 16-char fingerprint."""
    return hashlib.sha256(pub_bytes).hexdigest()[:16]


def _load_verification_public_key() -> bytes:
    """Load public key bytes for verification.

    Tries FG_EVIDENCE_VERIFY_KEY_B64 first (verification-only deployments).
    Falls back to deriving from FG_EVIDENCE_SIGNING_KEY_B64.
    """
    import os  # noqa: PLC0415

    raw = (os.getenv(_ENV_VERIFY_KEY) or "").strip()
    if raw:
        try:
            pub_bytes = base64.b64decode(raw)
        except Exception as exc:
            raise TrustGraphAuthorityError(
                f"{_ENV_VERIFY_KEY} must be valid base64"
            ) from exc
        if len(pub_bytes) != 32:
            raise TrustGraphAuthorityError(
                f"{_ENV_VERIFY_KEY} must decode to 32 bytes (got {len(pub_bytes)})"
            )
        return pub_bytes
    return _derive_public_key_bytes(_load_private_key_seed())


def _sign_canonical(payload: dict[str, Any]) -> str:
    """Ed25519-sign SHA-256(canonical_json_bytes(payload)). Returns hex signature."""
    seed = _load_private_key_seed()
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    digest = hashlib.sha256(canonical_json_bytes(payload)).digest()
    return priv.sign(digest).hex()


# ---------------------------------------------------------------------------
# Part 1 — Edge Authority
# ---------------------------------------------------------------------------


def build_edge_authority_event(edge: TrustGraphEdge) -> dict[str, Any]:
    """Build the canonical authority event dict for a trust graph edge.

    This is the payload that is (or will be) signed. A verifier recomputes this
    from the edge fields and checks the signature over the SHA-256 digest.

    Includes signing_key_id so stripping it is detected as signature_mismatch
    rather than silently passing. authority_version is forward-compatible.
    """
    try:
        key_id = _derive_key_id(_derive_public_key_bytes(_load_private_key_seed()))
    except TrustGraphAuthorityError:
        key_id = None

    return {
        "edge_type": edge.edge_type.value,
        "source_node_id": edge.source_node_id,
        "target_node_id": edge.target_node_id,
        "tenant_id": edge.tenant_id,
        "engagement_id": edge.engagement_id,
        "authority_version": EDGE_AUTHORITY_VERSION,
        "signing_key_id": key_id,
    }


def sign_edge_authority(edge: TrustGraphEdge) -> dict[str, Any]:
    """Sign a trust graph edge and return the authority fields.

    Returns:
        event_hash       SHA-256 hex of the canonical authority event
        signature        hex Ed25519 signature
        signing_key_id   SHA256(pub_bytes)[:16]
        authority_version EDGE_AUTHORITY_VERSION

    Raises TrustGraphAuthorityError if FG_EVIDENCE_SIGNING_KEY_B64 is not set.
    """
    seed = _load_private_key_seed()
    pub_bytes = _derive_public_key_bytes(seed)
    key_id = _derive_key_id(pub_bytes)

    canonical = {
        "edge_type": edge.edge_type.value,
        "source_node_id": edge.source_node_id,
        "target_node_id": edge.target_node_id,
        "tenant_id": edge.tenant_id,
        "engagement_id": edge.engagement_id,
        "authority_version": EDGE_AUTHORITY_VERSION,
        "signing_key_id": key_id,
    }
    event_hash = hashlib.sha256(canonical_json_bytes(canonical)).hexdigest()
    signature = _sign_canonical(canonical)

    return {
        "event_hash": event_hash,
        "signature": signature,
        "signing_key_id": key_id,
        "authority_version": EDGE_AUTHORITY_VERSION,
    }


# ---------------------------------------------------------------------------
# Part 2 — Edge Tamper Detection
# ---------------------------------------------------------------------------


def verify_edge_authority(
    edge: TrustGraphEdge,
    authority: dict[str, Any],
) -> dict[str, Any]:
    """Verify a signed edge authority record.

    Returns:
        {"valid": bool, "reason": str | None}

    Never raises. Fails closed on any integrity violation.

    Checks in order:
      1. Required authority fields present
      2. authority_version matches expected
      3. event_hash matches recomputed hash (tamper detection)
      4. Ed25519 signature verifies over canonical bytes
    """
    # --- Missing authority fields ---
    required = {"event_hash", "signature", "signing_key_id", "authority_version"}
    if not authority or not required.issubset(authority.keys()):
        missing = required - set(authority or {})
        return {
            "valid": False,
            "reason": f"missing_authority_fields: {sorted(missing)}",
        }

    # --- Authority version ---
    if authority.get("authority_version") != EDGE_AUTHORITY_VERSION:
        return {
            "valid": False,
            "reason": (
                f"invalid_authority_version: "
                f"expected={EDGE_AUTHORITY_VERSION!r} "
                f"got={authority.get('authority_version')!r}"
            ),
        }

    # --- Recompute canonical and check event_hash ---
    canonical = {
        "edge_type": edge.edge_type.value,
        "source_node_id": edge.source_node_id,
        "target_node_id": edge.target_node_id,
        "tenant_id": edge.tenant_id,
        "engagement_id": edge.engagement_id,
        "authority_version": EDGE_AUTHORITY_VERSION,
        "signing_key_id": authority.get("signing_key_id"),
    }
    expected_hash = hashlib.sha256(canonical_json_bytes(canonical)).hexdigest()
    if authority["event_hash"] != expected_hash:
        return {"valid": False, "reason": "tampered_payload"}

    # --- Signature verification ---
    try:
        sig_hex = authority["signature"]
        try:
            sig_bytes = bytes.fromhex(sig_hex)
        except (ValueError, TypeError):
            return {"valid": False, "reason": "signature_mismatch"}

        pub_bytes = _load_verification_public_key()
        pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
        digest = hashlib.sha256(canonical_json_bytes(canonical)).digest()
        pub.verify(sig_bytes, digest)
        return {"valid": True, "reason": None}

    except TrustGraphAuthorityError:
        return {"valid": False, "reason": "key_unavailable"}
    except InvalidSignature:
        return {"valid": False, "reason": "signature_mismatch"}
    except Exception:  # noqa: BLE001
        return {"valid": False, "reason": "signature_mismatch"}


# ---------------------------------------------------------------------------
# Part 3 & 4 — Trust Graph Snapshot Authority
# ---------------------------------------------------------------------------


def _canonical_snapshot_bytes(manifest: dict[str, Any]) -> bytes:
    """Deterministic canonical bytes for snapshot hashing.

    Derives from graph_manifest fields only — no timestamps, no runtime state.
    Produces identical output for identical graph structure.
    """
    stable = {
        "graph_version": manifest.get("graph_version"),
        "tenant_id": manifest.get("tenant_id"),
        "engagement_id": manifest.get("engagement_id"),
        "node_count": manifest.get("node_count"),
        "edge_count": manifest.get("edge_count"),
        "root_nodes": sorted(manifest.get("root_nodes") or []),
        "graph_hash": manifest.get("graph_hash"),
        "snapshot_version": SNAPSHOT_VERSION,
    }
    return json.dumps(
        stable, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()


def generate_signed_graph_snapshot(graph: TrustGraph) -> dict[str, Any]:
    """Generate a cryptographically signed, immutable graph state snapshot.

    The snapshot_hash derives from the graph manifest (structure only —
    timestamps excluded). Identical graph structure produces identical hash.

    Returns:
        snapshot_id         unique identifier for this snapshot instance
        snapshot_hash       SHA-256 of canonical graph manifest
        snapshot_signature  hex Ed25519 signature over snapshot_hash bytes
        snapshot_key_id     signing_key_id for key rotation queries
        snapshot_version    SNAPSHOT_VERSION
        graph_hash          from generate_trust_graph_manifest()
        created_at          ISO-8601 UTC timestamp

    Raises TrustGraphAuthorityError if FG_EVIDENCE_SIGNING_KEY_B64 is not set.
    """
    manifest = generate_trust_graph_manifest(graph)

    canonical = _canonical_snapshot_bytes(manifest)
    snapshot_hash = hashlib.sha256(canonical).hexdigest()

    seed = _load_private_key_seed()
    pub_bytes = _derive_public_key_bytes(seed)
    key_id = _derive_key_id(pub_bytes)

    priv = Ed25519PrivateKey.from_private_bytes(seed)
    digest = hashlib.sha256(snapshot_hash.encode()).digest()
    snapshot_signature = priv.sign(digest).hex()

    return {
        "snapshot_id": str(uuid.uuid4()),
        "snapshot_hash": snapshot_hash,
        "snapshot_signature": snapshot_signature,
        "snapshot_key_id": key_id,
        "snapshot_version": SNAPSHOT_VERSION,
        "graph_hash": manifest["graph_hash"],
        "created_at": utc_iso8601_z_now(),
    }


def verify_graph_snapshot(
    graph: TrustGraph,
    snapshot: dict[str, Any],
) -> dict[str, Any]:
    """Verify a signed graph snapshot against the current graph state.

    Checks:
      1. Required snapshot fields present
      2. snapshot_version matches
      3. snapshot_hash matches recomputed canonical (tamper detection)
      4. Ed25519 signature verifies over snapshot_hash

    Returns {"valid": bool, "reason": str | None}. Never raises.
    """
    required = {
        "snapshot_hash",
        "snapshot_signature",
        "snapshot_key_id",
        "snapshot_version",
        "graph_hash",
    }
    if not snapshot or not required.issubset(snapshot.keys()):
        missing = required - set(snapshot or {})
        return {"valid": False, "reason": f"missing_snapshot_fields: {sorted(missing)}"}

    if snapshot.get("snapshot_version") != SNAPSHOT_VERSION:
        return {
            "valid": False,
            "reason": (
                f"invalid_snapshot_version: "
                f"expected={SNAPSHOT_VERSION!r} "
                f"got={snapshot.get('snapshot_version')!r}"
            ),
        }

    manifest = generate_trust_graph_manifest(graph)
    expected_hash = hashlib.sha256(_canonical_snapshot_bytes(manifest)).hexdigest()
    if snapshot["snapshot_hash"] != expected_hash:
        return {"valid": False, "reason": "tampered_snapshot"}

    try:
        sig_bytes = bytes.fromhex(snapshot["snapshot_signature"])
        pub_bytes = _load_verification_public_key()
        pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
        digest = hashlib.sha256(snapshot["snapshot_hash"].encode()).digest()
        pub.verify(sig_bytes, digest)
        return {"valid": True, "reason": None}
    except TrustGraphAuthorityError:
        return {"valid": False, "reason": "key_unavailable"}
    except InvalidSignature:
        return {"valid": False, "reason": "signature_mismatch"}
    except Exception:  # noqa: BLE001
        return {"valid": False, "reason": "signature_mismatch"}


# ---------------------------------------------------------------------------
# Part 5 — Replay Anchors
# ---------------------------------------------------------------------------


def build_replay_anchor(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Build a deterministic, self-contained replay anchor from a signed snapshot.

    PR 1.9 consumes replay anchors to reconstruct "What trust state existed at
    time T?" without redesign. The anchor is hashable and immutable.

    Returns:
        graph_hash          identifies the graph structure at anchor time
        snapshot_hash       identifies the signed snapshot state
        snapshot_signature  cryptographic proof of snapshot integrity
        snapshot_version    forward-compatibility marker
    """
    return {
        "graph_hash": snapshot["graph_hash"],
        "snapshot_hash": snapshot["snapshot_hash"],
        "snapshot_signature": snapshot["snapshot_signature"],
        "snapshot_version": snapshot["snapshot_version"],
    }


# ---------------------------------------------------------------------------
# Part 6 — Trust Explainability
# ---------------------------------------------------------------------------


def _explain_lineage(
    subject_label: str,
    lineage: list[TrustGraphNode],
) -> str:
    """Format a deterministic, human-readable trust explanation.

    Groups upstream nodes by type in dependency order (evidence → finding →
    control/risk → report). Nodes within each type are sorted by node_id.
    Same graph always produces identical output.
    """
    # Separate subject from upstream chain
    by_type: dict[NodeType, list[TrustGraphNode]] = {}
    for n in lineage:
        by_type.setdefault(n.node_type, []).append(n)

    for nodes in by_type.values():
        nodes.sort(key=lambda n: n.node_id)

    lines: list[str] = [f"{subject_label} exists because:\n"]

    # Display order: evidence → finding → control → risk → framework → report
    # (excludes the subject itself)
    display_order = [
        NodeType.EVIDENCE,
        NodeType.FINDING,
        NodeType.CONTROL,
        NodeType.RISK,
        NodeType.FRAMEWORK,
        NodeType.REPORT,
    ]

    first = True
    prev_arrow = False
    for node_type in display_order:
        nodes = by_type.get(node_type, [])
        if not nodes:
            continue
        if not first and not prev_arrow:
            lines.append("  ↓")
        for n in nodes:
            payload = n.payload
            if node_type == NodeType.EVIDENCE:
                detail = (
                    f"authority={payload.get('authority_status', 'unknown')}, "
                    f"trust={payload.get('trust_score', 0)}"
                )
            elif node_type == NodeType.FINDING:
                detail = (
                    f"severity={payload.get('severity', 'unknown')}, "
                    f"confidence={payload.get('confidence', 'unknown')}"
                )
            elif node_type == NodeType.CONTROL:
                detail = (
                    f"framework={payload.get('framework', 'unknown')}, "
                    f"status={payload.get('control_status', 'unknown')}"
                )
            elif node_type == NodeType.RISK:
                detail = (
                    f"level={payload.get('risk_level', 'unknown')}, "
                    f"type={payload.get('risk_type', 'unknown')}"
                )
            elif node_type == NodeType.FRAMEWORK:
                detail = (
                    f"name={payload.get('framework_name', 'unknown')}, "
                    f"version={payload.get('version', 'unknown')}"
                )
            else:
                detail = f"status={payload.get('report_status', 'unknown')}"
            lines.append(f"  [{node_type.value.upper()}] {n.node_id} ({detail})")
        first = False
        prev_arrow = False

    return "\n".join(lines)


def why_report(graph: TrustGraph, node_id: str) -> str:
    """Deterministic explanation of why a report exists.

    Traverses upstream: Report ← Risk ← Finding ← Evidence.
    Pure graph traversal — no AI, no inference, no heuristics.
    """
    node = graph.get_node(node_id)
    if node is None or node.node_type != NodeType.REPORT:
        from services.field_assessment.trust_graph import TrustGraphError  # noqa: PLC0415

        raise TrustGraphError(f"report node not found or wrong type: {node_id!r}")
    report_id = node.payload.get("report_id", node_id)
    lineage = get_report_lineage(graph, node_id)
    return _explain_lineage(f'Report "{report_id}"', lineage)


def why_risk(graph: TrustGraph, node_id: str) -> str:
    """Deterministic explanation of why a risk is present.

    Traverses upstream: Risk ← Finding ← Evidence.
    Pure graph traversal — no AI, no inference, no heuristics.
    """
    node = graph.get_node(node_id)
    if node is None or node.node_type != NodeType.RISK:
        from services.field_assessment.trust_graph import TrustGraphError  # noqa: PLC0415

        raise TrustGraphError(f"risk node not found or wrong type: {node_id!r}")
    risk_id = node.payload.get("risk_id", node_id)
    lineage = get_risk_lineage(graph, node_id)
    return _explain_lineage(f'Risk "{risk_id}"', lineage)


def why_control(graph: TrustGraph, node_id: str) -> str:
    """Deterministic explanation of what evidence supports a control.

    Traverses upstream: Control ← Finding ← Evidence.
    Pure graph traversal — no AI, no inference, no heuristics.
    """
    node = graph.get_node(node_id)
    if node is None or node.node_type != NodeType.CONTROL:
        from services.field_assessment.trust_graph import TrustGraphError  # noqa: PLC0415

        raise TrustGraphError(f"control node not found or wrong type: {node_id!r}")
    control_id = node.payload.get("control_id", node_id)
    lineage = get_control_lineage(graph, node_id)
    return _explain_lineage(f'Control "{control_id}"', lineage)


def why_finding(graph: TrustGraph, node_id: str) -> str:
    """Deterministic explanation of what evidence generated a finding.

    Traverses upstream: Finding ← Evidence.
    Pure graph traversal — no AI, no inference, no heuristics.
    """
    node = graph.get_node(node_id)
    if node is None or node.node_type != NodeType.FINDING:
        from services.field_assessment.trust_graph import TrustGraphError  # noqa: PLC0415

        raise TrustGraphError(f"finding node not found or wrong type: {node_id!r}")
    finding_id = node.payload.get("finding_id", node_id)
    lineage = get_finding_lineage(graph, node_id)
    return _explain_lineage(f'Finding "{finding_id}"', lineage)


# ---------------------------------------------------------------------------
# Part 7 — Trust Query Foundation
# ---------------------------------------------------------------------------


@dataclass
class TrustQueryResult:
    """Trust query result container.

    confidence is a placeholder at 100 until PR 1.7 (Corroboration & Confidence)
    implements per-evidence scoring. Do not implement confidence logic here.

    path: ordered list of nodes from query start to end (from generate_trust_path)
    node_count: total nodes in the source graph
    edge_count: total edges in the source graph
    graph_hash: SHA-256 canonical hash of the graph structure
    snapshot_hash: hash of a signed snapshot if one was generated; None otherwise
    confidence: placeholder = 100 (PR 1.7 will replace)
    """

    path: list[TrustGraphNode]
    node_count: int
    edge_count: int
    graph_hash: str
    snapshot_hash: str | None = None
    confidence: int = 100

    def to_dict(self) -> dict[str, Any]:
        """Serializable representation for audit logs and API responses."""
        return {
            "path": [
                {
                    "node_id": n.node_id,
                    "node_type": n.node_type.value,
                    "tenant_id": n.tenant_id,
                    "engagement_id": n.engagement_id,
                }
                for n in self.path
            ],
            "node_count": self.node_count,
            "edge_count": self.edge_count,
            "graph_hash": self.graph_hash,
            "snapshot_hash": self.snapshot_hash,
            "confidence": self.confidence,
        }
