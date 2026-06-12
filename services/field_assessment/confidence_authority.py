"""Confidence Authority & Drift Intelligence — PR 1.7A.

Transforms trust confidence from a calculated value into a cryptographically
verifiable governance artifact.

Every confidence decision becomes:
  Explainable  — generate_confidence_explainability_graph()
  Replayable   — replay_confidence_snapshot()
  Verifiable   — verify_confidence_manifest() / verify_confidence_snapshot()
  Signable     — sign_confidence_manifest() / generate_confidence_snapshot()
  Enforceable  — evaluate_trust_policy()
  Auditable    — generate_confidence_timeline() / detect_confidence_anomalies()

Architecture:
  Part 1  sign_confidence_manifest() / verify_confidence_manifest()
  Part 2  generate_confidence_snapshot() / verify_confidence_snapshot()
  Part 3  calculate_confidence_drift()
  Part 4  generate_confidence_timeline()
  Part 5  generate_confidence_explainability_graph()
  Part 6  TrustPolicy / evaluate_trust_policy()
  Part 7  replay_confidence_snapshot()
  Part 8  detect_confidence_anomalies()

Signing model:
  Ed25519 over SHA-256 of canonical JSON bytes.
  Same key material as evidence_authority and trust_graph_authority:
    FG_EVIDENCE_SIGNING_KEY_B64 (32-byte seed, private operations)
    FG_EVIDENCE_VERIFY_KEY_B64  (32-byte pub, verify-only mode)
  signing_key_id = SHA256(pub_bytes)[:16]

Future compatibility:
  TrustPolicy.subject_type is extensible to any trust entity:
  evidence, finding, report, identity, agent, agi_governance,
  model_registry, model_deployment, autonomous_system, agent_swarm —
  without schema migration.

Replay compatibility (PR 1.9):
  snapshot_hash excludes snapshot_id and created_at.
  Identical confidence state → identical snapshot_hash regardless of
  when generate_confidence_snapshot() is called.
"""

from __future__ import annotations

import base64
import hashlib
import os
import uuid
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from services.canonical import canonical_json_bytes, utc_iso8601_z_now
from services.field_assessment.trust_confidence import CONFIDENCE_VERSION

# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------

CONFIDENCE_AUTHORITY_VERSION: str = "confidence-authority-v1"

# ---------------------------------------------------------------------------
# Anomaly detection thresholds (named constants — auditor visible)
# ---------------------------------------------------------------------------

_ANOMALY_DROP_THRESHOLD: int = 15
_ANOMALY_RISE_THRESHOLD: int = 15
_ANOMALY_CORROBORATION_DROP: int = 20

# ---------------------------------------------------------------------------
# Drift classification threshold
# ---------------------------------------------------------------------------

_RAPID_DRIFT_THRESHOLD: int = 10

# ---------------------------------------------------------------------------
# Trust policy names — extensible, not enforced at runtime
# ---------------------------------------------------------------------------

_VALID_POLICY_NAMES: tuple[str, ...] = (
    "evidence_approval",
    "qa_approval",
    "report_finalization",
    "report_export",
    "ai_deployment",
    "agent_approval",
    "agent_execution",
    "agent_autonomy",
)

# ---------------------------------------------------------------------------
# Explainability factor groupings (ordered for tree rendering)
# ---------------------------------------------------------------------------

_EVIDENCE_FACTORS: frozenset[str] = frozenset(
    {
        "evidence_present",
        "all_evidence_signed",
        "some_evidence_signed",
        "fresh_evidence",
        "all_event_hashes_present",
        "high_avg_trust_score",
        "unsigned_evidence",
        "some_unsigned_evidence",
        "missing_event_hash",
        "low_avg_trust_score",
        "no_evidence",
    }
)

_CORROBORATION_FACTORS: frozenset[str] = frozenset(
    {
        "independent_corroboration_2",
        "independent_corroboration_4",
        "duplicate_corroboration",
    }
)

_REPLAY_FACTORS: frozenset[str] = frozenset(
    {
        "chain_replay_score_100",
        "chain_replay_score_75",
        "chain_replay_degraded",
        "broken_chain",
    }
)

_SNAPSHOT_FACTORS: frozenset[str] = frozenset(
    {
        "snapshot_verified",
        "snapshot_unverified",
        "replay_anchor_valid",
    }
)

_AUTHORITY_FACTORS: frozenset[str] = frozenset(
    {
        "authority_version_current",
        "authority_version_downgraded",
        "report_link_verified",
    }
)

_INTEGRITY_FACTORS: frozenset[str] = frozenset(
    {
        "circular_dependency",
    }
)

# Ordered section registry used by the explainability tree
_SECTIONS: tuple[tuple[str, frozenset[str]], ...] = (
    ("Evidence Strength", _EVIDENCE_FACTORS),
    ("Corroboration", _CORROBORATION_FACTORS),
    ("Chain Replay", _REPLAY_FACTORS),
    ("Snapshot", _SNAPSHOT_FACTORS),
    ("Authority", _AUTHORITY_FACTORS),
    ("Integrity", _INTEGRITY_FACTORS),
)


# ---------------------------------------------------------------------------
# Exception
# ---------------------------------------------------------------------------


class ConfidenceAuthorityError(RuntimeError):
    """Raised when a confidence authority operation fails or key material unavailable.

    Fail closed: callers must handle explicitly. Never silently corrects.
    """


# ---------------------------------------------------------------------------
# Key management — same env vars as evidence_authority / trust_graph_authority
# ---------------------------------------------------------------------------


def _load_private_key_seed() -> bytes:
    raw = os.environ.get("FG_EVIDENCE_SIGNING_KEY_B64", "").strip()
    if not raw:
        raise ConfidenceAuthorityError(
            "FG_EVIDENCE_SIGNING_KEY_B64 not set — cannot sign confidence artifacts"
        )
    try:
        seed = base64.b64decode(raw)
    except Exception as exc:
        raise ConfidenceAuthorityError(
            f"Invalid base64 in FG_EVIDENCE_SIGNING_KEY_B64: {exc}"
        ) from exc
    if len(seed) != 32:
        raise ConfidenceAuthorityError(
            f"FG_EVIDENCE_SIGNING_KEY_B64 must be a 32-byte Ed25519 seed "
            f"(got {len(seed)} bytes)"
        )
    return seed


def _derive_public_key_bytes(seed: bytes) -> bytes:
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )


def _derive_key_id(pub_bytes: bytes) -> str:
    return hashlib.sha256(pub_bytes).hexdigest()[:16]


def _load_verification_public_key() -> bytes:
    raw = os.environ.get("FG_EVIDENCE_VERIFY_KEY_B64", "").strip()
    if raw:
        try:
            pub_bytes = base64.b64decode(raw)
            if len(pub_bytes) == 32:
                return pub_bytes
        except Exception:
            pass
    seed = _load_private_key_seed()
    return _derive_public_key_bytes(seed)


def _sign_canonical(payload: dict[str, Any]) -> tuple[str, str, str]:
    """Sign canonical JSON payload. Returns (event_hash_hex, signature_hex, key_id)."""
    seed = _load_private_key_seed()
    private = Ed25519PrivateKey.from_private_bytes(seed)
    pub_bytes = _derive_public_key_bytes(seed)
    key_id = _derive_key_id(pub_bytes)
    canonical = canonical_json_bytes(payload)
    digest = hashlib.sha256(canonical).digest()
    return (
        hashlib.sha256(canonical).hexdigest(),
        private.sign(digest).hex(),
        key_id,
    )


# ---------------------------------------------------------------------------
# Part 1 — Confidence Manifest Authority
# ---------------------------------------------------------------------------

_MANIFEST_REQUIRED: frozenset[str] = frozenset(
    {
        "confidence_score",
        "corroboration_score",
        "strength_score",
        "trust_quality_score",
        "manifest_hash",
    }
)


def sign_confidence_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    """Sign a confidence manifest with Ed25519.

    The canonical payload covers stable scoring fields only:
    confidence_version, confidence_score, corroboration_score,
    strength_score, trust_quality_score, manifest_hash, authority_version.

    Raises ConfidenceAuthorityError if key unavailable or manifest is missing
    required fields.

    Returns authority dict:
        event_hash        SHA-256 of canonical payload (hex)
        signature         Ed25519 signature over SHA-256(canonical) (hex)
        signing_key_id    SHA-256(pub_bytes)[:16]
        authority_version CONFIDENCE_AUTHORITY_VERSION
    """
    missing = _MANIFEST_REQUIRED - set(manifest)
    if missing:
        raise ConfidenceAuthorityError(
            f"Manifest missing required fields: {sorted(missing)}"
        )

    payload: dict[str, Any] = {
        "authority_version": CONFIDENCE_AUTHORITY_VERSION,
        "confidence_score": int(manifest["confidence_score"]),
        "confidence_version": manifest.get("confidence_version", CONFIDENCE_VERSION),
        "corroboration_score": int(manifest["corroboration_score"]),
        "manifest_hash": str(manifest["manifest_hash"]),
        "strength_score": int(manifest["strength_score"]),
        "trust_quality_score": int(manifest["trust_quality_score"]),
    }

    event_hash, sig, key_id = _sign_canonical(payload)
    return {
        "event_hash": event_hash,
        "signature": sig,
        "signing_key_id": key_id,
        "authority_version": CONFIDENCE_AUTHORITY_VERSION,
    }


def verify_confidence_manifest(
    manifest: dict[str, Any],
    authority: dict[str, Any],
) -> dict[str, Any]:
    """Verify a signed confidence manifest. Never raises. Returns {valid, reason}."""
    if not isinstance(authority, dict) or not authority:
        return {"valid": False, "reason": "missing_authority"}
    if not isinstance(manifest, dict):
        return {"valid": False, "reason": "invalid_manifest"}

    required_auth = {"event_hash", "signature", "signing_key_id", "authority_version"}
    missing_auth = required_auth - set(authority)
    if missing_auth:
        return {
            "valid": False,
            "reason": f"missing_authority_fields: {sorted(missing_auth)}",
        }

    if authority.get("authority_version") != CONFIDENCE_AUTHORITY_VERSION:
        return {
            "valid": False,
            "reason": f"invalid_authority_version: {authority.get('authority_version')}",
        }

    missing_manifest = _MANIFEST_REQUIRED - set(manifest)
    if missing_manifest:
        return {
            "valid": False,
            "reason": f"missing_manifest_fields: {sorted(missing_manifest)}",
        }

    try:
        pub_bytes = _load_verification_public_key()
    except ConfidenceAuthorityError:
        return {"valid": False, "reason": "key_unavailable"}

    payload: dict[str, Any] = {
        "authority_version": CONFIDENCE_AUTHORITY_VERSION,
        "confidence_score": int(manifest["confidence_score"]),
        "confidence_version": manifest.get("confidence_version", CONFIDENCE_VERSION),
        "corroboration_score": int(manifest["corroboration_score"]),
        "manifest_hash": str(manifest["manifest_hash"]),
        "strength_score": int(manifest["strength_score"]),
        "trust_quality_score": int(manifest["trust_quality_score"]),
    }

    canonical = canonical_json_bytes(payload)
    expected_hash = hashlib.sha256(canonical).hexdigest()
    if authority["event_hash"] != expected_hash:
        return {"valid": False, "reason": "event_hash_mismatch"}

    try:
        sig_bytes = bytes.fromhex(authority["signature"])
        pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
        digest = hashlib.sha256(canonical).digest()
        pub.verify(sig_bytes, digest)
    except (InvalidSignature, ValueError, Exception):
        return {"valid": False, "reason": "signature_mismatch"}

    return {"valid": True, "reason": None}


# ---------------------------------------------------------------------------
# Part 2 — Confidence Snapshot Authority
# ---------------------------------------------------------------------------

_SNAPSHOT_REQUIRED: frozenset[str] = frozenset(
    {
        "tenant_id",
        "engagement_id",
        "confidence_score",
        "confidence_level",
        "manifest_hash",
        "snapshot_hash",
        "snapshot_signature",
        "authority_version",
    }
)


def _canonical_snapshot_bytes(
    tenant_id: str,
    engagement_id: str,
    confidence_score: int,
    confidence_level: str,
    manifest_hash: str,
    authority_version: str,
) -> bytes:
    """Canonical bytes for snapshot hash computation.

    Excludes snapshot_id and created_at so that identical confidence state
    produces identical bytes regardless of when the snapshot was generated.
    """
    stable: dict[str, Any] = {
        "authority_version": authority_version,
        "confidence_level": confidence_level,
        "confidence_score": confidence_score,
        "engagement_id": engagement_id,
        "manifest_hash": manifest_hash,
        "tenant_id": tenant_id,
    }
    return canonical_json_bytes(stable)


def generate_confidence_snapshot(
    tenant_id: str,
    engagement_id: str,
    confidence_result: dict[str, Any],
    manifest: dict[str, Any],
) -> dict[str, Any]:
    """Generate a signed confidence snapshot for a tenant/engagement pair.

    snapshot_hash excludes snapshot_id and created_at. Identical confidence
    state always produces the same snapshot_hash regardless of call time.

    Raises ConfidenceAuthorityError if tenant_id/engagement_id absent or
    key unavailable.

    Returns:
        snapshot_id         unique per call
        tenant_id           echoed
        engagement_id       echoed
        confidence_score    int
        confidence_level    str
        manifest_hash       str
        snapshot_hash       SHA-256 of canonical stable fields (hex)
        snapshot_signature  Ed25519 signature over SHA-256(snapshot_hash) (hex)
        signing_key_id      SHA-256(pub_bytes)[:16]
        authority_version   CONFIDENCE_AUTHORITY_VERSION
        created_at          ISO-8601 UTC
    """
    if not tenant_id or not engagement_id:
        raise ConfidenceAuthorityError("tenant_id and engagement_id are required")

    confidence_score = int(confidence_result.get("confidence_score", 0))
    confidence_level = str(confidence_result.get("confidence_level", "unknown"))
    manifest_hash = str(manifest.get("manifest_hash", ""))

    canonical = _canonical_snapshot_bytes(
        tenant_id,
        engagement_id,
        confidence_score,
        confidence_level,
        manifest_hash,
        CONFIDENCE_AUTHORITY_VERSION,
    )
    snapshot_hash = hashlib.sha256(canonical).hexdigest()

    seed = _load_private_key_seed()
    private = Ed25519PrivateKey.from_private_bytes(seed)
    pub_bytes = _derive_public_key_bytes(seed)
    key_id = _derive_key_id(pub_bytes)
    digest = hashlib.sha256(snapshot_hash.encode()).digest()
    sig = private.sign(digest).hex()

    return {
        "snapshot_id": uuid.uuid4().hex,
        "tenant_id": tenant_id,
        "engagement_id": engagement_id,
        "confidence_score": confidence_score,
        "confidence_level": confidence_level,
        "manifest_hash": manifest_hash,
        "snapshot_hash": snapshot_hash,
        "snapshot_signature": sig,
        "signing_key_id": key_id,
        "authority_version": CONFIDENCE_AUTHORITY_VERSION,
        "created_at": utc_iso8601_z_now(),
    }


def verify_confidence_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Verify a confidence snapshot. Never raises. Returns {valid, reason}."""
    if not isinstance(snapshot, dict) or not snapshot:
        return {"valid": False, "reason": "missing_snapshot"}

    missing = _SNAPSHOT_REQUIRED - set(snapshot)
    if missing:
        return {"valid": False, "reason": f"missing_fields: {sorted(missing)}"}

    if snapshot.get("authority_version") != CONFIDENCE_AUTHORITY_VERSION:
        return {
            "valid": False,
            "reason": f"invalid_authority_version: {snapshot.get('authority_version')}",
        }

    canonical = _canonical_snapshot_bytes(
        str(snapshot["tenant_id"]),
        str(snapshot["engagement_id"]),
        int(snapshot["confidence_score"]),
        str(snapshot["confidence_level"]),
        str(snapshot["manifest_hash"]),
        CONFIDENCE_AUTHORITY_VERSION,
    )
    expected_hash = hashlib.sha256(canonical).hexdigest()
    if snapshot["snapshot_hash"] != expected_hash:
        return {"valid": False, "reason": "tampered_snapshot_hash"}

    try:
        pub_bytes = _load_verification_public_key()
    except ConfidenceAuthorityError:
        return {"valid": False, "reason": "key_unavailable"}

    try:
        sig_bytes = bytes.fromhex(snapshot["snapshot_signature"])
        pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
        digest = hashlib.sha256(snapshot["snapshot_hash"].encode()).digest()
        pub.verify(sig_bytes, digest)
    except (InvalidSignature, ValueError, Exception):
        return {"valid": False, "reason": "signature_mismatch"}

    return {"valid": True, "reason": None}


# ---------------------------------------------------------------------------
# Part 3 — Confidence Drift Engine
# ---------------------------------------------------------------------------


def calculate_confidence_drift(
    previous: dict[str, Any],
    current: dict[str, Any],
) -> dict[str, Any]:
    """Compute confidence drift between two snapshots or confidence results.

    Deterministic: identical inputs always produce identical output.
    Replayable: pass historical snapshots to reconstruct past drift reports.
    Auditable: every output field is derived from named thresholds.

    Returns:
        previous_score  int
        current_score   int
        delta           int (positive = improving, negative = degrading)
        direction       improving / stable / degrading /
                        rapidly_improving / rapidly_degrading
        velocity        minimal / low / moderate / significant / rapid
        trend           positive / neutral / negative
    """
    prev_score = int(previous.get("confidence_score", 0))
    curr_score = int(current.get("confidence_score", 0))
    delta = curr_score - prev_score

    if delta >= _RAPID_DRIFT_THRESHOLD:
        direction = "rapidly_improving"
        trend = "positive"
    elif delta > 0:
        direction = "improving"
        trend = "positive"
    elif delta == 0:
        direction = "stable"
        trend = "neutral"
    elif delta > -_RAPID_DRIFT_THRESHOLD:
        direction = "degrading"
        trend = "negative"
    else:
        direction = "rapidly_degrading"
        trend = "negative"

    abs_delta = abs(delta)
    if abs_delta <= 2:
        velocity = "minimal"
    elif abs_delta <= 5:
        velocity = "low"
    elif abs_delta <= 10:
        velocity = "moderate"
    elif abs_delta <= 20:
        velocity = "significant"
    else:
        velocity = "rapid"

    return {
        "previous_score": prev_score,
        "current_score": curr_score,
        "delta": delta,
        "direction": direction,
        "velocity": velocity,
        "trend": trend,
    }


# ---------------------------------------------------------------------------
# Part 4 — Confidence Timeline
# ---------------------------------------------------------------------------


def generate_confidence_timeline(
    snapshots: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Generate a stable, ordered confidence timeline from a list of snapshots.

    Sorts by (created_at, snapshot_id) for deterministic ordering even when
    two snapshots share the same timestamp. O(n log n) sort; O(n) thereafter.

    Supports 100 / 1,000 / 10,000 snapshots with no performance degradation.

    Returns list of:
        timestamp         str (created_at, empty string if absent)
        confidence_score  int
        confidence_level  str
        snapshot_id       str
    """
    if not snapshots:
        return []

    timeline = [
        {
            "timestamp": s.get("created_at", ""),
            "confidence_score": int(s.get("confidence_score", 0)),
            "confidence_level": s.get("confidence_level", "unknown"),
            "snapshot_id": s.get("snapshot_id", ""),
        }
        for s in snapshots
    ]
    timeline.sort(key=lambda x: (x["timestamp"], x["snapshot_id"]))
    return timeline


# ---------------------------------------------------------------------------
# Part 5 — Confidence Explainability Graph
# ---------------------------------------------------------------------------


def _factor_label(name: str) -> str:
    return " ".join(w.capitalize() for w in name.replace("-", "_").split("_"))


def _classify_factor(name: str) -> str:
    """Return the section name for a factor, or 'Other'."""
    if name.startswith("stale_"):
        return "Evidence Strength"
    for section_name, factor_set in _SECTIONS:
        if name in factor_set:
            return section_name
    return "Other"


def generate_confidence_explainability_graph(
    confidence_result: dict[str, Any],
) -> str:
    """Generate a deterministic, auditor-readable confidence explainability tree.

    Groups factors into semantic sections and renders a Unicode tree. Suitable
    for audit logs, regulator packages, portal rendering, and PDF export.

    Deterministic: same confidence_result always produces the same string.

    Example output:
        Confidence 87 (strong)

        ├─ Evidence Strength +43
        │  ├─ Evidence Present +10
        │  ├─ All Evidence Signed +20
        │  └─ Fresh Evidence +10
        │
        ├─ Corroboration +15
        │  ├─ Independent Corroboration 2 +8
        │  └─ Independent Corroboration 4 +7
        │
        └─ Snapshot +10
           └─ Snapshot Verified +10
    """
    score = confidence_result.get("confidence_score", 0)
    level = confidence_result.get("confidence_level", "unknown")
    pos_factors = confidence_result.get("confidence_factors", [])
    neg_factors = confidence_result.get("negative_factors", [])

    all_factors: list[tuple[str, int]] = [
        (f["factor"], int(f.get("points", 0))) for f in pos_factors
    ] + [(f["factor"], int(f.get("points", 0))) for f in neg_factors]

    # Bucket factors into ordered sections
    section_order = [name for name, _ in _SECTIONS] + ["Other"]
    bucket: dict[str, list[tuple[str, int]]] = {k: [] for k in section_order}

    for factor_name, pts in all_factors:
        section = _classify_factor(factor_name)
        bucket[section].append((factor_name, pts))

    active: list[tuple[str, list[tuple[str, int]]]] = [
        (name, bucket[name]) for name in section_order if bucket[name]
    ]

    lines: list[str] = [f"Confidence {score} ({level})", ""]

    for i, (section_name, items) in enumerate(active):
        is_last = i == len(active) - 1
        section_total = sum(pts for _, pts in items)
        s_sign = "+" if section_total >= 0 else ""
        s_conn = "└─" if is_last else "├─"
        lines.append(f"{s_conn} {section_name} {s_sign}{section_total}")

        for j, (factor_name, pts) in enumerate(items):
            is_last_item = j == len(items) - 1
            indent = "   " if is_last else "│  "
            i_conn = "└─" if is_last_item else "├─"
            i_sign = "+" if pts >= 0 else ""
            lines.append(f"{indent}{i_conn} {_factor_label(factor_name)} {i_sign}{pts}")

        if not is_last:
            lines.append("│")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Part 6 — Trust Policy Engine
# ---------------------------------------------------------------------------


@dataclass
class TrustPolicy:
    """A named trust policy gate with a minimum confidence threshold.

    policy_name references one of _VALID_POLICY_NAMES or any future value.
    Not restricted at runtime — future entity types (identity, agent,
    agi_governance, model_deployment, autonomous_system) add new policy
    names without changing this dataclass.

    subject_type is extensible: evidence / finding / report / identity /
    agent / agi_governance / model_registry / autonomous_system / any.

    policy_version is a forward-compatibility marker.
    """

    policy_name: str
    minimum_confidence: int
    subject_type: str = "any"
    policy_version: str = "trust-policy-v1"

    def __post_init__(self) -> None:
        if not (0 <= self.minimum_confidence <= 100):
            raise ValueError(
                f"minimum_confidence must be 0–100, got {self.minimum_confidence}"
            )


def evaluate_trust_policy(
    policy: TrustPolicy,
    confidence_result: dict[str, Any],
) -> dict[str, Any]:
    """Evaluate whether a confidence score satisfies a trust policy gate.

    Deterministic: identical (policy, confidence_result) always produces
    identical output. Suitable for audit logs and point-in-time replay.

    Returns:
        allowed              bool
        policy_name          str
        subject_type         str
        required_confidence  int
        actual_confidence    int
        reason               str
        policy_version       str
        authority_version    CONFIDENCE_AUTHORITY_VERSION
    """
    actual = int(confidence_result.get("confidence_score", 0))
    required = policy.minimum_confidence
    allowed = actual >= required

    if allowed:
        reason = "policy_satisfied"
    else:
        shortfall = required - actual
        reason = f"confidence_below_threshold_by_{shortfall}_points"

    return {
        "allowed": allowed,
        "policy_name": policy.policy_name,
        "subject_type": policy.subject_type,
        "required_confidence": required,
        "actual_confidence": actual,
        "reason": reason,
        "policy_version": policy.policy_version,
        "authority_version": CONFIDENCE_AUTHORITY_VERSION,
    }


# ---------------------------------------------------------------------------
# Part 7 — Confidence Replay Authority
# ---------------------------------------------------------------------------


def replay_confidence_snapshot(
    snapshot_id: str,
    snapshots: list[dict[str, Any]],
    *,
    verify: bool = True,
    manifest_authority: dict[str, Any] | None = None,
    graph_hash: str | None = None,
    replay_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Locate and verify a confidence snapshot by ID.

    Validation layers (in order):
    1. Snapshot located in the provided list
    2. Snapshot signature verified (verify_confidence_snapshot)
    3. Manifest authority cross-checked (if manifest_authority provided)
    4. Graph hash consistency (if graph_hash provided)
    5. Replay chain integrity (if replay_result provided)

    Fail closed: any failed validation returns valid=False with reason.
    Never raises on validation failures — callers must check valid field.

    Parameters:
        snapshot_id        ID of the snapshot to locate and verify
        snapshots          List of confidence snapshots to search
        verify             If False, skips cryptographic verification
        manifest_authority Optional result of verify_confidence_manifest()
        graph_hash         Optional graph manifest hash to cross-check
        replay_result      Optional dict with chain_replay_score (0–100)

    Returns:
        valid        bool
        reason       str | None
        snapshot     dict | None
        validations  list[str] of completed validation step names
    """
    if not snapshot_id:
        return {
            "valid": False,
            "reason": "missing_snapshot_id",
            "snapshot": None,
            "validations": [],
        }

    target: dict[str, Any] | None = None
    for s in snapshots:
        if s.get("snapshot_id") == snapshot_id:
            target = s
            break

    if target is None:
        return {
            "valid": False,
            "reason": "snapshot_not_found",
            "snapshot": None,
            "validations": [],
        }

    validations: list[str] = ["snapshot_located"]

    if not verify:
        return {
            "valid": True,
            "reason": None,
            "snapshot": target,
            "validations": validations,
        }

    snap_result = verify_confidence_snapshot(target)
    if not snap_result["valid"]:
        return {
            "valid": False,
            "reason": snap_result["reason"],
            "snapshot": target,
            "validations": validations,
        }
    validations.append("snapshot_authority")

    if manifest_authority is not None:
        if manifest_authority.get("valid") is not True:
            return {
                "valid": False,
                "reason": f"manifest_authority_failed: {manifest_authority.get('reason')}",
                "snapshot": target,
                "validations": validations,
            }
        validations.append("manifest_authority")

    if graph_hash is not None:
        snap_manifest_hash = target.get("manifest_hash", "")
        if graph_hash and snap_manifest_hash and graph_hash != snap_manifest_hash:
            return {
                "valid": False,
                "reason": "graph_hash_mismatch",
                "snapshot": target,
                "validations": validations,
            }
        validations.append("graph_authority")

    if replay_result is not None:
        chain_score = int(replay_result.get("chain_replay_score", 100))
        if chain_score == 0:
            return {
                "valid": False,
                "reason": "replay_chain_broken",
                "snapshot": target,
                "validations": validations,
            }
        validations.append("replay_authority")

    return {
        "valid": True,
        "reason": None,
        "snapshot": target,
        "validations": validations,
    }


# ---------------------------------------------------------------------------
# Part 8 — Confidence Anomaly Detection
# ---------------------------------------------------------------------------

_SEVERITY_RANK: dict[str, int] = {
    "critical": 3,
    "high": 2,
    "medium": 1,
    "low": 0,
    "none": -1,
}


def detect_confidence_anomalies(
    snapshots: list[dict[str, Any]],
    *,
    reference: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Detect confidence anomalies across a sequence of snapshots.

    Compares consecutive snapshots (latest pair) for:
    - confidence_collapse      sudden drop >= _ANOMALY_DROP_THRESHOLD
    - confidence_inflation     sudden rise >= _ANOMALY_RISE_THRESHOLD
    - authority_downgrade      authority_version mismatch in latest snapshot
    - corroboration_collapse   corroboration_score drop >= _ANOMALY_CORROBORATION_DROP
    - replay_degradation       chain_replay_score drops between snapshots
    - signature_loss           snapshot_signature absent on latest snapshot
    - trust_score_manipulation score rises while corroboration falls

    Single-snapshot mode checks signature presence and authority version.

    Deterministic: identical snapshot list always produces identical output.
    Replayable: pass historical snapshots to reconstruct past anomaly reports.

    Returns:
        anomaly_detected  bool
        severity          none / low / medium / high / critical
        reason            str — primary anomaly reason
        anomalies         list of anomaly dicts
    """
    valid_snapshots = [s for s in (snapshots or []) if isinstance(s, dict)]
    if not valid_snapshots:
        return {
            "anomaly_detected": False,
            "severity": "none",
            "reason": "no_snapshots",
            "anomalies": [],
        }

    anomalies: list[dict[str, Any]] = []

    # Single-snapshot invariants
    latest = valid_snapshots[-1]

    if not latest.get("snapshot_signature"):
        anomalies.append(
            {
                "type": "signature_loss",
                "severity": "critical",
                "reason": "snapshot_signature_absent",
            }
        )

    curr_ver = latest.get("authority_version")
    if curr_ver and curr_ver != CONFIDENCE_AUTHORITY_VERSION:
        anomalies.append(
            {
                "type": "authority_downgrade",
                "severity": "critical",
                "reason": f"authority_version_mismatch: {curr_ver}",
            }
        )

    if len(valid_snapshots) < 2:
        if not anomalies:
            return {
                "anomaly_detected": False,
                "severity": "none",
                "reason": "no_anomalies_detected",
                "anomalies": [],
            }
        max_sev = max(anomalies, key=lambda a: _SEVERITY_RANK.get(a["severity"], 0))[
            "severity"
        ]
        return {
            "anomaly_detected": True,
            "severity": max_sev,
            "reason": anomalies[0]["reason"],
            "anomalies": anomalies,
        }

    prev = valid_snapshots[-2]
    curr = valid_snapshots[-1]

    prev_score = int(prev.get("confidence_score", 0))
    curr_score = int(curr.get("confidence_score", 0))
    delta = curr_score - prev_score

    if delta <= -_ANOMALY_DROP_THRESHOLD:
        anomalies.append(
            {
                "type": "confidence_collapse",
                "severity": "critical" if delta <= -25 else "high",
                "reason": f"confidence_drop_{abs(delta)}_points",
                "delta": delta,
            }
        )

    if delta >= _ANOMALY_RISE_THRESHOLD:
        anomalies.append(
            {
                "type": "confidence_inflation",
                "severity": "high",
                "reason": f"confidence_rise_{delta}_points",
                "delta": delta,
            }
        )

    prev_corr = prev.get("corroboration_score")
    curr_corr = curr.get("corroboration_score")
    corr_delta: int | None = None
    if prev_corr is not None and curr_corr is not None:
        corr_delta = int(curr_corr) - int(prev_corr)
        if corr_delta <= -_ANOMALY_CORROBORATION_DROP:
            anomalies.append(
                {
                    "type": "corroboration_collapse",
                    "severity": "high",
                    "reason": f"corroboration_drop_{abs(corr_delta)}_points",
                    "delta": corr_delta,
                }
            )

    prev_replay = prev.get("chain_replay_score")
    curr_replay = curr.get("chain_replay_score")
    if prev_replay is not None and curr_replay is not None:
        if int(curr_replay) < int(prev_replay):
            anomalies.append(
                {
                    "type": "replay_degradation",
                    "severity": "medium",
                    "reason": (
                        f"replay_score_dropped_{int(prev_replay)}_to_{int(curr_replay)}"
                    ),
                    "delta": int(curr_replay) - int(prev_replay),
                }
            )

    # Trust score manipulation: score rises while corroboration falls
    if delta >= 10 and corr_delta is not None and corr_delta < 0:
        anomalies.append(
            {
                "type": "trust_score_manipulation",
                "severity": "critical",
                "reason": "score_increased_without_corroboration_increase",
                "delta": delta,
            }
        )

    if not anomalies:
        return {
            "anomaly_detected": False,
            "severity": "none",
            "reason": "no_anomalies_detected",
            "anomalies": [],
        }

    max_sev = max(anomalies, key=lambda a: _SEVERITY_RANK.get(a["severity"], 0))[
        "severity"
    ]
    return {
        "anomaly_detected": True,
        "severity": max_sev,
        "reason": anomalies[0]["reason"],
        "anomalies": anomalies,
    }
