"""Trust Intelligence Authority — PR 1.8A.

Transforms Trust Intelligence (PR 1.8) from runtime computation into
cryptographically verifiable, immutable, replayable governance artifacts.

Every intelligence state becomes:
  Persistent       — generate_trust_intelligence_snapshot()
  Signable         — sign_trust_intelligence_snapshot()
  Verifiable       — verify_trust_intelligence_snapshot()
  Replayable       — replay_trust_intelligence()
  Historical       — generate_trust_memory()
  Evolutionary     — calculate_trust_evolution()
  Comparable       — compare_trust_snapshots()
  Defensible       — generate_trust_ledger() (hash-chained, tamper-evident)
  Auditable        — generate_decision_memory() / generate_executive_timeline()

Architecture:
  Part 1   generate_trust_intelligence_snapshot()  — immutable state capture
  Part 2   sign_trust_intelligence_snapshot()      — Ed25519 signing
           verify_trust_intelligence_snapshot()    — fail-closed verification
  Part 3   generate_trust_memory()                 — historical intelligence timeline
  Part 4   calculate_trust_evolution()             — explain trust change over time
  Part 5   replay_trust_intelligence()             — deterministic historical replay
  Part 6   compare_trust_snapshots()               — intelligence diff engine
  Part 7   generate_decision_memory()              — governance decision records
  Part 8   generate_executive_timeline()           — board-level reporting
  Part 9   generate_trust_ledger()                 — append-only hash-chained ledger
           verify_trust_ledger()                   — chain integrity check

Signing model:
  Ed25519 over SHA-256 of canonical JSON bytes.
  Same key material as all prior authorities:
    FG_EVIDENCE_SIGNING_KEY_B64 (32-byte seed, private operations)
    FG_EVIDENCE_VERIFY_KEY_B64  (32-byte pub, verify-only mode)
  signing_key_id = SHA256(pub_bytes)[:16]

Snapshot hash:
  Covers stable intelligence fields; excludes snapshot_id and created_at.
  Identical intelligence state → identical snapshot_hash regardless of
  when generate_trust_intelligence_snapshot() is called.

Ledger:
  Append-only, hash-chained. First entry: previous_hash = LEDGER_GENESIS_HASH.
  Tampering any entry breaks the chain from that point forward.

Future compatibility:
  entity_type is extensible: human, agent, autonomous_system, agi, any string.
  Decision memory supports all governed entity types without code changes.
"""

from __future__ import annotations

import base64
import hashlib
import os
import uuid
from datetime import datetime, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from services.canonical import canonical_json_bytes, utc_iso8601_z_now

# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------

TRUST_INTELLIGENCE_AUTHORITY_VERSION: str = "trust-intelligence-authority-v1"

# ---------------------------------------------------------------------------
# Ledger sentinel — genesis previous_hash for first ledger entry
# ---------------------------------------------------------------------------

LEDGER_GENESIS_HASH: str = "0" * 64

# ---------------------------------------------------------------------------
# Replay score component weights (must sum to 100)
# ---------------------------------------------------------------------------

_REPLAY_SCORE_LOCATED: int = 15  # snapshot found in snapshots_store
_REPLAY_SCORE_INTEGRITY: int = 25  # snapshot_hash recomputed and verified
_REPLAY_SCORE_SIGNATURE: int = 25  # Ed25519 signature verified
_REPLAY_SCORE_GRAPH: int = 15  # graph_result present and non-empty
_REPLAY_SCORE_CONFIDENCE: int = 10  # posture data present
_REPLAY_SCORE_AUTHORITY: int = 10  # authority_version matches current

# ---------------------------------------------------------------------------
# Evolution change classification thresholds
# ---------------------------------------------------------------------------

_EVOLUTION_MAJOR_THRESHOLD: int = 15
_EVOLUTION_MODERATE_THRESHOLD: int = 5

# ---------------------------------------------------------------------------
# Memory window presets (days)
# ---------------------------------------------------------------------------

MEMORY_WINDOW_30: int = 30
MEMORY_WINDOW_90: int = 90
MEMORY_WINDOW_180: int = 180
MEMORY_WINDOW_365: int = 365

# ---------------------------------------------------------------------------
# Decision entity types — extensible without code changes
# ---------------------------------------------------------------------------

DECISION_ENTITY_HUMAN: str = "human"
DECISION_ENTITY_AGENT: str = "agent"
DECISION_ENTITY_AUTONOMOUS: str = "autonomous_system"
DECISION_ENTITY_AGI: str = "agi"

# ---------------------------------------------------------------------------
# Posture level ordering for comparison (higher = better)
# ---------------------------------------------------------------------------

_POSTURE_ORDER: dict[str, int] = {
    "critical": 0,
    "degraded": 1,
    "watch": 2,
    "stable": 3,
    "healthy": 4,
    "excellent": 5,
}

# Trend direction ordering for comparison (higher = better)
_TREND_ORDER: dict[str, int] = {
    "rapidly_degrading": 0,
    "degrading": 1,
    "stable": 2,
    "improving": 3,
    "rapidly_improving": 4,
}

# ---------------------------------------------------------------------------
# Exception
# ---------------------------------------------------------------------------


class TrustIntelligenceAuthorityError(RuntimeError):
    """Raised when a trust intelligence authority operation cannot proceed.

    Fail closed: callers must handle explicitly. Never silently corrects.
    """


# ---------------------------------------------------------------------------
# Key management — same env vars and patterns as all prior authorities
# ---------------------------------------------------------------------------


def _load_private_key_seed() -> bytes:
    raw = os.environ.get("FG_EVIDENCE_SIGNING_KEY_B64", "").strip()
    if not raw:
        raise TrustIntelligenceAuthorityError(
            "FG_EVIDENCE_SIGNING_KEY_B64 not set — cannot sign intelligence artifacts"
        )
    try:
        seed = base64.b64decode(raw)
    except Exception as exc:
        raise TrustIntelligenceAuthorityError(
            f"Invalid base64 in FG_EVIDENCE_SIGNING_KEY_B64: {exc}"
        ) from exc
    if len(seed) != 32:
        raise TrustIntelligenceAuthorityError(
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
        except Exception as exc:
            raise TrustIntelligenceAuthorityError(
                "malformed FG_EVIDENCE_VERIFY_KEY_B64: base64 decode failed"
            ) from exc
        if len(pub_bytes) != 32:
            raise TrustIntelligenceAuthorityError(
                f"malformed FG_EVIDENCE_VERIFY_KEY_B64: expected 32 bytes, "
                f"got {len(pub_bytes)}"
            )
        return pub_bytes
    seed = _load_private_key_seed()
    return _derive_public_key_bytes(seed)


def _sign_digest(digest: bytes) -> tuple[str, str]:
    """Sign SHA-256 digest. Returns (signature_hex, key_id)."""
    seed = _load_private_key_seed()
    private = Ed25519PrivateKey.from_private_bytes(seed)
    pub_bytes = _derive_public_key_bytes(seed)
    key_id = _derive_key_id(pub_bytes)
    return private.sign(digest).hex(), key_id


# ---------------------------------------------------------------------------
# Snapshot canonical bytes
# Excludes snapshot_id, created_at, snapshot_signature — deterministic by state.
# ---------------------------------------------------------------------------


def _compute_payload_hashes(
    posture_result: dict[str, Any],
    trend_result: dict[str, Any],
    risk_result: dict[str, Any],
    priorities: list[Any],
    insights: list[Any],
    recommendations: list[Any],
    forecast_result: dict[str, Any],
    graph_result: dict[str, Any],
) -> dict[str, str]:
    """SHA-256 hash each full intelligence payload for binding into snapshot_hash.

    Keys sorted for determinism inside canonical_json_bytes.
    Any payload substitution breaks the stored snapshot_hash.
    """
    return {
        "forecast_result": hashlib.sha256(
            canonical_json_bytes(forecast_result)
        ).hexdigest(),
        "graph_result": hashlib.sha256(canonical_json_bytes(graph_result)).hexdigest(),
        "insights": hashlib.sha256(canonical_json_bytes(insights)).hexdigest(),
        "posture_result": hashlib.sha256(
            canonical_json_bytes(posture_result)
        ).hexdigest(),
        "priorities": hashlib.sha256(canonical_json_bytes(priorities)).hexdigest(),
        "recommendations": hashlib.sha256(
            canonical_json_bytes(recommendations)
        ).hexdigest(),
        "risk_result": hashlib.sha256(canonical_json_bytes(risk_result)).hexdigest(),
        "trend_result": hashlib.sha256(canonical_json_bytes(trend_result)).hexdigest(),
    }


def _extract_and_hash_payloads(snapshot: dict[str, Any]) -> dict[str, str]:
    """Re-derive payload hashes from a stored snapshot's full payload fields."""

    def _nd(k: str) -> dict[str, Any]:
        v = snapshot.get(k, {})
        return v if isinstance(v, dict) else {}

    def _nl(k: str) -> list[Any]:
        v = snapshot.get(k, [])
        return v if isinstance(v, list) else []

    return _compute_payload_hashes(
        _nd("posture_result"),
        _nd("trend_result"),
        _nd("risk_result"),
        _nl("priorities"),
        _nl("insights"),
        _nl("recommendations"),
        _nd("forecast_result"),
        _nd("graph_result"),
    )


def _canonical_intelligence_bytes(
    authority_version: str,
    tenant_id: str,
    engagement_id: str,
    posture_score: int,
    posture_level: str,
    trend_direction: str,
    trend_velocity: str,
    risk_level: str,
    risk_score: int,
    priorities_count: int,
    insights_count: int,
    recommendations_count: int,
    forecast_projected_score: int,
    graph_node_count: int,
    payload_hashes: dict[str, str],
) -> bytes:
    stable: dict[str, Any] = {
        "authority_version": authority_version,
        "engagement_id": engagement_id,
        "forecast_projected_score": forecast_projected_score,
        "graph_node_count": graph_node_count,
        "insights_count": insights_count,
        "payload_hashes": payload_hashes,
        "posture_level": posture_level,
        "posture_score": posture_score,
        "priorities_count": priorities_count,
        "recommendations_count": recommendations_count,
        "risk_level": risk_level,
        "risk_score": risk_score,
        "tenant_id": tenant_id,
        "trend_direction": trend_direction,
        "trend_velocity": trend_velocity,
    }
    return canonical_json_bytes(stable)


# ---------------------------------------------------------------------------
# Part 1 — Trust Intelligence Snapshot Generation
# ---------------------------------------------------------------------------

_SNAPSHOT_REQUIRED: frozenset[str] = frozenset(
    {
        "tenant_id",
        "engagement_id",
        "authority_version",
        "posture_score",
        "posture_level",
        "trend_direction",
        "trend_velocity",
        "risk_level",
        "risk_score",
        "priorities_count",
        "insights_count",
        "recommendations_count",
        "forecast_projected_score",
        "graph_node_count",
        "payload_hashes",
        "snapshot_hash",
        "snapshot_signature",
        "signing_key_id",
    }
)


def generate_trust_intelligence_snapshot(
    tenant_id: str,
    engagement_id: str,
    posture_result: dict[str, Any] | None = None,
    trend_result: dict[str, Any] | None = None,
    risk_result: dict[str, Any] | None = None,
    priorities: list[dict[str, Any]] | None = None,
    insights: list[dict[str, Any]] | None = None,
    recommendations: list[dict[str, Any]] | None = None,
    forecast_result: dict[str, Any] | None = None,
    graph_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Generate an immutable, cryptographically signed trust intelligence snapshot.

    snapshot_hash is computed over stable intelligence fields only, excluding
    snapshot_id and created_at. Identical intelligence state always produces
    the same snapshot_hash regardless of call time.

    Raises TrustIntelligenceAuthorityError if tenant_id/engagement_id absent
    or signing key unavailable.

    Returns all intelligence inputs embedded alongside snapshot authority fields.
    """
    if not tenant_id or not engagement_id:
        raise TrustIntelligenceAuthorityError(
            "tenant_id and engagement_id are required"
        )

    p = posture_result if isinstance(posture_result, dict) else {}
    t = trend_result if isinstance(trend_result, dict) else {}
    r = risk_result if isinstance(risk_result, dict) else {}
    f = forecast_result if isinstance(forecast_result, dict) else {}
    g = graph_result if isinstance(graph_result, dict) else {}

    posture_score = _safe_int(p.get("score", 0))
    posture_level = str(p.get("trust_posture", "unknown"))
    trend_direction = str(t.get("direction", "stable"))
    trend_velocity = str(t.get("velocity", "none"))
    risk_level = str(r.get("risk_level", "unknown"))
    risk_score = _safe_int(r.get("risk_score", 0))
    pri_list = list(priorities) if isinstance(priorities, list) else []
    ins_list = list(insights) if isinstance(insights, list) else []
    rec_list = list(recommendations) if isinstance(recommendations, list) else []

    priorities_count = len(pri_list)
    insights_count = len(ins_list)
    recommendations_count = len(rec_list)
    forecast_projected_score = _safe_int(
        f.get("projected_score", posture_score), fallback=posture_score
    )
    graph_nodes = g.get("nodes", [])
    graph_node_count = len(graph_nodes) if isinstance(graph_nodes, list) else 0

    payload_hashes = _compute_payload_hashes(
        p, t, r, pri_list, ins_list, rec_list, f, g
    )

    canonical = _canonical_intelligence_bytes(
        TRUST_INTELLIGENCE_AUTHORITY_VERSION,
        tenant_id,
        engagement_id,
        posture_score,
        posture_level,
        trend_direction,
        trend_velocity,
        risk_level,
        risk_score,
        priorities_count,
        insights_count,
        recommendations_count,
        forecast_projected_score,
        graph_node_count,
        payload_hashes,
    )
    snapshot_hash = hashlib.sha256(canonical).hexdigest()
    digest = hashlib.sha256(snapshot_hash.encode()).digest()
    sig, key_id = _sign_digest(digest)

    return {
        "snapshot_id": uuid.uuid4().hex,
        "tenant_id": tenant_id,
        "engagement_id": engagement_id,
        "authority_version": TRUST_INTELLIGENCE_AUTHORITY_VERSION,
        # Scalar summary fields (included in hash)
        "posture_score": posture_score,
        "posture_level": posture_level,
        "trend_direction": trend_direction,
        "trend_velocity": trend_velocity,
        "risk_level": risk_level,
        "risk_score": risk_score,
        "priorities_count": priorities_count,
        "insights_count": insights_count,
        "recommendations_count": recommendations_count,
        "forecast_projected_score": forecast_projected_score,
        "graph_node_count": graph_node_count,
        # Payload hashes bound into snapshot_hash; any payload swap breaks verification
        "payload_hashes": payload_hashes,
        # Full intelligence payloads (stored for replay; authenticated via payload_hashes)
        "posture_result": p,
        "trend_result": t,
        "risk_result": r,
        "priorities": pri_list,
        "insights": ins_list,
        "recommendations": rec_list,
        "forecast_result": f,
        "graph_result": g,
        # Authority fields
        "snapshot_hash": snapshot_hash,
        "snapshot_signature": sig,
        "signing_key_id": key_id,
        "created_at": utc_iso8601_z_now(),
    }


# ---------------------------------------------------------------------------
# Part 2 — Signing and Verification
# ---------------------------------------------------------------------------


def sign_trust_intelligence_snapshot(
    snapshot: dict[str, Any],
) -> dict[str, Any]:
    """Sign an existing snapshot dict (e.g. one deserialized from storage).

    Raises TrustIntelligenceAuthorityError if snapshot_hash is absent or
    signing key is unavailable.

    Returns a new dict with snapshot_signature and signing_key_id updated.
    """
    if not isinstance(snapshot, dict) or not snapshot.get("snapshot_hash"):
        raise TrustIntelligenceAuthorityError(
            "snapshot missing snapshot_hash — cannot sign"
        )
    snapshot_hash = snapshot["snapshot_hash"]
    digest = hashlib.sha256(snapshot_hash.encode()).digest()
    sig, key_id = _sign_digest(digest)
    return {**snapshot, "snapshot_signature": sig, "signing_key_id": key_id}


def verify_trust_intelligence_snapshot(
    snapshot: dict[str, Any],
) -> dict[str, Any]:
    """Verify a trust intelligence snapshot. Never raises. Returns {valid, reason}."""
    if not isinstance(snapshot, dict) or not snapshot:
        return {"valid": False, "reason": "missing_snapshot"}

    missing = _SNAPSHOT_REQUIRED - set(snapshot)
    if missing:
        return {"valid": False, "reason": f"missing_fields: {sorted(missing)}"}

    if snapshot.get("authority_version") != TRUST_INTELLIGENCE_AUTHORITY_VERSION:
        return {
            "valid": False,
            "reason": (
                f"invalid_authority_version: {snapshot.get('authority_version')}"
            ),
        }

    try:
        recomputed_payload_hashes = _extract_and_hash_payloads(snapshot)
    except Exception:
        return {"valid": False, "reason": "payload_hash_recomputation_failed"}

    if snapshot.get("payload_hashes") != recomputed_payload_hashes:
        return {"valid": False, "reason": "tampered_payload"}

    try:
        canonical = _canonical_intelligence_bytes(
            TRUST_INTELLIGENCE_AUTHORITY_VERSION,
            str(snapshot["tenant_id"]),
            str(snapshot["engagement_id"]),
            int(snapshot["posture_score"]),
            str(snapshot["posture_level"]),
            str(snapshot["trend_direction"]),
            str(snapshot["trend_velocity"]),
            str(snapshot["risk_level"]),
            int(snapshot["risk_score"]),
            int(snapshot["priorities_count"]),
            int(snapshot["insights_count"]),
            int(snapshot["recommendations_count"]),
            int(snapshot["forecast_projected_score"]),
            int(snapshot["graph_node_count"]),
            recomputed_payload_hashes,
        )
    except (TypeError, ValueError):
        return {"valid": False, "reason": "invalid_snapshot_values"}

    expected_hash = hashlib.sha256(canonical).hexdigest()
    if snapshot["snapshot_hash"] != expected_hash:
        return {"valid": False, "reason": "tampered_snapshot_hash"}

    try:
        pub_bytes = _load_verification_public_key()
    except TrustIntelligenceAuthorityError:
        return {"valid": False, "reason": "key_unavailable"}

    try:
        sig_bytes = bytes.fromhex(snapshot["snapshot_signature"])
        pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
        digest = hashlib.sha256(snapshot["snapshot_hash"].encode()).digest()
        pub.verify(sig_bytes, digest)
    except (InvalidSignature, ValueError, Exception):
        return {"valid": False, "reason": "signature_mismatch"}

    if snapshot["signing_key_id"] != _derive_key_id(pub_bytes):
        return {"valid": False, "reason": "signing_key_id_mismatch"}

    return {"valid": True, "reason": None}


# ---------------------------------------------------------------------------
# Part 3 — Trust Memory Engine
# ---------------------------------------------------------------------------


def generate_trust_memory(
    snapshots: list[dict[str, Any]] | None,
    window_days: int = MEMORY_WINDOW_90,
    *,
    tenant_id: str | None = None,
    engagement_id: str | None = None,
) -> dict[str, Any]:
    """Generate a historical intelligence timeline from a collection of snapshots.

    Filters to the requested window_days, then assembles posture, trend, and
    risk histories sorted chronologically. Future-dated snapshots are excluded.

    tenant_id and engagement_id scope the query to a single tenant/engagement.
    Callers should always pass these in multi-tenant environments to prevent
    cross-tenant data bleed when the snapshot collection contains mixed data.
    """
    if not isinstance(snapshots, list):
        snapshots = []
    valid: list[dict[str, Any]] = [
        s
        for s in snapshots
        if isinstance(s, dict)
        and s.get("snapshot_hash")
        and (tenant_id is None or s.get("tenant_id") == tenant_id)
        and (engagement_id is None or s.get("engagement_id") == engagement_id)
    ]
    now = datetime.now(timezone.utc)
    w = max(int(window_days), 0)

    in_window: list[dict[str, Any]] = []
    for s in valid:
        ts = _parse_ts(s.get("created_at", ""))
        if ts is None:
            continue
        delta = (now - ts).total_seconds() / 86400.0
        # Allow 1-second epsilon at upper boundary to absorb timing jitter
        if 0 <= delta <= w + (1.0 / 86400.0):
            in_window.append(s)

    in_window.sort(key=lambda s: s.get("created_at", ""))

    timeline = [
        {
            "snapshot_id": s.get("snapshot_id", ""),
            "created_at": s.get("created_at", ""),
            "posture_score": s.get("posture_score", 0),
            "posture_level": s.get("posture_level", "unknown"),
            "trend_direction": s.get("trend_direction", "stable"),
            "risk_level": s.get("risk_level", "unknown"),
            "snapshot_hash": s.get("snapshot_hash", ""),
        }
        for s in in_window
    ]
    posture_history = [
        {
            "date": s.get("created_at", ""),
            "score": s.get("posture_score", 0),
            "level": s.get("posture_level", "unknown"),
        }
        for s in in_window
    ]
    trend_history = [
        {
            "date": s.get("created_at", ""),
            "direction": s.get("trend_direction", "stable"),
            "velocity": s.get("trend_velocity", "none"),
        }
        for s in in_window
    ]
    risk_history = [
        {
            "date": s.get("created_at", ""),
            "level": s.get("risk_level", "unknown"),
            "score": s.get("risk_score", 0),
        }
        for s in in_window
    ]

    out_tenant_id = tenant_id or (in_window[0].get("tenant_id") if in_window else None)
    out_engagement_id = engagement_id or (
        in_window[0].get("engagement_id") if in_window else None
    )

    return {
        "window_days": w,
        "snapshot_count": len(in_window),
        "timeline": timeline,
        "posture_history": posture_history,
        "trend_history": trend_history,
        "risk_history": risk_history,
        "tenant_id": out_tenant_id,
        "engagement_id": out_engagement_id,
    }


# ---------------------------------------------------------------------------
# Part 4 — Trust Evolution Engine
# ---------------------------------------------------------------------------


def calculate_trust_evolution(
    snapshots: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    """Explain trust change over time across a collection of snapshots.

    Requires at least 2 snapshots. Deterministic: sorted by created_at.
    """
    if not isinstance(snapshots, list):
        snapshots = []
    valid: list[dict[str, Any]] = [
        s for s in snapshots if isinstance(s, dict) and s.get("snapshot_hash")
    ]
    valid.sort(key=lambda s: s.get("created_at", ""))

    if len(valid) < 2:
        return {
            "overall_change": "insufficient_data",
            "score_delta": 0,
            "largest_improvements": [],
            "largest_regressions": [],
            "root_causes": [],
            "snapshot_count": len(valid),
            "first_date": valid[0].get("created_at", "") if valid else "",
            "last_date": valid[-1].get("created_at", "") if valid else "",
            "first_posture": valid[0].get("posture_level", "unknown") if valid else "",
            "last_posture": valid[-1].get("posture_level", "unknown") if valid else "",
        }

    first = valid[0]
    last = valid[-1]
    score_delta = last.get("posture_score", 0) - first.get("posture_score", 0)

    if abs(score_delta) >= _EVOLUTION_MAJOR_THRESHOLD:
        overall_change = "major_improvement" if score_delta > 0 else "major_regression"
    elif abs(score_delta) >= _EVOLUTION_MODERATE_THRESHOLD:
        overall_change = (
            "moderate_improvement" if score_delta > 0 else "moderate_regression"
        )
    elif score_delta > 0:
        overall_change = "minor_improvement"
    elif score_delta < 0:
        overall_change = "minor_regression"
    else:
        overall_change = "stable"

    improvements: list[dict[str, Any]] = []
    regressions: list[dict[str, Any]] = []
    for i in range(1, len(valid)):
        prev = valid[i - 1]
        curr = valid[i]
        delta = curr.get("posture_score", 0) - prev.get("posture_score", 0)
        entry: dict[str, Any] = {
            "from_date": prev.get("created_at", ""),
            "to_date": curr.get("created_at", ""),
            "score_delta": delta,
            "from_level": prev.get("posture_level", "unknown"),
            "to_level": curr.get("posture_level", "unknown"),
        }
        if delta >= _EVOLUTION_MODERATE_THRESHOLD:
            improvements.append(entry)
        elif delta <= -_EVOLUTION_MODERATE_THRESHOLD:
            regressions.append(entry)

    improvements.sort(key=lambda x: -x["score_delta"])
    regressions.sort(key=lambda x: x["score_delta"])

    root_causes: list[str] = []
    directions = {s.get("trend_direction", "stable") for s in valid}
    risk_levels = {s.get("risk_level", "unknown") for s in valid}
    if len(directions) > 1:
        root_causes.append(f"trend_direction_changed: {sorted(directions)}")
    if len(risk_levels) > 1:
        root_causes.append(f"risk_level_changed: {sorted(risk_levels)}")
    if score_delta != 0:
        root_causes.append(
            f"posture_score_changed: "
            f"{first.get('posture_score', 0)} → {last.get('posture_score', 0)}"
        )
    if first.get("posture_level") != last.get("posture_level"):
        root_causes.append(
            f"posture_level_changed: "
            f"{first.get('posture_level', 'unknown')} → {last.get('posture_level', 'unknown')}"
        )

    return {
        "overall_change": overall_change,
        "score_delta": score_delta,
        "largest_improvements": improvements[:3],
        "largest_regressions": regressions[:3],
        "root_causes": root_causes,
        "snapshot_count": len(valid),
        "first_date": first.get("created_at", ""),
        "last_date": last.get("created_at", ""),
        "first_posture": first.get("posture_level", "unknown"),
        "last_posture": last.get("posture_level", "unknown"),
    }


# ---------------------------------------------------------------------------
# Part 5 — Intelligence Replay Authority
# ---------------------------------------------------------------------------


def replay_trust_intelligence(
    snapshot: dict[str, Any],
    snapshots_store: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Replay historical trust intelligence with layered validation.

    Validation layers (replay_score accumulates per layer passed):
      snapshot_located    — snapshot found in snapshots_store (skipped if no store)
      snapshot_integrity  — snapshot_hash recomputed and verified
      snapshot_signature  — Ed25519 signature verified
      graph_integrity     — graph_result nodes present and non-empty
      confidence_integrity— posture data present in snapshot
      authority_integrity — authority_version matches current

    replay_score: 0–100. valid: True only when integrity + signature pass.
    Never raises.
    """
    if not isinstance(snapshot, dict) or not snapshot:
        return {
            "valid": False,
            "snapshot": snapshot,
            "replay_score": 0,
            "validations": [],
            "reason": "missing_snapshot",
        }

    validations: list[str] = []
    replay_score = 0

    snapshot_hash = snapshot.get("snapshot_hash", "")

    # Layer 1: locate
    store = snapshots_store or []
    if store:
        located = any(
            isinstance(s, dict) and s.get("snapshot_hash") == snapshot_hash
            for s in store
        )
        if located:
            validations.append("snapshot_located")
            replay_score += _REPLAY_SCORE_LOCATED
    else:
        # No store = offline replay; treat as located
        validations.append("snapshot_located")
        replay_score += _REPLAY_SCORE_LOCATED

    # Layer 2: integrity — recompute hash independently
    integrity_ok = False
    try:
        replay_payload_hashes = _extract_and_hash_payloads(snapshot)
        canonical = _canonical_intelligence_bytes(
            TRUST_INTELLIGENCE_AUTHORITY_VERSION,
            str(snapshot.get("tenant_id", "")),
            str(snapshot.get("engagement_id", "")),
            int(snapshot.get("posture_score", 0)),
            str(snapshot.get("posture_level", "unknown")),
            str(snapshot.get("trend_direction", "stable")),
            str(snapshot.get("trend_velocity", "none")),
            str(snapshot.get("risk_level", "unknown")),
            int(snapshot.get("risk_score", 0)),
            int(snapshot.get("priorities_count", 0)),
            int(snapshot.get("insights_count", 0)),
            int(snapshot.get("recommendations_count", 0)),
            int(snapshot.get("forecast_projected_score", 0)),
            int(snapshot.get("graph_node_count", 0)),
            replay_payload_hashes,
        )
        expected_hash = hashlib.sha256(canonical).hexdigest()
        if snapshot_hash and snapshot_hash == expected_hash:
            validations.append("snapshot_integrity")
            replay_score += _REPLAY_SCORE_INTEGRITY
            integrity_ok = True
    except (TypeError, ValueError):
        pass

    # Layer 3: signature — only if integrity passed
    sig_ok = False
    if integrity_ok:
        try:
            pub_bytes = _load_verification_public_key()
            sig_bytes = bytes.fromhex(snapshot.get("snapshot_signature", ""))
            pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
            digest = hashlib.sha256(snapshot_hash.encode()).digest()
            pub.verify(sig_bytes, digest)
            if snapshot.get("signing_key_id") == _derive_key_id(pub_bytes):
                validations.append("snapshot_signature")
                replay_score += _REPLAY_SCORE_SIGNATURE
                sig_ok = True
        except Exception:
            pass

    # Layer 4: graph integrity
    graph_result = snapshot.get("graph_result", {})
    if isinstance(graph_result, dict):
        nodes = graph_result.get("nodes", [])
        if isinstance(nodes, list) and len(nodes) > 0:
            validations.append("graph_integrity")
            replay_score += _REPLAY_SCORE_GRAPH

    # Layer 5: confidence integrity
    if snapshot.get("posture_score") is not None and snapshot.get("posture_level"):
        validations.append("confidence_integrity")
        replay_score += _REPLAY_SCORE_CONFIDENCE

    # Layer 6: authority version
    if snapshot.get("authority_version") == TRUST_INTELLIGENCE_AUTHORITY_VERSION:
        validations.append("authority_integrity")
        replay_score += _REPLAY_SCORE_AUTHORITY

    valid = integrity_ok and sig_ok
    reason: str | None = None
    if not valid:
        if not integrity_ok:
            reason = "snapshot_integrity_failed"
        elif not sig_ok:
            reason = "snapshot_signature_failed"

    return {
        "valid": valid,
        "snapshot": snapshot,
        "replay_score": min(replay_score, 100),
        "validations": validations,
        "reason": reason,
    }


# ---------------------------------------------------------------------------
# Part 6 — Intelligence Difference Engine
# ---------------------------------------------------------------------------


def compare_trust_snapshots(
    snapshot_a: dict[str, Any],
    snapshot_b: dict[str, Any],
) -> dict[str, Any]:
    """Compare two intelligence states. Deterministic. Never raises.

    snapshot_a is the earlier / baseline state.
    snapshot_b is the later / current state.
    trust_delta = snapshot_b.posture_score - snapshot_a.posture_score.
    """
    a = snapshot_a if isinstance(snapshot_a, dict) else {}
    b = snapshot_b if isinstance(snapshot_b, dict) else {}

    score_a = _safe_int(a.get("posture_score", 0))
    score_b = _safe_int(b.get("posture_score", 0))
    trust_delta = score_b - score_a

    level_a = a.get("posture_level", "unknown")
    level_b = b.get("posture_level", "unknown")
    trend_a = a.get("trend_direction", "stable")
    trend_b = b.get("trend_direction", "stable")

    # Risk category comparison
    risk_a = set(_extract_high_risk_categories(a))
    risk_b = set(_extract_high_risk_categories(b))
    added_risks = sorted(risk_b - risk_a)
    removed_risks = sorted(risk_a - risk_b)

    # Control improvements and degradations
    improved_controls: list[str] = []
    degraded_controls: list[str] = []

    rank_a = _POSTURE_ORDER.get(level_a, -1)
    rank_b = _POSTURE_ORDER.get(level_b, -1)
    if rank_a >= 0 and rank_b >= 0 and rank_b != rank_a:
        if rank_b > rank_a:
            improved_controls.append(f"posture: {level_a} → {level_b}")
        else:
            degraded_controls.append(f"posture: {level_a} → {level_b}")

    trend_rank_a = _TREND_ORDER.get(trend_a, 2)
    trend_rank_b = _TREND_ORDER.get(trend_b, 2)
    if trend_rank_b != trend_rank_a:
        if trend_rank_b > trend_rank_a:
            improved_controls.append(f"trend: {trend_a} → {trend_b}")
        else:
            degraded_controls.append(f"trend: {trend_a} → {trend_b}")

    risk_score_a = _safe_int(a.get("risk_score", 0))
    risk_score_b = _safe_int(b.get("risk_score", 0))
    risk_delta = risk_score_b - risk_score_a
    if risk_delta <= -10:
        improved_controls.append(
            f"risk_score: {risk_score_a} → {risk_score_b} ({risk_delta:+d})"
        )
    elif risk_delta >= 10:
        degraded_controls.append(
            f"risk_score: {risk_score_a} → {risk_score_b} ({risk_delta:+d})"
        )

    return {
        "trust_delta": trust_delta,
        "posture_change": f"{level_a} → {level_b}",
        "trend_change": f"{trend_a} → {trend_b}",
        "added_risks": added_risks,
        "removed_risks": removed_risks,
        "improved_controls": improved_controls,
        "degraded_controls": degraded_controls,
        "snapshot_a_date": a.get("created_at", ""),
        "snapshot_b_date": b.get("created_at", ""),
        "snapshot_a_hash": a.get("snapshot_hash", ""),
        "snapshot_b_hash": b.get("snapshot_hash", ""),
    }


def _extract_high_risk_categories(snapshot: dict[str, Any]) -> list[str]:
    """Return risk categories with score >= 50 from snapshot's risk_result."""
    risk_result = snapshot.get("risk_result", {})
    if not isinstance(risk_result, dict):
        return []
    category_scores = risk_result.get("category_scores", {})
    if not isinstance(category_scores, dict):
        return []
    return [
        cat
        for cat, score in category_scores.items()
        if isinstance(score, (int, float)) and score >= 50
    ]


# ---------------------------------------------------------------------------
# Part 7 — Trust Decision Memory
# ---------------------------------------------------------------------------


def generate_decision_memory(
    decision_id: str,
    decision_type: str,
    entity_type: str = DECISION_ENTITY_HUMAN,
    reasoning: list[str] | None = None,
    supporting_snapshots: list[dict[str, Any]] | None = None,
    supporting_evidence_ids: list[str] | None = None,
    tenant_id: str = "",
    engagement_id: str = "",
) -> dict[str, Any]:
    """Record why a governance decision occurred.

    entity_type is extensible without code changes: human, agent,
    autonomous_system, agi, or any future governed entity type.

    Never raises. Deterministic for same inputs.
    """
    snaps = [s for s in (supporting_snapshots or []) if isinstance(s, dict)]

    supporting_intelligence = [
        {
            "snapshot_id": s.get("snapshot_id", ""),
            "snapshot_hash": s.get("snapshot_hash", ""),
            "created_at": s.get("created_at", ""),
            "posture_level": s.get("posture_level", "unknown"),
            "risk_level": s.get("risk_level", "unknown"),
            "posture_score": s.get("posture_score", 0),
        }
        for s in snaps
    ]

    return {
        "decision_id": decision_id or uuid.uuid4().hex,
        "decision_type": decision_type,
        "entity_type": entity_type,
        "tenant_id": tenant_id,
        "engagement_id": engagement_id,
        "decision_reasoning": list(reasoning or []),
        "supporting_intelligence": supporting_intelligence,
        "supporting_evidence": list(supporting_evidence_ids or []),
        "authority_version": TRUST_INTELLIGENCE_AUTHORITY_VERSION,
        "created_at": utc_iso8601_z_now(),
    }


# ---------------------------------------------------------------------------
# Part 8 — Executive Timeline
# ---------------------------------------------------------------------------


def generate_executive_timeline(
    snapshots: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    """Generate board-level reporting timeline from a sorted snapshot collection.

    Output is auditor-readable, investor-readable, GovCon-friendly.
    Never raises. Deterministic for same inputs.
    """
    if not isinstance(snapshots, list):
        snapshots = []
    valid: list[dict[str, Any]] = [
        s for s in snapshots if isinstance(s, dict) and s.get("created_at")
    ]
    valid.sort(key=lambda s: s.get("created_at", ""))

    timeline: list[dict[str, Any]] = []
    for i, snap in enumerate(valid):
        level = snap.get("posture_level", "unknown")
        score = snap.get("posture_score", 0)

        if i == 0:
            event = f"Trust baseline established: {level} (score: {score})"
            trust_change = "baseline"
        else:
            prev = valid[i - 1]
            prev_level = prev.get("posture_level", "unknown")
            prev_score = prev.get("posture_score", 0)
            delta = score - prev_score
            prev_rank = _POSTURE_ORDER.get(prev_level, -1)
            curr_rank = _POSTURE_ORDER.get(level, -1)

            if curr_rank > prev_rank and prev_rank >= 0:
                event = f"Trust improved: {prev_level} → {level} ({delta:+d})"
            elif curr_rank < prev_rank and curr_rank >= 0:
                event = f"Trust degraded: {prev_level} → {level} ({delta:+d})"
            elif delta > 0:
                event = f"Trust score increased: {prev_score} → {score} ({delta:+d})"
            elif delta < 0:
                event = f"Trust score decreased: {prev_score} → {score} ({delta:+d})"
            else:
                event = f"Trust unchanged: {level} (score: {score})"

            trust_change = f"{delta:+d}" if delta != 0 else "0"

        timeline.append(
            {
                "date": snap.get("created_at", ""),
                "event": event,
                "trust_change": trust_change,
                "impact": _executive_impact(level),
                "posture_level": level,
                "posture_score": score,
                "snapshot_id": snap.get("snapshot_id", ""),
            }
        )

    return timeline


def _executive_impact(posture_level: str) -> str:
    _IMPACTS: dict[str, str] = {
        "excellent": (
            "No action required. Trust posture exceeds governance thresholds."
        ),
        "healthy": "Monitor. Trust posture within acceptable bounds.",
        "stable": "Review. Trust posture adequate; improvement recommended.",
        "watch": "Attention required. Trust posture approaching risk threshold.",
        "degraded": ("Escalation required. Trust posture below acceptable threshold."),
        "critical": ("Immediate action required. Trust posture at critical level."),
    }
    return _IMPACTS.get(posture_level, "Assessment required.")


# ---------------------------------------------------------------------------
# Part 9 — Trust Intelligence Ledger
# ---------------------------------------------------------------------------


def generate_trust_ledger(
    snapshots: list[dict[str, Any]] | None,
    previous_ledger: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Generate an append-only, hash-chained trust intelligence ledger.

    Each entry carries previous_hash pointing to the preceding entry's
    ledger_entry_hash. The first entry in a fresh ledger uses LEDGER_GENESIS_HASH.
    If previous_ledger is supplied, new entries are appended after existing ones.

    Snapshots already present in the ledger (by snapshot_hash) are skipped.
    Never raises.
    """
    if not isinstance(snapshots, list):
        snapshots = []
    if not isinstance(previous_ledger, list):
        previous_ledger = []
    existing = [
        e for e in previous_ledger if isinstance(e, dict) and e.get("ledger_entry_hash")
    ]
    valid_snaps = [
        s for s in snapshots if isinstance(s, dict) and s.get("snapshot_hash")
    ]
    valid_snaps.sort(key=lambda s: s.get("created_at", ""))

    ledger = list(existing)
    ledgered_hashes = {e.get("snapshot_hash") for e in ledger}

    for snap in valid_snaps:
        snap_hash = snap.get("snapshot_hash", "")
        if snap_hash in ledgered_hashes:
            continue

        previous_hash = (
            ledger[-1]["ledger_entry_hash"] if ledger else LEDGER_GENESIS_HASH
        )

        entry: dict[str, Any] = {
            "snapshot_hash": snap_hash,
            "snapshot_id": snap.get("snapshot_id", ""),
            "snapshot_signature": snap.get("snapshot_signature", ""),
            "signing_key_id": snap.get("signing_key_id", ""),
            "authority_version": snap.get(
                "authority_version", TRUST_INTELLIGENCE_AUTHORITY_VERSION
            ),
            "tenant_id": snap.get("tenant_id", ""),
            "engagement_id": snap.get("engagement_id", ""),
            "posture_level": snap.get("posture_level", "unknown"),
            "risk_level": snap.get("risk_level", "unknown"),
            "posture_score": snap.get("posture_score", 0),
            "timestamp": snap.get("created_at", ""),
            "previous_hash": previous_hash,
        }

        entry_canonical = canonical_json_bytes(entry)
        entry["ledger_entry_hash"] = hashlib.sha256(entry_canonical).hexdigest()

        ledger.append(entry)
        ledgered_hashes.add(snap_hash)

    return ledger


def verify_trust_ledger(
    ledger: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    """Verify the integrity of a trust ledger chain. Never raises.

    Checks:
      1. Each entry's ledger_entry_hash matches recomputed value.
      2. First entry's previous_hash == LEDGER_GENESIS_HASH.
      3. Each subsequent entry's previous_hash == preceding entry's ledger_entry_hash.
    """
    if not isinstance(ledger, list):
        ledger = []
    entries = [e for e in ledger if isinstance(e, dict)]
    if not entries:
        return {
            "valid": True,
            "reason": None,
            "entry_count": 0,
            "chain_intact": True,
        }

    for i, entry in enumerate(entries):
        stored_hash = entry.get("ledger_entry_hash", "")
        entry_without_hash = {
            k: v for k, v in entry.items() if k != "ledger_entry_hash"
        }
        expected_hash = hashlib.sha256(
            canonical_json_bytes(entry_without_hash)
        ).hexdigest()
        if stored_hash != expected_hash:
            return {
                "valid": False,
                "reason": f"tampered_ledger_entry: index {i}",
                "entry_count": len(entries),
                "chain_intact": False,
                "tampered_index": i,
            }

        if i == 0:
            if entry.get("previous_hash") != LEDGER_GENESIS_HASH:
                return {
                    "valid": False,
                    "reason": "invalid_genesis_hash",
                    "entry_count": len(entries),
                    "chain_intact": False,
                    "tampered_index": 0,
                }
        else:
            expected_prev = entries[i - 1].get("ledger_entry_hash")
            if entry.get("previous_hash") != expected_prev:
                return {
                    "valid": False,
                    "reason": f"broken_chain: index {i}",
                    "entry_count": len(entries),
                    "chain_intact": False,
                    "tampered_index": i,
                }

    return {
        "valid": True,
        "reason": None,
        "entry_count": len(entries),
        "chain_intact": True,
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _safe_int(value: Any, fallback: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


def _parse_ts(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
