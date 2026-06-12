"""Auditor Proof Package Authority — PR 1.9.

Transforms verified trust into deliverable, defensible proof artifacts.

Every authority output (Evidence, Replay, Graph, Confidence, Intelligence,
Trust Ledger, Decision Memory) is assembled into an externally verifiable,
cryptographically signed proof package — auditor-ready, board-ready,
regulator-ready, legal-defense-ready, and machine-verifiable.

Architecture:
  Part 1   generate_auditor_proof_package()       — complete signed proof bundle
  Part 2   generate_executive_trust_brief()       — board/investor summary
  Part 3   generate_regulator_package()           — framework-mapped compliance proof
  Part 4   generate_legal_defense_package()       — decision reconstruction
  Part 5   generate_machine_verification_bundle() — third-party verifiable export
  Part 6   generate_trust_certification()         — scored, leveled certification
  Part 7   generate_chain_of_custody()            — hash-linked custody chain
  Part 8   sign_proof_package()                   — Ed25519 package signing
           verify_proof_package()                 — fail-closed verification
  Part 9   replay_auditor_package()               — multi-layer replay engine
  Part 10  generate_enterprise_export()           — multi-format enterprise export

Signing model:
  Ed25519 over SHA-256 of canonical JSON bytes.
  Same key material as all prior authorities:
    FG_EVIDENCE_SIGNING_KEY_B64 (32-byte seed, private operations)
    FG_EVIDENCE_VERIFY_KEY_B64  (32-byte pub, verify-only mode)
  signing_key_id = SHA256(pub_bytes)[:16]

Package hash:
  Covers stable proof fields; excludes package_id and verified_at.
  Identical proof state → identical package_hash regardless of when called.
  Section hashes bind every section's content into the package_hash.
  Any section modification breaks the signature chain.

Future compatibility:
  entity_type is extensible: human, reviewer, approver, agent, agent_fleet,
  autonomous_workflow, autonomous_system, agi, any string.
  Proof packages support all governed entity types without code changes.
"""

from __future__ import annotations

import base64
import hashlib
import os
import uuid
from datetime import datetime, timedelta, timezone
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

AUDITOR_PROOF_AUTHORITY_VERSION: str = "auditor-proof-authority-v1"

# ---------------------------------------------------------------------------
# Ledger / custody sentinel
# ---------------------------------------------------------------------------

PROOF_GENESIS_HASH: str = "0" * 64

# ---------------------------------------------------------------------------
# Certification level constants and score thresholds
# ---------------------------------------------------------------------------

CERT_BRONZE: str = "bronze"
CERT_SILVER: str = "silver"
CERT_GOLD: str = "gold"
CERT_PLATINUM: str = "platinum"
CERT_ENTERPRISE: str = "enterprise"
CERT_NOT_CERTIFIED: str = "not_certified"

_CERT_ENTERPRISE_THRESHOLD: int = 90
_CERT_PLATINUM_THRESHOLD: int = 80
_CERT_GOLD_THRESHOLD: int = 70
_CERT_SILVER_THRESHOLD: int = 60
_CERT_BRONZE_THRESHOLD: int = 50

_CERT_VALIDITY_DAYS: int = 90

# ---------------------------------------------------------------------------
# Certification scoring weights
# ---------------------------------------------------------------------------

_CERT_TRUST_WEIGHT: float = 0.7
_CERT_CONFIDENCE_WEIGHT: float = 0.3
_CERT_SCORED_BY: str = "deterministic_composite_v1"

# ---------------------------------------------------------------------------
# Replay layer weights (must sum to 100)
# ---------------------------------------------------------------------------

_REPLAY_EVIDENCE_WEIGHT: int = 20
_REPLAY_REPLAY_WEIGHT: int = 15
_REPLAY_GRAPH_WEIGHT: int = 15
_REPLAY_CONFIDENCE_WEIGHT: int = 15
_REPLAY_INTELLIGENCE_WEIGHT: int = 15
_REPLAY_LEDGER_WEIGHT: int = 10
_REPLAY_DECISION_WEIGHT: int = 10

# ---------------------------------------------------------------------------
# Chain of custody event types
# ---------------------------------------------------------------------------

CUSTODY_EVIDENCE_CREATED: str = "evidence_created"
CUSTODY_EVIDENCE_REVIEWED: str = "evidence_reviewed"
CUSTODY_EVIDENCE_APPROVED: str = "evidence_approved"
CUSTODY_REPORT_GENERATED: str = "report_generated"
CUSTODY_REPORT_EXPORTED: str = "report_exported"
CUSTODY_TRUST_VERIFIED: str = "trust_verified"
CUSTODY_PACKAGE_GENERATED: str = "package_generated"

# ---------------------------------------------------------------------------
# Enterprise export formats
# ---------------------------------------------------------------------------

EXPORT_JSON: str = "json"
EXPORT_PDF: str = "pdf"
EXPORT_HTML: str = "html"
EXPORT_MANIFEST: str = "manifest"
EXPORT_MACHINE_BUNDLE: str = "machine_bundle"

_EXPORT_FORMATS: frozenset[str] = frozenset(
    {EXPORT_JSON, EXPORT_PDF, EXPORT_HTML, EXPORT_MANIFEST, EXPORT_MACHINE_BUNDLE}
)

# ---------------------------------------------------------------------------
# Supported compliance frameworks — extensible, never hardcoded
# ---------------------------------------------------------------------------

FRAMEWORK_NIST: str = "NIST CSF"
FRAMEWORK_NIST_AI: str = "NIST AI RMF"
FRAMEWORK_ISO_42001: str = "ISO 42001"
FRAMEWORK_SOC2: str = "SOC 2"
FRAMEWORK_HIPAA: str = "HIPAA"
FRAMEWORK_PCI_DSS: str = "PCI DSS"

_DEFAULT_FRAMEWORKS: list[str] = [
    FRAMEWORK_NIST,
    FRAMEWORK_NIST_AI,
    FRAMEWORK_ISO_42001,
    FRAMEWORK_SOC2,
]

# ---------------------------------------------------------------------------
# Decision entity types — extensible without code changes
# ---------------------------------------------------------------------------

ENTITY_HUMAN: str = "human"
ENTITY_REVIEWER: str = "reviewer"
ENTITY_APPROVER: str = "approver"
ENTITY_AGENT: str = "agent"
ENTITY_AGENT_FLEET: str = "agent_fleet"
ENTITY_AUTONOMOUS_WORKFLOW: str = "autonomous_workflow"
ENTITY_AUTONOMOUS_SYSTEM: str = "autonomous_system"
ENTITY_AGI: str = "agi"

# ---------------------------------------------------------------------------
# Posture narrative maps — board/auditor language
# ---------------------------------------------------------------------------

_POSTURE_NARRATIVE: dict[str, str] = {
    "critical": (
        "Trust posture requires immediate executive attention. "
        "Critical gaps exist in the trust infrastructure."
    ),
    "degraded": (
        "Trust posture has declined and requires prompt corrective action. "
        "Multiple trust factors are operating below acceptable thresholds."
    ),
    "watch": (
        "Trust posture is below target. Monitoring and improvement "
        "actions are recommended to prevent further degradation."
    ),
    "stable": (
        "Trust posture is stable and meets baseline requirements. "
        "Continued investment will achieve higher trust maturity."
    ),
    "healthy": (
        "Trust posture is strong and above industry baseline. "
        "The organization demonstrates effective trust management."
    ),
    "excellent": (
        "Trust posture is excellent. This represents industry-leading "
        "trust maturity and is suitable for enterprise certification."
    ),
}

_TREND_NARRATIVE: dict[str, str] = {
    "rapidly_improving": "Trust metrics are showing significant positive momentum.",
    "improving": "Trust metrics show consistent positive movement.",
    "stable": "Trust metrics are holding steady.",
    "degrading": "Trust metrics show early signs of decline. Proactive action recommended.",
    "rapidly_degrading": "Trust metrics are declining rapidly. Immediate action required.",
}

_BOARD_RECOMMENDATION: dict[str, str] = {
    "critical": (
        "Immediate executive action required. "
        "Recommend an emergency trust remediation program."
    ),
    "degraded": (
        "Recommend prioritizing trust remediation in the current planning cycle."
    ),
    "watch": (
        "Recommend prioritizing trust improvement initiatives "
        "in the next planning cycle."
    ),
    "stable": (
        "Recommend continued investment in trust infrastructure "
        "to achieve healthy status."
    ),
    "healthy": (
        "Recommend maintaining current trust posture and "
        "planning for enterprise certification."
    ),
    "excellent": (
        "Recommend pursuing formal trust certification and external validation."
    ),
}

# ---------------------------------------------------------------------------
# Required package fields for verification
# ---------------------------------------------------------------------------

_PACKAGE_REQUIRED: frozenset[str] = frozenset(
    {
        "tenant_id",
        "engagement_id",
        "authority_version",
        "assessed_by",
        "sections",
        "section_count",
        "section_hashes",
        "package_hash",
        "package_signature",
        "signing_key_id",
    }
)

# ---------------------------------------------------------------------------
# Exception
# ---------------------------------------------------------------------------


class AuditorProofAuthorityError(RuntimeError):
    """Raised when an auditor proof authority operation cannot proceed.

    Fail closed: callers must handle explicitly. Never silently corrects.
    """


# ---------------------------------------------------------------------------
# Key management — same env vars and patterns as all prior authorities
# ---------------------------------------------------------------------------


def _load_private_key_seed() -> bytes:
    raw = os.environ.get("FG_EVIDENCE_SIGNING_KEY_B64", "").strip()
    if not raw:
        raise AuditorProofAuthorityError(
            "FG_EVIDENCE_SIGNING_KEY_B64 not set — cannot sign proof artifacts"
        )
    try:
        seed = base64.b64decode(raw)
    except Exception as exc:
        raise AuditorProofAuthorityError(
            f"Invalid base64 in FG_EVIDENCE_SIGNING_KEY_B64: {exc}"
        ) from exc
    if len(seed) != 32:
        raise AuditorProofAuthorityError(
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
            raise AuditorProofAuthorityError(
                "malformed FG_EVIDENCE_VERIFY_KEY_B64: base64 decode failed"
            ) from exc
        if len(pub_bytes) != 32:
            raise AuditorProofAuthorityError(
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
# Canonical proof bytes — deterministic, excludes package_id and verified_at
# ---------------------------------------------------------------------------


def _canonical_proof_bytes(
    authority_version: str,
    tenant_id: str,
    engagement_id: str,
    assessed_by: str,
    section_count: int,
    section_hashes: dict[str, str],
) -> bytes:
    stable: dict[str, Any] = {
        "assessed_by": assessed_by,
        "authority_version": authority_version,
        "engagement_id": engagement_id,
        "section_count": section_count,
        "section_hashes": dict(sorted(section_hashes.items())),
        "tenant_id": tenant_id,
    }
    return canonical_json_bytes(stable)


def _section_hash(data: Any) -> str:
    """SHA-256 of canonical JSON of section data."""
    return hashlib.sha256(canonical_json_bytes(data)).hexdigest()


def _is_ledger_chain_intact(ledger: list[dict[str, Any]]) -> bool:
    """Verify previous_hash linkage across all ledger entries.

    Returns False if any entry is missing hash fields or if any
    previous_hash does not match the prior entry's ledger_entry_hash.
    """
    if not ledger:
        return False
    prev_hash: str | None = None
    for entry in ledger:
        if not isinstance(entry, dict):
            return False
        entry_hash = entry.get("ledger_entry_hash", "")
        previous_hash = entry.get("previous_hash", "")
        if not entry_hash or not previous_hash:
            return False
        if prev_hash is not None and previous_hash != prev_hash:
            return False
        prev_hash = entry_hash
    return True


# ---------------------------------------------------------------------------
# Part 1 — Auditor Proof Package
# ---------------------------------------------------------------------------


def generate_auditor_proof_package(
    tenant_id: str,
    engagement_id: str,
    *,
    intelligence_snapshot: dict[str, Any] | None = None,
    trust_ledger: list[dict[str, Any]] | None = None,
    decision_memories: list[dict[str, Any]] | None = None,
    confidence_manifest: dict[str, Any] | None = None,
    graph_snapshot: dict[str, Any] | None = None,
    replay_result: dict[str, Any] | None = None,
    evidence_summary: dict[str, Any] | None = None,
    assessed_by: str = ENTITY_HUMAN,
) -> dict[str, Any]:
    """Generate a complete, cryptographically signed auditor proof package.

    Assembles all trust authority outputs into a single, tamper-evident,
    externally verifiable artifact. Package hash covers all section hashes;
    any section modification breaks the signature chain.

    Raises AuditorProofAuthorityError if tenant_id/engagement_id absent
    or signing key unavailable.
    """
    if not tenant_id or not engagement_id:
        raise AuditorProofAuthorityError("tenant_id and engagement_id are required")

    snap = intelligence_snapshot if isinstance(intelligence_snapshot, dict) else {}
    ledger = trust_ledger if isinstance(trust_ledger, list) else []
    decisions = decision_memories if isinstance(decision_memories, list) else []
    conf = confidence_manifest if isinstance(confidence_manifest, dict) else {}
    graph = graph_snapshot if isinstance(graph_snapshot, dict) else {}
    replay = replay_result if isinstance(replay_result, dict) else {}
    evidence = evidence_summary if isinstance(evidence_summary, dict) else {}
    by = str(assessed_by) if assessed_by else ENTITY_HUMAN

    sections: dict[str, Any] = {
        "evidence": {
            "status": "present" if evidence else "absent",
            "source": evidence,
            "item_count": _safe_int(evidence.get("item_count", len(evidence))),
        },
        "replay": {
            "status": "verified"
            if replay.get("valid")
            else ("failed" if replay else "absent"),
            "replay_score": _safe_int(replay.get("replay_score", 0)),
            "validations": (
                replay.get("validations", [])
                if isinstance(replay.get("validations"), list)
                else []
            ),
        },
        "graph": {
            "status": "present" if graph else "absent",
            "node_count": _safe_int(
                graph.get("node_count", 0)
                if not graph.get("nodes")
                else len(graph.get("nodes", []))
            ),
            "edge_count": _safe_int(
                graph.get("edge_count", 0)
                if not graph.get("edges")
                else len(graph.get("edges", []))
            ),
        },
        "confidence": {
            "status": "present" if conf else "absent",
            "manifest_hash": conf.get("manifest_hash", ""),
            "composite_score": _safe_int(conf.get("composite_score", 0)),
        },
        "intelligence": {
            "status": "present" if snap else "absent",
            "snapshot_hash": snap.get("snapshot_hash", ""),
            "posture_score": _safe_int(snap.get("posture_score", 0)),
            "posture_level": snap.get("posture_level", "unknown"),
            "risk_level": snap.get("risk_level", "unknown"),
            "authority_version": snap.get(
                "authority_version", "trust-intelligence-authority-v1"
            ),
        },
        "ledger": {
            "status": "present" if ledger else "absent",
            "entry_count": len(ledger),
            "chain_intact": _is_ledger_chain_intact(ledger),
            "ledger_hash": hashlib.sha256(canonical_json_bytes(ledger)).hexdigest()
            if ledger
            else "",
        },
        "decisions": {
            "status": "present" if decisions else "absent",
            "decision_count": len(decisions),
            "entity_types": sorted(
                {
                    d.get("entity_type", "unknown")
                    for d in decisions
                    if isinstance(d, dict)
                }
            ),
        },
        "historical": {
            "status": "present" if snap.get("created_at") else "absent",
            "earliest_record": snap.get("created_at", ""),
            "ledger_entries": len(ledger),
            "decision_entries": len(decisions),
        },
    }

    section_hashes: dict[str, str] = {
        name: _section_hash(section) for name, section in sections.items()
    }
    section_count = len(sections)

    canonical = _canonical_proof_bytes(
        AUDITOR_PROOF_AUTHORITY_VERSION,
        tenant_id,
        engagement_id,
        by,
        section_count,
        section_hashes,
    )
    package_hash = hashlib.sha256(canonical).hexdigest()
    digest = hashlib.sha256(package_hash.encode()).digest()
    sig, key_id = _sign_digest(digest)

    return {
        "package_id": uuid.uuid4().hex,
        "tenant_id": tenant_id,
        "engagement_id": engagement_id,
        "authority_version": AUDITOR_PROOF_AUTHORITY_VERSION,
        "assessed_by": by,
        "sections": sections,
        "section_count": section_count,
        "section_hashes": section_hashes,
        "package_hash": package_hash,
        "package_signature": sig,
        "signing_key_id": key_id,
        "verified_at": utc_iso8601_z_now(),
    }


# ---------------------------------------------------------------------------
# Part 2 — Executive Trust Brief
# ---------------------------------------------------------------------------


def generate_executive_trust_brief(
    tenant_id: str,
    engagement_id: str,
    *,
    intelligence_snapshot: dict[str, Any] | None = None,
    trust_memory: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Generate a board-level, non-technical trust summary.

    Intended for executive, investor, and M&A due diligence consumption.
    Maps technical trust metrics to plain English narratives. Never raises.
    """
    snap = intelligence_snapshot if isinstance(intelligence_snapshot, dict) else {}
    mem = trust_memory if isinstance(trust_memory, dict) else {}

    posture_score = _safe_int(snap.get("posture_score", 0))
    posture_level = str(snap.get("posture_level", "unknown"))
    trend_direction = str(snap.get("trend_direction", "stable"))
    risk_level = str(snap.get("risk_level", "unknown"))
    risk_score = _safe_int(snap.get("risk_score", 0))

    posture_narrative = _POSTURE_NARRATIVE.get(
        posture_level,
        "Trust posture assessment is in progress.",
    )
    trend_narrative = _TREND_NARRATIVE.get(
        trend_direction,
        "Trust trend data is being collected.",
    )
    board_recommendation = _BOARD_RECOMMENDATION.get(
        posture_level,
        "Continue monitoring trust posture metrics.",
    )

    snap_count = _safe_int(mem.get("snapshot_count", 0))
    window_days = _safe_int(mem.get("window_days", 90))

    posture_history = mem.get("posture_history", [])
    if isinstance(posture_history, list) and len(posture_history) >= 2:
        oldest_score = _safe_int(posture_history[0].get("score", posture_score))
        change = posture_score - oldest_score
        change_str = f"+{change}" if change >= 0 else str(change)
        trend_context = (
            f"Over the past {window_days} days ({snap_count} assessments), "
            f"trust posture has changed by {change_str} points."
        )
    else:
        trend_context = f"Trust posture monitoring is active across {snap_count} recorded assessments."

    risk_summary = _risk_plain_english(risk_level, risk_score)

    top_risks: list[str] = []
    risk_result = snap.get("risk_result", {})
    if isinstance(risk_result, dict):
        cat_scores = risk_result.get("category_scores", {})
        if isinstance(cat_scores, dict):
            top_cats = sorted(
                [(k, v) for k, v in cat_scores.items() if isinstance(v, (int, float))],
                key=lambda x: -x[1],
            )[:3]
            top_risks = [
                f"{cat.replace('_', ' ').title()}: score {int(score)}"
                for cat, score in top_cats
            ]
    if not top_risks:
        top_risks = [f"Overall risk level: {risk_level}"]

    priority_actions: list[str] = []
    priorities = snap.get("priorities", [])
    if isinstance(priorities, list):
        for p in priorities[:3]:
            if isinstance(p, dict) and p.get("issue"):
                priority_actions.append(str(p["issue"]).replace("_", " ").title())
    if not priority_actions:
        priority_actions = ["Continue trust monitoring and assessment cadence"]

    forecast_snap = snap.get("forecast_result", {})
    if isinstance(forecast_snap, dict) and forecast_snap.get("projected_score"):
        projected = _safe_int(forecast_snap.get("projected_score", posture_score))
        forecast_narrative = (
            f"Trust posture is forecast to reach {projected}/100 "
            f"based on current trajectory."
        )
    else:
        forecast_narrative = (
            "Forecast requires additional historical data. "
            "Maintain current assessment cadence."
        )

    executive_summary = (
        f"This organization's trust posture is currently rated '{posture_level}' "
        f"({posture_score}/100). {posture_narrative} {trend_narrative} "
        f"{trend_context}"
    )

    return {
        "brief_id": uuid.uuid4().hex,
        "tenant_id": tenant_id,
        "engagement_id": engagement_id,
        "brief_date": utc_iso8601_z_now(),
        "current_posture": {
            "level": posture_level,
            "score": posture_score,
            "plain_english": posture_narrative,
        },
        "trust_trend": {
            "direction": trend_direction,
            "plain_english": trend_narrative,
            "context": trend_context,
        },
        "risk_summary": risk_summary,
        "top_risks": top_risks,
        "priority_actions": priority_actions,
        "forecast": {
            "narrative": forecast_narrative,
        },
        "executive_summary": executive_summary,
        "board_recommendation": board_recommendation,
    }


# ---------------------------------------------------------------------------
# Part 3 — Regulator Package
# ---------------------------------------------------------------------------


def generate_regulator_package(
    tenant_id: str,
    engagement_id: str,
    *,
    intelligence_snapshot: dict[str, Any] | None = None,
    evidence_summary: dict[str, Any] | None = None,
    frameworks: list[str] | None = None,
    control_results: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Generate a regulator-facing proof package.

    Framework-agnostic: any framework string is accepted; readiness is derived
    from posture score, not from hardcoded control mappings. Extensible to any
    future framework without code changes.

    Never raises.
    """
    snap = intelligence_snapshot if isinstance(intelligence_snapshot, dict) else {}
    evidence = evidence_summary if isinstance(evidence_summary, dict) else {}
    fws: list[str] = (
        [str(f) for f in frameworks if isinstance(f, str)]
        if isinstance(frameworks, list) and frameworks
        else list(_DEFAULT_FRAMEWORKS)
    )
    controls = control_results if isinstance(control_results, list) else []

    posture_score = _safe_int(snap.get("posture_score", 0))
    posture_level = str(snap.get("posture_level", "unknown"))
    risk_level = str(snap.get("risk_level", "unknown"))

    readiness_level = _readiness_from_score(posture_score)
    readiness_gaps = _readiness_gaps(posture_score)

    framework_readiness: dict[str, Any] = {}
    for fw in fws:
        framework_readiness[fw] = {
            "framework": fw,
            "readiness_level": readiness_level,
            "posture_score": posture_score,
            "gaps": readiness_gaps,
            "status": "assessment_complete",
        }

    evidence_sources: list[dict[str, Any]] = []
    if evidence:
        evidence_sources.append(
            {
                "source_type": "field_assessment",
                "item_count": _safe_int(evidence.get("item_count", 1)),
                "status": "collected",
            }
        )

    control_mapping: list[dict[str, Any]] = []
    for cr in controls:
        if isinstance(cr, dict):
            control_mapping.append(
                {
                    "control_id": cr.get("control_id", ""),
                    "control_name": cr.get("control_name", ""),
                    "status": cr.get("status", "assessed"),
                    "score": _safe_int(cr.get("score", 0)),
                }
            )

    verification_results = {
        "trust_chain": snap.get("snapshot_hash", "") != "",
        "evidence_signed": evidence.get("signed", False),
        "posture_verified": posture_level != "unknown",
        "risk_assessed": risk_level != "unknown",
        "intelligence_present": bool(snap),
    }

    trust_chain_validation = {
        "snapshot_hash": snap.get("snapshot_hash", ""),
        "authority_version": snap.get(
            "authority_version", "trust-intelligence-authority-v1"
        ),
        "chain_intact": snap.get("snapshot_hash", "") != "",
    }

    decision_chain_validation = {
        "decisions_recorded": False,
        "chain_verifiable": snap.get("snapshot_hash", "") != "",
    }

    return {
        "package_id": uuid.uuid4().hex,
        "tenant_id": tenant_id,
        "engagement_id": engagement_id,
        "generated_at": utc_iso8601_z_now(),
        "authority_version": AUDITOR_PROOF_AUTHORITY_VERSION,
        "assessment_scope": {
            "tenant_id": tenant_id,
            "engagement_id": engagement_id,
            "posture_level": posture_level,
            "posture_score": posture_score,
            "risk_level": risk_level,
        },
        "evidence_sources": evidence_sources,
        "assessed_frameworks": fws,
        "framework_readiness": framework_readiness,
        "control_mapping": control_mapping,
        "verification_results": verification_results,
        "trust_chain_validation": trust_chain_validation,
        "decision_chain_validation": decision_chain_validation,
    }


# ---------------------------------------------------------------------------
# Part 4 — Legal Defense Package
# ---------------------------------------------------------------------------


def generate_legal_defense_package(
    tenant_id: str,
    engagement_id: str,
    *,
    decision_memories: list[dict[str, Any]] | None = None,
    intelligence_snapshot: dict[str, Any] | None = None,
    replay_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Generate a court-defensible decision reconstruction package.

    Answers: what was known, when, what evidence existed, what intelligence
    existed, who approved, why the decision was made, and whether the
    decision can be independently replayed.

    Never raises.
    """
    decisions = decision_memories if isinstance(decision_memories, list) else []
    snap = intelligence_snapshot if isinstance(intelligence_snapshot, dict) else {}
    replay = replay_result if isinstance(replay_result, dict) else {}

    decision_list = [d for d in decisions if isinstance(d, dict)]
    decision_list.sort(key=lambda d: d.get("created_at", ""))

    entity_types = sorted({d.get("entity_type", "unknown") for d in decision_list})
    total_decisions = len(decision_list)

    decision_reconstruction = {
        "decisions": decision_list,
        "total_decisions": total_decisions,
        "entity_types": entity_types,
        "decision_types": sorted({d.get("decision_type", "") for d in decision_list}),
    }

    posture_score = _safe_int(snap.get("posture_score", 0))
    posture_level = snap.get("posture_level", "unknown")
    risk_level = snap.get("risk_level", "unknown")
    snap_created = snap.get("created_at", "")

    evidence_chain = {
        "snapshot_hash": snap.get("snapshot_hash", ""),
        "snapshot_created_at": snap_created,
        "posture_score": posture_score,
        "posture_level": posture_level,
        "risk_level": risk_level,
        "evidence_present": bool(snap),
    }

    intelligence_chain = {
        "snapshot_hash": snap.get("snapshot_hash", ""),
        "authority_version": snap.get(
            "authority_version", "trust-intelligence-authority-v1"
        ),
        "posture_score": posture_score,
        "priorities_count": _safe_int(snap.get("priorities_count", 0)),
        "insights_count": _safe_int(snap.get("insights_count", 0)),
        "recommendations_count": _safe_int(snap.get("recommendations_count", 0)),
    }

    replay_validation = {
        "valid": replay.get("valid", False),
        "replay_score": _safe_int(replay.get("replay_score", 0)),
        "validations": (
            replay.get("validations", [])
            if isinstance(replay.get("validations"), list)
            else []
        ),
        "can_replay": replay.get("valid", False),
    }

    decision_timeline = [
        {
            "sequence": i + 1,
            "decision_id": d.get("decision_id", d.get("id", "")),
            "decision_type": d.get("decision_type", ""),
            "entity_type": d.get("entity_type", "unknown"),
            "created_at": d.get("created_at", ""),
            "reasoning_summary": str(d.get("decision_reasoning", ""))[:200],
        }
        for i, d in enumerate(decision_list)
    ]

    who_approved = ", ".join(entity_types) if entity_types else "not_recorded"
    why_decided = (
        decision_list[0].get("decision_reasoning", "")
        if decision_list
        else "no_decisions_recorded"
    )

    questions_answered = {
        "what_was_known": f"Posture: {posture_level} ({posture_score}/100), "
        f"Risk: {risk_level}",
        "when_was_it_known": snap_created or "timestamp_not_recorded",
        "what_evidence_existed": f"Snapshot hash: {snap.get('snapshot_hash', 'absent')}",
        "what_intelligence_existed": (
            f"Intelligence snapshot with "
            f"{_safe_int(snap.get('priorities_count', 0))} priorities, "
            f"{_safe_int(snap.get('insights_count', 0))} insights, "
            f"{_safe_int(snap.get('recommendations_count', 0))} recommendations"
        ),
        "who_approved": who_approved,
        "why_was_decision_made": str(why_decided)[:500],
        "can_decision_be_replayed": replay_validation["can_replay"],
    }

    decision_contents_hash = hashlib.sha256(
        canonical_json_bytes(decision_list)
    ).hexdigest()
    reconstruction_stable = {
        "authority_version": AUDITOR_PROOF_AUTHORITY_VERSION,
        "decision_contents_hash": decision_contents_hash,
        "engagement_id": engagement_id,
        "replay_valid": replay_validation["valid"],
        "snapshot_hash": snap.get("snapshot_hash", ""),
        "tenant_id": tenant_id,
        "total_decisions": total_decisions,
    }
    reconstruction_hash = hashlib.sha256(
        canonical_json_bytes(reconstruction_stable)
    ).hexdigest()

    return {
        "package_id": uuid.uuid4().hex,
        "tenant_id": tenant_id,
        "engagement_id": engagement_id,
        "generated_at": utc_iso8601_z_now(),
        "authority_version": AUDITOR_PROOF_AUTHORITY_VERSION,
        "decision_reconstruction": decision_reconstruction,
        "evidence_chain": evidence_chain,
        "intelligence_chain": intelligence_chain,
        "replay_validation": replay_validation,
        "decision_timeline": decision_timeline,
        "questions_answered": questions_answered,
        "reconstruction_hash": reconstruction_hash,
    }


# ---------------------------------------------------------------------------
# Part 5 — Machine Verification Bundle
# ---------------------------------------------------------------------------


def generate_machine_verification_bundle(
    tenant_id: str,
    engagement_id: str,
    *,
    proof_package: dict[str, Any] | None = None,
    trust_ledger: list[dict[str, Any]] | None = None,
    intelligence_snapshot: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Generate a third-party verifiable export bundle.

    Designed for independent offline verification without FrostGate dependency.
    Exports trust, ledger, proof, manifest, and verification components.

    Never raises.
    """
    pkg = proof_package if isinstance(proof_package, dict) else {}
    ledger = trust_ledger if isinstance(trust_ledger, list) else []
    snap = intelligence_snapshot if isinstance(intelligence_snapshot, dict) else {}

    trust_component = {
        "snapshot_hash": snap.get("snapshot_hash", ""),
        "package_hash": pkg.get("package_hash", ""),
        "posture_score": _safe_int(snap.get("posture_score", 0)),
        "posture_level": snap.get("posture_level", "unknown"),
        "risk_level": snap.get("risk_level", "unknown"),
        "authority_version": snap.get(
            "authority_version", "trust-intelligence-authority-v1"
        ),
    }

    ledger_entries = [
        {
            "ledger_entry_hash": e.get("ledger_entry_hash", ""),
            "previous_hash": e.get("previous_hash", ""),
            "snapshot_hash": e.get("snapshot_hash", ""),
            "timestamp": e.get("timestamp", e.get("created_at", "")),
        }
        for e in ledger
        if isinstance(e, dict)
    ]

    proof_component = {
        "package_hash": pkg.get("package_hash", ""),
        "package_signature": pkg.get("package_signature", ""),
        "signing_key_id": pkg.get("signing_key_id", ""),
        "authority_version": pkg.get(
            "authority_version", AUDITOR_PROOF_AUTHORITY_VERSION
        ),
        "section_count": _safe_int(pkg.get("section_count", 0)),
        "assessed_by": pkg.get("assessed_by", ""),
        "section_hashes": pkg.get("section_hashes", {}),
    }

    component_names = ["trust", "ledger", "proof", "manifest", "verification"]
    components_present = {
        "trust": bool(snap.get("snapshot_hash")),
        "ledger": len(ledger) > 0,
        "proof": bool(pkg.get("package_hash")),
        "manifest": True,
        "verification": True,
    }
    manifest_component = {
        "component_count": len(component_names),
        "components": [
            {
                "name": name,
                "present": components_present.get(name, False),
                "hash": _section_hash(
                    trust_component
                    if name == "trust"
                    else ledger_entries
                    if name == "ledger"
                    else proof_component
                    if name == "proof"
                    else name
                ),
            }
            for name in component_names
        ],
    }

    verification_steps = [
        "1. Verify snapshot_hash: recompute SHA-256 of canonical intelligence fields "
        "and compare to trust.snapshot_hash",
        "2. Verify package_hash: recompute SHA-256 of canonical proof fields "
        "(authority_version, tenant_id, engagement_id, assessed_by, section_hashes) "
        "and compare to proof.package_hash",
        "3. Verify package_signature: verify Ed25519 signature of SHA-256(package_hash) "
        "using the registered public key for signing_key_id",
        "4. Verify ledger chain: for each entry, recompute ledger_entry_hash from "
        "canonical entry fields and verify previous_hash links",
        "5. Verify genesis: confirm ledger[0].previous_hash == '0' * 64",
    ]
    verification_component = {
        "steps": verification_steps,
        "authority_version": AUDITOR_PROOF_AUTHORITY_VERSION,
        "requires_frostgate": False,
        "supports_offline_verification": True,
        "supports_third_party_verification": True,
    }

    bundle_stable = {
        "authority_version": AUDITOR_PROOF_AUTHORITY_VERSION,
        "engagement_id": engagement_id,
        "posture_level": snap.get("posture_level", "unknown"),
        "posture_score": _safe_int(snap.get("posture_score", 0)),
        "proof_hash": pkg.get("package_hash", ""),
        "snapshot_hash": snap.get("snapshot_hash", ""),
        "tenant_id": tenant_id,
    }
    bundle_hash = hashlib.sha256(canonical_json_bytes(bundle_stable)).hexdigest()

    return {
        "bundle_id": uuid.uuid4().hex,
        "bundle_hash": bundle_hash,
        "tenant_id": tenant_id,
        "engagement_id": engagement_id,
        "authority_version": AUDITOR_PROOF_AUTHORITY_VERSION,
        "components": {
            "trust": trust_component,
            "ledger": ledger_entries,
            "proof": proof_component,
            "manifest": manifest_component,
            "verification": verification_component,
        },
        "generated_at": utc_iso8601_z_now(),
    }


# ---------------------------------------------------------------------------
# Part 6 — Trust Certification Engine
# ---------------------------------------------------------------------------


def generate_trust_certification(
    tenant_id: str,
    engagement_id: str,
    *,
    intelligence_snapshot: dict[str, Any] | None = None,
    confidence_manifest: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Generate a verifiable, evidence-backed trust certification.

    Composite score = 0.70 × trust_score + 0.30 × confidence_score.
    Certification level derived deterministically from composite score.
    No AI scoring. No randomness. Fully replayable.

    verification_hash excludes certification_id, valid_from, valid_until
    for determinism across calls with identical inputs. Never raises.
    """
    snap = intelligence_snapshot if isinstance(intelligence_snapshot, dict) else {}
    conf = confidence_manifest if isinstance(confidence_manifest, dict) else {}

    trust_score = _safe_int(snap.get("posture_score", 0))
    confidence_score = _safe_int(
        conf.get("composite_score", conf.get("confidence_score", 0))
    )

    composite = int(
        round(
            _CERT_TRUST_WEIGHT * trust_score
            + _CERT_CONFIDENCE_WEIGHT * confidence_score
        )
    )
    composite = max(0, min(100, composite))

    level = _cert_level_from_score(composite)

    now = datetime.now(timezone.utc)
    valid_from = now.isoformat().replace("+00:00", "Z")
    valid_until = (
        (now + timedelta(days=_CERT_VALIDITY_DAYS)).isoformat().replace("+00:00", "Z")
    )

    basis: list[str] = []
    if snap:
        basis.append(f"trust_posture: {snap.get('posture_level', 'unknown')}")
    if conf:
        basis.append("confidence_manifest: present")
    if snap.get("snapshot_hash"):
        basis.append("cryptographic_verification: sha256_signed")
    if not basis:
        basis.append("insufficient_evidence")

    stable = {
        "authority_version": AUDITOR_PROOF_AUTHORITY_VERSION,
        "certification_level": level,
        "composite_score": composite,
        "confidence_score": confidence_score,
        "engagement_id": engagement_id,
        "scored_by": _CERT_SCORED_BY,
        "tenant_id": tenant_id,
        "trust_score": trust_score,
    }
    verification_hash = hashlib.sha256(canonical_json_bytes(stable)).hexdigest()

    return {
        "certification_id": uuid.uuid4().hex,
        "tenant_id": tenant_id,
        "engagement_id": engagement_id,
        "certification_level": level,
        "trust_score": trust_score,
        "confidence_score": confidence_score,
        "composite_score": composite,
        "valid_from": valid_from,
        "valid_until": valid_until,
        "verification_hash": verification_hash,
        "authority_version": AUDITOR_PROOF_AUTHORITY_VERSION,
        "scored_by": _CERT_SCORED_BY,
        "certification_basis": basis,
    }


# ---------------------------------------------------------------------------
# Part 7 — Chain of Custody Authority
# ---------------------------------------------------------------------------


def generate_chain_of_custody(
    tenant_id: str,
    engagement_id: str,
    events: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Generate an immutable, hash-linked chain of custody.

    Each event is linked to the previous via SHA-256 of the canonical entry.
    The first entry carries PROOF_GENESIS_HASH as previous_hash.

    Never raises. Returns [] for invalid or empty input.
    """
    if not isinstance(events, list):
        events = []

    chain: list[dict[str, Any]] = []
    previous_hash = PROOF_GENESIS_HASH

    for i, event in enumerate(events):
        if not isinstance(event, dict):
            continue

        entry_stable: dict[str, Any] = {
            "authority_version": AUDITOR_PROOF_AUTHORITY_VERSION,
            "description": str(event.get("description", "")),
            "engagement_id": engagement_id,
            "entity_id": str(event.get("entity_id", "")),
            "entity_type": str(event.get("entity_type", ENTITY_HUMAN)),
            "event_type": str(event.get("event_type", CUSTODY_PACKAGE_GENERATED)),
            "metadata": (
                event.get("metadata", {})
                if isinstance(event.get("metadata"), dict)
                else {}
            ),
            "previous_hash": previous_hash,
            "sequence": i + 1,
            "tenant_id": tenant_id,
            "timestamp": str(event.get("timestamp", utc_iso8601_z_now())),
        }
        custody_hash = hashlib.sha256(canonical_json_bytes(entry_stable)).hexdigest()
        entry: dict[str, Any] = {
            **entry_stable,
            "custody_id": custody_hash,
            "custody_hash": custody_hash,
        }

        chain.append(entry)
        previous_hash = custody_hash

    return chain


# ---------------------------------------------------------------------------
# Part 8 — Proof Package Signing and Verification
# ---------------------------------------------------------------------------


def sign_proof_package(
    package: dict[str, Any],
) -> dict[str, Any]:
    """Sign an existing proof package dict (e.g. one deserialized from storage).

    Raises AuditorProofAuthorityError if package_hash is absent or
    signing key is unavailable.

    Returns a new dict with package_signature and signing_key_id updated.
    """
    if not isinstance(package, dict) or not package.get("package_hash"):
        raise AuditorProofAuthorityError("package missing package_hash — cannot sign")
    package_hash = package["package_hash"]
    digest = hashlib.sha256(package_hash.encode()).digest()
    sig, key_id = _sign_digest(digest)
    return {**package, "package_signature": sig, "signing_key_id": key_id}


def verify_proof_package(
    package: dict[str, Any],
) -> dict[str, Any]:
    """Verify a proof package. Never raises. Returns {valid, reason}.

    Checks:
      1. Required fields present
      2. Authority version matches current
      3. Section hashes match stored sections
      4. Package hash matches recomputed canonical bytes
      5. Ed25519 signature valid
      6. signing_key_id matches public key
    """
    if not isinstance(package, dict) or not package:
        return {"valid": False, "reason": "missing_package"}

    missing = _PACKAGE_REQUIRED - set(package)
    if missing:
        return {"valid": False, "reason": f"missing_fields: {sorted(missing)}"}

    if package.get("authority_version") != AUDITOR_PROOF_AUTHORITY_VERSION:
        return {
            "valid": False,
            "reason": (
                f"invalid_authority_version: {package.get('authority_version')}"
            ),
        }

    stored_sections = package.get("sections", {})
    if not isinstance(stored_sections, dict):
        return {"valid": False, "reason": "invalid_sections"}

    recomputed_section_hashes: dict[str, str] = {
        name: _section_hash(section) for name, section in stored_sections.items()
    }

    if package.get("section_hashes") != recomputed_section_hashes:
        return {"valid": False, "reason": "tampered_section"}

    try:
        canonical = _canonical_proof_bytes(
            AUDITOR_PROOF_AUTHORITY_VERSION,
            str(package["tenant_id"]),
            str(package["engagement_id"]),
            str(package["assessed_by"]),
            int(package["section_count"]),
            recomputed_section_hashes,
        )
    except (TypeError, ValueError):
        return {"valid": False, "reason": "invalid_package_values"}

    expected_hash = hashlib.sha256(canonical).hexdigest()
    if package["package_hash"] != expected_hash:
        return {"valid": False, "reason": "tampered_package_hash"}

    try:
        pub_bytes = _load_verification_public_key()
    except AuditorProofAuthorityError:
        return {"valid": False, "reason": "key_unavailable"}

    try:
        sig_bytes = bytes.fromhex(package["package_signature"])
        pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
        digest = hashlib.sha256(package["package_hash"].encode()).digest()
        pub.verify(sig_bytes, digest)
    except (InvalidSignature, ValueError, Exception):
        return {"valid": False, "reason": "signature_mismatch"}

    if package["signing_key_id"] != _derive_key_id(pub_bytes):
        return {"valid": False, "reason": "signing_key_id_mismatch"}

    return {"valid": True, "reason": None}


# ---------------------------------------------------------------------------
# Part 9 — Auditor Replay Engine
# ---------------------------------------------------------------------------


def replay_auditor_package(
    proof_package: dict[str, Any],
    *,
    intelligence_snapshot: dict[str, Any] | None = None,
    trust_ledger: list[dict[str, Any]] | None = None,
    confidence_manifest: dict[str, Any] | None = None,
    graph_snapshot: dict[str, Any] | None = None,
    replay_result: dict[str, Any] | None = None,
    decision_memories: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Replay an entire proof package with multi-layer validation.

    Validation layers (replay_score accumulates per layer passed):
      evidence_authority    — package has evidence section (20 pts)
      replay_authority      — replay_result.valid is True (15 pts)
      graph_authority       — graph_snapshot has nodes (15 pts)
      confidence_authority  — confidence_manifest present (15 pts)
      intelligence_authority— intelligence_snapshot has posture_score (15 pts)
      trust_ledger          — ledger non-empty (10 pts)
      decision_memory       — decision_memories non-empty (10 pts)

    replay_score: 0–100. valid: True only when evidence + intelligence pass.
    Fail closed. Never raises.
    """
    if not isinstance(proof_package, dict) or not proof_package:
        return {
            "valid": False,
            "replay_score": 0,
            "validations": [],
            "reason": "missing_proof_package",
            "layer_details": {},
            "package_id": "",
        }

    pkg = proof_package
    snap = intelligence_snapshot if isinstance(intelligence_snapshot, dict) else {}
    ledger = trust_ledger if isinstance(trust_ledger, list) else []
    conf = confidence_manifest if isinstance(confidence_manifest, dict) else {}
    graph = graph_snapshot if isinstance(graph_snapshot, dict) else {}
    replay = replay_result if isinstance(replay_result, dict) else {}
    decisions = decision_memories if isinstance(decision_memories, list) else []

    validations: list[str] = []
    replay_score = 0
    layer_details: dict[str, Any] = {}

    sections = pkg.get("sections", {})
    evidence_section = (
        sections.get("evidence", {}) if isinstance(sections, dict) else {}
    )
    evidence_present = evidence_section.get("status") == "present"
    if evidence_present:
        validations.append("evidence_authority")
        replay_score += _REPLAY_EVIDENCE_WEIGHT
    layer_details["evidence_authority"] = {
        "passed": evidence_present,
        "score": _REPLAY_EVIDENCE_WEIGHT if evidence_present else 0,
        "reason": None if evidence_present else "evidence_section_absent",
    }

    replay_valid = bool(replay.get("valid"))
    if replay_valid:
        validations.append("replay_authority")
        replay_score += _REPLAY_REPLAY_WEIGHT
    layer_details["replay_authority"] = {
        "passed": replay_valid,
        "score": _REPLAY_REPLAY_WEIGHT if replay_valid else 0,
        "reason": None if replay_valid else "replay_result_not_valid",
    }

    graph_nodes = graph.get("nodes", [])
    graph_ok = isinstance(graph_nodes, list) and len(graph_nodes) > 0
    if graph_ok:
        validations.append("graph_authority")
        replay_score += _REPLAY_GRAPH_WEIGHT
    layer_details["graph_authority"] = {
        "passed": graph_ok,
        "score": _REPLAY_GRAPH_WEIGHT if graph_ok else 0,
        "reason": None if graph_ok else "graph_snapshot_absent_or_empty",
    }

    conf_ok = bool(conf)
    if conf_ok:
        validations.append("confidence_authority")
        replay_score += _REPLAY_CONFIDENCE_WEIGHT
    layer_details["confidence_authority"] = {
        "passed": conf_ok,
        "score": _REPLAY_CONFIDENCE_WEIGHT if conf_ok else 0,
        "reason": None if conf_ok else "confidence_manifest_absent",
    }

    intel_ok = bool(snap.get("posture_score") is not None and snap.get("posture_level"))
    if intel_ok:
        validations.append("intelligence_authority")
        replay_score += _REPLAY_INTELLIGENCE_WEIGHT
    layer_details["intelligence_authority"] = {
        "passed": intel_ok,
        "score": _REPLAY_INTELLIGENCE_WEIGHT if intel_ok else 0,
        "reason": None if intel_ok else "intelligence_snapshot_absent",
    }

    ledger_ok = len(ledger) > 0
    if ledger_ok:
        validations.append("trust_ledger")
        replay_score += _REPLAY_LEDGER_WEIGHT
    layer_details["trust_ledger"] = {
        "passed": ledger_ok,
        "score": _REPLAY_LEDGER_WEIGHT if ledger_ok else 0,
        "reason": None if ledger_ok else "ledger_absent_or_empty",
    }

    decisions_ok = len([d for d in decisions if isinstance(d, dict)]) > 0
    if decisions_ok:
        validations.append("decision_memory")
        replay_score += _REPLAY_DECISION_WEIGHT
    layer_details["decision_memory"] = {
        "passed": decisions_ok,
        "score": _REPLAY_DECISION_WEIGHT if decisions_ok else 0,
        "reason": None if decisions_ok else "no_decision_records",
    }

    valid = evidence_present and intel_ok
    reason: str | None = None
    if not valid:
        if not evidence_present:
            reason = "evidence_authority_failed"
        elif not intel_ok:
            reason = "intelligence_authority_failed"

    return {
        "valid": valid,
        "replay_score": min(replay_score, 100),
        "validations": validations,
        "reason": reason,
        "layer_details": layer_details,
        "package_id": pkg.get("package_id", ""),
    }


# ---------------------------------------------------------------------------
# Part 10 — Enterprise Export Authority
# ---------------------------------------------------------------------------


def generate_enterprise_export(
    export_format: str,
    tenant_id: str,
    engagement_id: str,
    *,
    proof_package: dict[str, Any] | None = None,
    certification: dict[str, Any] | None = None,
    executive_brief: dict[str, Any] | None = None,
    machine_bundle: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Generate a multi-format enterprise export artifact.

    Supported formats: json, pdf, html, manifest, machine_bundle.
    For pdf/html: produces structured content representation.
    For manifest: produces component hash listing.
    For machine_bundle: embeds the full machine verification bundle.
    For json: full package export.

    Deterministic content_hash over stable export content. Never raises.
    """
    fmt = str(export_format) if export_format else EXPORT_JSON
    if fmt not in _EXPORT_FORMATS:
        fmt = EXPORT_JSON

    pkg = proof_package if isinstance(proof_package, dict) else {}
    cert = certification if isinstance(certification, dict) else {}
    brief = executive_brief if isinstance(executive_brief, dict) else {}
    bundle = machine_bundle if isinstance(machine_bundle, dict) else {}

    if fmt == EXPORT_JSON:
        content: Any = {
            "proof_package": pkg,
            "certification": cert,
            "executive_brief": brief,
        }

    elif fmt == EXPORT_PDF:
        content = {
            "title": "Enterprise Trust Certification Package",
            "subtitle": f"Tenant: {tenant_id} | Engagement: {engagement_id}",
            "sections": [
                {
                    "heading": "Executive Summary",
                    "body": brief.get(
                        "executive_summary", "Trust assessment completed."
                    ),
                },
                {
                    "heading": "Trust Posture",
                    "body": (
                        f"Level: {brief.get('current_posture', {}).get('level', 'unknown')}, "
                        f"Score: {brief.get('current_posture', {}).get('score', 0)}/100"
                    ),
                },
                {
                    "heading": "Certification",
                    "body": (
                        f"Level: {cert.get('certification_level', 'pending')}, "
                        f"Valid until: {cert.get('valid_until', 'not set')}"
                    ),
                },
                {
                    "heading": "Board Recommendation",
                    "body": brief.get(
                        "board_recommendation", "Continue monitoring trust posture."
                    ),
                },
                {
                    "heading": "Verification",
                    "body": (
                        f"Package hash: {pkg.get('package_hash', 'not generated')}. "
                        "Independently verifiable via Ed25519 signature."
                    ),
                },
            ],
            "format": "pdf",
        }

    elif fmt == EXPORT_HTML:
        sections_html = "".join(
            f"<h2>{sec['heading']}</h2><p>{sec['body']}</p>"
            for sec in [
                {
                    "heading": "Executive Summary",
                    "body": brief.get(
                        "executive_summary", "Trust assessment completed."
                    ),
                },
                {
                    "heading": "Certification",
                    "body": (f"Level: {cert.get('certification_level', 'pending')}"),
                },
            ]
        )
        content = {
            "html": (
                f"<html><head><title>Trust Package</title></head><body>"
                f"<h1>Enterprise Trust Package: {tenant_id}</h1>"
                f"{sections_html}</body></html>"
            ),
            "format": "html",
        }

    elif fmt == EXPORT_MANIFEST:
        components = []
        for name, data in [
            ("proof_package", pkg),
            ("certification", cert),
            ("executive_brief", brief),
            ("machine_bundle", bundle),
        ]:
            components.append(
                {
                    "component": name,
                    "present": bool(data),
                    "hash": _section_hash(data) if data else "",
                }
            )
        content = {
            "manifest_type": "enterprise_trust_manifest",
            "tenant_id": tenant_id,
            "engagement_id": engagement_id,
            "components": components,
            "total_components": len(components),
            "present_components": sum(1 for c in components if c["present"]),
        }

    else:
        content = bundle or {"bundle_id": "", "note": "machine_bundle_not_provided"}

    content_hash = hashlib.sha256(canonical_json_bytes(content)).hexdigest()

    return {
        "export_id": uuid.uuid4().hex,
        "format": fmt,
        "tenant_id": tenant_id,
        "engagement_id": engagement_id,
        "content": content,
        "content_hash": content_hash,
        "exported_at": utc_iso8601_z_now(),
        "authority_version": AUDITOR_PROOF_AUTHORITY_VERSION,
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _safe_int(value: Any, fallback: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


def _cert_level_from_score(score: int) -> str:
    if score >= _CERT_ENTERPRISE_THRESHOLD:
        return CERT_ENTERPRISE
    if score >= _CERT_PLATINUM_THRESHOLD:
        return CERT_PLATINUM
    if score >= _CERT_GOLD_THRESHOLD:
        return CERT_GOLD
    if score >= _CERT_SILVER_THRESHOLD:
        return CERT_SILVER
    if score >= _CERT_BRONZE_THRESHOLD:
        return CERT_BRONZE
    return CERT_NOT_CERTIFIED


def _readiness_from_score(score: int) -> str:
    if score >= 80:
        return "compliant_ready"
    if score >= 60:
        return "substantially_compliant"
    if score >= 40:
        return "partially_compliant"
    return "requires_remediation"


def _readiness_gaps(score: int) -> list[str]:
    gaps: list[str] = []
    if score < 90:
        gaps.append("Full trust posture documentation required for highest tier")
    if score < 75:
        gaps.append("Trust posture must reach healthy status for full compliance")
    if score < 60:
        gaps.append("Trust posture improvement program required")
    if score < 40:
        gaps.append("Foundational trust controls must be established")
    return gaps


def _risk_plain_english(risk_level: str, risk_score: int) -> str:
    narratives = {
        "critical": f"Critical risk ({risk_score}/100). Immediate risk mitigation required.",
        "high": f"High risk ({risk_score}/100). Risk reduction plan should be activated.",
        "medium": f"Moderate risk ({risk_score}/100). Risk is being actively managed.",
        "low": f"Low risk ({risk_score}/100). Risk is well-controlled.",
        "minimal": f"Minimal risk ({risk_score}/100). Risk posture is exemplary.",
    }
    return narratives.get(
        risk_level,
        f"Risk level: {risk_level} ({risk_score}/100).",
    )
