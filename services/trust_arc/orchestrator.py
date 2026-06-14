"""P0-6A: Trust Arc Orchestrator.

Coordinates trust intelligence snapshot, auditor proof package,
trust certification, and decision memory generation + persistence.

Two public functions:

  generate_and_persist_trust_arc()
      Called during verification bundle generation and any workflow
      that needs a complete trust arc activation. Generates snapshot,
      proof, and certification atomically within the caller's transaction.

  persist_decision_memory()
      Called at governance decision points (QA approval, risk acceptance,
      etc.) to record why and by whom a decision was made. Stores
      the supporting trust intelligence context.

Both functions are non-blocking: if FG_EVIDENCE_SIGNING_KEY_B64 is
absent (e.g. dev without signing keys), a warning is logged and the
function returns without touching the DB or raising. Any unexpected
exception is also caught and logged — the host workflow is never
interrupted by trust arc failures.

The caller owns the DB transaction; neither function calls db.commit().
Records are added via db.add() and will be committed when the caller
does so.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from typing import Any

from sqlalchemy.orm import Session

log = logging.getLogger("frostgate.trust_arc")

# Result key used by callers to confirm trust arc ran
_SKIPPED_KEY = "skipped"


def _signing_key_available() -> bool:
    return bool(os.environ.get("FG_EVIDENCE_SIGNING_KEY_B64", "").strip())


def generate_and_persist_trust_arc(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
    posture_result: dict[str, Any] | None = None,
    trend_result: dict[str, Any] | None = None,
    risk_result: dict[str, Any] | None = None,
    priorities: list[Any] | None = None,
    insights: list[Any] | None = None,
    recommendations: list[Any] | None = None,
    forecast_result: dict[str, Any] | None = None,
    graph_result: dict[str, Any] | None = None,
    confidence_manifest: dict[str, Any] | None = None,
    trust_ledger: list[dict[str, Any]] | None = None,
    decision_memories: list[dict[str, Any]] | None = None,
    replay_result: dict[str, Any] | None = None,
    evidence_summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Generate and persist trust intelligence snapshot, auditor proof,
    and trust certification for an engagement.

    All intelligence inputs are optional. When called with no inputs
    (e.g. from bundle generation where detailed intelligence is not yet
    computed), the generators apply sensible defaults, producing a
    cryptographically valid baseline snapshot that can be enriched by
    subsequent activations.

    Returns a summary dict with persisted record IDs, or {"skipped": True}
    if the signing key is absent or any unrecoverable error occurs.
    """
    if not _signing_key_available():
        log.warning(
            "trust_arc.generate_and_persist: FG_EVIDENCE_SIGNING_KEY_B64 not set "
            "— skipping for tenant=%s engagement=%s",
            tenant_id,
            engagement_id,
        )
        return {_SKIPPED_KEY: True, "reason": "signing_key_absent"}

    try:
        return _run_trust_arc(
            db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            posture_result=posture_result,
            trend_result=trend_result,
            risk_result=risk_result,
            priorities=priorities,
            insights=insights,
            recommendations=recommendations,
            forecast_result=forecast_result,
            graph_result=graph_result,
            confidence_manifest=confidence_manifest,
            trust_ledger=trust_ledger,
            decision_memories=decision_memories,
            replay_result=replay_result,
            evidence_summary=evidence_summary,
        )
    except Exception:
        log.exception(
            "trust_arc.generate_and_persist: unexpected error tenant=%s engagement=%s",
            tenant_id,
            engagement_id,
        )
        return {_SKIPPED_KEY: True, "reason": "unexpected_error"}


def _run_trust_arc(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
    posture_result: dict[str, Any] | None,
    trend_result: dict[str, Any] | None,
    risk_result: dict[str, Any] | None,
    priorities: list[Any] | None,
    insights: list[Any] | None,
    recommendations: list[Any] | None,
    forecast_result: dict[str, Any] | None,
    graph_result: dict[str, Any] | None,
    confidence_manifest: dict[str, Any] | None,
    trust_ledger: list[dict[str, Any]] | None,
    decision_memories: list[dict[str, Any]] | None,
    replay_result: dict[str, Any] | None,
    evidence_summary: dict[str, Any] | None,
) -> dict[str, Any]:
    from services.field_assessment.trust_intelligence_authority import (  # noqa: PLC0415
        TrustIntelligenceAuthorityError,
        generate_trust_intelligence_snapshot,
    )
    from services.field_assessment.auditor_proof_authority import (  # noqa: PLC0415
        AuditorProofAuthorityError,
        generate_auditor_proof_package,
        generate_trust_certification,
    )
    from api.db_models_trust_arc import (  # noqa: PLC0415
        FaTrustIntelligenceSnapshot,
        FaAuditorProofPackage,
        FaTrustCertification,
    )

    # ── Step 1: Trust Intelligence Snapshot ──────────────────────────────────
    try:
        snapshot = generate_trust_intelligence_snapshot(
            tenant_id,
            engagement_id,
            posture_result=posture_result,
            trend_result=trend_result,
            risk_result=risk_result,
            priorities=priorities,
            insights=insights,
            recommendations=recommendations,
            forecast_result=forecast_result,
            graph_result=graph_result,
        )
    except TrustIntelligenceAuthorityError:
        log.exception(
            "trust_arc: snapshot generation failed tenant=%s engagement=%s",
            tenant_id,
            engagement_id,
        )
        return {_SKIPPED_KEY: True, "reason": "snapshot_generation_failed"}

    snap_record = FaTrustIntelligenceSnapshot(
        id=snapshot["snapshot_id"],
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        authority_version=snapshot.get("authority_version", ""),
        posture_score=snapshot.get("posture_score", 0),
        posture_level=snapshot.get("posture_level", "unknown"),
        trend_direction=snapshot.get("trend_direction", "stable"),
        trend_velocity=snapshot.get("trend_velocity", "none"),
        risk_level=snapshot.get("risk_level", "unknown"),
        risk_score=snapshot.get("risk_score", 0),
        priorities_count=snapshot.get("priorities_count", 0),
        insights_count=snapshot.get("insights_count", 0),
        recommendations_count=snapshot.get("recommendations_count", 0),
        forecast_projected_score=snapshot.get("forecast_projected_score", 0),
        graph_node_count=snapshot.get("graph_node_count", 0),
        payload_hashes=json.dumps(snapshot.get("payload_hashes", {})),
        posture_result=json.dumps(snapshot["posture_result"])
        if snapshot.get("posture_result")
        else None,
        trend_result=json.dumps(snapshot["trend_result"])
        if snapshot.get("trend_result")
        else None,
        risk_result=json.dumps(snapshot["risk_result"])
        if snapshot.get("risk_result")
        else None,
        priorities=json.dumps(snapshot["priorities"])
        if snapshot.get("priorities")
        else None,
        insights=json.dumps(snapshot["insights"]) if snapshot.get("insights") else None,
        recommendations=json.dumps(snapshot["recommendations"])
        if snapshot.get("recommendations")
        else None,
        forecast_result=json.dumps(snapshot["forecast_result"])
        if snapshot.get("forecast_result")
        else None,
        graph_result=json.dumps(snapshot["graph_result"])
        if snapshot.get("graph_result")
        else None,
        snapshot_hash=snapshot["snapshot_hash"],
        snapshot_signature=snapshot["snapshot_signature"],
        signing_key_id=snapshot.get("signing_key_id", ""),
        created_at=snapshot.get("created_at", ""),
        schema_version=snapshot.get("schema_version", "1.0"),
    )
    db.add(snap_record)
    log.info(
        "trust_arc: snapshot persisted id=%s posture=%s/%s tenant=%s",
        snapshot["snapshot_id"][:16],
        snapshot.get("posture_score"),
        snapshot.get("posture_level"),
        tenant_id,
    )

    # ── Step 2: Auditor Proof Package ────────────────────────────────────────
    pkg_id: str | None = None
    try:
        package = generate_auditor_proof_package(
            tenant_id,
            engagement_id,
            intelligence_snapshot=snapshot,
            confidence_manifest=confidence_manifest,
            trust_ledger=trust_ledger,
            decision_memories=decision_memories,
            replay_result=replay_result,
            evidence_summary=evidence_summary,
        )
        pkg_record = FaAuditorProofPackage(
            id=package["package_id"],
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            authority_version=package.get("authority_version", ""),
            assessed_by=package.get("assessed_by", "human"),
            section_count=package.get("section_count", 0),
            section_hashes=json.dumps(package.get("section_hashes", {})),
            sections=json.dumps(package.get("sections", {})),
            package_hash=package["package_hash"],
            package_signature=package["package_signature"],
            signing_key_id=package.get("signing_key_id", ""),
            verified_at=package.get("verified_at", ""),
            schema_version=package.get("schema_version", "1.0"),
        )
        db.add(pkg_record)
        pkg_id = package["package_id"]
        log.info(
            "trust_arc: proof package persisted id=%s sections=%s tenant=%s",
            (pkg_id or "")[:16],
            package.get("section_count"),
            tenant_id,
        )
    except AuditorProofAuthorityError:
        log.exception(
            "trust_arc: proof package generation failed tenant=%s engagement=%s",
            tenant_id,
            engagement_id,
        )

    # ── Step 3: Trust Certification ──────────────────────────────────────────
    cert_id: str | None = None
    cert_level: str = "not_certified"
    try:
        certification = generate_trust_certification(
            tenant_id,
            engagement_id,
            intelligence_snapshot=snapshot,
            confidence_manifest=confidence_manifest,
        )
        cert_record = FaTrustCertification(
            id=certification["certification_id"],
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            certification_level=certification.get(
                "certification_level", "not_certified"
            ),
            trust_score=certification.get("trust_score", 0),
            confidence_score=certification.get("confidence_score", 0),
            composite_score=certification.get("composite_score", 0),
            scored_by=certification.get("scored_by", "deterministic_composite_v1"),
            valid_from=certification.get("valid_from", ""),
            valid_until=certification.get("valid_until", ""),
            verification_hash=certification.get("verification_hash", ""),
            authority_version=certification.get("authority_version", ""),
            schema_version=certification.get("schema_version", "1.0"),
        )
        db.add(cert_record)
        cert_id = certification["certification_id"]
        cert_level = certification.get("certification_level", "not_certified")
        log.info(
            "trust_arc: certification persisted id=%s level=%s composite=%s tenant=%s",
            (cert_id or "")[:16],
            cert_level,
            certification.get("composite_score"),
            tenant_id,
        )
    except Exception:
        log.exception(
            "trust_arc: certification generation failed tenant=%s engagement=%s",
            tenant_id,
            engagement_id,
        )

    return {
        _SKIPPED_KEY: False,
        "snapshot_id": snapshot["snapshot_id"],
        "package_id": pkg_id,
        "certification_id": cert_id,
        "certification_level": cert_level,
        "posture_score": snapshot.get("posture_score", 0),
        "posture_level": snapshot.get("posture_level", "unknown"),
    }


def persist_decision_memory(
    db: Session,
    *,
    decision_id: str,
    decision_type: str,
    entity_type: str = "human",
    reasoning: list[str] | None = None,
    supporting_snapshots: list[dict[str, Any]] | None = None,
    supporting_evidence_ids: list[str] | None = None,
    tenant_id: str = "",
    engagement_id: str = "",
) -> str | None:
    """Record a governance decision in the trust memory ledger.

    Calls generate_decision_memory() and persists the result to
    fa_trust_decision_memory. The caller owns the transaction.

    Non-blocking: returns None if signing key is absent or on error.
    Returns the persisted record id on success.
    """
    if not _signing_key_available():
        log.warning(
            "trust_arc.persist_decision_memory: FG_EVIDENCE_SIGNING_KEY_B64 "
            "not set — skipping decision_type=%s tenant=%s",
            decision_type,
            tenant_id,
        )
        return None

    try:
        from services.field_assessment.trust_intelligence_authority import (  # noqa: PLC0415
            generate_decision_memory,
        )
        from api.db_models_trust_arc import FaTrustDecisionMemory  # noqa: PLC0415

        memory = generate_decision_memory(
            decision_id=decision_id,
            decision_type=decision_type,
            entity_type=entity_type,
            reasoning=reasoning,
            supporting_snapshots=supporting_snapshots,
            supporting_evidence_ids=supporting_evidence_ids,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
        )

        record_id = uuid.uuid4().hex
        record = FaTrustDecisionMemory(
            id=record_id,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            decision_type=memory.get("decision_type", decision_type),
            entity_type=memory.get("entity_type", entity_type),
            decision_reasoning=json.dumps(memory.get("decision_reasoning", [])),
            supporting_intelligence=json.dumps(
                memory.get("supporting_intelligence", [])
            ),
            supporting_evidence=json.dumps(memory.get("supporting_evidence", [])),
            authority_version=memory.get("authority_version", ""),
            created_at=memory.get("created_at", ""),
            schema_version="1.0",
        )
        db.add(record)
        log.info(
            "trust_arc: decision memory persisted id=%s type=%s entity=%s tenant=%s",
            record_id[:16],
            decision_type,
            entity_type,
            tenant_id,
        )
        return record_id
    except Exception:
        log.exception(
            "trust_arc.persist_decision_memory: error decision_type=%s tenant=%s",
            decision_type,
            tenant_id,
        )
        return None
