"""P0-6A: Trust Arc API — intelligence snapshot, proof package, certification.

Routes (all under /field-assessment/engagements/{engagement_id}/trust-arc/):

  GET  .../intelligence-snapshot   — latest FaTrustIntelligenceSnapshot
  GET  .../proof-package           — latest FaAuditorProofPackage
  GET  .../certification           — latest FaTrustCertification (by valid_until DESC)
  POST .../rebuild                 — regenerate all three artifacts on demand

Scopes:
  governance:read  — GET routes (customers, auditors, executives)
  governance:write — POST rebuild (internal governance/admin only)

The rebuild route is NOT customer-facing and NOT portal-facing. It exists
for governance workflows: quarterly trust briefs, monitoring regeneration,
continuous governance cycles that need up-to-date trust artifacts without
waiting for a new verification bundle.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.auth_scopes import require_scopes
from api.deps import auth_ctx_db_session
from api.entitlements import require_capability
from api.error_contracts import api_error
from api.db_models_trust_arc import (
    FaAuditorProofPackage,
    FaTrustCertification,
    FaTrustIntelligenceSnapshot,
)

log = logging.getLogger("frostgate.trust_arc")

router = APIRouter(
    prefix="/field-assessment",
    tags=["trust-arc"],
)


# ---------------------------------------------------------------------------
# Tenant resolution (mirrors field_assessment._resolve_caller_tenant)
# ---------------------------------------------------------------------------


def _resolve_caller_tenant(request: Request) -> str:
    auth = getattr(getattr(request, "state", None), "auth", None)
    tenant_id = getattr(getattr(request, "state", None), "tenant_id", None) or getattr(
        auth, "tenant_id", None
    )
    if not tenant_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="tenant context required",
        )
    return str(tenant_id)


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------


def _load_json_field(value: str | None) -> Any:
    if not value:
        return None
    try:
        return json.loads(value)
    except (ValueError, TypeError):
        return value


def _snap_to_dict(row: FaTrustIntelligenceSnapshot) -> dict[str, Any]:
    return {
        "snapshot_id": row.id,
        "tenant_id": row.tenant_id,
        "engagement_id": row.engagement_id,
        "authority_version": row.authority_version,
        "posture_score": row.posture_score,
        "posture_level": row.posture_level,
        "trend_direction": row.trend_direction,
        "trend_velocity": row.trend_velocity,
        "risk_level": row.risk_level,
        "risk_score": row.risk_score,
        "priorities_count": row.priorities_count,
        "insights_count": row.insights_count,
        "recommendations_count": row.recommendations_count,
        "forecast_projected_score": row.forecast_projected_score,
        "graph_node_count": row.graph_node_count,
        "snapshot_hash": row.snapshot_hash,
        "snapshot_signature": row.snapshot_signature,
        "signing_key_id": row.signing_key_id,
        "created_at": row.created_at,
        "schema_version": row.schema_version,
        # Full intelligence payloads (deserialized)
        "payload_hashes": _load_json_field(row.payload_hashes),
        "posture_result": _load_json_field(row.posture_result),
        "trend_result": _load_json_field(row.trend_result),
        "risk_result": _load_json_field(row.risk_result),
        "priorities": _load_json_field(row.priorities),
        "insights": _load_json_field(row.insights),
        "recommendations": _load_json_field(row.recommendations),
        "forecast_result": _load_json_field(row.forecast_result),
        "graph_result": _load_json_field(row.graph_result),
    }


def _pkg_to_dict(row: FaAuditorProofPackage) -> dict[str, Any]:
    return {
        "package_id": row.id,
        "tenant_id": row.tenant_id,
        "engagement_id": row.engagement_id,
        "authority_version": row.authority_version,
        "assessed_by": row.assessed_by,
        "section_count": row.section_count,
        "package_hash": row.package_hash,
        "package_signature": row.package_signature,
        "signing_key_id": row.signing_key_id,
        "verified_at": row.verified_at,
        "schema_version": row.schema_version,
        "section_hashes": _load_json_field(row.section_hashes),
        "sections": _load_json_field(row.sections),
    }


def _cert_to_dict(row: FaTrustCertification) -> dict[str, Any]:
    return {
        "certification_id": row.id,
        "tenant_id": row.tenant_id,
        "engagement_id": row.engagement_id,
        "certification_level": row.certification_level,
        "trust_score": row.trust_score,
        "confidence_score": row.confidence_score,
        "composite_score": row.composite_score,
        "scored_by": row.scored_by,
        "valid_from": row.valid_from,
        "valid_until": row.valid_until,
        "verification_hash": row.verification_hash,
        "authority_version": row.authority_version,
        "schema_version": row.schema_version,
    }


# ---------------------------------------------------------------------------
# GET /engagements/{engagement_id}/trust-arc/intelligence-snapshot
# ---------------------------------------------------------------------------


@router.get(
    "/engagements/{engagement_id}/trust-arc/intelligence-snapshot",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability("trust.intelligence")),
    ],
    summary="Latest trust intelligence snapshot for an engagement",
)
def get_trust_intelligence_snapshot(
    engagement_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """Return the most recent trust intelligence snapshot for an engagement.

    The snapshot contains the posture score, trend direction, risk level,
    confidence metrics, and cryptographic proof of the trust state at the
    time of generation.
    """
    tenant_id = _resolve_caller_tenant(request)
    row = db.execute(
        select(FaTrustIntelligenceSnapshot)
        .where(
            FaTrustIntelligenceSnapshot.tenant_id == tenant_id,
            FaTrustIntelligenceSnapshot.engagement_id == engagement_id,
        )
        .order_by(FaTrustIntelligenceSnapshot.created_at.desc())
        .limit(1)
    ).scalar_one_or_none()

    if row is None:
        raise HTTPException(
            status_code=404,
            detail=api_error(
                "TRUST_ARC_NOT_FOUND",
                f"No trust intelligence snapshot found for engagement {engagement_id!r}. "
                "Generate a verification bundle to activate trust arc.",
            ),
        )

    return _snap_to_dict(row)


# ---------------------------------------------------------------------------
# GET /engagements/{engagement_id}/trust-arc/proof-package
# ---------------------------------------------------------------------------


@router.get(
    "/engagements/{engagement_id}/trust-arc/proof-package",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability("trust.proof_package")),
    ],
    summary="Latest auditor proof package for an engagement",
)
def get_auditor_proof_package(
    engagement_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """Return the most recent auditor proof package for an engagement.

    The proof package is a cryptographically signed bundle containing
    8 sections: evidence, replay, graph, confidence, intelligence, ledger,
    decisions, and historical records. Suitable for third-party verification
    and regulatory submission.
    """
    tenant_id = _resolve_caller_tenant(request)
    row = db.execute(
        select(FaAuditorProofPackage)
        .where(
            FaAuditorProofPackage.tenant_id == tenant_id,
            FaAuditorProofPackage.engagement_id == engagement_id,
        )
        .order_by(FaAuditorProofPackage.verified_at.desc())
        .limit(1)
    ).scalar_one_or_none()

    if row is None:
        raise HTTPException(
            status_code=404,
            detail=api_error(
                "TRUST_ARC_NOT_FOUND",
                f"No auditor proof package found for engagement {engagement_id!r}. "
                "Generate a verification bundle to activate trust arc.",
            ),
        )

    return _pkg_to_dict(row)


# ---------------------------------------------------------------------------
# GET /engagements/{engagement_id}/trust-arc/certification
# ---------------------------------------------------------------------------


@router.get(
    "/engagements/{engagement_id}/trust-arc/certification",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability("trust.certification")),
    ],
    summary="Latest trust certification for an engagement",
)
def get_trust_certification(
    engagement_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """Return the most recent trust certification for an engagement.

    Certification is deterministically derived from the composite trust and
    confidence score (0.70×trust + 0.30×confidence). Levels: not_certified,
    bronze (≥50), silver (≥60), gold (≥70), platinum (≥80), enterprise (≥90).
    Valid for 90 days from generation.
    """
    tenant_id = _resolve_caller_tenant(request)
    row = db.execute(
        select(FaTrustCertification)
        .where(
            FaTrustCertification.tenant_id == tenant_id,
            FaTrustCertification.engagement_id == engagement_id,
        )
        .order_by(FaTrustCertification.valid_until.desc())
        .limit(1)
    ).scalar_one_or_none()

    if row is None:
        raise HTTPException(
            status_code=404,
            detail=api_error(
                "TRUST_ARC_NOT_FOUND",
                f"No trust certification found for engagement {engagement_id!r}. "
                "Generate a verification bundle to activate trust arc.",
            ),
        )

    return _cert_to_dict(row)


# ---------------------------------------------------------------------------
# POST /engagements/{engagement_id}/trust-arc/rebuild
# ---------------------------------------------------------------------------


@router.post(
    "/engagements/{engagement_id}/trust-arc/rebuild",
    dependencies=[
        Depends(require_scopes("governance:write")),
        Depends(require_capability("trust.intelligence")),
    ],
    summary="Regenerate trust arc artifacts for an engagement (internal/governance only)",
    status_code=200,
)
def rebuild_trust_arc(
    engagement_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """Regenerate the trust intelligence snapshot, auditor proof package,
    and trust certification for an engagement.

    This route is NOT customer-facing and NOT portal-facing. It is
    governance/admin-only, used for:
      - Quarterly trust briefs
      - Trust intelligence monitoring
      - Continuous governance cycles
      - On-demand trust posture refresh

    Returns the IDs of the newly created artifacts. Idempotent: each call
    creates a new append-only record without invalidating prior records.
    """
    tenant_id = _resolve_caller_tenant(request)

    from services.field_assessment.models import EngagementNotFound  # noqa: PLC0415
    from services.field_assessment.store import get_engagement  # noqa: PLC0415
    from services.trust_arc.orchestrator import (  # noqa: PLC0415
        generate_and_persist_trust_arc,
    )

    try:
        get_engagement(db, engagement_id=engagement_id, tenant_id=tenant_id)
    except EngagementNotFound:
        raise HTTPException(
            status_code=404,
            detail=api_error(
                "ENGAGEMENT_NOT_FOUND", f"Engagement {engagement_id!r} not found."
            ),
        )

    result = generate_and_persist_trust_arc(
        db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
    )

    if result.get("skipped"):
        raise HTTPException(
            status_code=503,
            detail=api_error(
                "TRUST_ARC_UNAVAILABLE",
                f"Trust arc generation is not available: {result.get('reason', 'unknown')}. "
                "Ensure FG_EVIDENCE_SIGNING_KEY_B64 is configured.",
            ),
        )

    db.commit()

    log.info(
        "trust_arc.rebuild: completed tenant=%s engagement=%s snapshot=%s cert_level=%s",
        tenant_id,
        engagement_id,
        result.get("snapshot_id", "")[:16],
        result.get("certification_level"),
    )

    return {
        "engagement_id": engagement_id,
        "snapshot_id": result.get("snapshot_id"),
        "package_id": result.get("package_id"),
        "certification_id": result.get("certification_id"),
        "certification_level": result.get("certification_level"),
        "posture_score": result.get("posture_score"),
        "posture_level": result.get("posture_level"),
    }
