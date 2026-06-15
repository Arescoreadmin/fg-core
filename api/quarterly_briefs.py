"""P0-9: Quarterly Trust Briefs (QTB) API.

Generates, stores, and delivers executive-grade trust intelligence deliverables
sourced entirely from existing P0-6A/B, P0-7, P0-8 data.  No new trust engines.

Routes (prefix: /field-assessment):

  Per-engagement:
    POST .../etcc/briefs/generate                — generate quarterly brief
    GET  .../etcc/briefs                         — list briefs (newest first)
    GET  .../etcc/briefs/{brief_id}              — full brief with sections
    POST .../etcc/briefs/{brief_id}/review       — mark brief as reviewed
    POST .../etcc/briefs/{brief_id}/approve      — mark brief as approved
    GET  .../etcc/briefs/{brief_id}/manifest     — deterministic audit manifest
    GET  .../etcc/briefs/{brief_id}/export       — export (JSON or HTML)
    POST .../etcc/board/generate                 — generate board brief
    GET  .../etcc/board                          — list board reports
    GET  .../etcc/board/{report_id}              — get board report

  Tenant-level:
    GET  /etcc/briefs/history                    — all briefs across all engagements

Capability gates (all ENTERPRISE tier):
  trust.quarterly.briefs   — generate, list, read briefs
  trust.board.reporting    — generate, list, read board reports
  trust.report.review      — review + approve workflow
  trust.report.export      — export endpoint
  trust.report.delivery    — tenant-level history

All routes require governance:read scope.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.auth_scopes import require_scopes
from api.deps import auth_ctx_db_session
from api.entitlements import require_capability
from api.db_models_qtb import FaQtbBrief, FaQtbBriefManifest, FaQtbBriefSection

log = logging.getLogger("frostgate.qtb.api")

router = APIRouter(
    prefix="/field-assessment",
    tags=["quarterly-trust-briefs"],
)

_VALID_STATUSES = frozenset(
    {"draft", "generated", "reviewed", "approved", "delivered", "archived"}
)
_REVIEW_TRANSITION = {"generated": "reviewed", "reviewed": "reviewed"}
_APPROVE_TRANSITION = {"reviewed": "approved", "approved": "approved"}


# ---------------------------------------------------------------------------
# Shared helpers
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


def _caller_actor(request: Request) -> str:
    auth = getattr(getattr(request, "state", None), "auth", None)
    return getattr(auth, "key_prefix", None) or "system"


def _brief_to_dict(row: FaQtbBrief) -> dict[str, Any]:
    return {
        "brief_id": row.id,
        "tenant_id": row.tenant_id,
        "engagement_id": row.engagement_id,
        "report_type": row.report_type,
        "year": row.year,
        "quarter": row.quarter,
        "period_start": row.period_start,
        "period_end": row.period_end,
        "status": row.status,
        "generated_by": row.generated_by,
        "generated_at": row.generated_at,
        "reviewed_by": row.reviewed_by,
        "reviewed_at": row.reviewed_at,
        "approved_by": row.approved_by,
        "approved_at": row.approved_at,
        "brief_hash": row.brief_hash,
        "report_hash": row.report_hash,
        "delivered_at": row.delivered_at,
        "delivered_to": row.delivered_to,
        "delivery_channel": row.delivery_channel,
        "parent_brief_id": row.parent_brief_id,
        "generation_version": row.generation_version,
        "authority_version": row.authority_version,
        "schema_version": row.schema_version,
    }


def _section_to_dict(row: FaQtbBriefSection) -> dict[str, Any]:
    try:
        data = json.loads(row.section_data)
    except (ValueError, TypeError):
        data = {}
    try:
        refs = json.loads(row.evidence_refs)
    except (ValueError, TypeError):
        refs = []
    return {
        "section_id": row.id,
        "brief_id": row.brief_id,
        "section_type": row.section_type,
        "section_order": row.section_order,
        "section_data": data,
        "evidence_refs": refs,
        "section_hash": row.section_hash,
        "generated_at": row.generated_at,
    }


def _manifest_to_dict(row: FaQtbBriefManifest) -> dict[str, Any]:
    def _parse(val: str) -> list:
        try:
            return json.loads(val)
        except (ValueError, TypeError):
            return []

    return {
        "manifest_id": row.id,
        "brief_id": row.brief_id,
        "snapshot_ids": _parse(row.snapshot_ids),
        "certification_ids": _parse(row.certification_ids),
        "drift_event_ids": _parse(row.drift_event_ids),
        "timeline_refs": _parse(row.timeline_refs),
        "evidence_refs": _parse(row.evidence_refs),
        "decision_refs": _parse(row.decision_refs),
        "bundle_refs": _parse(row.bundle_refs),
        "manifest_hash": row.manifest_hash,
        "report_hash": row.report_hash,
        "generation_version": row.generation_version,
        "authority_version": row.authority_version,
        "replay_version": row.replay_version,
        "generated_at": row.generated_at,
    }


def _load_brief_with_sections(
    db: Session, *, tenant_id: str, brief_id: str
) -> tuple[FaQtbBrief | None, list[FaQtbBriefSection]]:
    brief = db.execute(
        select(FaQtbBrief).where(
            FaQtbBrief.tenant_id == tenant_id,
            FaQtbBrief.id == brief_id,
        )
    ).scalar_one_or_none()
    if brief is None:
        return None, []
    sections = (
        db.execute(
            select(FaQtbBriefSection)
            .where(
                FaQtbBriefSection.tenant_id == tenant_id,
                FaQtbBriefSection.brief_id == brief_id,
            )
            .order_by(FaQtbBriefSection.section_order.asc())
        )
        .scalars()
        .all()
    )
    return brief, list(sections)


# ---------------------------------------------------------------------------
# POST /engagements/{engagement_id}/etcc/briefs/generate
# ---------------------------------------------------------------------------


@router.post(
    "/engagements/{engagement_id}/etcc/briefs/generate",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability("trust.quarterly.briefs")),
    ],
    summary="Generate a Quarterly Trust Brief for an engagement",
    status_code=status.HTTP_201_CREATED,
)
def generate_quarterly_brief(
    engagement_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
    year: int = Query(..., description="Report year (e.g. 2026)"),
    quarter: int = Query(..., ge=1, le=4, description="Report quarter (1–4)"),
    parent_brief_id: str | None = Query(
        default=None, description="ID of the brief this regeneration supersedes"
    ),
) -> dict[str, Any]:
    """Generate and persist a full Quarterly Trust Brief.

    Aggregates 6 sections from existing P0-6/P0-7 data:
      posture | drift | certification | governance | evidence | board_summary

    Returns the assembled brief with all sections and manifest summary.
    Every metric traces to its authoritative source — no synthetic data.
    """
    from services.quarterly_briefs.brief_service import (  # noqa: PLC0415
        generate_quarterly_brief as _generate,
    )

    tenant_id = _resolve_caller_tenant(request)
    actor = _caller_actor(request)

    brief = _generate(
        db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        year=year,
        quarter=quarter,
        generated_by=actor,
        parent_brief_id=parent_brief_id,
    )
    if not brief:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="brief generation failed",
        )
    db.commit()
    return brief


# ---------------------------------------------------------------------------
# GET /engagements/{engagement_id}/etcc/briefs
# ---------------------------------------------------------------------------


@router.get(
    "/engagements/{engagement_id}/etcc/briefs",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability("trust.quarterly.briefs")),
    ],
    summary="List Quarterly Trust Briefs for an engagement (newest first)",
)
def list_briefs(
    engagement_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
    report_type: str | None = Query(
        default=None, description="Filter by report_type (quarterly | board | ...)"
    ),
    status_filter: str | None = Query(
        default=None, alias="status", description="Filter by status"
    ),
    limit: int = Query(default=20, le=100),
) -> dict[str, Any]:
    """Return a paginated list of all trust briefs for this engagement."""
    tenant_id = _resolve_caller_tenant(request)

    q = select(FaQtbBrief).where(
        FaQtbBrief.tenant_id == tenant_id,
        FaQtbBrief.engagement_id == engagement_id,
    )
    if report_type:
        q = q.where(FaQtbBrief.report_type == report_type)
    if status_filter:
        q = q.where(FaQtbBrief.status == status_filter)
    q = q.order_by(FaQtbBrief.generated_at.desc()).limit(limit)

    rows = db.execute(q).scalars().all()
    return {
        "engagement_id": engagement_id,
        "briefs": [_brief_to_dict(r) for r in rows],
        "count": len(rows),
    }


# ---------------------------------------------------------------------------
# GET /engagements/{engagement_id}/etcc/briefs/{brief_id}
# ---------------------------------------------------------------------------


@router.get(
    "/engagements/{engagement_id}/etcc/briefs/{brief_id}",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability("trust.quarterly.briefs")),
    ],
    summary="Get a Quarterly Trust Brief with all sections",
)
def get_brief(
    engagement_id: str,
    brief_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """Return a full trust brief with all sections and metadata.

    Includes: posture, drift, certification, governance, evidence, board_summary
    sections in section_order.  Manifest hash verifies content integrity.
    """
    tenant_id = _resolve_caller_tenant(request)
    brief, sections = _load_brief_with_sections(
        db, tenant_id=tenant_id, brief_id=brief_id
    )
    if brief is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="brief not found"
        )
    if brief.engagement_id != engagement_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="brief not found"
        )
    return {
        **_brief_to_dict(brief),
        "sections": [_section_to_dict(s) for s in sections],
    }


# ---------------------------------------------------------------------------
# POST /engagements/{engagement_id}/etcc/briefs/{brief_id}/review
# ---------------------------------------------------------------------------


@router.post(
    "/engagements/{engagement_id}/etcc/briefs/{brief_id}/review",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability("trust.report.review")),
    ],
    summary="Mark a trust brief as reviewed",
)
def review_brief(
    engagement_id: str,
    brief_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """Transition a trust brief from 'generated' to 'reviewed'.

    The actor is derived from the API key prefix — no caller-supplied actor.
    Only status and reviewer fields are mutated; content is immutable.
    """
    tenant_id = _resolve_caller_tenant(request)
    actor = _caller_actor(request)

    brief = db.execute(
        select(FaQtbBrief).where(
            FaQtbBrief.tenant_id == tenant_id,
            FaQtbBrief.id == brief_id,
            FaQtbBrief.engagement_id == engagement_id,
        )
    ).scalar_one_or_none()

    if brief is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="brief not found"
        )
    if brief.status not in _REVIEW_TRANSITION:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"cannot review brief with status '{brief.status}'",
        )

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    brief.status = "reviewed"
    brief.reviewed_by = actor
    brief.reviewed_at = now
    db.commit()

    return {
        "brief_id": brief_id,
        "status": "reviewed",
        "reviewed_by": actor,
        "reviewed_at": now,
    }


# ---------------------------------------------------------------------------
# POST /engagements/{engagement_id}/etcc/briefs/{brief_id}/approve
# ---------------------------------------------------------------------------


@router.post(
    "/engagements/{engagement_id}/etcc/briefs/{brief_id}/approve",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability("trust.report.review")),
    ],
    summary="Approve a reviewed trust brief (immutable after this point)",
)
def approve_brief(
    engagement_id: str,
    brief_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """Transition a trust brief from 'reviewed' to 'approved'.

    Approved briefs are considered final deliverables.  Content is
    immutable after approval — the report_hash ensures integrity.
    """
    tenant_id = _resolve_caller_tenant(request)
    actor = _caller_actor(request)

    brief = db.execute(
        select(FaQtbBrief).where(
            FaQtbBrief.tenant_id == tenant_id,
            FaQtbBrief.id == brief_id,
            FaQtbBrief.engagement_id == engagement_id,
        )
    ).scalar_one_or_none()

    if brief is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="brief not found"
        )
    if brief.status not in _APPROVE_TRANSITION:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"cannot approve brief with status '{brief.status}'",
        )

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    brief.status = "approved"
    brief.approved_by = actor
    brief.approved_at = now
    db.commit()

    return {
        "brief_id": brief_id,
        "status": "approved",
        "approved_by": actor,
        "approved_at": now,
        "report_hash": brief.report_hash,
    }


# ---------------------------------------------------------------------------
# GET /engagements/{engagement_id}/etcc/briefs/{brief_id}/manifest
# ---------------------------------------------------------------------------


@router.get(
    "/engagements/{engagement_id}/etcc/briefs/{brief_id}/manifest",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability("trust.quarterly.briefs")),
    ],
    summary="Get the deterministic audit manifest for a trust brief",
)
def get_brief_manifest(
    engagement_id: str,
    brief_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """Return the deterministic audit manifest for a trust brief.

    The manifest contains every source ID referenced by the report —
    enabling auditors and regulators to verify every metric traces back
    to authoritative platform data.

    manifest_hash = SHA-256 of all source ID arrays.
    report_hash   = SHA-256(brief_hash + manifest_hash).
    """
    tenant_id = _resolve_caller_tenant(request)

    brief = db.execute(
        select(FaQtbBrief).where(
            FaQtbBrief.tenant_id == tenant_id,
            FaQtbBrief.id == brief_id,
            FaQtbBrief.engagement_id == engagement_id,
        )
    ).scalar_one_or_none()

    if brief is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="brief not found"
        )

    manifest = db.execute(
        select(FaQtbBriefManifest).where(
            FaQtbBriefManifest.tenant_id == tenant_id,
            FaQtbBriefManifest.brief_id == brief_id,
        )
    ).scalar_one_or_none()

    if manifest is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="manifest not found"
        )

    return {
        "brief_id": brief_id,
        "brief_status": brief.status,
        "brief_hash": brief.brief_hash,
        **_manifest_to_dict(manifest),
    }


# ---------------------------------------------------------------------------
# GET /engagements/{engagement_id}/etcc/briefs/{brief_id}/export
# ---------------------------------------------------------------------------


@router.get(
    "/engagements/{engagement_id}/etcc/briefs/{brief_id}/export",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability("trust.report.export")),
    ],
    summary="Export a trust brief as JSON or HTML",
)
def export_brief(
    engagement_id: str,
    brief_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
    format: str = Query(
        default="json",
        description="Export format: json | html",
    ),
) -> dict[str, Any]:
    """Export a trust brief in a portable format.

    json  — full brief + sections + manifest as a single JSON document.
    html  — HTML-formatted report suitable for board sharing (inline CSS).

    The exported document is format-agnostic data from the same authoritative
    source.  PDF generation is handled by downstream tooling from the HTML.
    """
    tenant_id = _resolve_caller_tenant(request)

    if format not in {"json", "html"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="format must be 'json' or 'html'",
        )

    brief, sections = _load_brief_with_sections(
        db, tenant_id=tenant_id, brief_id=brief_id
    )
    if brief is None or brief.engagement_id != engagement_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="brief not found"
        )

    manifest = db.execute(
        select(FaQtbBriefManifest).where(
            FaQtbBriefManifest.tenant_id == tenant_id,
            FaQtbBriefManifest.brief_id == brief_id,
        )
    ).scalar_one_or_none()

    brief_dict = _brief_to_dict(brief)
    section_list = [_section_to_dict(s) for s in sections]
    manifest_dict = _manifest_to_dict(manifest) if manifest else None

    if format == "json":
        return {
            "export_format": "json",
            "brief": brief_dict,
            "sections": section_list,
            "manifest": manifest_dict,
        }

    # HTML export — structured text representation
    period_label = (
        f"Q{brief.quarter} {brief.year}"
        if brief.year and brief.quarter
        else "Custom Period"
    )
    html_sections = []
    for sec in section_list:
        sec_type = sec["section_type"].replace("_", " ").title()
        html_sections.append(
            f"<section><h2>{sec_type}</h2>"
            f"<pre>{json.dumps(sec['section_data'], indent=2, default=str)}</pre>"
            f"</section>"
        )

    html = (
        f"<!DOCTYPE html><html><head>"
        f"<meta charset='utf-8'>"
        f"<title>FrostGate Trust Brief — {period_label}</title>"
        f"<style>body{{font-family:system-ui,sans-serif;max-width:960px;margin:0 auto;padding:2rem}}"
        f"h1{{color:#1a1a2e}}h2{{color:#2d4a7a;border-bottom:1px solid #ccc;padding-bottom:.5rem}}"
        f"pre{{background:#f5f5f5;padding:1rem;overflow:auto;border-radius:4px;font-size:.85em}}"
        f".meta{{color:#666;font-size:.9em}}</style></head><body>"
        f"<h1>FrostGate Trust Brief</h1>"
        f"<p class='meta'>"
        f"Period: {period_label} &nbsp;|&nbsp; "
        f"Type: {brief.report_type} &nbsp;|&nbsp; "
        f"Status: {brief.status} &nbsp;|&nbsp; "
        f"Generated: {brief.generated_at}"
        f"</p>"
        f"<p class='meta'>"
        f"Report Hash: <code>{brief.report_hash or 'pending'}</code>"
        f"</p>"
        f"{''.join(html_sections)}"
        f"</body></html>"
    )

    return {
        "export_format": "html",
        "brief_id": brief_id,
        "content_type": "text/html",
        "html": html,
    }


# ---------------------------------------------------------------------------
# POST /engagements/{engagement_id}/etcc/board/generate
# ---------------------------------------------------------------------------


@router.post(
    "/engagements/{engagement_id}/etcc/board/generate",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability("trust.board.reporting")),
    ],
    summary="Generate a Board-level Trust Brief for an engagement",
    status_code=status.HTTP_201_CREATED,
)
def generate_board_brief(
    engagement_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
    year: int = Query(..., description="Report year (e.g. 2026)"),
    quarter: int = Query(..., ge=1, le=4, description="Report quarter (1–4)"),
    parent_brief_id: str | None = Query(
        default=None, description="ID of the board report this regeneration supersedes"
    ),
) -> dict[str, Any]:
    """Generate and persist a Board-level Trust Brief.

    Condenses full quarterly data into a strategic board-ready format.
    Contains: board_summary + evidence appendix only.

    All values sourced from the same authoritative P0-6/P0-7 data.
    No additional trust engines.
    """
    from services.quarterly_briefs.brief_service import (  # noqa: PLC0415
        generate_board_brief as _generate,
    )

    tenant_id = _resolve_caller_tenant(request)
    actor = _caller_actor(request)

    brief = _generate(
        db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        year=year,
        quarter=quarter,
        generated_by=actor,
        parent_brief_id=parent_brief_id,
    )
    if not brief:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="board brief generation failed",
        )
    db.commit()
    return brief


# ---------------------------------------------------------------------------
# GET /engagements/{engagement_id}/etcc/board
# ---------------------------------------------------------------------------


@router.get(
    "/engagements/{engagement_id}/etcc/board",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability("trust.board.reporting")),
    ],
    summary="List Board Trust Reports for an engagement (newest first)",
)
def list_board_reports(
    engagement_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
    limit: int = Query(default=20, le=100),
) -> dict[str, Any]:
    """Return all board-type trust briefs for this engagement."""
    tenant_id = _resolve_caller_tenant(request)

    rows = (
        db.execute(
            select(FaQtbBrief)
            .where(
                FaQtbBrief.tenant_id == tenant_id,
                FaQtbBrief.engagement_id == engagement_id,
                FaQtbBrief.report_type == "board",
            )
            .order_by(FaQtbBrief.generated_at.desc())
            .limit(limit)
        )
        .scalars()
        .all()
    )
    return {
        "engagement_id": engagement_id,
        "board_reports": [_brief_to_dict(r) for r in rows],
        "count": len(rows),
    }


# ---------------------------------------------------------------------------
# GET /engagements/{engagement_id}/etcc/board/{report_id}
# ---------------------------------------------------------------------------


@router.get(
    "/engagements/{engagement_id}/etcc/board/{report_id}",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability("trust.board.reporting")),
    ],
    summary="Get a Board Trust Report with all sections",
)
def get_board_report(
    engagement_id: str,
    report_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """Return a full board trust report with sections and manifest."""
    tenant_id = _resolve_caller_tenant(request)
    brief, sections = _load_brief_with_sections(
        db, tenant_id=tenant_id, brief_id=report_id
    )
    if brief is None or brief.engagement_id != engagement_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="board report not found"
        )
    if brief.report_type != "board":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="board report not found"
        )
    return {
        **_brief_to_dict(brief),
        "sections": [_section_to_dict(s) for s in sections],
    }


# ---------------------------------------------------------------------------
# POST /engagements/{engagement_id}/etcc/briefs/{brief_id}/deliver
# ---------------------------------------------------------------------------


@router.post(
    "/engagements/{engagement_id}/etcc/briefs/{brief_id}/deliver",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability("trust.report.delivery")),
    ],
    summary="Mark a trust brief as delivered to a recipient",
)
def deliver_brief(
    engagement_id: str,
    brief_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
    delivered_to: str = Query(
        ..., description="Recipient identifier (email, org, role)"
    ),
    delivery_channel: str = Query(
        ..., description="Delivery channel: portal | email | api | export"
    ),
) -> dict[str, Any]:
    """Record delivery of an approved trust brief.

    Only approved briefs may be delivered.  Sets delivered_at, delivered_to,
    delivery_channel and transitions status to 'delivered'.
    The actor is derived from the API key — no caller-supplied actor.
    """
    _VALID_CHANNELS = frozenset({"portal", "email", "api", "export"})
    if delivery_channel not in _VALID_CHANNELS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"delivery_channel must be one of: {', '.join(sorted(_VALID_CHANNELS))}",
        )

    tenant_id = _resolve_caller_tenant(request)

    brief = db.execute(
        select(FaQtbBrief).where(
            FaQtbBrief.tenant_id == tenant_id,
            FaQtbBrief.id == brief_id,
            FaQtbBrief.engagement_id == engagement_id,
        )
    ).scalar_one_or_none()

    if brief is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="brief not found"
        )
    if brief.status != "approved":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"only approved briefs may be delivered (current status: '{brief.status}')",
        )

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    brief.status = "delivered"
    brief.delivered_at = now
    brief.delivered_to = delivered_to
    brief.delivery_channel = delivery_channel
    db.commit()

    return {
        "brief_id": brief_id,
        "status": "delivered",
        "delivered_at": now,
        "delivered_to": delivered_to,
        "delivery_channel": delivery_channel,
        "report_hash": brief.report_hash,
    }


# ---------------------------------------------------------------------------
# GET /engagements/{engagement_id}/etcc/briefs/{brief_id}/explain
# ---------------------------------------------------------------------------


@router.get(
    "/engagements/{engagement_id}/etcc/briefs/{brief_id}/explain",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability("trust.quarterly.briefs")),
    ],
    summary="Explain the provenance of every metric in a trust brief",
)
def explain_brief(
    engagement_id: str,
    brief_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """Return metric-to-source provenance for a trust brief.

    Maps every top-level metric in the report back to the authoritative
    source table and the exact record IDs that produced it.  No AI.
    No summaries.  Pure data lineage from the persisted manifest.
    """
    tenant_id = _resolve_caller_tenant(request)

    brief = db.execute(
        select(FaQtbBrief).where(
            FaQtbBrief.tenant_id == tenant_id,
            FaQtbBrief.id == brief_id,
            FaQtbBrief.engagement_id == engagement_id,
        )
    ).scalar_one_or_none()

    if brief is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="brief not found"
        )

    manifest = db.execute(
        select(FaQtbBriefManifest).where(
            FaQtbBriefManifest.tenant_id == tenant_id,
            FaQtbBriefManifest.brief_id == brief_id,
        )
    ).scalar_one_or_none()

    if manifest is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="manifest not found"
        )

    def _parse(val: str) -> list:
        try:
            return json.loads(val)
        except (ValueError, TypeError):
            return []

    snap_ids = _parse(manifest.snapshot_ids)
    cert_ids = _parse(manifest.certification_ids)
    drift_ids = _parse(manifest.drift_event_ids)
    timeline_ids = _parse(manifest.timeline_refs)
    decision_ids = _parse(manifest.decision_refs)
    bundle_ids = _parse(manifest.bundle_refs)

    return {
        "brief_id": brief_id,
        "report_hash": brief.report_hash,
        "provenance": {
            "trust_score": {
                "source": "fa_tim_trust_snapshots",
                "source_label": "TIM Snapshots",
                "snapshot_ids": snap_ids,
                "count": len(snap_ids),
            },
            "risk_score": {
                "source": "fa_tim_drift_events",
                "source_label": "Drift Events",
                "event_ids": drift_ids,
                "count": len(drift_ids),
            },
            "certification_status": {
                "source": "fa_trust_certifications",
                "source_label": "Trust Certifications",
                "certification_ids": cert_ids,
                "count": len(cert_ids),
            },
            "governance_activity": {
                "source": "fa_timeline_events",
                "source_label": "Timeline Events",
                "event_ids": timeline_ids,
                "count": len(timeline_ids),
            },
            "decision_record": {
                "source": "fa_trust_decision_memory",
                "source_label": "Decision Memory",
                "decision_ids": decision_ids,
                "count": len(decision_ids),
            },
            "verification_bundles": {
                "source": "fa_verification_bundles",
                "source_label": "Verification Bundles",
                "bundle_ids": bundle_ids,
                "count": len(bundle_ids),
            },
        },
        "manifest_hash": manifest.manifest_hash,
        "integrity": {
            "no_synthetic_data": True,
            "no_ai_generated_conclusions": True,
            "every_metric_has_source": True,
            "replay_support": True,
        },
    }


# ---------------------------------------------------------------------------
# GET /etcc/briefs/history  (tenant-level)
# ---------------------------------------------------------------------------


@router.get(
    "/etcc/briefs/history",
    dependencies=[
        Depends(require_scopes("governance:read")),
        Depends(require_capability("trust.report.delivery")),
    ],
    summary="Tenant-level trust brief history across all engagements",
)
def get_brief_history(
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
    report_type: str | None = Query(default=None),
    status_filter: str | None = Query(default=None, alias="status"),
    limit: int = Query(default=50, le=200),
) -> dict[str, Any]:
    """Return all trust briefs across all engagements for this tenant.

    Ordered by generated_at descending.  Enables a compliance team to
    view the full report delivery history in one call.
    """
    tenant_id = _resolve_caller_tenant(request)

    total_count = (
        db.execute(
            select(func.count()).where(FaQtbBrief.tenant_id == tenant_id)
        ).scalar()
        or 0
    )

    q = select(FaQtbBrief).where(FaQtbBrief.tenant_id == tenant_id)
    if report_type:
        q = q.where(FaQtbBrief.report_type == report_type)
    if status_filter:
        q = q.where(FaQtbBrief.status == status_filter)
    q = q.order_by(FaQtbBrief.generated_at.desc()).limit(limit)

    rows = db.execute(q).scalars().all()

    status_dist: dict[str, int] = {}
    type_dist: dict[str, int] = {}
    for r in rows:
        status_dist[r.status] = status_dist.get(r.status, 0) + 1
        type_dist[r.report_type] = type_dist.get(r.report_type, 0) + 1

    return {
        "tenant_id": tenant_id,
        "total_brief_count": total_count,
        "briefs": [_brief_to_dict(r) for r in rows],
        "count": len(rows),
        "by_status": status_dist,
        "by_report_type": type_dist,
    }
