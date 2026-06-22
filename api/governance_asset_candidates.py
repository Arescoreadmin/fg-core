"""Governance Asset Candidates API.

Operator inbox for pending governance asset detections. Candidates accumulate
detection history across rescans and provide a review queue for assets that
did not meet the auto-promotion confidence threshold.

Routes:
  GET  /governance/candidates              — list candidates (filterable by status)
  GET  /governance/candidates/inbox        — shortcut: detected + under_review
  GET  /governance/candidates/{id}         — single candidate detail
  POST /governance/candidates/{id}/review  — mark under_review
  POST /governance/candidates/{id}/promote — operator-promote to GaAsset
  POST /governance/candidates/{id}/reject  — operator-reject
  POST /governance/candidates/promote-batch — bulk promote by candidate_ids

Scopes:
  governance:read  — list, inbox, get
  governance:write — review, promote, reject, promote-batch
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.auth_scopes.resolution import require_scopes
from api.deps import auth_ctx_db_session
from api.error_contracts import api_error
from services.governance_asset_registry import candidates as candidate_svc
from services.governance_asset_registry.promotion import promote_candidate_to_asset

log = logging.getLogger("frostgate.api.governance_candidates")

router = APIRouter(
    prefix="/governance/candidates",
    tags=["governance-candidates"],
)


# ---------------------------------------------------------------------------
# Auth helpers (mirrors governance_assets.py pattern)
# ---------------------------------------------------------------------------


def _resolve_caller_tenant(request: Request) -> str:
    auth = getattr(getattr(request, "state", None), "auth", None)
    tid = getattr(getattr(request, "state", None), "tenant_id", None) or getattr(
        auth, "tenant_id", None
    )
    if not tid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="tenant context required",
        )
    return str(tid)


def _actor(request: Request) -> str:
    auth = getattr(getattr(request, "state", None), "auth", None)
    return (
        getattr(auth, "subject", None) or getattr(auth, "key_prefix", None) or "system"
    )


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class CandidateResponse(BaseModel):
    candidate_id: str
    tenant_id: str
    engagement_id: str | None
    scan_result_id: str | None
    report_id: str | None
    source_type: str
    candidate_type: str
    risk_signal: str
    suggested_name: str
    suggested_asset_type: str
    confidence: int
    peak_confidence: int
    status: str
    promoted_asset_id: str | None
    promoted_at: str | None
    auto_promoted: bool
    rejected_reason: str | None
    rejected_at: str | None
    reviewed_by: str | None
    detection_count: int
    evidence_ref_ids: list[str]
    first_detected_at: str
    last_detected_at: str
    schema_version: str


class PromoteRequest(BaseModel):
    reviewed_by: str | None = None


class RejectRequest(BaseModel):
    reason: str
    reviewed_by: str


class ReviewRequest(BaseModel):
    reviewed_by: str


class BatchPromoteRequest(BaseModel):
    candidate_ids: list[str]


class BatchPromoteResponse(BaseModel):
    promoted: list[str]
    already_promoted: list[str]
    not_found: list[str]
    errors: list[dict[str, Any]]


# ---------------------------------------------------------------------------
# Routes — read
# ---------------------------------------------------------------------------


@router.get(
    "",
    response_model=list[CandidateResponse],
    dependencies=[Depends(require_scopes("governance:read"))],
)
def list_candidates(
    request: Request,
    status_filter: str | None = Query(default=None, alias="status"),
    source_type: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(auth_ctx_db_session),
) -> list[CandidateResponse]:
    tenant_id = _resolve_caller_tenant(request)
    rows = candidate_svc.list_candidates(
        db,
        tenant_id=tenant_id,
        status=status_filter,
        source_type=source_type,
        limit=limit,
        offset=offset,
    )
    return [CandidateResponse(**candidate_svc.candidate_to_dict(r)) for r in rows]


@router.get(
    "/inbox",
    response_model=list[CandidateResponse],
    dependencies=[Depends(require_scopes("governance:read"))],
)
def get_inbox(
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(auth_ctx_db_session),
) -> list[CandidateResponse]:
    tenant_id = _resolve_caller_tenant(request)
    rows = candidate_svc.get_inbox(db, tenant_id=tenant_id, limit=limit, offset=offset)
    return [CandidateResponse(**candidate_svc.candidate_to_dict(r)) for r in rows]


@router.get(
    "/{candidate_id}",
    response_model=CandidateResponse,
    dependencies=[Depends(require_scopes("governance:read"))],
)
def get_candidate(
    candidate_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> CandidateResponse:
    tenant_id = _resolve_caller_tenant(request)
    candidate = candidate_svc.get_candidate(
        db, tenant_id=tenant_id, candidate_id=candidate_id
    )
    if candidate is None:
        raise HTTPException(
            status_code=404,
            detail=api_error("CANDIDATE_NOT_FOUND", "Candidate not found"),
        )
    return CandidateResponse(**candidate_svc.candidate_to_dict(candidate))


# ---------------------------------------------------------------------------
# Routes — mutations
# ---------------------------------------------------------------------------


@router.post(
    "/{candidate_id}/review",
    response_model=CandidateResponse,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def mark_under_review(
    candidate_id: str,
    body: ReviewRequest,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> CandidateResponse:
    tenant_id = _resolve_caller_tenant(request)
    candidate = candidate_svc.mark_under_review(
        db,
        tenant_id=tenant_id,
        candidate_id=candidate_id,
        reviewed_by=body.reviewed_by,
    )
    if candidate is None:
        raise HTTPException(
            status_code=404,
            detail=api_error("CANDIDATE_NOT_FOUND", "Candidate not found"),
        )
    db.commit()
    return CandidateResponse(**candidate_svc.candidate_to_dict(candidate))


@router.post(
    "/{candidate_id}/promote",
    response_model=CandidateResponse,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def promote_candidate(
    candidate_id: str,
    body: PromoteRequest,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> CandidateResponse:
    tenant_id = _resolve_caller_tenant(request)
    actor = _actor(request)

    candidate = candidate_svc.get_candidate(
        db, tenant_id=tenant_id, candidate_id=candidate_id
    )
    if candidate is None:
        raise HTTPException(
            status_code=404,
            detail=api_error("CANDIDATE_NOT_FOUND", "Candidate not found"),
        )
    if candidate.status == "rejected":
        raise HTTPException(
            status_code=409,
            detail=api_error(
                "CANDIDATE_REJECTED", "Cannot promote a rejected candidate"
            ),
        )

    promote_candidate_to_asset(
        db,
        candidate=candidate,
        actor_email=body.reviewed_by or actor,
        auto_promoted=False,
    )
    db.commit()
    db.refresh(candidate)
    return CandidateResponse(**candidate_svc.candidate_to_dict(candidate))


@router.post(
    "/{candidate_id}/reject",
    response_model=CandidateResponse,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def reject_candidate(
    candidate_id: str,
    body: RejectRequest,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> CandidateResponse:
    tenant_id = _resolve_caller_tenant(request)

    candidate = candidate_svc.mark_rejected(
        db,
        tenant_id=tenant_id,
        candidate_id=candidate_id,
        reason=body.reason,
        reviewed_by=body.reviewed_by,
    )
    if candidate is None:
        raise HTTPException(
            status_code=404,
            detail=api_error("CANDIDATE_NOT_FOUND", "Candidate not found"),
        )
    if candidate.status != "rejected":
        raise HTTPException(
            status_code=409,
            detail=api_error(
                "CANDIDATE_PROMOTED", "Cannot reject a promoted candidate"
            ),
        )
    db.commit()
    return CandidateResponse(**candidate_svc.candidate_to_dict(candidate))


@router.post(
    "/promote-batch",
    response_model=BatchPromoteResponse,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def promote_batch(
    body: BatchPromoteRequest,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> BatchPromoteResponse:
    tenant_id = _resolve_caller_tenant(request)
    actor = _actor(request)

    promoted: list[str] = []
    already_promoted: list[str] = []
    not_found: list[str] = []
    errors: list[dict[str, Any]] = []

    for cid in body.candidate_ids:
        candidate = candidate_svc.get_candidate(
            db, tenant_id=tenant_id, candidate_id=cid
        )
        if candidate is None:
            not_found.append(cid)
            continue
        if candidate.status == "promoted":
            already_promoted.append(cid)
            continue
        try:
            promote_candidate_to_asset(
                db, candidate=candidate, actor_email=actor, auto_promoted=False
            )
            promoted.append(cid)
        except Exception as exc:
            errors.append({"candidate_id": cid, "error": str(exc)})
            db.rollback()

    if promoted:
        db.commit()

    return BatchPromoteResponse(
        promoted=promoted,
        already_promoted=already_promoted,
        not_found=not_found,
        errors=errors,
    )
