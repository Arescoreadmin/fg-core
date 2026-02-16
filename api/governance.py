from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.auth_scopes import require_bound_tenant, require_scopes, verify_api_key
from api.config.startup_validation import compliance_module_enabled
from api.deps import tenant_db_required
from api.db_models import PolicyChangeRequest as PolicyChangeRequestModel

log = logging.getLogger("frostgate.governance")
_security_log = logging.getLogger("frostgate.security")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# -----------------------------------------------------------------------------
# API Models
# -----------------------------------------------------------------------------


class PolicyChangeResponse(BaseModel):
    """Response model for policy change requests."""

    change_id: str
    change_type: str
    proposed_by: str
    proposed_at: datetime
    justification: str
    rule_definition: Optional[dict] = None
    roe_update: Optional[dict] = None
    simulation_results: dict = Field(default_factory=dict)
    estimated_false_positives: int = 0
    estimated_true_positives: int = 0
    confidence: str = "medium"
    requires_approval_from: List[str] = Field(default_factory=list)
    approvals: List[dict] = Field(default_factory=list)
    status: str = "pending"
    deployed_at: Optional[datetime] = None


class PolicyChangeCreate(BaseModel):
    """Request model for creating a policy change."""

    change_type: str
    proposed_by: str
    justification: str
    rule_definition: Optional[dict] = None
    roe_update: Optional[dict] = None


class PolicyApprovalRequest(BaseModel):
    """Request model for approving a policy change."""

    approver: str
    notes: Optional[str] = None


# -----------------------------------------------------------------------------
# Helper functions
# -----------------------------------------------------------------------------


def _model_to_response(m: PolicyChangeRequestModel) -> PolicyChangeResponse:
    """Convert DB model to API response model."""
    return PolicyChangeResponse(
        change_id=m.change_id,
        change_type=m.change_type,
        proposed_by=m.proposed_by,
        proposed_at=m.proposed_at,
        justification=m.justification,
        rule_definition=m.rule_definition_json,
        roe_update=m.roe_update_json,
        simulation_results=m.simulation_results_json or {},
        estimated_false_positives=m.estimated_false_positives or 0,
        estimated_true_positives=m.estimated_true_positives or 0,
        confidence=m.confidence or "medium",
        requires_approval_from=m.requires_approval_from_json or [],
        approvals=m.approvals_json or [],
        status=m.status,
        deployed_at=m.deployed_at,
    )


def _require_known_tenant(request: Request) -> str:
    return require_bound_tenant(request)


# -----------------------------------------------------------------------------
# Router with authentication + governance scope on ALL endpoints
# -----------------------------------------------------------------------------

router = APIRouter(
    prefix="/governance",
    tags=["governance"],
    dependencies=[
        Depends(verify_api_key),
        Depends(require_scopes("governance:write")),  # INV-005: Scope required
    ],
)


@router.get("/changes", response_model=List[PolicyChangeResponse])
def list_changes(
    request: Request,
    db: Session = Depends(tenant_db_required),
    limit: int = Query(50, ge=1),
    offset: int = Query(0, ge=0),
) -> List[PolicyChangeResponse]:
    """
    List all policy change requests.

    Security: Requires authentication + governance scope (INV-005).
    Persistence: Database-backed, survives restart (P0).
    """
    try:
        tenant_id = _require_known_tenant(request)
        limit = min(limit, 200)
        stmt = (
            select(PolicyChangeRequestModel)
            .where(PolicyChangeRequestModel.tenant_id == tenant_id)
            .order_by(
                PolicyChangeRequestModel.proposed_at.desc(),
                PolicyChangeRequestModel.id.desc(),
            )
            .limit(limit)
            .offset(offset)
        )
        rows = db.execute(stmt).scalars().all()
        return [_model_to_response(r) for r in rows]
    except HTTPException:
        raise
    except Exception as e:
        # P0: Fail closed on DB error - do not return empty list
        log.error("governance.list_changes DB error: %s", e)
        raise HTTPException(
            status_code=503,
            detail="Governance service unavailable - database error",
        )


@router.post("/changes", response_model=PolicyChangeResponse)
def create_change(
    req: PolicyChangeCreate,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> PolicyChangeResponse:
    """
    Create a new policy change request.

    Security: Requires authentication + governance scope (INV-005).
    Persistence: Database-backed, survives restart (P0).
    Audit: Timestamp and proposer recorded.
    """
    try:
        tenant_id = _require_known_tenant(request)
        change_id = f"pcr-{uuid.uuid4().hex[:8]}"

        model = PolicyChangeRequestModel(
            change_id=change_id,
            tenant_id=tenant_id,
            change_type=req.change_type,
            proposed_by=req.proposed_by,
            proposed_at=_utcnow(),
            justification=req.justification,
            rule_definition_json=req.rule_definition,
            roe_update_json=req.roe_update,
            simulation_results_json={},
            estimated_false_positives=0,
            estimated_true_positives=0,
            confidence="medium",
            requires_approval_from_json=["security-lead", "ciso"],
            approvals_json=[],
            status="pending",
        )

        db.add(model)
        db.commit()
        db.refresh(model)

        log.info(
            "governance.create_change: change_id=%s proposed_by=%s",
            change_id,
            req.proposed_by,
        )

        return _model_to_response(model)
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        # P0: Fail closed on DB error - do not silently fail
        log.error("governance.create_change DB error: %s", e)
        raise HTTPException(
            status_code=503,
            detail="Governance service unavailable - database error",
        )


@router.post("/changes/{change_id}/approve", response_model=PolicyChangeResponse)
def approve_change(
    change_id: str,
    req: PolicyApprovalRequest,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> PolicyChangeResponse:
    """
    Approve a policy change request.

    Security: Requires authentication + governance scope (INV-005).
    Persistence: Database-backed, survives restart (P0).
    Audit: Approval timestamp and approver recorded.
    """
    try:
        tenant_id = _require_known_tenant(request)
        stmt = select(PolicyChangeRequestModel).where(
            PolicyChangeRequestModel.change_id == change_id,
            PolicyChangeRequestModel.tenant_id == tenant_id,
        )
        model = db.execute(stmt).scalar_one_or_none()

        if model is None:
            raise HTTPException(status_code=404, detail="Change request not found")

        # Add approval
        approvals = list(model.approvals_json or [])
        approvals.append(
            {
                "approver": req.approver,
                "approved_at": _utcnow().isoformat(),
                "notes": req.notes,
            }
        )
        model.approvals_json = approvals

        # Check if fully approved
        required = model.requires_approval_from_json or []
        if len(approvals) >= len(required):
            model.status = "deployed"
            model.deployed_at = _utcnow()
        else:
            model.status = "pending"

        db.commit()
        db.refresh(model)

        log.info(
            "governance.approve_change: change_id=%s approver=%s status=%s",
            change_id,
            req.approver,
            model.status,
        )

        return _model_to_response(model)
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        # P0: Fail closed on DB error
        log.error("governance.approve_change DB error: %s", e)
        raise HTTPException(
            status_code=503,
            detail="Governance service unavailable - database error",
        )


def governance_enabled() -> bool:
    """Check if governance feature is enabled."""
    return compliance_module_enabled("governance")
