from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from api.auth_scopes import require_bound_tenant, require_scopes
from api.deps import tenant_db_required
from services.ai_plane_extension import (
    AIChatRequest,
    AIChatResponse,
    AIInferRequest,
    AIPlaneService,
    AIPolicyUpsertRequest,
)

router = APIRouter(tags=["ai-plane"])
service = AIPlaneService()


@router.post(
    "/ai/infer",
    dependencies=[Depends(require_scopes("compliance:read"))],
)
def ai_infer(
    request: Request,
    payload: AIInferRequest,
    db: Session = Depends(tenant_db_required),
) -> dict[str, object]:
    tenant_id = require_bound_tenant(request)
    try:
        return service.infer(db, tenant_id, payload)
    except ValueError as exc:
        code = str(exc)
        raise HTTPException(
            status_code=400,
            detail={"error_code": code, "reason": "ai policy rejection"},
        ) from exc


@router.post(
    "/ai/chat",
    dependencies=[Depends(require_scopes("compliance:read"))],
    response_model=AIChatResponse,
    responses={
        400: {
            "description": "AI policy rejection",
            "content": {
                "application/json": {
                    "schema": {
                        "properties": {
                            "detail": {
                                "properties": {
                                    "error_code": {"type": "string"},
                                    "reason": {"type": "string"},
                                },
                                "required": ["error_code", "reason"],
                                "type": "object",
                            }
                        },
                        "required": ["detail"],
                        "type": "object",
                    }
                }
            },
        },
        401: {
            "description": "Unauthorized",
            "content": {
                "application/json": {
                    "schema": {
                        "properties": {"detail": {"type": "string"}},
                        "required": ["detail"],
                        "type": "object",
                    }
                }
            },
        },
        403: {
            "description": "Forbidden",
            "content": {
                "application/json": {
                    "schema": {
                        "properties": {"detail": {"type": "string"}},
                        "required": ["detail"],
                        "type": "object",
                    }
                }
            },
        },
    },
)
def ai_chat(
    request: Request,
    payload: AIChatRequest,
    db: Session = Depends(tenant_db_required),
) -> dict[str, object]:
    tenant_id = require_bound_tenant(request)
    try:
        return service.chat(db, tenant_id, payload)
    except ValueError as exc:
        code = str(exc)
        raise HTTPException(
            status_code=400,
            detail={"error_code": code, "reason": "ai policy rejection"},
        ) from exc


@router.get(
    "/ai-plane/policies",
    dependencies=[Depends(require_scopes("compliance:read"))],
)
def ai_plane_policy_get(
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> dict[str, object]:
    tenant_id = require_bound_tenant(request)
    return service.get_policy(db, tenant_id)


@router.post(
    "/ai-plane/policies",
    dependencies=[Depends(require_scopes("admin:write"))],
)
def ai_plane_policy_upsert(
    request: Request,
    payload: AIPolicyUpsertRequest,
    db: Session = Depends(tenant_db_required),
) -> dict[str, object]:
    tenant_id = require_bound_tenant(request)
    return service.upsert_policy(db, tenant_id, payload)


@router.get(
    "/ai-plane/inference",
    dependencies=[Depends(require_scopes("compliance:read"))],
)
def ai_plane_inference_list(
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> dict[str, object]:
    tenant_id = require_bound_tenant(request)
    return {"inference": service.list_inference(db, tenant_id)}
