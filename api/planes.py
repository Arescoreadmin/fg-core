from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from api.auth_scopes import require_bound_tenant, require_scopes
from services.plane_registry import list_planes

router = APIRouter(tags=["planes"])


@router.get("/planes", dependencies=[Depends(require_scopes("admin:write"))])
def get_planes(request: Request) -> dict[str, object]:
    _ = require_bound_tenant(request)
    return {"planes": list_planes()}
