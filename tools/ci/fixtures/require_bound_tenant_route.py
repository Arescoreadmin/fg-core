from fastapi import APIRouter, Depends

from api.auth_scopes import require_bound_tenant, require_scopes

router = APIRouter(prefix="/tenant")


@router.get("/bound", dependencies=[Depends(require_scopes("tenant:read"))])
def bound(_tenant=Depends(require_bound_tenant)):
    return {"ok": True}
