from fastapi import APIRouter, Depends

from api.auth_scopes import require_scopes

router = APIRouter(prefix="/admin")


@router.get("/status", dependencies=[Depends(require_scopes("admin:read"))])
def admin_status():
    return {"ok": True}
