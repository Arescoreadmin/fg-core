from fastapi import APIRouter, Depends

from api.auth_scopes import require_scopes
from api.deps import tenant_db_required

router = APIRouter(prefix="/tenant")


@router.get("/items", dependencies=[Depends(require_scopes("tenant:read"))])
def good(db=Depends(tenant_db_required)):
    return {"ok": True}
