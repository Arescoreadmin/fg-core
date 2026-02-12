from fastapi import APIRouter, Depends

from api.deps import tenant_db_required

router = APIRouter(prefix="/tenant")


@router.get("/items")
def missing_scope(db=Depends(tenant_db_required)):
    return {"ok": True}
