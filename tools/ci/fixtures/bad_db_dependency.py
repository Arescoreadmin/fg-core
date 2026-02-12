from fastapi import APIRouter, Depends

from api.db import get_db
from api.auth_scopes import require_scopes

router = APIRouter(
    prefix="/tenant", dependencies=[Depends(require_scopes("tenant:read"))]
)


@router.get("/items")
def bad(db=Depends(get_db)):
    return {"ok": True}
