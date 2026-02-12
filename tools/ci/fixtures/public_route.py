from fastapi import APIRouter, Depends

from api.db import get_db

router = APIRouter(prefix="/health")


@router.get("/ready")
def ready(db=Depends(get_db)):
    return {"ok": True}
