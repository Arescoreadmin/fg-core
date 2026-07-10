"""api/identity_administration/routes — Combined router for identity administration."""

from __future__ import annotations

from fastapi import APIRouter

from api.identity_administration.routes.admin import router as admin_router
from api.identity_administration.routes.groups import router as groups_router
from api.identity_administration.routes.invitations import router as invitations_router
from api.identity_administration.routes.self_service import (
    router as self_service_router,
)

router = APIRouter(tags=["identity-administration"])
router.include_router(admin_router)
router.include_router(invitations_router)
router.include_router(self_service_router)
router.include_router(groups_router)

__all__ = ["router"]
