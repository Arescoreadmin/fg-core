"""Routers package for admin-gateway."""

from admin_gateway.routers.auth import router as auth_router
from admin_gateway.routers.admin import router as admin_router

__all__ = ["auth_router", "admin_router"]
