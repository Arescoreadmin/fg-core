"""Admin Gateway API Routers."""

from admin_gateway.routers.admin import router as admin_router
from admin_gateway.routers.auth import router as auth_router
from admin_gateway.routers.products import router as products_router

__all__ = ["admin_router", "auth_router", "products_router"]
