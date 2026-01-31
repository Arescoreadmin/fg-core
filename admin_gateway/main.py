"""Admin Gateway - FastAPI Application.

Provides administrative API for FrostGate management console.
Includes OIDC authentication, RBAC, CSRF protection, and audit logging.
"""

from __future__ import annotations

import logging
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from admin_gateway.auth import Scope, get_current_session, require_scope_dependency
from admin_gateway.auth.config import get_auth_config
from admin_gateway.auth.tenant import get_allowed_tenants, validate_tenant_access
from admin_gateway.auth.session import Session
from admin_gateway.middleware.request_id import RequestIdMiddleware
from admin_gateway.middleware.logging import StructuredLoggingMiddleware
from admin_gateway.middleware.audit import AuditMiddleware
from admin_gateway.middleware.auth import AuthMiddleware
from admin_gateway.middleware.auth_context import AuthContextMiddleware
from admin_gateway.middleware.csrf import CSRFMiddleware
from admin_gateway.middleware.session_cookie import SessionCookieMiddleware
from admin_gateway.audit import AuditLogger
from admin_gateway.db import init_db, close_db
from admin_gateway.routers import admin_router, auth_router, products_router


class LegacyProductCreate(BaseModel):
    tenant_id: str = Field(..., description="Tenant identifier")
    name: str | None = Field(default=None, description="Product name")


# Version info
SERVICE_NAME = "admin-gateway"
VERSION = "0.2.0"
API_VERSION = "v1"

# Configure structured logging
log = logging.getLogger(SERVICE_NAME)


def build_app() -> FastAPI:
    """Build and configure the FastAPI application."""

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        """Application lifespan handler."""
        log.info(
            "Starting %s v%s",
            SERVICE_NAME,
            VERSION,
            extra={"service": SERVICE_NAME, "version": VERSION},
        )

        # Initialize database
        await init_db()
        log.info("Database initialized")

        # Initialize audit logger
        if getattr(app.state, "audit_logger", None) is None:
            app.state.audit_logger = AuditLogger(
                core_base_url=os.getenv("AG_CORE_BASE_URL"),
                core_api_key=os.getenv("AG_CORE_API_KEY"),
                enabled=os.getenv("AG_AUDIT_ENABLED", "1").lower()
                not in {"0", "false", "no"},
                forward_enabled=os.getenv("AG_AUDIT_FORWARD_ENABLED", "0").lower()
                in {"1", "true", "yes"},
            )

        yield

        # Cleanup
        await close_db()
        log.info("Shutting down %s", SERVICE_NAME)

    app = FastAPI(
        title="FrostGate Admin Gateway",
        description="Administrative API for FrostGate management console",
        version=VERSION,
        lifespan=lifespan,
    )

    config = get_auth_config()

    # P0: Validate config and fail startup on any errors (including env typos)
    config_errors = config.validate()
    if config_errors:
        error_msg = "; ".join(config_errors)
        log.error("Configuration validation failed: %s", error_msg)
        raise RuntimeError(f"Configuration validation failed: {error_msg}")

    if config.is_prod and config.dev_auth_bypass:
        raise RuntimeError("FG_DEV_AUTH_BYPASS cannot be enabled in production.")
    if config.is_prod and not config.oidc_enabled:
        raise RuntimeError("Missing OIDC configuration in production.")

    # Add middleware (order matters: outermost first)
    # Audit comes after auth so it can see the session
    app.add_middleware(AuditMiddleware)
    app.add_middleware(AuthMiddleware, auto_csrf=True)
    app.add_middleware(StructuredLoggingMiddleware)
    app.add_middleware(RequestIdMiddleware)
    app.add_middleware(AuthContextMiddleware)
    app.add_middleware(AuditMiddleware)
    app.add_middleware(CSRFMiddleware)
    from starlette.middleware.sessions import SessionMiddleware

    session_secret = config.session_secret
    app.add_middleware(
        SessionMiddleware,
        secret_key=session_secret,
        max_age=config.session_ttl_seconds,
        same_site="strict",
        https_only=config.is_prod,
    )
    app.add_middleware(SessionCookieMiddleware)

    # CORS configuration - P0: No wildcard allowed in production
    cors_origins_raw = os.getenv("AG_CORS_ORIGINS", "")
    if not cors_origins_raw.strip():
        if config.is_prod:
            raise RuntimeError(
                "AG_CORS_ORIGINS must be set in production (no wildcard allowed)"
            )
        cors_origins_raw = "http://localhost:3000,http://localhost:13000"
        log.warning("AG_CORS_ORIGINS not set, using dev defaults: %s", cors_origins_raw)

    cors_origins = [o.strip() for o in cors_origins_raw.split(",") if o.strip()]

    # P0: Reject wildcard CORS in production
    if config.is_prod and "*" in cors_origins:
        raise RuntimeError("Wildcard CORS origin (*) is not allowed in production")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=[
            "Authorization",
            "Content-Type",
            "X-API-Key",
            "X-CSRF-Token",
            "X-Request-Id",
        ],
        expose_headers=["X-Request-Id", "X-CSRF-Token"],
    )

    # Store service metadata
    app.state.service = SERVICE_NAME
    app.state.version = VERSION
    app.state.api_version = API_VERSION
    app.state.instance_id = str(uuid.uuid4())
    app.state.start_time = datetime.now(timezone.utc)

    # Include routers
    app.include_router(admin_router)
    app.include_router(auth_router)
    app.include_router(products_router)

    # Health endpoint
    @app.get("/health")
    async def health(request: Request) -> dict[str, Any]:
        """Health check endpoint."""
        return {
            "status": "ok",
            "service": request.app.state.service,
            "version": request.app.state.version,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "request_id": getattr(request.state, "request_id", None),
        }

    # Version endpoint (public, no auth)
    @app.get("/version")
    async def version(request: Request) -> dict[str, Any]:
        """Version information endpoint."""
        return {
            "service": request.app.state.service,
            "version": request.app.state.version,
            "api_version": request.app.state.api_version,
            "build_commit": os.getenv("AG_BUILD_COMMIT"),
            "build_time": os.getenv("AG_BUILD_TIME"),
        }

    # OpenAPI JSON endpoint (explicit for clarity)
    @app.get("/openapi.json", include_in_schema=False)
    async def openapi_json(request: Request) -> JSONResponse:
        """OpenAPI schema endpoint."""
        return JSONResponse(content=request.app.openapi())

    # Placeholder admin endpoints
    @app.get(
        "/api/v1/tenants",
        dependencies=[Depends(require_scope_dependency(Scope.CONSOLE_ADMIN))],
    )
    async def list_tenants(
        request: Request,
        session: Session = Depends(get_current_session),
    ) -> dict:
        """List tenants (placeholder)."""
        allowed = get_allowed_tenants(session)
        request.state.tenant_id = None
        return {"tenants": sorted(allowed), "total": len(allowed)}

    @app.get(
        "/api/v1/keys",
        dependencies=[Depends(require_scope_dependency(Scope.KEYS_READ))],
    )
    async def list_keys(
        request: Request,
        tenant_id: str | None = None,
        session: Session = Depends(get_current_session),
    ) -> dict:
        """List API keys (placeholder)."""
        validate_tenant_access(session, tenant_id)
        return {"keys": [], "total": 0}

    @app.get(
        "/api/v1/dashboard",
        dependencies=[Depends(require_scope_dependency(Scope.CONSOLE_ADMIN))],
    )
    async def dashboard(
        request: Request,
        tenant_id: str | None = None,
        session: Session = Depends(get_current_session),
    ) -> dict:
        """Dashboard data endpoint (placeholder)."""
        validate_tenant_access(session, tenant_id)
        return {
            "stats": {
                "total_requests": 0,
                "blocked_requests": 0,
                "active_tenants": 0,
                "active_keys": 0,
            },
            "recent_events": [],
        }

    @app.post(
        "/api/v1/products",
        dependencies=[Depends(require_scope_dependency(Scope.PRODUCT_WRITE))],
    )
    async def create_product(
        request: Request,
        payload: LegacyProductCreate,
        session: Session = Depends(get_current_session),
    ) -> dict:
        validate_tenant_access(session, payload.tenant_id, is_write=True)
        return {"status": "created", "tenant_id": payload.tenant_id}

    return app


app = build_app()
