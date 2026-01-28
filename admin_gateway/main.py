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

from admin_gateway.middleware.request_id import RequestIdMiddleware
from admin_gateway.middleware.logging import StructuredLoggingMiddleware
from admin_gateway.middleware.audit import AuditMiddleware
from admin_gateway.middleware.auth import AuthMiddleware
from admin_gateway.audit import AuditLogger
from admin_gateway.routers import auth_router, admin_router

# Version info
SERVICE_NAME = "admin-gateway"
VERSION = "0.2.0"
API_VERSION = "v1"

# Configure structured logging
log = logging.getLogger(SERVICE_NAME)


def _env_bool(name: str, default: bool = False) -> bool:
    """Parse boolean environment variable."""
    v = os.getenv(name)
    if v is None:
        return default
    return str(v).strip().lower() in {"1", "true", "yes", "y", "on"}


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

        # Log auth configuration
        from admin_gateway.auth.config import get_auth_config

        config = get_auth_config()
        log.info(
            "Auth config: env=%s, oidc_enabled=%s, dev_bypass=%s",
            config.env,
            config.oidc_enabled,
            config.dev_bypass_allowed,
        )

        # Validate config
        errors = config.validate()
        if errors:
            for error in errors:
                log.warning("Config validation: %s", error)

        # Initialize audit logger
        app.state.audit_logger = AuditLogger(
            core_base_url=os.getenv("AG_CORE_BASE_URL"),
            enabled=_env_bool("AG_AUDIT_ENABLED", True),
        )

        yield

        log.info("Shutting down %s", SERVICE_NAME)

    app = FastAPI(
        title="FrostGate Admin Gateway",
        description="Administrative API for FrostGate management console",
        version=VERSION,
        lifespan=lifespan,
    )

    # Add middleware (order matters: outermost first)
    # Audit comes after auth so it can see the session
    app.add_middleware(AuditMiddleware)
    app.add_middleware(AuthMiddleware, auto_csrf=True)
    app.add_middleware(StructuredLoggingMiddleware)
    app.add_middleware(RequestIdMiddleware)

    # CORS configuration
    cors_origins = os.getenv("AG_CORS_ORIGINS", "*").split(",")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[o.strip() for o in cors_origins],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["X-Request-Id", "X-CSRF-Token"],
    )

    # Store service metadata
    app.state.service = SERVICE_NAME
    app.state.version = VERSION
    app.state.api_version = API_VERSION
    app.state.instance_id = str(uuid.uuid4())
    app.state.start_time = datetime.now(timezone.utc)

    # Include routers
    app.include_router(auth_router)
    app.include_router(admin_router)

    # Health endpoint (public, no auth)
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

    # Legacy placeholder endpoints (moved to /api/v1 prefix, require auth)
    from admin_gateway.auth import get_current_session, require_scope_dependency, Scope

    @app.get(
        "/api/v1/tenants",
        dependencies=[Depends(require_scope_dependency(Scope.PRODUCT_READ))],
    )
    async def list_tenants_v1(
        request: Request,
        session=Depends(get_current_session),
    ) -> dict[str, Any]:
        """List tenants (placeholder)."""
        await request.app.state.audit_logger.log(
            request_id=getattr(request.state, "request_id", "unknown"),
            action="list_tenants",
            resource="tenants",
            outcome="success",
            actor=session.user_id,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )
        return {"tenants": [], "total": 0}

    @app.get(
        "/api/v1/keys",
        dependencies=[Depends(require_scope_dependency(Scope.KEYS_READ))],
    )
    async def list_keys_v1(
        request: Request,
        session=Depends(get_current_session),
    ) -> dict[str, Any]:
        """List API keys (placeholder)."""
        await request.app.state.audit_logger.log(
            request_id=getattr(request.state, "request_id", "unknown"),
            action="list_keys",
            resource="keys",
            outcome="success",
            actor=session.user_id,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )
        return {"keys": [], "total": 0}

    @app.get("/api/v1/dashboard")
    async def dashboard(
        request: Request,
        session=Depends(get_current_session),
    ) -> dict[str, Any]:
        """Dashboard data endpoint (placeholder)."""
        return {
            "stats": {
                "total_requests": 0,
                "blocked_requests": 0,
                "active_tenants": 0,
                "active_keys": 0,
            },
            "recent_events": [],
        }

    return app


app = build_app()
