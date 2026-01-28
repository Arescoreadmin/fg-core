"""Admin Gateway - FastAPI Application.

Provides administrative API for FrostGate management console.
"""

from __future__ import annotations

import logging
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from admin_gateway.middleware.request_id import RequestIdMiddleware
from admin_gateway.middleware.logging import StructuredLoggingMiddleware
from admin_gateway.audit import AuditLogger
from admin_gateway.db import init_db, close_db
from admin_gateway.routers import products_router

# Version info
SERVICE_NAME = "admin-gateway"
VERSION = "0.1.0"
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

        # Initialize database
        await init_db()
        log.info("Database initialized")

        # Initialize audit logger
        app.state.audit_logger = AuditLogger(
            core_base_url=os.getenv("AG_CORE_BASE_URL"),
            enabled=_env_bool("AG_AUDIT_ENABLED", True),
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

    # Add middleware (order matters: outermost first)
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
    )

    # Store service metadata
    app.state.service = SERVICE_NAME
    app.state.version = VERSION
    app.state.api_version = API_VERSION
    app.state.instance_id = str(uuid.uuid4())
    app.state.start_time = datetime.now(timezone.utc)

    # Include routers
    app.include_router(products_router)

    # Health endpoint
    @app.get("/health")
    async def health(request: Request) -> dict:
        """Health check endpoint."""
        return {
            "status": "ok",
            "service": request.app.state.service,
            "version": request.app.state.version,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "request_id": getattr(request.state, "request_id", None),
        }

    # Version endpoint
    @app.get("/version")
    async def version(request: Request) -> dict:
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
    async def openapi_json(request: Request) -> Response:
        """OpenAPI schema endpoint."""
        return JSONResponse(content=request.app.openapi())

    # Placeholder admin endpoints
    @app.get("/api/v1/tenants")
    async def list_tenants(request: Request) -> dict:
        """List tenants (placeholder)."""
        # Audit log the action
        await request.app.state.audit_logger.log(
            request_id=getattr(request.state, "request_id", "unknown"),
            action="list_tenants",
            resource="tenants",
            outcome="success",
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )
        return {"tenants": [], "total": 0}

    @app.get("/api/v1/keys")
    async def list_keys(request: Request) -> dict:
        """List API keys (placeholder)."""
        await request.app.state.audit_logger.log(
            request_id=getattr(request.state, "request_id", "unknown"),
            action="list_keys",
            resource="keys",
            outcome="success",
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )
        return {"keys": [], "total": 0}

    @app.get("/api/v1/dashboard")
    async def dashboard(request: Request) -> dict:
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
