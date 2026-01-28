"""Admin Gateway - FastAPI Application.

Provides administrative API for FrostGate management console.
"""

from __future__ import annotations

import logging
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, Field

from admin_gateway.auth import (
    AuthUser,
    build_login_redirect,
    build_user_from_claims,
    dev_bypass_enabled,
    ensure_csrf_token,
    environment,
    exchange_code_for_tokens,
    get_allowed_tenant,
    get_current_user,
    require_oidc_env,
    require_scopes,
    require_session_secret,
    session_max_age,
    verify_id_token,
)
from admin_gateway.middleware.request_id import RequestIdMiddleware
from admin_gateway.middleware.logging import StructuredLoggingMiddleware
from admin_gateway.middleware.audit import AuditMiddleware
from admin_gateway.middleware.auth_context import AuthContextMiddleware
from admin_gateway.middleware.csrf import CSRFMiddleware
from admin_gateway.audit import AuditLogger


class ProductCreate(BaseModel):
    tenant_id: str = Field(..., description="Tenant identifier")
    name: str | None = Field(default=None, description="Product name")

# Version info
SERVICE_NAME = "admin-gateway"
VERSION = "0.1.0"
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

        # Initialize audit logger
        app.state.audit_logger = AuditLogger(
            core_base_url=os.getenv("AG_CORE_BASE_URL"),
            enabled=os.getenv("AG_AUDIT_ENABLED", "1").lower() not in {"0", "false", "no"},
        )

        yield

        log.info("Shutting down %s", SERVICE_NAME)

    app = FastAPI(
        title="FrostGate Admin Gateway",
        description="Administrative API for FrostGate management console",
        version=VERSION,
        lifespan=lifespan,
    )

    if environment() == "prod" and dev_bypass_enabled():
        raise RuntimeError("FG_DEV_AUTH_BYPASS cannot be enabled in production.")
    require_oidc_env()

    if os.getenv("FG_CONTRACTS_GEN") != "1":
        from starlette.middleware.sessions import SessionMiddleware

        session_secret = require_session_secret()
        app.add_middleware(
            SessionMiddleware,
            secret_key=session_secret,
            max_age=session_max_age(),
            same_site="strict",
            https_only=environment() == "prod",
            httponly=True,
        )

    # Add middleware (order matters: outermost first)
    app.add_middleware(StructuredLoggingMiddleware)
    app.add_middleware(RequestIdMiddleware)
    app.add_middleware(AuthContextMiddleware)
    app.add_middleware(AuditMiddleware)
    app.add_middleware(CSRFMiddleware)

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

    @app.get("/auth/login")
    async def auth_login(request: Request) -> Response:
        """Redirect to OIDC provider for login."""
        url = await build_login_redirect(request)
        return RedirectResponse(url=url)

    @app.get("/auth/callback")
    async def auth_callback(request: Request, code: str, state: str) -> Response:
        """Handle OIDC callback and establish session."""
        if state != request.session.get("oidc_state"):
            return JSONResponse(status_code=400, content={"detail": "Invalid state"})
        tokens = await exchange_code_for_tokens(code)
        id_token = tokens.get("id_token")
        if not id_token:
            return JSONResponse(status_code=400, content={"detail": "Missing id_token"})
        claims = await verify_id_token(id_token, request.session.get("oidc_nonce"))
        user = build_user_from_claims(claims, tokens.get("scope"))
        request.session.pop("oidc_state", None)
        request.session.pop("oidc_nonce", None)
        request.session["user"] = {
            "sub": user.sub,
            "email": user.email,
            "scopes": user.scopes,
            "tenants": user.tenants,
            "exp": user.exp,
        }
        return JSONResponse(content={"status": "ok"})

    @app.get("/auth/csrf")
    async def auth_csrf(request: Request) -> dict:
        """Return a CSRF token tied to the session."""
        return {"csrf_token": ensure_csrf_token(request)}

    @app.get("/admin/me")
    async def admin_me(user: AuthUser = Depends(get_current_user)) -> dict:
        """Return current admin session details."""
        return {
            "id": user.sub,
            "email": user.email,
            "scopes": user.scopes,
            "tenants": user.tenants,
            "session_expires_at": user.exp,
        }

    # Placeholder admin endpoints
    @app.get("/api/v1/tenants")
    async def list_tenants(
        request: Request,
        user: AuthUser = Depends(require_scopes(["console:admin"])),
    ) -> dict:
        """List tenants (placeholder)."""
        request.state.tenant_id = None
        return {"tenants": user.tenants, "total": len(user.tenants)}

    @app.get("/api/v1/keys")
    async def list_keys(
        request: Request,
        tenant_id: str | None = None,
        user: AuthUser = Depends(require_scopes(["keys:read"])),
    ) -> dict:
        """List API keys (placeholder)."""
        get_allowed_tenant(request, tenant_id, user)
        return {"keys": [], "total": 0}

    @app.get("/api/v1/dashboard")
    async def dashboard(
        request: Request,
        tenant_id: str | None = None,
        user: AuthUser = Depends(require_scopes(["console:admin"])),
    ) -> dict:
        """Dashboard data endpoint (placeholder)."""
        get_allowed_tenant(request, tenant_id, user)
        return {
            "stats": {
                "total_requests": 0,
                "blocked_requests": 0,
                "active_tenants": 0,
                "active_keys": 0,
            },
            "recent_events": [],
        }

    @app.post("/api/v1/products")
    async def create_product(
        request: Request,
        payload: ProductCreate,
        user: AuthUser = Depends(require_scopes(["product:write"])),
    ) -> dict:
        get_allowed_tenant(request, payload.tenant_id, user)
        return {"status": "created", "tenant_id": payload.tenant_id}

    return app


app = build_app()
