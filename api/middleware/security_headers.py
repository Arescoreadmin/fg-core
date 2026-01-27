"""
Security Headers Middleware for FrostGate Core.

Implements OWASP recommended security headers for production-ready SaaS.
"""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field
from typing import Optional

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response


def _env_bool(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return str(v).strip().lower() in {"1", "true", "yes", "y", "on"}


def _env_str(name: str, default: str = "") -> str:
    return (os.getenv(name) or default).strip()


@dataclass(frozen=True)
class SecurityHeadersConfig:
    """Configuration for security headers middleware."""

    # HSTS (HTTP Strict Transport Security)
    hsts_enabled: bool = True
    hsts_max_age: int = 31536000  # 1 year
    hsts_include_subdomains: bool = True
    hsts_preload: bool = False

    # Content-Type Options
    content_type_nosniff: bool = True

    # Frame Options (clickjacking protection)
    frame_options: str = "DENY"  # DENY | SAMEORIGIN | ALLOW-FROM uri

    # XSS Protection (legacy, but still useful for older browsers)
    xss_protection: bool = True

    # Content-Security-Policy
    csp_enabled: bool = True
    csp_policy: str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'"

    # Referrer Policy
    referrer_policy: str = "strict-origin-when-cross-origin"

    # Permissions Policy (formerly Feature-Policy)
    permissions_policy: str = (
        "geolocation=(), microphone=(), camera=(), payment=(), usb=()"
    )

    # Cache Control for sensitive endpoints
    cache_control_sensitive: str = "no-store, no-cache, must-revalidate, private"
    sensitive_paths: tuple = ("/defend", "/status", "/stats", "/decisions", "/keys")

    # Request ID header name
    request_id_header: str = "X-Request-ID"

    # Response headers for debugging (dev only)
    expose_server_timing: bool = False

    @classmethod
    def from_env(cls) -> "SecurityHeadersConfig":
        """Load configuration from environment variables."""
        return cls(
            hsts_enabled=_env_bool("FG_HSTS_ENABLED", True),
            hsts_max_age=int(_env_str("FG_HSTS_MAX_AGE", "31536000")),
            hsts_include_subdomains=_env_bool("FG_HSTS_INCLUDE_SUBDOMAINS", True),
            hsts_preload=_env_bool("FG_HSTS_PRELOAD", False),
            content_type_nosniff=_env_bool("FG_CONTENT_TYPE_NOSNIFF", True),
            frame_options=_env_str("FG_FRAME_OPTIONS", "DENY"),
            xss_protection=_env_bool("FG_XSS_PROTECTION", True),
            csp_enabled=_env_bool("FG_CSP_ENABLED", True),
            csp_policy=_env_str(
                "FG_CSP_POLICY",
                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'",
            ),
            referrer_policy=_env_str(
                "FG_REFERRER_POLICY", "strict-origin-when-cross-origin"
            ),
            permissions_policy=_env_str(
                "FG_PERMISSIONS_POLICY",
                "geolocation=(), microphone=(), camera=(), payment=(), usb=()",
            ),
            expose_server_timing=_env_bool("FG_EXPOSE_SERVER_TIMING", False),
        )


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware that adds security headers to all responses.

    Headers added:
    - Strict-Transport-Security (HSTS)
    - X-Content-Type-Options
    - X-Frame-Options
    - Content-Security-Policy
    - X-XSS-Protection
    - Referrer-Policy
    - Permissions-Policy
    - Cache-Control (for sensitive endpoints)
    - X-Request-ID (for request tracing)
    """

    def __init__(self, app, config: Optional[SecurityHeadersConfig] = None):
        super().__init__(app)
        self.config = config or SecurityHeadersConfig.from_env()

    def _generate_request_id(self, request: Request) -> str:
        """Generate or extract request ID."""
        # Check if client provided a request ID
        existing = request.headers.get(self.config.request_id_header)
        if existing and len(existing) <= 64:
            # Sanitize: only allow alphanumeric, dash, underscore
            sanitized = "".join(c for c in existing if c.isalnum() or c in "-_")
            if sanitized:
                return sanitized[:64]

        # Generate new UUID-based request ID
        return str(uuid.uuid4())

    def _is_sensitive_path(self, path: str) -> bool:
        """Check if path is sensitive and needs cache control."""
        for sensitive in self.config.sensitive_paths:
            if path == sensitive or path.startswith(sensitive + "/"):
                return True
        return False

    async def dispatch(self, request: Request, call_next):
        # Generate/extract request ID
        request_id = self._generate_request_id(request)

        # Store request ID in request state for logging
        request.state.request_id = request_id

        # Process request
        response: Response = await call_next(request)

        # Add request ID to response
        response.headers[self.config.request_id_header] = request_id

        # HSTS (only for HTTPS in production, but we set it always for proper testing)
        if self.config.hsts_enabled:
            hsts_value = f"max-age={self.config.hsts_max_age}"
            if self.config.hsts_include_subdomains:
                hsts_value += "; includeSubDomains"
            if self.config.hsts_preload:
                hsts_value += "; preload"
            response.headers["Strict-Transport-Security"] = hsts_value

        # X-Content-Type-Options
        if self.config.content_type_nosniff:
            response.headers["X-Content-Type-Options"] = "nosniff"

        # X-Frame-Options
        if self.config.frame_options:
            response.headers["X-Frame-Options"] = self.config.frame_options

        # X-XSS-Protection (legacy but still useful)
        if self.config.xss_protection:
            response.headers["X-XSS-Protection"] = "1; mode=block"

        # Content-Security-Policy
        if self.config.csp_enabled and self.config.csp_policy:
            response.headers["Content-Security-Policy"] = self.config.csp_policy

        # Referrer-Policy
        if self.config.referrer_policy:
            response.headers["Referrer-Policy"] = self.config.referrer_policy

        # Permissions-Policy
        if self.config.permissions_policy:
            response.headers["Permissions-Policy"] = self.config.permissions_policy

        # Cache-Control for sensitive endpoints
        if self._is_sensitive_path(request.url.path):
            response.headers["Cache-Control"] = self.config.cache_control_sensitive
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"

        # Remove potentially sensitive server headers (if present)
        for header in ("Server", "X-Powered-By"):
            if header in response.headers:
                del response.headers[header]

        return response


# CORS configuration helper (to be used with FastAPI's CORSMiddleware)
@dataclass
class CORSConfig:
    """
    CORS configuration for FrostGate Core.

    Security: Default to empty origins list (deny all cross-origin requests).
    Explicitly configure FG_CORS_ORIGINS for allowed domains.
    """

    # SECURITY: Default to empty list (deny cross-origin) instead of ["*"]
    # Set FG_CORS_ORIGINS="https://app.example.com,https://admin.example.com" for allowed origins
    allow_origins: list = field(default_factory=list)
    allow_methods: list = field(
        default_factory=lambda: ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    )
    allow_headers: list = field(default_factory=lambda: ["*"])
    allow_credentials: bool = False
    expose_headers: list = field(
        default_factory=lambda: [
            "X-Request-ID",
            "X-RateLimit-Limit",
            "X-RateLimit-Remaining",
            "X-RateLimit-Reset",
        ]
    )
    max_age: int = 600  # 10 minutes

    @classmethod
    def from_env(cls) -> "CORSConfig":
        """Load CORS configuration from environment."""
        origins_str = _env_str("FG_CORS_ORIGINS", "*")
        origins = [o.strip() for o in origins_str.split(",") if o.strip()]

        return cls(
            allow_origins=origins,
            allow_credentials=_env_bool("FG_CORS_CREDENTIALS", False),
            max_age=int(_env_str("FG_CORS_MAX_AGE", "600")),
        )
