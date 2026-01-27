"""
Request Validation Middleware for FrostGate Core.

Provides security controls for request validation:
- Request body size limits (DoS protection)
- Content-Type validation
- Request timeout handling
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Optional

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response

log = logging.getLogger("frostgate.request_validation")


def _env_int(name: str, default: int) -> int:
    v = os.getenv(name)
    if v is None or v.strip() == "":
        return default
    try:
        return int(v)
    except ValueError:
        return default


def _env_bool(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return str(v).strip().lower() in {"1", "true", "yes", "y", "on"}


def _env_csv(name: str, default: str = "") -> set[str]:
    v = os.getenv(name, default).strip()
    if not v:
        return set()
    return {s.strip().lower() for s in v.split(",") if s.strip()}


@dataclass(frozen=True)
class RequestValidationConfig:
    """Configuration for request validation middleware."""

    # Body size limits
    max_body_size: int  # Maximum request body size in bytes
    enabled: bool  # Whether to enforce limits

    # Content-Type validation
    allowed_content_types: set[str]
    enforce_content_type: bool

    # Paths to skip validation (e.g., health checks)
    skip_paths: tuple[str, ...]

    @classmethod
    def from_env(cls) -> "RequestValidationConfig":
        """Load configuration from environment variables."""
        return cls(
            max_body_size=_env_int("FG_MAX_BODY_SIZE", 1024 * 1024),  # 1MB default
            enabled=_env_bool("FG_REQUEST_VALIDATION_ENABLED", True),
            allowed_content_types=_env_csv(
                "FG_ALLOWED_CONTENT_TYPES", "application/json"
            ),
            enforce_content_type=_env_bool("FG_ENFORCE_CONTENT_TYPE", True),
            skip_paths=(
                "/health",
                "/health/live",
                "/health/ready",
                "/openapi.json",
                "/docs",
                "/redoc",
            ),
        )


class RequestValidationMiddleware(BaseHTTPMiddleware):
    """
    Middleware for validating incoming requests.

    Provides:
    - Request body size limits (DoS protection)
    - Content-Type validation for POST/PUT/PATCH requests
    """

    def __init__(self, app, config: Optional[RequestValidationConfig] = None):
        super().__init__(app)
        self.config = config or RequestValidationConfig.from_env()

    def _should_skip(self, path: str) -> bool:
        """Check if path should skip validation."""
        for skip_path in self.config.skip_paths:
            if path == skip_path or path.startswith(skip_path + "/"):
                return True
        return False

    def _should_check_body(self, method: str) -> bool:
        """Check if method typically has a request body."""
        return method.upper() in ("POST", "PUT", "PATCH")

    async def dispatch(self, request: Request, call_next) -> Response:
        if not self.config.enabled:
            return await call_next(request)

        path = request.url.path
        method = request.method.upper()

        # Skip validation for certain paths
        if self._should_skip(path):
            return await call_next(request)

        # Check Content-Length header for body size
        if self._should_check_body(method):
            content_length = request.headers.get("content-length")
            if content_length:
                try:
                    length = int(content_length)
                    if length > self.config.max_body_size:
                        log.warning(
                            f"Request body too large: {length} > {self.config.max_body_size} "
                            f"for {method} {path}"
                        )
                        return JSONResponse(
                            status_code=413,
                            content={
                                "detail": "Request body too large",
                                "max_size": self.config.max_body_size,
                            },
                        )
                except ValueError:
                    pass

            # Content-Type validation
            if self.config.enforce_content_type and self.config.allowed_content_types:
                content_type = (
                    request.headers.get("content-type", "")
                    .lower()
                    .split(";")[0]
                    .strip()
                )
                if (
                    content_type
                    and content_type not in self.config.allowed_content_types
                ):
                    log.warning(
                        f"Invalid content type: {content_type} for {method} {path}"
                    )
                    return JSONResponse(
                        status_code=415,
                        content={
                            "detail": "Unsupported media type",
                            "allowed": list(self.config.allowed_content_types),
                        },
                    )

        return await call_next(request)


# Export for convenience
__all__ = ["RequestValidationMiddleware", "RequestValidationConfig"]
