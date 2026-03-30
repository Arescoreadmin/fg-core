"""
SignedContextGateMiddleware — enforce cryptographically signed gateway-to-core
internal context on all protected (non-public) routes.

Enabled when (evaluated once at middleware init / app-build time):
  - FG_ENV is prod / production / staging, OR
  - FG_GATEWAY_SIGNED_CONTEXT_REQUIRED=1

Enforcement state is snapshotted at __init__ time, NOT re-evaluated per request.
This ensures that tests which monkeypatch FG_ENV after build_app() do not
inadvertently activate enforcement.

Required env (when enforcement is active):
  - FG_GATEWAY_SIGNING_SECRET  (RuntimeError at middleware-stack build time if absent)

Header expected:  X-FG-Signed-Context   (value produced by sign_context())

On success:
  - request.state.signed_ctx        = SignedContextPayload
  - request.state.tenant_id         = ctx.tenant_id   (authoritative)
  - request.state.tenant_is_key_bound = True
  - request.state.request_id        = ctx.request_id  (if not already set)

On failure:
  - 401  missing / invalid / tampered / expired signed context
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Optional

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response

from api.security.public_paths import PUBLIC_PATHS_EXACT, PUBLIC_PATHS_PREFIX
from api.security.signed_context import (
    HEADER_NAME,
    SignedContextError,
    get_signing_secret,
    verify_signed_context,
)

log = logging.getLogger("frostgate.security")


def _is_enforcement_active() -> bool:
    """
    Signed-context enforcement is active in production/staging OR when
    explicitly enabled via FG_GATEWAY_SIGNED_CONTEXT_REQUIRED=1.

    Used by the middleware at init time and by unit tests directly.
    """
    env = (os.getenv("FG_ENV") or "").strip().lower()
    if env in {"prod", "production", "staging"}:
        return True
    v = (os.getenv("FG_GATEWAY_SIGNED_CONTEXT_REQUIRED") or "").strip().lower()
    return v in {"1", "true", "yes", "y", "on"}


def _is_public(path: str) -> bool:
    if path in PUBLIC_PATHS_EXACT:
        return True
    return any(path.startswith(prefix) for prefix in PUBLIC_PATHS_PREFIX)


@dataclass(frozen=True)
class SignedContextGateConfig:
    max_age_seconds: int = 60


class SignedContextGateMiddleware(BaseHTTPMiddleware):
    """
    Enforce signed gateway context on all non-public protected routes.

    Enforcement state and signing secret are snapshotted at __init__ time so that
    post-build environment changes (e.g. test monkeypatching) do not affect
    an already-constructed app's enforcement posture.

    When enforcement is NOT active (dev/test without explicit flag), the
    middleware is a pass-through so existing tests are unaffected.
    """

    def __init__(
        self,
        app,
        config: Optional[SignedContextGateConfig] = None,
        enforcement_active: Optional[bool] = None,
    ) -> None:
        super().__init__(app)
        self.config = config or SignedContextGateConfig()

        # Use caller-supplied value when available (passed from build_app() at
        # add_middleware() time, before Starlette's lazy stack construction).
        # Fall back to env read when instantiated directly (e.g. in tests).
        self._enforcement_active: bool = (
            enforcement_active if enforcement_active is not None else _is_enforcement_active()
        )

        if self._enforcement_active:
            secret = get_signing_secret()
            if not secret:
                raise RuntimeError(
                    "SignedContextGateMiddleware: FG_GATEWAY_SIGNING_SECRET is required "
                    "when signed-context enforcement is active "
                    "(FG_ENV=prod/staging or FG_GATEWAY_SIGNED_CONTEXT_REQUIRED=1)"
                )
            self._secret: str = secret
        else:
            self._secret = ""

    async def dispatch(self, request: Request, call_next) -> Response:
        if not self._enforcement_active:
            return await call_next(request)

        path = request.url.path
        if _is_public(path):
            return await call_next(request)

        header_val = (request.headers.get(HEADER_NAME) or "").strip()

        if not header_val:
            log.warning(
                "signed_context_missing",
                extra={"path": path, "method": request.method},
            )
            return JSONResponse(
                status_code=401,
                content={"detail": "signed_context_required"},
            )

        try:
            ctx = verify_signed_context(
                header_val, self._secret, self.config.max_age_seconds
            )
        except SignedContextError as exc:
            log.warning(
                "signed_context_rejected",
                extra={"reason": exc.reason, "path": path, "method": request.method},
            )
            return JSONResponse(
                status_code=401,
                content={"detail": f"signed_context_invalid:{exc.reason}"},
            )

        # Propagate verified trust fields — these are now authoritative.
        request.state.signed_ctx = ctx
        request.state.tenant_id = ctx.tenant_id
        request.state.tenant_is_key_bound = True
        # Only set request_id if not already assigned by SecurityHeadersMiddleware.
        if not getattr(request.state, "request_id", None):
            request.state.request_id = ctx.request_id

        return await call_next(request)
