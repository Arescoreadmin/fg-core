from __future__ import annotations


import os
from dataclasses import dataclass
from typing import Callable, Optional

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response

from api.auth_scopes import _extract_key, verify_api_key_detailed
from api.security.public_paths import PUBLIC_PATHS_EXACT, PUBLIC_PATHS_PREFIX

ROUTE_SCOPE_PREFIX: dict[str, tuple[str, ...]] = {
    "/stats": ("stats:read",),
}


def _required_scopes(path: str) -> set[str]:
    for prefix, scopes in ROUTE_SCOPE_PREFIX.items():
        if path == prefix or path.startswith(prefix.rstrip("/") + "/"):
            return set(scopes)
    return set()


def _is_production_like() -> bool:
    return (os.getenv("FG_ENV") or "").strip().lower() in {
        "prod",
        "production",
        "staging",
    }


def _assert_runtime_invariants() -> None:
    if not _is_production_like():
        return
    fail_open = (os.getenv("FG_AUTH_DB_FAIL_OPEN") or "").strip().lower()
    db_url = (os.getenv("FG_DB_URL") or "").strip()
    global_key = (os.getenv("FG_API_KEY") or "").strip()
    if fail_open in {"1", "true", "yes", "on", "y"}:
        raise RuntimeError("FG_AUTH_DB_FAIL_OPEN=true")
    if not db_url:
        raise RuntimeError("FG_DB_URL missing")
    if db_url.lower().startswith("sqlite"):
        raise RuntimeError("sqlite FG_DB_URL forbidden")
    if global_key:
        raise RuntimeError("FG_API_KEY fallback forbidden")


@dataclass(frozen=True)
class AuthGateConfig:
    public_paths_exact: tuple[str, ...] = PUBLIC_PATHS_EXACT
    public_paths_prefix: tuple[str, ...] = PUBLIC_PATHS_PREFIX
    header_authgate: str = "x-fg-authgate"
    header_gate: str = "x-fg-gate"
    header_path: str = "x-fg-path"

    @property
    def public_paths(self) -> tuple[str, ...]:
        return (
            "/health",
            "/health/live",
            "/health/ready",
            "/ui",
            "/ui/token",
            "/openapi.json",
            "/docs",
            "/redoc",
        )


def _is_public(path: str, config: AuthGateConfig) -> bool:
    if path in config.public_paths_exact:
        return True
    return any(path.startswith(prefix) for prefix in config.public_paths_prefix)


class AuthGateMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        require_status_auth: Callable[[Request], None],
        config: Optional[AuthGateConfig] = None,
    ):
        super().__init__(app)
        self._ignored_require_status_auth = require_status_auth
        self.config = config or AuthGateConfig()

    def _stamp(self, resp: Response, request: Request, gate: str) -> Response:
        resp.headers[self.config.header_authgate] = "1"
        resp.headers[self.config.header_gate] = gate
        resp.headers[self.config.header_path] = request.url.path
        return resp

    async def dispatch(self, request: Request, call_next):
        _assert_runtime_invariants()
        path = request.url.path

        if not bool(getattr(request.app.state, "auth_enabled", True)):
            resp = await call_next(request)
            return self._stamp(resp, request, "auth_disabled")

        if _is_public(path, self.config):
            resp = await call_next(request)
            return self._stamp(resp, request, "public")

        got = _extract_key(request, request.headers.get("X-API-Key"))
        if not got:
            return self._stamp(
                JSONResponse(
                    status_code=401,
                    content={"detail": "Invalid or missing API key"},
                ),
                request,
                "denied_missing_key",
            )

        result = verify_api_key_detailed(raw=got, request=request)
        if not result.valid:
            return self._stamp(
                JSONResponse(
                    status_code=401,
                    content={"detail": "Invalid or missing API key"},
                ),
                request,
                "denied_invalid_key",
            )

        scopes = set(result.scopes or set())
        if not scopes:
            return self._stamp(
                JSONResponse(
                    status_code=401, content={"detail": "missing_scope_claim"}
                ),
                request,
                "denied_missing_scope",
            )

        required_scopes = _required_scopes(path)
        if required_scopes and not required_scopes.issubset(scopes):
            return self._stamp(
                JSONResponse(status_code=403, content={"detail": "insufficient_scope"}),
                request,
                "denied_scope",
            )

        requested_tenant = (request.headers.get("X-Tenant-Id") or "").strip()
        if (
            result.tenant_id
            and requested_tenant
            and requested_tenant != result.tenant_id
        ):
            return self._stamp(
                JSONResponse(status_code=403, content={"detail": "Tenant mismatch"}),
                request,
                "denied_tenant",
            )

        request.state.auth = result
        request.state.tenant_id = result.tenant_id or requested_tenant or "unknown"

        resp = await call_next(request)
        return self._stamp(resp, request, "protected")
