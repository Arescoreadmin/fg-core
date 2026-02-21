from __future__ import annotations


import os
from dataclasses import dataclass
from typing import Callable, Optional

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response
from starlette.routing import Match

from api.auth_scopes import (
    _extract_key,
    log_tenant_denial_event,
    redact_detail,
    verify_api_key_detailed,
)
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
    if fail_open in {"1", "true", "yes", "on", "y"}:
        raise RuntimeError("FG_AUTH_DB_FAIL_OPEN=true")
    if not db_url:
        raise RuntimeError("FG_DB_URL missing")
    if db_url.lower().startswith("sqlite"):
        raise RuntimeError("sqlite FG_DB_URL forbidden")


def _route_is_registered(request: Request) -> bool:
    scope = dict(request.scope)
    for route in request.app.router.routes:
        try:
            match, _ = route.matches(scope)
        except Exception:
            continue
        if match == Match.FULL:
            return True
    return False


@dataclass(frozen=True)
class AuthGateConfig:
    public_paths_exact: tuple[str, ...] = PUBLIC_PATHS_EXACT
    public_paths_prefix: tuple[str, ...] = PUBLIC_PATHS_PREFIX
    header_authgate: str = "x-fg-authgate"
    header_gate: str = "x-fg-gate"
    header_path: str = "x-fg-path"
    # FG-AUD-014: removed dead `public_paths` property — _is_public() uses
    # public_paths_exact and public_paths_prefix fields only. The property
    # was never called and listed a stale, diverged set of paths.


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

        if not _route_is_registered(request):
            # FG-AUD-006: Previously this passed unregistered routes through without
            # authentication (fail-open).  FastAPI will return 404 for unknown paths,
            # but if any middleware further down the stack intercepts the request the
            # auth gate would have been bypassed.  Now we apply the same auth check
            # for unregistered routes so the gate is always fail-closed.
            # The 404 from FastAPI is still returned; we just ensure a valid key is
            # presented first (prevents auth-bypass for misconfigured routers).
            got = _extract_key(request, request.headers.get("X-API-Key"))
            if not got:
                return self._stamp(
                    JSONResponse(
                        status_code=401,
                        content={"detail": "Invalid or missing API key"},
                    ),
                    request,
                    "denied_missing_key_unmatched",
                )
            result = verify_api_key_detailed(raw=got, request=request)
            if not result.valid:
                return self._stamp(
                    JSONResponse(
                        status_code=401,
                        content={"detail": "Invalid or missing API key"},
                    ),
                    request,
                    "denied_invalid_key_unmatched",
                )
            request.state.auth = result
            request.state.tenant_id = result.tenant_id
            request.state.tenant_is_key_bound = bool(result.tenant_id)
            resp = await call_next(request)
            return self._stamp(resp, request, "unmatched_authed")

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

        required_scopes = _required_scopes(path)
        scopes = set(result.scopes or set())
        if (
            required_scopes
            and result.reason != "global_key"
            and not required_scopes.issubset(scopes)
        ):
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
            log_tenant_denial_event(
                request=request,
                reason="header_tenant_mismatch",
                tenant_from_key=getattr(result, "tenant_id", None),
                tenant_supplied=requested_tenant,
                key_id=getattr(result, "key_prefix", None),
            )
            return self._stamp(
                JSONResponse(
                    status_code=403,
                    content={
                        "detail": redact_detail("tenant mismatch", generic="forbidden")
                    },
                ),
                request,
                "denied_tenant",
            )

        request.state.auth = result
        request.state.tenant_id = result.tenant_id
        request.state.tenant_is_key_bound = bool(result.tenant_id)

        resp = await call_next(request)
        return self._stamp(resp, request, "protected")
