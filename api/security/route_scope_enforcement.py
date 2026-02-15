from __future__ import annotations

import logging
import os
from typing import Iterable

from fastapi import FastAPI
from fastapi.routing import APIRoute

log = logging.getLogger("frostgate.security.route_scope")

PUBLIC_ALLOWLIST_EXACT: tuple[str, ...] = (
    "/health",
    "/health/detailed",
    "/health/ready",
    "/health/live",
    "/openapi.json",
    "/docs",
    "/redoc",
    "/status",
    "/v1/status",
    "/stats/debug",
)
PUBLIC_ALLOWLIST_PREFIX: tuple[str, ...] = (
    "/_debug",
    "/static",
)


def _is_prod_or_staging() -> bool:
    env = (os.getenv("FG_ENV") or "").strip().lower()
    return env in {"prod", "production", "staging", "stage"}


def _is_allowlisted(path: str) -> bool:
    if path in PUBLIC_ALLOWLIST_EXACT:
        return True
    return any(path.startswith(prefix) for prefix in PUBLIC_ALLOWLIST_PREFIX)


def _route_has_scope_dependency(route: APIRoute) -> bool:
    dependant = getattr(route, "dependant", None)
    if dependant is None:
        return False

    dependencies: Iterable = getattr(dependant, "dependencies", ())
    for dep in dependencies:
        call = getattr(dep, "call", None)
        if call is not None and getattr(call, "__fg_scope_dependency__", False):
            return True
    return False


def enforce_api_route_scope_invariant(app: FastAPI) -> None:
    missing_scope_paths: list[str] = []
    protected_route_count = 0

    for route in app.router.routes:
        if not isinstance(route, APIRoute):
            continue
        path = str(getattr(route, "path", "") or "")
        if _is_allowlisted(path):
            continue

        protected_route_count += 1
        if not _route_has_scope_dependency(route):
            missing_scope_paths.append(path)

    if missing_scope_paths:
        missing_list = ", ".join(sorted(missing_scope_paths))
        msg = (
            "Route scope invariant failed: missing scope dependency on routes: "
            f"{missing_list}"
        )
        if _is_prod_or_staging():
            raise RuntimeError(msg)
        log.warning(msg)

    if protected_route_count == 0:
        msg = "Route scope invariant vacuous: no protected routes inspected"
        if _is_prod_or_staging():
            raise RuntimeError(msg)
        log.warning(msg)
