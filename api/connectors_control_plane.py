# /home/jcosat/Projects/fg-core/api/connectors_control_plane.py
from __future__ import annotations

import importlib
import logging
import os
import sys
from typing import Optional

from fastapi import APIRouter

log = logging.getLogger("frostgate.connectors")


def _in_pytest() -> bool:
    # PYTEST_CURRENT_TEST is the most reliable signal when running tests.
    return "PYTEST_CURRENT_TEST" in os.environ or "pytest" in sys.modules


def _warn(msg: str) -> None:
    """
    Logging must never be allowed to crash app import.
    Keep messages self-contained (pytest captures msg, not `extra`).
    """
    try:
        log.warning(msg)
    except Exception:
        return


def _import_router(import_path: str, attr: str = "router") -> Optional[APIRouter]:
    """
    Import a router from another module without killing import-time, but:
      - Under pytest: FAIL FAST so we see the real error instead of 404s.
      - In runtime: log loudly and continue; startup validation can enforce.
    """
    try:
        mod = importlib.import_module(import_path)
    except Exception as e:
        msg = f"connectors_router_import_failed import_path={import_path} error={e!r}"
        if _in_pytest():
            raise RuntimeError(msg) from e
        _warn(msg)
        return None

    try:
        r = getattr(mod, attr)
    except Exception as e:
        msg = f"connectors_router_attr_failed import_path={import_path} attr={attr} error={e!r}"
        if _in_pytest():
            raise RuntimeError(msg) from e
        _warn(msg)
        return None

    if not isinstance(r, APIRouter):
        msg = (
            "connectors_router_wrong_type "
            f"import_path={import_path} attr={attr} type={type(r)!r}"
        )
        if _in_pytest():
            raise RuntimeError(msg)
        _warn(msg)
        return None

    return r


# ---------------------------------------------------------------------
# Connectors control-plane router export
# api/main.py includes this router.
# ---------------------------------------------------------------------
router = APIRouter(tags=["connectors-control-plane"])

# Strictly import and include known connector routers.
# If any of these fail under pytest, we raise immediately (no more 404 mystery meat).
_admin_router = _import_router("api.connectors_admin", "router")
_internal_router = _import_router("api.connectors_internal", "router")
_policy_router = _import_router("api.connectors_policy", "router")
_status_router = _import_router("api.connectors_status", "router")

for r in (_admin_router, _internal_router, _policy_router, _status_router):
    if r is not None:
        router.include_router(r)


def assert_connectors_router_wired() -> None:
    """
    Optional: call during startup validation to prevent empty connector surfaces.
    """
    if not getattr(router, "routes", None):
        raise RuntimeError(
            "Connectors control-plane router is empty. "
            "Expected routers: api.connectors_admin/internal/policy/status."
        )
