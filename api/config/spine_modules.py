from __future__ import annotations

import os
from dataclasses import dataclass


def _env_bool(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return str(v).strip().lower() in {"1", "true", "yes", "y", "on"}


@dataclass(frozen=True)
class SpineModules:
    admin_router: object | None
    connection_tracking_middleware: type | None
    get_shutdown_manager: object | None


def load_spine_modules() -> SpineModules:
    admin_enabled = _env_bool("FG_ADMIN_API_ENABLED", False)
    graceful_shutdown_enabled = _env_bool("FG_GRACEFUL_SHUTDOWN_ENABLED", True)

    admin_router = None
    if admin_enabled:
        from api.admin import router as admin_router  # noqa: WPS433 (explicit import)

    if graceful_shutdown_enabled:
        from api.graceful_shutdown import (  # noqa: WPS433 (explicit import)
            ConnectionTrackingMiddleware,
            get_shutdown_manager,
        )
    else:
        ConnectionTrackingMiddleware = None  # type: ignore[assignment]
        get_shutdown_manager = None  # type: ignore[assignment]

    return SpineModules(
        admin_router=admin_router,
        connection_tracking_middleware=ConnectionTrackingMiddleware,
        get_shutdown_manager=get_shutdown_manager,
    )
