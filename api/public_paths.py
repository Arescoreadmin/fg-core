from __future__ import annotations

BASE_PUBLIC_PATH_PREFIXES: tuple[str, ...] = (
    "/health",
    "/health/live",
    "/health/ready",
    "/openapi.json",
    "/docs",
    "/redoc",
    "/forensics/chain/verify",
    "/forensics/snapshot",
    "/forensics/audit-trail",
)

DEV_UI_PUBLIC_PATH_PREFIXES: tuple[str, ...] = (
    "/ui",
    "/ui/token",
)

# Static-analysis checker exemptions for intentionally public or legacy endpoints.
LINTER_PUBLIC_PATH_PREFIXES: tuple[str, ...] = (
    "/health",
    "/metrics",
    "/_debug",
    "/ui",
    "/status",
    "/v1/status",
    "/stats/debug",
    "/missions",
    "/rings",
    "/roe",
    "/_legacy",
)


def resolve_public_paths(*, include_ui_dev_routes: bool) -> tuple[str, ...]:
    paths = list(BASE_PUBLIC_PATH_PREFIXES)
    if include_ui_dev_routes:
        paths.extend(DEV_UI_PUBLIC_PATH_PREFIXES)
    return tuple(paths)
