from __future__ import annotations

PUBLIC_PATHS_EXACT: tuple[str, ...] = (
    "/health",
    "/health/live",
    "/health/ready",
    "/openapi.json",
    "/docs",
    "/redoc",
    "/forensics/chain/verify",
    "/forensics/snapshot",
    "/forensics/audit-trail",
    "/metrics",
    "/status",
    "/v1/status",
    "/stats/debug",
)

PUBLIC_PATHS_PREFIX: tuple[str, ...] = (
    "/health/",
    "/_debug",
    "/missions",
    "/rings",
    "/roe",
    "/_legacy",
    "/ui",
)
