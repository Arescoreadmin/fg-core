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
    "/agent/enroll",
    "/agent/heartbeat",
    "/agent/key/rotate",
    "/agent/cert/enroll",
    "/agent/cert/renew",
    "/agent/cert/status",
    "/agent/update/manifest",
    "/agent/update/report",
    "/agent/commands/poll",
    "/agent/commands/ack",
    "/agent/policy/fetch",
    "/agent/log/anchor",
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
