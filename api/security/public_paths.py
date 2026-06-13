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
    "/agent/config",
    "/ingest/assessment/webhooks/stripe",
    # Single-use invite-token exchange: no prior auth exists; token IS the credential.
    # Tenant binding is enforced via tenant_db_required + DB lookup on the token itself.
    "/workforce/users/accept-invite",
    # Public key endpoint — external auditors need this to verify report signatures
    # without possessing the private key.
    "/signing/public-key",
)

PUBLIC_PATHS_PREFIX: tuple[str, ...] = (
    "/health/",
    "/missions",
    "/rings",
    "/roe",
    "/_legacy",
    "/ui",
    "/field-assessment/reports/verify/",
)
