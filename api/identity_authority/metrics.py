"""api/identity_authority/metrics.py — Prometheus metrics for the Identity Authority."""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram

# ---------------------------------------------------------------------------
# Authentication metrics
# ---------------------------------------------------------------------------

AUTH_SUCCESS_TOTAL = Counter(
    "frostgate_identity_auth_success_total",
    "Successful authentications",
    ["provider", "identity_type"],
)

AUTH_FAILED_TOTAL = Counter(
    "frostgate_identity_auth_failed_total",
    "Failed authentications",
    ["provider", "reason"],
)

AUTH_LATENCY = Histogram(
    "frostgate_identity_auth_latency_seconds",
    "End-to-end authentication latency",
    ["provider"],
    buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5),
)

# ---------------------------------------------------------------------------
# Session metrics
# ---------------------------------------------------------------------------

ACTIVE_SESSIONS = Gauge(
    "frostgate_identity_active_sessions_total",
    "Estimated active sessions (non-revoked, non-expired)",
    ["provider"],
)

SESSION_CREATED_TOTAL = Counter(
    "frostgate_identity_session_created_total",
    "Sessions created",
    ["provider", "identity_type"],
)

SESSION_REVOKED_TOTAL = Counter(
    "frostgate_identity_session_revoked_total",
    "Sessions revoked",
    ["reason"],
)

SESSION_REFRESHED_TOTAL = Counter(
    "frostgate_identity_session_refreshed_total",
    "Session refresh rotations",
    ["provider"],
)

SESSION_EXPIRED_TOTAL = Counter(
    "frostgate_identity_session_expired_total",
    "Sessions that expired naturally",
    ["reason"],  # "absolute" | "idle"
)

# ---------------------------------------------------------------------------
# MFA metrics
# ---------------------------------------------------------------------------

MFA_VERIFIED_TOTAL = Counter(
    "frostgate_identity_mfa_verified_total",
    "Requests with verified MFA",
    ["method", "provider"],
)

MFA_MISSING_TOTAL = Counter(
    "frostgate_identity_mfa_missing_total",
    "Requests missing required MFA",
    ["provider"],
)

# ---------------------------------------------------------------------------
# Provider metrics
# ---------------------------------------------------------------------------

PROVIDER_USAGE = Counter(
    "frostgate_identity_provider_usage_total",
    "Authentication requests per provider",
    ["provider"],
)

OIDC_FAILURES = Counter(
    "frostgate_identity_oidc_failures_total",
    "OIDC validation failures",
    ["provider", "reason"],
)

JWKS_REFRESH_TOTAL = Counter(
    "frostgate_identity_jwks_refresh_total",
    "JWKS cache refreshes",
    ["provider"],
)

# ---------------------------------------------------------------------------
# Tenant resolution metrics
# ---------------------------------------------------------------------------

TENANT_RESOLUTION_LATENCY = Histogram(
    "frostgate_identity_tenant_resolution_seconds",
    "Tenant resolution latency",
    ["result"],  # "resolved" | "not_found" | "error"
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25),
)

TENANT_RESOLUTION_TOTAL = Counter(
    "frostgate_identity_tenant_resolution_total",
    "Tenant resolution outcomes",
    ["result"],
)

# ---------------------------------------------------------------------------
# Migration metrics
# ---------------------------------------------------------------------------

LEGACY_MIGRATION_TOTAL = Counter(
    "frostgate_identity_legacy_migration_total",
    "Legacy session migrations",
    ["result"],  # "success" | "invalid" | "error"
)
