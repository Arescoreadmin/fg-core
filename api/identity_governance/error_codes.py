"""api/identity_governance/error_codes.py — Machine-readable identity error codes.

Every error returned by an identity-runtime code path MUST use one of these
codes in the ``code`` field of the JSON error body. Downstream systems
(portal, admin UI, external assessors) key off these values.

Rules:
    - Every enum value MUST equal its member name.
    - Nothing PII, secret, or tenant-specific may leak into the ``code``
      or ``message`` fields at any callsite; keep messages generic.
    - Adding a new code requires updating :data:`IDENTITY_ERROR_MESSAGES`
      and any downstream consumer (portal error UI, SDK error types).
"""

from __future__ import annotations

from enum import Enum


class IdentityErrorCode(str, Enum):
    """Canonical machine-readable identity error codes."""

    # Lifecycle
    IDENTITY_SUSPENDED = "IDENTITY_SUSPENDED"
    IDENTITY_DISABLED = "IDENTITY_DISABLED"
    IDENTITY_ARCHIVED = "IDENTITY_ARCHIVED"
    IDENTITY_DELETED = "IDENTITY_DELETED"

    # Session
    SESSION_EXPIRED = "SESSION_EXPIRED"
    SESSION_REVOKED = "SESSION_REVOKED"

    # Device
    DEVICE_REVOKED = "DEVICE_REVOKED"
    DEVICE_COMPROMISED = "DEVICE_COMPROMISED"

    # Authentication step-up
    MFA_STEP_UP_REQUIRED = "MFA_STEP_UP_REQUIRED"

    # Authorization
    POLICY_DENIED = "POLICY_DENIED"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    CAPABILITY_DENIED = "CAPABILITY_DENIED"
    AUTHORIZATION_DENIED = "AUTHORIZATION_DENIED"

    # Tenancy
    TENANT_MISMATCH = "TENANT_MISMATCH"

    # Break-glass
    BREAK_GLASS_REQUIRED = "BREAK_GLASS_REQUIRED"
    BREAK_GLASS_EXPIRED = "BREAK_GLASS_EXPIRED"

    # Governance runtime infrastructure
    GOVERNANCE_UNAVAILABLE = "GOVERNANCE_UNAVAILABLE"


# ---------------------------------------------------------------------------
# Safe, generic user-facing messages per code.
# NOTE: never include tenant IDs, subject IDs, emails, policy rule text,
# device fingerprints, or any other detail beyond what the caller already
# has. The client already knows which request it made.
# ---------------------------------------------------------------------------

IDENTITY_ERROR_MESSAGES: dict[IdentityErrorCode, str] = {
    IdentityErrorCode.IDENTITY_SUSPENDED: "Identity is suspended.",
    IdentityErrorCode.IDENTITY_DISABLED: "Identity is disabled.",
    IdentityErrorCode.IDENTITY_ARCHIVED: "Identity has been archived.",
    IdentityErrorCode.IDENTITY_DELETED: "Identity is no longer valid.",
    IdentityErrorCode.SESSION_EXPIRED: "Session has expired.",
    IdentityErrorCode.SESSION_REVOKED: "Session has been revoked.",
    IdentityErrorCode.DEVICE_REVOKED: "Device trust revoked.",
    IdentityErrorCode.DEVICE_COMPROMISED: "Device flagged; step-up required.",
    IdentityErrorCode.MFA_STEP_UP_REQUIRED: "Multi-factor step-up required.",
    IdentityErrorCode.POLICY_DENIED: "Access denied by conditional access policy.",
    IdentityErrorCode.PERMISSION_DENIED: "Missing required permission.",
    IdentityErrorCode.CAPABILITY_DENIED: "Missing required capability.",
    IdentityErrorCode.AUTHORIZATION_DENIED: "Authorization denied.",
    IdentityErrorCode.TENANT_MISMATCH: "Tenant context mismatch.",
    IdentityErrorCode.BREAK_GLASS_REQUIRED: "Break-glass authorization required.",
    IdentityErrorCode.BREAK_GLASS_EXPIRED: "Break-glass authorization expired.",
    IdentityErrorCode.GOVERNANCE_UNAVAILABLE: "Governance evaluation unavailable.",
}


def error_body(code: IdentityErrorCode, *, reason: str | None = None) -> dict[str, str]:
    """Return the standard JSON error body for an identity error.

    ``reason`` is optional and used only for callable-safe classification
    like ``"identity_state"`` or ``"session_revocation"`` — never PII.
    """
    body: dict[str, str] = {
        "code": code.value,
        "message": IDENTITY_ERROR_MESSAGES[code],
    }
    if reason:
        body["reason"] = reason
    return body


__all__ = [
    "IDENTITY_ERROR_MESSAGES",
    "IdentityErrorCode",
    "error_body",
]
