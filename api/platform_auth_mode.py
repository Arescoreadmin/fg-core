"""Canonical platform authentication mode resolver for FrostGate Core.

P-113.6.1 — resolves PLATFORM_AUTH_MODE from environment at import time.
This module is the single authority for mode semantics in Core; do not read
PLATFORM_AUTH_MODE directly in other modules.

Modes
-----
COMPATIBILITY (default)
    Path E (admin_internal_token) remains active.  X-API-Key ==
    FG_INTERNAL_GATEWAY_SECRET is recognised as a platform-admin credential on
    /admin/** paths.  Canonical fgk.* credentials are also accepted.

CANONICAL
    Path E is completely disabled as a source of platform.admin authority.
    X-API-Key must carry FG_PLATFORM_ADMIN_KEY (a canonical fgk.* credential).
    X-FG-Internal-Token independently authenticates gateway provenance and is
    enforced by require_internal_admin_gateway().
    The two values MUST be distinct (enforced at startup).

Unknown / malformed values
    Treated as COMPATIBILITY + a one-time WARNING log at import time.
    Never silently escalated to CANONICAL — an operator error must not
    accidentally enable the stricter mode.

Security invariants (not relaxed by this module)
    - Gateway provenance (X-FG-Internal-Token) is always independently enforced
      by require_internal_admin_gateway() regardless of mode.
    - A denied or absent canonical credential never falls through to Path E.
    - FG_PLATFORM_ADMIN_KEY and FG_INTERNAL_GATEWAY_SECRET must be distinct
      in CANONICAL mode (validated at startup via validate_canonical_mode_config()).
"""

from __future__ import annotations

import logging
import os

log = logging.getLogger("frostgate.platform_auth_mode")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MODE_COMPATIBILITY = "COMPATIBILITY"
MODE_CANONICAL = "CANONICAL"
_VALID_MODES = frozenset({MODE_COMPATIBILITY, MODE_CANONICAL})

# ---------------------------------------------------------------------------
# Module-level mode resolution (read env once at import time).
# ---------------------------------------------------------------------------

_raw_env = (os.getenv("PLATFORM_AUTH_MODE") or "").strip().upper()

if not _raw_env or _raw_env == MODE_COMPATIBILITY:
    PLATFORM_AUTH_MODE: str = MODE_COMPATIBILITY
elif _raw_env == MODE_CANONICAL:
    PLATFORM_AUTH_MODE = MODE_CANONICAL
else:
    # Unknown value — fail safe: treat as COMPATIBILITY + log a warning.
    log.warning(
        "platform_auth_mode.unknown_value",
        extra={
            "raw_value": _raw_env[:32],
            "effective_mode": MODE_COMPATIBILITY,
            "action": "treating as COMPATIBILITY; set PLATFORM_AUTH_MODE=CANONICAL or leave unset",
        },
    )
    PLATFORM_AUTH_MODE = MODE_COMPATIBILITY


def is_canonical_mode() -> bool:
    """Return True when PLATFORM_AUTH_MODE=CANONICAL is in effect."""
    return PLATFORM_AUTH_MODE == MODE_CANONICAL


def validate_canonical_mode_config() -> list[str]:
    """Validate configuration required for CANONICAL mode.

    Returns a list of warning/error strings (empty = all ok).
    Called from startup validation; does NOT raise — callers decide severity.

    In CANONICAL mode:
    - FG_PLATFORM_ADMIN_KEY must be set.
    - FG_INTERNAL_GATEWAY_SECRET must be set (checked via resolver).
    - FG_PLATFORM_ADMIN_KEY must differ from FG_INTERNAL_GATEWAY_SECRET.
    """
    if not is_canonical_mode():
        return []

    issues: list[str] = []

    from api.config.internal_gateway_secret import resolve_internal_gateway_secret

    platform_admin_key = (os.getenv("FG_PLATFORM_ADMIN_KEY") or "").strip()
    gateway_secret = resolve_internal_gateway_secret()

    if not platform_admin_key:
        issues.append(
            "PLATFORM_AUTH_MODE=CANONICAL but FG_PLATFORM_ADMIN_KEY is not set. "
            "Platform admin operations will fail. Bootstrap the credential and set FG_PLATFORM_ADMIN_KEY."
        )

    if not gateway_secret:
        issues.append(
            "PLATFORM_AUTH_MODE=CANONICAL but FG_INTERNAL_GATEWAY_SECRET is not set. "
            "Gateway provenance cannot be verified."
        )

    if platform_admin_key and gateway_secret and platform_admin_key == gateway_secret:
        issues.append(
            "PLATFORM_AUTH_MODE=CANONICAL: FG_PLATFORM_ADMIN_KEY and FG_INTERNAL_GATEWAY_SECRET "
            "must be distinct values. Using the same secret for both is a security violation (P-113.6)."
        )

    return issues
