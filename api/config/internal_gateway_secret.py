"""Canonical resolver for the internal gateway secret during the R6 staged migration.

Single authority for precedence order. Import resolve_internal_gateway_secret()
from here; do not inline the fallback chain in individual modules.
"""

from __future__ import annotations

import os

_CANONICAL_ENV = "FG_INTERNAL_GATEWAY_SECRET"

# Legacy names in descending precedence.
# FG_ADMIN_GATEWAY_INTERNAL_TOKEN — Python-side preferred name; present in code
#   and test fixtures but never deployed in Docker or CI (infra never activated it).
# FG_INTERNAL_AUTH_SECRET — the one name actually set in docker-compose, GitHub
#   Actions, and required_env.py; the operational truth until Deploy 2.
# FG_INTERNAL_TOKEN — legacy compat alias; present in code and test fixtures only.
_LEGACY_ENV_ORDER: tuple[str, ...] = (
    "FG_ADMIN_GATEWAY_INTERNAL_TOKEN",
    "FG_INTERNAL_AUTH_SECRET",
    "FG_INTERNAL_TOKEN",
)


def resolve_internal_gateway_secret() -> str:
    """Resolve the internal gateway secret during the staged R6 migration.

    The canonical variable is preferred. Legacy variables remain as fallbacks
    until the infrastructure rotation (Deploy 2) and cleanup (Deploy 3) are done.

    Blank and whitespace-only values are treated as absent.
    """
    value = (os.getenv(_CANONICAL_ENV) or "").strip()
    if value:
        return value

    for name in _LEGACY_ENV_ORDER:
        value = (os.getenv(name) or "").strip()
        if value:
            return value

    return ""
