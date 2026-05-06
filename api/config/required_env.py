"""
Authoritative source of required production environment variables.

Both CI (tools/ci/check_required_env.py) and runtime startup
(api/config/prod_invariants.py -> assert_prod_invariants) enforce this
single list. Do not duplicate it elsewhere.
"""

from __future__ import annotations

import os
from typing import Mapping

_PROD_ENVS: frozenset[str] = frozenset({"prod", "production", "staging"})

# Single authoritative list of env vars required in every prod/staging deployment.
REQUIRED_PROD_ENV_VARS: tuple[str, ...] = (
    "DATABASE_URL",
    "FG_SIGNING_SECRET",
    "FG_INTERNAL_AUTH_SECRET",
    "FG_API_KEY",
    # Revenue + AI provider requirements — must be set before accepting payments
    # or generating AI reports in any prod/staging deployment.
    "STRIPE_SECRET_KEY",
    "STRIPE_WEBHOOK_SECRET",
    "FG_ANTHROPIC_API_KEY",
)


def get_missing_required_env(
    env: Mapping[str, str] | None = None,
) -> list[str]:
    """Return names of required production env vars that are absent, blank, or
    still contain a CHANGE_ME_* placeholder (i.e. never rotated)."""
    e: Mapping[str, str] = env if env is not None else os.environ
    missing: list[str] = []
    for k in REQUIRED_PROD_ENV_VARS:
        v = (e.get(k) or "").strip()
        if not v or v.startswith("CHANGE_ME_"):
            missing.append(k)
    return missing


def enforce_required_env(
    env: Mapping[str, str] | None = None,
) -> None:
    """Raise RuntimeError in prod-like environments when required env vars are missing.

    No-op in dev/test environments — only enforced for FG_ENV in
    {prod, production, staging}.
    """
    e: Mapping[str, str] = env if env is not None else os.environ
    fg_env = (e.get("FG_ENV") or "").strip().lower()
    if fg_env not in _PROD_ENVS:
        return
    missing = get_missing_required_env(e)
    if missing:
        raise RuntimeError(f"Missing required production env vars: {missing}")
