"""
CI check: enforce required production env vars.

Uses api.config.required_env as the single source of truth for the
required var list. This script and the runtime startup path must never
drift from each other.

Exit codes:
  0  non-prod env (check skipped) OR prod env with all vars present
  1  prod-like env with one or more required vars missing
"""
# ruff: noqa: E402
from __future__ import annotations

import os
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from api.config.required_env import get_missing_required_env

_PROD_ENVS: frozenset[str] = frozenset({"prod", "production", "staging"})


def is_prod_like() -> bool:
    return (os.getenv("FG_ENV") or "").strip().lower() in _PROD_ENVS


def main() -> int:
    if not is_prod_like():
        print("Skipping prod-check (non-prod environment)")
        return 0

    missing = get_missing_required_env()
    if missing:
        print(f"Missing required env vars: {missing}", file=sys.stderr)
        return 1

    print("prod-check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
