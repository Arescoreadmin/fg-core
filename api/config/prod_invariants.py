from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping

from api.config.required_env import enforce_required_env

_PROD_ENVS = {"prod", "production", "staging"}
_TRUE = {"1", "true", "yes", "y", "on"}


@dataclass
class ProdInvariantViolation(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}:{self.message}"


def _env_bool(env: Mapping[str, str], key: str, default: bool = False) -> bool:
    raw = env.get(key)
    if raw is None:
        return default
    return str(raw).strip().lower() in _TRUE


def assert_prod_invariants(settings: Mapping[str, str] | None = None) -> None:
    env = settings or os.environ
    fg_env = (env.get("FG_ENV") or "dev").strip().lower()
    if fg_env not in _PROD_ENVS:
        return

    if not _env_bool(env, "FG_AUTH_ENABLED", True):
        raise ProdInvariantViolation(
            "FG-PROD-001",
            "AUTH_DISABLED_IN_PROD: auth cannot be disabled in production-like environments",
        )

    for flag in ("FG_AUTH_DB_FAIL_OPEN", "FG_RL_FAIL_OPEN", "FG_AUTH_ALLOW_FALLBACK"):
        if _env_bool(env, flag, False):
            raise ProdInvariantViolation(
                "FG-PROD-002", f"{flag} must be false in prod/staging"
            )

    db_url = (env.get("FG_DB_URL") or "").strip()
    if not db_url:
        raise ProdInvariantViolation(
            "FG-PROD-003", "FG_DB_URL is required in prod/staging"
        )
    if db_url.lower().startswith("sqlite"):
        raise ProdInvariantViolation(
            "FG-PROD-004", "sqlite FG_DB_URL is forbidden in prod/staging"
        )

    if (env.get("FG_DB_BACKEND") or "postgres").strip().lower() != "postgres":
        raise ProdInvariantViolation(
            "FG-PROD-005", "FG_DB_BACKEND must be postgres in prod/staging"
        )

    if (env.get("FG_CONTRACT_SPEC") or "").strip():
        raise ProdInvariantViolation(
            "FG-PROD-006",
            "FG_CONTRACT_SPEC must not be set at runtime in prod/staging",
        )

    raw_mode = (env.get("FG_ENFORCEMENT_MODE") or "").strip()
    if not raw_mode:
        raise ProdInvariantViolation(
            "FG-PROD-007",
            "FG_ENFORCEMENT_MODE must be explicitly set to enforce in prod/staging",
        )

    mode = raw_mode.lower()
    if mode != "enforce":
        raise ProdInvariantViolation(
            "FG-PROD-007", "FG_ENFORCEMENT_MODE must be enforce in prod/staging"
        )

    # Admin gateway: dev-auth bypass is forbidden in prod/staging.
    _raw_dev_bypass = (env.get("FG_DEV_AUTH_BYPASS") or "").strip().lower()
    if _raw_dev_bypass in _TRUE:
        raise ProdInvariantViolation(
            "FG-PROD-008",
            "ADMIN_DEV_AUTH_FORBIDDEN_IN_PROD: FG_DEV_AUTH_BYPASS must be disabled in prod/staging",
        )

    # Admin gateway: real OIDC issuer is required in prod/staging.
    # Accept Option A: FG_OIDC_ISSUER is set, non-blank, non-CHANGE_ME.
    # Accept Option B: FG_KEYCLOAK_BASE_URL + FG_KEYCLOAK_REALM are both set,
    #   non-blank, non-CHANGE_ME (admin_gateway derives the issuer from these).
    # Partial Keycloak config (one without the other) must still fail.
    _oidc_issuer = (env.get("FG_OIDC_ISSUER") or "").strip()
    _kc_base = (env.get("FG_KEYCLOAK_BASE_URL") or "").strip()
    _kc_realm = (env.get("FG_KEYCLOAK_REALM") or "").strip()

    _issuer_ok = bool(_oidc_issuer) and not _oidc_issuer.startswith("CHANGE_ME")
    _kc_ok = (
        bool(_kc_base)
        and not _kc_base.startswith("CHANGE_ME")
        and bool(_kc_realm)
        and not _kc_realm.startswith("CHANGE_ME")
    )

    if not _issuer_ok and not _kc_ok:
        raise ProdInvariantViolation(
            "FG-PROD-009",
            "ADMIN_OIDC_CONFIG_REQUIRED: FG_OIDC_ISSUER must be set to a real value in prod/staging"
            " (or provide both FG_KEYCLOAK_BASE_URL and FG_KEYCLOAK_REALM)",
        )

    # Enforce the shared required-env list (single source of truth).
    enforce_required_env(env)
