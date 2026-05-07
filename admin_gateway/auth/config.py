"""Authentication configuration.

Handles OIDC configuration and environment-based settings.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Optional

_TRUE = {"1", "true", "yes", "y", "on"}


def _env_bool(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return str(v).strip().lower() in _TRUE


def _env_int(name: str, default: int) -> int:
    v = os.getenv(name)
    if v is None:
        return default
    try:
        return int(v)
    except ValueError:
        return default


@dataclass(frozen=True)
class AuthConfig:
    """Authentication configuration from environment variables.

    Environment Variables:
        FG_OIDC_ISSUER: OIDC issuer URL
        FG_OIDC_CLIENT_ID: OAuth client ID
        FG_OIDC_CLIENT_SECRET: OAuth client secret
        FG_OIDC_REDIRECT_URL: OAuth callback URL
        FG_OIDC_SCOPES: Space-separated OIDC scopes (required in production)
        FG_ENV: Environment (prod/staging/dev/test)
        FG_DEV_AUTH_BYPASS: Enable dev auth bypass (dev/test only)
        FG_DEV_TENANT_ID: Tenant id to mint in dev bypass session (default: default)
        FG_DEV_ALLOWED_TENANTS: CSV allowed tenants for dev bypass session (default: FG_DEV_TENANT_ID)
        FG_SESSION_SECRET: Secret for signing session cookies
        FG_SESSION_COOKIE_NAME: Session cookie name (default: fg_admin_session)
        FG_SESSION_TTL_SECONDS: Session TTL in seconds (default: 28800 = 8 hours)
    """

    oidc_issuer: Optional[str] = None
    oidc_client_id: Optional[str] = None
    oidc_client_secret: Optional[str] = None
    oidc_redirect_url: Optional[str] = None
    oidc_scopes: Optional[str] = None

    env: str = "dev"
    dev_auth_bypass: bool = False

    # Dev-bypass tenant controls (dev/test only)
    dev_tenant_id: str = "default"
    dev_allowed_tenants: list[str] = field(default_factory=list)
    session_secret: str = field(default_factory=lambda: os.urandom(32).hex())
    session_cookie_name: str = "fg_admin_session"
    session_ttl_seconds: int = 28800

    csrf_cookie_name: str = "fg_csrf_token"
    csrf_header_name: str = "X-CSRF-Token"

    @property
    def env_lower(self) -> str:
        return (self.env or "dev").strip().lower()

    @property
    def is_prod(self) -> bool:
        return self.env_lower in ("prod", "production")

    @property
    def is_prod_like(self) -> bool:
        return self.env_lower in ("prod", "production", "staging")

    @property
    def is_dev(self) -> bool:
        return self.env_lower in ("dev", "development", "local")

    @property
    def is_test(self) -> bool:
        return self.env_lower == "test"

    @property
    def oidc_enabled(self) -> bool:
        return bool(
            self.oidc_issuer
            and self.oidc_client_id
            and self.oidc_client_secret
            and self.oidc_redirect_url
        )

    @property
    def dev_bypass_allowed(self) -> bool:
        # Allowed only outside prod-like envs.
        return (not self.is_prod_like) and bool(self.dev_auth_bypass)

    def validate(self) -> list[str]:
        errors: list[str] = []

        valid_envs = {
            "prod",
            "production",
            "staging",
            "dev",
            "development",
            "local",
            "test",
        }
        if self.env_lower not in valid_envs:
            errors.append(
                f"Invalid FG_ENV='{self.env}'. Valid values: {', '.join(sorted(valid_envs))}."
            )

        if self.is_prod_like and self.dev_auth_bypass:
            errors.append(
                "ADMIN_DEV_AUTH_FORBIDDEN_IN_PROD: "
                "FG_DEV_AUTH_BYPASS cannot be enabled in production/staging"
            )

        if self.is_prod_like and not self.oidc_enabled:
            errors.append(
                "ADMIN_OIDC_CONFIG_REQUIRED: "
                "OIDC must be fully configured in production/staging"
            )

        if self.is_prod_like and not self.oidc_scopes:
            errors.append(
                "ADMIN_OIDC_CONFIG_REQUIRED: "
                "FG_OIDC_SCOPES is required in production/staging"
            )

        # Reject CHANGE_ME placeholder values for OIDC issuer in prod-like envs.
        _change_me = "CHANGE_ME"
        if (
            self.is_prod_like
            and self.oidc_issuer
            and self.oidc_issuer.startswith(_change_me)
        ):
            errors.append(
                "ADMIN_OIDC_CONFIG_REQUIRED: "
                "FG_OIDC_ISSUER must not be a CHANGE_ME placeholder in production/staging"
            )

        oidc_fields = [
            self.oidc_issuer,
            self.oidc_client_id,
            self.oidc_client_secret,
            self.oidc_redirect_url,
        ]
        if any(oidc_fields) and not all(oidc_fields):
            missing: list[str] = []
            if not self.oidc_issuer:
                missing.append("FG_OIDC_ISSUER")
            if not self.oidc_client_id:
                missing.append("FG_OIDC_CLIENT_ID")
            if not self.oidc_client_secret:
                missing.append("FG_OIDC_CLIENT_SECRET")
            if not self.oidc_redirect_url:
                missing.append("FG_OIDC_REDIRECT_URL")
            errors.append(f"OIDC partially configured, missing: {', '.join(missing)}")

        return errors


@lru_cache(maxsize=1)
def get_auth_config() -> AuthConfig:
    # Keycloak-specific env vars (Task 6.1): derive OIDC settings when not explicitly set.
    kc_base = os.getenv("FG_KEYCLOAK_BASE_URL")
    kc_realm = os.getenv("FG_KEYCLOAK_REALM")
    kc_client_id = os.getenv("FG_KEYCLOAK_CLIENT_ID")
    kc_client_secret = os.getenv("FG_KEYCLOAK_CLIENT_SECRET")

    oidc_issuer = os.getenv("FG_OIDC_ISSUER")
    if not oidc_issuer and kc_base and kc_realm:
        oidc_issuer = f"{kc_base.rstrip('/')}/realms/{kc_realm}"

    oidc_client_id = os.getenv("FG_OIDC_CLIENT_ID") or kc_client_id
    oidc_client_secret = os.getenv("FG_OIDC_CLIENT_SECRET") or kc_client_secret

    return AuthConfig(
        oidc_issuer=oidc_issuer,
        oidc_client_id=oidc_client_id,
        oidc_client_secret=oidc_client_secret,
        oidc_redirect_url=os.getenv("FG_OIDC_REDIRECT_URL"),
        oidc_scopes=os.getenv("FG_OIDC_SCOPES"),
        env=os.getenv("FG_ENV", "dev"),
        dev_auth_bypass=_env_bool("FG_DEV_AUTH_BYPASS", False),
        session_secret=os.getenv("FG_SESSION_SECRET", os.urandom(32).hex()),
        session_cookie_name=os.getenv("FG_SESSION_COOKIE_NAME", "fg_admin_session"),
        session_ttl_seconds=_env_int("FG_SESSION_TTL_SECONDS", 28800),
    )


def reset_auth_config() -> None:
    get_auth_config.cache_clear()


def _is_contracts_gen_context() -> bool:
    """True when running under contract/OpenAPI generation — skip runtime-only checks."""
    import sys

    for var in ("AG_CONTRACTS_GEN", "FG_CONTRACTS_GEN"):
        if os.getenv(var, "").strip().lower() in {"1", "true", "yes", "on"}:
            return True
    argv0 = (sys.argv[0] if sys.argv else "").lower()
    return (
        "contracts_gen.py" in argv0
        or "contracts-gen" in argv0
        or "contracts_gen" in argv0
    )


def enforce_prod_auth_safety() -> None:
    """
    Fail-fast guard used by admin_gateway.main at import time.

    Raises RuntimeError with stable error codes when:
      - FG_ENV is prod/staging AND FG_DEV_AUTH_BYPASS is enabled
        (ADMIN_DEV_AUTH_FORBIDDEN_IN_PROD)
      - FG_ENV is prod/staging AND OIDC is not fully configured or is a placeholder
        (ADMIN_OIDC_CONFIG_REQUIRED)

    OIDC enforcement is skipped during contract generation (AG_CONTRACTS_GEN=1)
    to allow OpenAPI schema generation without requiring live OIDC credentials.
    Dev-bypass enforcement is always applied.
    """
    cfg = get_auth_config()
    if cfg.is_prod_like and cfg.dev_auth_bypass:
        raise RuntimeError(
            "ADMIN_DEV_AUTH_FORBIDDEN_IN_PROD: "
            "FG_DEV_AUTH_BYPASS is forbidden in production/staging"
        )
    if cfg.is_prod_like and not _is_contracts_gen_context():
        # Accept either FG_OIDC_ISSUER directly (Option A) or
        # the Keycloak-derived issuer path via FG_KEYCLOAK_BASE_URL + FG_KEYCLOAK_REALM
        # (Option B).  get_auth_config() already derives oidc_issuer from Keycloak vars,
        # so checking cfg.oidc_issuer covers both paths.
        _issuer = (cfg.oidc_issuer or "").strip()
        _kc_base = (os.getenv("FG_KEYCLOAK_BASE_URL") or "").strip()
        _kc_realm = (os.getenv("FG_KEYCLOAK_REALM") or "").strip()
        _issuer_ok = bool(_issuer) and not _issuer.startswith("CHANGE_ME")
        _kc_ok = (
            bool(_kc_base)
            and not _kc_base.startswith("CHANGE_ME")
            and bool(_kc_realm)
            and not _kc_realm.startswith("CHANGE_ME")
        )
        if not _issuer_ok and not _kc_ok:
            raise RuntimeError(
                "ADMIN_OIDC_CONFIG_REQUIRED: "
                "FG_OIDC_ISSUER must be set to a real value in production/staging"
                " (or provide both FG_KEYCLOAK_BASE_URL and FG_KEYCLOAK_REALM)"
            )
        if not cfg.oidc_enabled:
            raise RuntimeError(
                "ADMIN_OIDC_CONFIG_REQUIRED: "
                "OIDC must be fully configured in production/staging"
            )
