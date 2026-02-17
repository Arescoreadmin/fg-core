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
            errors.append("FG_DEV_AUTH_BYPASS cannot be enabled in production/staging")

        if self.is_prod and not self.oidc_enabled:
            errors.append("OIDC must be configured in production")

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
    return AuthConfig(
        oidc_issuer=os.getenv("FG_OIDC_ISSUER"),
        oidc_client_id=os.getenv("FG_OIDC_CLIENT_ID"),
        oidc_client_secret=os.getenv("FG_OIDC_CLIENT_SECRET"),
        oidc_redirect_url=os.getenv("FG_OIDC_REDIRECT_URL"),
        env=os.getenv("FG_ENV", "dev"),
        dev_auth_bypass=_env_bool("FG_DEV_AUTH_BYPASS", False),
        session_secret=os.getenv("FG_SESSION_SECRET", os.urandom(32).hex()),
        session_cookie_name=os.getenv("FG_SESSION_COOKIE_NAME", "fg_admin_session"),
        session_ttl_seconds=_env_int("FG_SESSION_TTL_SECONDS", 28800),
    )


def reset_auth_config() -> None:
    get_auth_config.cache_clear()


def enforce_prod_auth_safety() -> None:
    """
    Fail-fast guard used by admin_gateway.main at import time.

    The test expects importing admin_gateway.main to raise RuntimeError when:
      FG_ENV=prod and FG_DEV_AUTH_BYPASS=true
    """
    cfg = get_auth_config()
    if cfg.is_prod_like and cfg.dev_auth_bypass:
        raise RuntimeError("FG_DEV_AUTH_BYPASS is forbidden in production/staging")
