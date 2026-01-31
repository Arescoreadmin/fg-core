"""Authentication configuration.

Handles OIDC configuration and environment-based settings.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Optional


@dataclass(frozen=True)
class AuthConfig:
    """Authentication configuration from environment variables.

    Environment Variables:
        FG_OIDC_ISSUER: OIDC issuer URL (e.g., https://accounts.google.com)
        FG_OIDC_CLIENT_ID: OAuth client ID
        FG_OIDC_CLIENT_SECRET: OAuth client secret
        FG_OIDC_REDIRECT_URL: OAuth callback URL
        FG_ENV: Environment (prod/staging/dev)
        FG_DEV_AUTH_BYPASS: Enable dev auth bypass (dev only)
        FG_SESSION_SECRET: Secret for signing session cookies (auto-generated if not set)
        FG_SESSION_COOKIE_NAME: Session cookie name (default: fg_admin_session)
        FG_SESSION_TTL_SECONDS: Session TTL in seconds (default: 28800 = 8 hours)
    """

    # OIDC settings
    oidc_issuer: Optional[str] = None
    oidc_client_id: Optional[str] = None
    oidc_client_secret: Optional[str] = None
    oidc_redirect_url: Optional[str] = None

    # Environment
    env: str = "dev"

    # Dev bypass (ONLY allowed in dev)
    dev_auth_bypass: bool = False

    # Session settings
    session_secret: str = field(default_factory=lambda: os.urandom(32).hex())
    session_cookie_name: str = "fg_admin_session"
    session_ttl_seconds: int = 28800  # 8 hours

    # CSRF settings
    csrf_cookie_name: str = "fg_csrf_token"
    csrf_header_name: str = "X-CSRF-Token"

    @property
    def is_prod(self) -> bool:
        """Check if running in production environment."""
        return self.env.lower() in ("prod", "production")

    @property
    def is_dev(self) -> bool:
        """Check if running in development environment."""
        return self.env.lower() in ("dev", "development", "local")

    @property
    def oidc_enabled(self) -> bool:
        """Check if OIDC is properly configured."""
        return bool(
            self.oidc_issuer
            and self.oidc_client_id
            and self.oidc_client_secret
            and self.oidc_redirect_url
        )

    @property
    def dev_bypass_allowed(self) -> bool:
        """Check if dev bypass is allowed (dev only, never in prod)."""
        if self.is_prod:
            return False
        return self.dev_auth_bypass

    def validate(self) -> list[str]:
        """Validate configuration and return list of errors."""
        errors = []

        # P0: Validate environment value to prevent typo-based security bypass
        valid_envs = {
            "prod",
            "production",
            "staging",
            "dev",
            "development",
            "local",
            "test",
        }
        env_lower = self.env.lower()
        if env_lower not in valid_envs:
            errors.append(
                f"Invalid FG_ENV='{self.env}'. Valid values: {', '.join(sorted(valid_envs))}. "
                "This prevents accidental security bypass via typos."
            )

        # In prod, must have OIDC configured OR dev bypass is forced (which is blocked)
        if self.is_prod:
            if not self.oidc_enabled:
                errors.append("OIDC must be configured in production")
            if self.dev_auth_bypass:
                errors.append("FG_DEV_AUTH_BYPASS cannot be enabled in production")

        # P0: Staging should also be treated as production-like
        if env_lower == "staging":
            if self.dev_auth_bypass:
                errors.append("FG_DEV_AUTH_BYPASS cannot be enabled in staging")

        # If OIDC is partially configured, warn about missing fields
        oidc_fields = [
            self.oidc_issuer,
            self.oidc_client_id,
            self.oidc_client_secret,
            self.oidc_redirect_url,
        ]
        if any(oidc_fields) and not all(oidc_fields):
            missing = []
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


def _env_bool(name: str, default: bool = False) -> bool:
    """Parse boolean environment variable."""
    v = os.getenv(name)
    if v is None:
        return default
    return str(v).strip().lower() in {"1", "true", "yes", "y", "on"}


def _env_int(name: str, default: int) -> int:
    """Parse integer environment variable."""
    v = os.getenv(name)
    if v is None:
        return default
    try:
        return int(v)
    except ValueError:
        return default


@lru_cache(maxsize=1)
def get_auth_config() -> AuthConfig:
    """Get authentication configuration from environment.

    Uses lru_cache to ensure consistent config across the application.
    """
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
    """Reset the cached auth config. Useful for testing."""
    get_auth_config.cache_clear()
