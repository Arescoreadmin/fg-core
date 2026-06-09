"""Auth0 adapter configuration loaded from environment variables only.

Secrets never appear in tenant-facing records, database rows, or audit payloads.
All Auth0 configuration is resolved at startup time from the process environment.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from typing import Optional


class Auth0ConfigError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Auth0Config:
    """Auth0 OIDC + Management API configuration.

    Environment variables:
        AUTH0_DOMAIN            - Auth0 tenant domain (e.g. example.us.auth0.com)
        AUTH0_AUDIENCE          - API audience for the application client
        AUTH0_CLIENT_ID         - Application client ID
        AUTH0_CLIENT_SECRET     - Application client secret  [SECRET]
        AUTH0_MGMT_AUDIENCE     - Management API audience (https://<domain>/api/v2/)
        AUTH0_MGMT_CLIENT_ID    - Management client ID
        AUTH0_MGMT_CLIENT_SECRET - Management client secret [SECRET]
        AUTH0_CALLBACK_URL      - Redirect URI after Auth0 login
        AUTH0_LOGOUT_RETURN_URL - Return URL after Auth0 logout
        AUTH0_ORG_LOGIN         - Require organization-aware login ("true"/"false")
        AUTH0_ALLOWED_CONNECTIONS - Comma-separated allowed connection strategies
    """

    domain: str
    audience: str
    client_id: str
    client_secret: str
    mgmt_audience: str
    mgmt_client_id: str
    mgmt_client_secret: str
    callback_url: str
    logout_return_url: str
    org_login_required: bool
    allowed_connection_strategies: tuple[str, ...]

    @property
    def issuer(self) -> str:
        return f"https://{self.domain}/"

    @property
    def oidc_discovery_url(self) -> str:
        return f"https://{self.domain}/.well-known/openid-configuration"

    @property
    def mgmt_base_url(self) -> str:
        return f"https://{self.domain}/api/v2"

    @property
    def authorize_url(self) -> str:
        return f"https://{self.domain}/authorize"

    @property
    def token_url(self) -> str:
        return f"https://{self.domain}/oauth/token"

    @property
    def jwks_uri(self) -> str:
        return f"https://{self.domain}/.well-known/jwks.json"

    def is_connection_strategy_allowed(self, strategy: str) -> bool:
        return (
            not self.allowed_connection_strategies
            or strategy in self.allowed_connection_strategies
        )


_TRUE = {"1", "true", "yes", "y", "on"}


def _env_bool(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in _TRUE


def _env_str(name: str) -> Optional[str]:
    v = os.getenv(name, "").strip()
    return v if v else None


@lru_cache(maxsize=1)
def get_auth0_config() -> Auth0Config:
    """Load Auth0 configuration from environment. Raises on missing required values."""
    missing = []
    required = [
        "AUTH0_DOMAIN",
        "AUTH0_AUDIENCE",
        "AUTH0_CLIENT_ID",
        "AUTH0_CLIENT_SECRET",
        "AUTH0_MGMT_AUDIENCE",
        "AUTH0_MGMT_CLIENT_ID",
        "AUTH0_MGMT_CLIENT_SECRET",
        "AUTH0_CALLBACK_URL",
        "AUTH0_LOGOUT_RETURN_URL",
    ]
    for name in required:
        if not _env_str(name):
            missing.append(name)
    if missing:
        raise Auth0ConfigError(f"AUTH0_CONFIG_MISSING:{','.join(missing)}")

    raw_strategies = os.getenv("AUTH0_ALLOWED_CONNECTIONS", "").strip()
    strategies = tuple(s.strip() for s in raw_strategies.split(",") if s.strip())

    return Auth0Config(
        domain=_env_str("AUTH0_DOMAIN"),  # type: ignore[arg-type]
        audience=_env_str("AUTH0_AUDIENCE"),  # type: ignore[arg-type]
        client_id=_env_str("AUTH0_CLIENT_ID"),  # type: ignore[arg-type]
        client_secret=_env_str("AUTH0_CLIENT_SECRET"),  # type: ignore[arg-type]
        mgmt_audience=_env_str("AUTH0_MGMT_AUDIENCE"),  # type: ignore[arg-type]
        mgmt_client_id=_env_str("AUTH0_MGMT_CLIENT_ID"),  # type: ignore[arg-type]
        mgmt_client_secret=_env_str("AUTH0_MGMT_CLIENT_SECRET"),  # type: ignore[arg-type]
        callback_url=_env_str("AUTH0_CALLBACK_URL"),  # type: ignore[arg-type]
        logout_return_url=_env_str("AUTH0_LOGOUT_RETURN_URL"),  # type: ignore[arg-type]
        org_login_required=_env_bool("AUTH0_ORG_LOGIN", default=True),
        allowed_connection_strategies=strategies,
    )


def clear_auth0_config_cache() -> None:
    """Clear the cached Auth0 config. Use in tests only."""
    get_auth0_config.cache_clear()
