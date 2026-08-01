"""api/identity_authority/management/auth0.py — Auth0 management provider implementation."""

from __future__ import annotations

import logging
import os
import re
import threading
import time
from typing import Any

import requests

from api.identity_authority.management.base import (
    ManagementProviderError,
    OrganizationRecord,
    RetryableProviderError,
)

log = logging.getLogger("frostgate.ia.auth0")

# Module-level token cache — never log the token value
_token_cache: dict[str, Any] = {}
_token_lock = threading.Lock()

# Slug rule: fg-{slugified_tenant_id}, max 50 chars total
_NON_ALNUM_RE = re.compile(r"[^a-z0-9]+")
_LEADING_TRAILING_DASH_RE = re.compile(r"^-+|-+$")


def _slugify_tenant_id(tenant_id: str) -> str:
    """Derive a deterministic, safe Auth0 org name slug from a tenant_id.

    Lowercase, replace non-alphanumeric with '-', collapse repeated '-',
    strip leading/trailing '-', prefix 'fg-'. Max 50 chars total.
    """
    slug = tenant_id.lower()
    slug = _NON_ALNUM_RE.sub("-", slug)
    slug = re.sub(r"-{2,}", "-", slug)
    slug = _LEADING_TRAILING_DASH_RE.sub("", slug)
    name = f"fg-{slug}"
    return name[:50]


class Auth0ManagementProvider:
    """Auth0 implementation of ManagementProviderProtocol.

    Consumes env vars:
      AUTH0_MANAGEMENT_DOMAIN
      AUTH0_MANAGEMENT_CLIENT_ID
      AUTH0_MANAGEMENT_CLIENT_SECRET  (never logged)
      AUTH0_MANAGEMENT_AUDIENCE
    """

    provider_name = "auth0"

    def __init__(self) -> None:
        self._domain = os.getenv("AUTH0_MANAGEMENT_DOMAIN", "").strip()
        self._client_id = os.getenv("AUTH0_MANAGEMENT_CLIENT_ID", "").strip()
        self._client_secret = os.getenv("AUTH0_MANAGEMENT_CLIENT_SECRET", "").strip()
        self._audience = os.getenv("AUTH0_MANAGEMENT_AUDIENCE", "").strip()
        self._timeout = 10  # seconds

    def is_configured(self) -> bool:
        """Return True if all four required env vars are present."""
        return bool(
            self._domain and self._client_id and self._client_secret and self._audience
        )

    def _get_access_token(self) -> str:
        """Return a valid M2M access token, refreshing if within 60s of expiry.

        The token value is never logged.
        """
        with _token_lock:
            now = time.time()
            cached = _token_cache.get("auth0")
            if cached and cached["expires_at"] - now > 60:
                return cached["token"]  # type: ignore[return-value]

            # Fetch a new token
            url = f"https://{self._domain}/oauth/token"
            payload = {
                "grant_type": "client_credentials",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "audience": self._audience,
            }
            try:
                resp = requests.post(url, json=payload, timeout=self._timeout)
            except requests.Timeout:
                raise RetryableProviderError(
                    "Auth0 token request timed out",
                    code="TIMEOUT",
                    provider="auth0",
                )
            except requests.RequestException as exc:
                raise RetryableProviderError(
                    "Auth0 token request failed",
                    code="PROVIDER_UNAVAILABLE",
                    provider="auth0",
                ) from exc

            if resp.status_code == 429:
                # Rate limit on the token endpoint is transient — retry after backoff.
                retry_after = int(resp.headers.get("Retry-After", 60))
                raise RetryableProviderError(
                    "Auth0 token endpoint rate limited",
                    code="RATE_LIMITED",
                    provider="auth0",
                    retry_after=retry_after,
                )
            if resp.status_code >= 500:
                # Auth0 server error — transient, not a misconfiguration.
                raise RetryableProviderError(
                    "Auth0 token endpoint server error",
                    code="PROVIDER_UNAVAILABLE",
                    provider="auth0",
                )
            if not resp.ok:
                # 4xx (other than 429): genuine auth rejection — credentials wrong or
                # audience invalid. Non-retryable until operator fixes configuration.
                raise ManagementProviderError(
                    "Auth0 token fetch rejected",
                    code="AUTH_FAILED",
                    provider="auth0",
                )

            data = resp.json()
            token: str = data["access_token"]
            expires_in: int = data.get("expires_in", 86400)
            _token_cache["auth0"] = {
                "token": token,
                "expires_at": now + expires_in,
            }
            return token

    def _api_base(self) -> str:
        return f"https://{self._domain}/api/v2"

    def _auth_headers(self, correlation_id: str | None = None) -> dict[str, str]:
        token = self._get_access_token()
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        if correlation_id:
            headers["X-Correlation-ID"] = correlation_id
        # Never log this dict — it contains the Bearer token
        return headers

    def create_organization(
        self,
        *,
        name: str,
        display_name: str,
        idempotency_key: str,
        correlation_id: str,
    ) -> OrganizationRecord:
        """Create an Auth0 organization.

        The ``name`` parameter MUST be the pre-slugified ``fg-{slug}`` value
        (derived from tenant_id by the caller / provisioning service).

        Raises:
            RetryableProviderError: transient failure (rate limit, 5xx, timeout)
            ManagementProviderError: non-retryable failure including ownership conflict
        """
        url = f"{self._api_base()}/organizations"
        payload = {
            "name": name,
            "display_name": display_name,
            "metadata": {
                "frostgate_tenant_id": idempotency_key.split(":")[1]
                if idempotency_key.startswith("ia1:")
                else idempotency_key,
                "frostgate_idempotency_key": idempotency_key,
            },
        }

        try:
            resp = requests.post(
                url,
                json=payload,
                headers=self._auth_headers(correlation_id),
                timeout=self._timeout,
            )
        except requests.Timeout:
            raise RetryableProviderError(
                "Auth0 org creation timed out",
                code="TIMEOUT",
                provider="auth0",
            )
        except requests.RequestException as exc:
            raise RetryableProviderError(
                "Auth0 org creation request failed",
                code="PROVIDER_UNAVAILABLE",
                provider="auth0",
            ) from exc

        # Log only: HTTP status, correlation_id, org name, provider — never response body
        log.info(
            "auth0.org.create",
            extra={
                "http_status": resp.status_code,
                "org_name": name,
                "provider": "auth0",
                "correlation_id": correlation_id,
            },
        )

        if resp.status_code == 201:
            data = resp.json()
            return OrganizationRecord(
                provider_org_id=data["id"],
                provider_org_name=data["name"],
                provider="auth0",
            )

        if resp.status_code == 409:
            # Org name already exists — fetch it and verify ownership
            return self._recover_409(name=name, idempotency_key=idempotency_key)

        if resp.status_code == 429:
            retry_after_raw = resp.headers.get("Retry-After")
            retry_after = int(retry_after_raw) if retry_after_raw else None
            raise RetryableProviderError(
                "Auth0 rate limited",
                code="RATE_LIMITED",
                provider="auth0",
                retry_after=retry_after,
            )

        if resp.status_code >= 500:
            raise RetryableProviderError(
                "Auth0 server error",
                code="PROVIDER_UNAVAILABLE",
                provider="auth0",
            )

        # Other 4xx — non-retryable
        raise ManagementProviderError(
            "Auth0 rejected org creation",
            code="PROVIDER_REJECTED",
            provider="auth0",
        )

    def _recover_409(self, *, name: str, idempotency_key: str) -> OrganizationRecord:
        """Recover from a 409 by fetching the existing org and verifying ownership.

        The idempotency_key has form ``ia1:{tenant_id}:auth0``.
        We extract tenant_id to verify ``metadata.frostgate_tenant_id``.

        Raises:
            ManagementProviderError(code="AUTH0_ORG_OWNERSHIP_CONFLICT"):
                if the existing org belongs to a different tenant or metadata absent.
        """
        # Extract tenant_id from idempotency_key
        parts = idempotency_key.split(":")
        tenant_id = parts[1] if len(parts) >= 2 and parts[0] == "ia1" else ""

        fetch_url = f"{self._api_base()}/organizations/name/{name}"
        try:
            resp = requests.get(
                fetch_url,
                headers=self._auth_headers(),
                timeout=self._timeout,
            )
        except requests.Timeout:
            raise RetryableProviderError(
                "Auth0 org fetch timed out during 409 recovery",
                code="TIMEOUT",
                provider="auth0",
            )
        except requests.RequestException as exc:
            raise RetryableProviderError(
                "Auth0 org fetch failed during 409 recovery",
                code="PROVIDER_UNAVAILABLE",
                provider="auth0",
            ) from exc

        log.info(
            "auth0.org.recover_409",
            extra={
                "http_status": resp.status_code,
                "org_name": name,
                "provider": "auth0",
            },
        )

        if resp.status_code == 404:
            # Org gone between 409 and fetch — raise retryable
            raise RetryableProviderError(
                "Auth0 org disappeared during 409 recovery",
                code="PROVIDER_UNAVAILABLE",
                provider="auth0",
            )

        if not resp.ok:
            raise RetryableProviderError(
                "Auth0 org fetch returned unexpected status during 409 recovery",
                code="PROVIDER_UNAVAILABLE",
                provider="auth0",
            )

        data = resp.json()
        metadata: dict[str, str] = data.get("metadata") or {}
        existing_tenant_id = metadata.get("frostgate_tenant_id", "")

        if not existing_tenant_id or existing_tenant_id != tenant_id:
            # Ownership conflict — another tenant owns this org name
            raise ManagementProviderError(
                "Auth0 org ownership conflict: org exists but belongs to a different tenant",
                code="AUTH0_ORG_OWNERSHIP_CONFLICT",
                provider="auth0",
            )

        # Ownership verified — return existing org (idempotent)
        return OrganizationRecord(
            provider_org_id=data["id"],
            provider_org_name=data["name"],
            provider="auth0",
        )

    def get_organization(self, *, provider_org_id: str) -> OrganizationRecord | None:
        """Fetch an Auth0 organization by provider org ID.

        Returns None if 404. Raises on transient or non-retryable errors.
        """
        url = f"{self._api_base()}/organizations/{provider_org_id}"
        try:
            resp = requests.get(
                url,
                headers=self._auth_headers(),
                timeout=self._timeout,
            )
        except requests.Timeout:
            raise RetryableProviderError(
                "Auth0 get_organization timed out",
                code="TIMEOUT",
                provider="auth0",
            )
        except requests.RequestException as exc:
            raise RetryableProviderError(
                "Auth0 get_organization request failed",
                code="PROVIDER_UNAVAILABLE",
                provider="auth0",
            ) from exc

        log.info(
            "auth0.org.get",
            extra={
                "http_status": resp.status_code,
                "provider_org_id": provider_org_id,
                "provider": "auth0",
            },
        )

        if resp.status_code == 404:
            return None

        if resp.status_code == 429:
            retry_after_raw = resp.headers.get("Retry-After")
            retry_after = int(retry_after_raw) if retry_after_raw else None
            raise RetryableProviderError(
                "Auth0 rate limited on get_organization",
                code="RATE_LIMITED",
                provider="auth0",
                retry_after=retry_after,
            )

        if resp.status_code >= 500:
            raise RetryableProviderError(
                "Auth0 server error on get_organization",
                code="PROVIDER_UNAVAILABLE",
                provider="auth0",
            )

        if not resp.ok:
            raise ManagementProviderError(
                "Auth0 rejected get_organization",
                code="PROVIDER_REJECTED",
                provider="auth0",
            )

        data = resp.json()
        return OrganizationRecord(
            provider_org_id=data["id"],
            provider_org_name=data["name"],
            provider="auth0",
        )
