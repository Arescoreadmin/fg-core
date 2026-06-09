"""Auth0 Management API client.

Wraps the Auth0 Management API for organization and connection provisioning.
All operations are idempotent: duplicate org names or already-attached
connections return safe results rather than errors.

Secrets (management token) are never logged, stored in the database,
or returned in provisioning metadata.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any, Optional

import httpx

from admin_gateway.identity.auth0_config import Auth0Config
from admin_gateway.identity.auth0_models import Auth0ConnectionResult, Auth0OrgResult

log = logging.getLogger("admin-gateway.auth0.management")

# Never log these field names from any API response
_REDACTED_FIELDS = frozenset(
    {
        "access_token",
        "id_token",
        "refresh_token",
        "client_secret",
        "authorization",
        "token",
    }
)


def _safe_log_dict(data: dict[str, Any]) -> dict[str, Any]:
    return {k: ("***" if k in _REDACTED_FIELDS else v) for k, v in data.items()}


class Auth0ManagementError(RuntimeError):
    def __init__(self, code: str, status: int = 0) -> None:
        super().__init__(code)
        self.code = code
        self.status = status


class Auth0ManagementClient:
    """Synchronous wrapper around the Auth0 Management API v2.

    A fresh management token is requested per client lifetime; the token is
    held in memory only and is never written to any database record or log line.
    """

    def __init__(self, config: Auth0Config) -> None:
        self._config = config
        self._token: Optional[str] = None

    # ------------------------------------------------------------------
    # Token management (in-memory only, never persisted or logged)
    # ------------------------------------------------------------------

    def _acquire_token(self) -> str:
        payload = {
            "grant_type": "client_credentials",
            "client_id": self._config.mgmt_client_id,
            "client_secret": self._config.mgmt_client_secret,
            "audience": self._config.mgmt_audience,
        }
        resp = httpx.post(
            self._config.token_url,
            json=payload,
            timeout=10.0,
        )
        if resp.status_code != 200:
            log.warning(
                "auth0.management.token_request_failed status=%d", resp.status_code
            )
            raise Auth0ManagementError("MGMT_TOKEN_ACQUIRE_FAILED", resp.status_code)
        # Extract token from response — never log the raw response
        return resp.json()["access_token"]

    def _token_headers(self) -> dict[str, str]:
        if self._token is None:
            self._token = self._acquire_token()
        return {"Authorization": f"Bearer {self._token}"}

    def _get(self, path: str, **params: Any) -> Any:
        resp = httpx.get(
            f"{self._config.mgmt_base_url}{path}",
            headers=self._token_headers(),
            params=params,
            timeout=10.0,
        )
        if resp.status_code == 401:
            # Token may have expired — retry once
            self._token = None
            resp = httpx.get(
                f"{self._config.mgmt_base_url}{path}",
                headers=self._token_headers(),
                params=params,
                timeout=10.0,
            )
        if resp.status_code not in (200, 404):
            raise Auth0ManagementError(
                f"MGMT_GET_FAILED:{resp.status_code}", resp.status_code
            )
        return resp.json() if resp.status_code == 200 else None

    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        resp = httpx.post(
            f"{self._config.mgmt_base_url}{path}",
            headers=self._token_headers(),
            json=body,
            timeout=10.0,
        )
        if resp.status_code == 401:
            self._token = None
            resp = httpx.post(
                f"{self._config.mgmt_base_url}{path}",
                headers=self._token_headers(),
                json=body,
                timeout=10.0,
            )
        if resp.status_code not in (200, 201, 204, 409):
            raise Auth0ManagementError(
                f"MGMT_POST_FAILED:{resp.status_code}", resp.status_code
            )
        return resp.json() if resp.content else {}

    def _delete(self, path: str) -> None:
        resp = httpx.delete(
            f"{self._config.mgmt_base_url}{path}",
            headers=self._token_headers(),
            timeout=10.0,
        )
        if resp.status_code == 401:
            self._token = None
            resp = httpx.delete(
                f"{self._config.mgmt_base_url}{path}",
                headers=self._token_headers(),
                timeout=10.0,
            )
        if resp.status_code not in (204, 404):
            raise Auth0ManagementError(
                f"MGMT_DELETE_FAILED:{resp.status_code}", resp.status_code
            )

    # ------------------------------------------------------------------
    # Organization operations
    # ------------------------------------------------------------------

    def get_organization_by_name(self, name: str) -> Optional[dict[str, Any]]:
        result = self._get("/organizations/name/" + name)
        if result:
            log.info("auth0.org.found name=%s id=%s", name, result.get("id"))
        return result

    def get_organization_by_id(self, org_id: str) -> Optional[dict[str, Any]]:
        result = self._get(f"/organizations/{org_id}")
        if result:
            log.info("auth0.org.found id=%s", org_id)
        return result

    def create_organization(
        self,
        *,
        name: str,
        display_name: str,
        tenant_id: str,
    ) -> Auth0OrgResult:
        """Create an Auth0 org or return the existing one with the same name."""
        existing = self.get_organization_by_name(name)
        if existing:
            existing_meta_tenant = (existing.get("metadata") or {}).get("fg_tenant_id")
            if existing_meta_tenant != tenant_id:
                raise Auth0ManagementError("ORG_OWNED_BY_DIFFERENT_TENANT", 409)
            log.info("auth0.org.already_exists name=%s id=%s", name, existing["id"])
            return Auth0OrgResult(
                organization_id=existing["id"],
                organization_name=existing["name"],
                was_created=False,
            )
        body = {
            "name": name,
            "display_name": display_name,
            "metadata": {"fg_tenant_id": tenant_id},
        }
        data = self._post("/organizations", body)
        log.info("auth0.org.created name=%s id=%s", name, data.get("id"))
        return Auth0OrgResult(
            organization_id=data["id"],
            organization_name=data["name"],
            was_created=True,
        )

    def associate_organization(self, org_id: str) -> Auth0OrgResult:
        """Verify an existing Auth0 org is accessible (association use case)."""
        data = self.get_organization_by_id(org_id)
        if data is None:
            raise Auth0ManagementError("ORG_NOT_FOUND", 404)
        return Auth0OrgResult(
            organization_id=data["id"],
            organization_name=data["name"],
            was_created=False,
        )

    # ------------------------------------------------------------------
    # Connection operations
    # ------------------------------------------------------------------

    def get_connection_by_id(self, connection_id: str) -> Optional[dict[str, Any]]:
        return self._get(f"/connections/{connection_id}")

    def list_org_connections(self, org_id: str) -> list[dict[str, Any]]:
        result = self._get(f"/organizations/{org_id}/enabled_connections")
        if isinstance(result, dict) and "enabled_connections" in result:
            return result["enabled_connections"]
        if isinstance(result, list):
            return result
        return []

    def attach_connection_to_org(
        self,
        *,
        org_id: str,
        connection_id: str,
        assign_membership_on_login: bool = False,
    ) -> Auth0ConnectionResult:
        """Attach a connection to an org, idempotently."""
        existing = self.list_org_connections(org_id)
        for ec in existing:
            conn = ec.get("connection", ec)
            if conn.get("id") == connection_id:
                log.info(
                    "auth0.connection.already_attached org=%s conn=%s",
                    org_id,
                    connection_id,
                )
                existing_detail: dict[str, Any] = (
                    self.get_connection_by_id(connection_id) or {}
                )
                return Auth0ConnectionResult(
                    connection_id=connection_id,
                    connection_name=existing_detail.get("name", connection_id),
                    strategy=existing_detail.get("strategy", "unknown"),
                    was_attached=False,
                )

        conn_detail = self.get_connection_by_id(connection_id)
        if conn_detail is None:
            raise Auth0ManagementError("CONNECTION_NOT_FOUND", 404)

        strategy = conn_detail.get("strategy", "")
        if not self._config.is_connection_strategy_allowed(strategy):
            raise Auth0ManagementError("CONNECTION_STRATEGY_NOT_ALLOWED", 400)

        body: dict[str, Any] = {
            "connection_id": connection_id,
            "assign_membership_on_login": assign_membership_on_login,
        }
        self._post(f"/organizations/{org_id}/enabled_connections", body)
        log.info(
            "auth0.connection.attached org=%s conn=%s strategy=%s",
            org_id,
            connection_id,
            strategy,
        )
        return Auth0ConnectionResult(
            connection_id=connection_id,
            connection_name=conn_detail.get("name", connection_id),
            strategy=strategy,
            was_attached=True,
        )

    # ------------------------------------------------------------------
    # JWKS retrieval for callback token verification
    # ------------------------------------------------------------------

    def get_jwks(self) -> dict[str, Any]:
        resp = httpx.get(self._config.jwks_uri, timeout=10.0)
        resp.raise_for_status()
        return resp.json()

    # ------------------------------------------------------------------
    # Utility: safe subject hash for audit payloads
    # ------------------------------------------------------------------

    @staticmethod
    def hash_subject(subject: str) -> str:
        return hashlib.sha256(subject.encode()).hexdigest()[:16]
