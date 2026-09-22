"""Bounded HashiCorp Vault Transit adapter for Customer-Zero trust roles.

This module deliberately contains no private-key handling.  Vault performs the
signing operation and only returns a versioned signature.  Public keys are
retrieved for verification and are checked against the configured trust role
and fingerprint.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
import threading
import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Callable, Mapping, Protocol
from urllib.parse import urlsplit

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_public_key,
)


class TrustRole(StrEnum):
    IDENTITY = "customer-zero-identity"
    ACCEPTANCE = "customer-zero-acceptance"
    APPROVAL = "customer-zero-approval"


@dataclass(frozen=True)
class ManagedSignature:
    issuer: str
    trust_role: TrustRole
    key_id: str
    key_version: int
    algorithm: str
    public_key_fingerprint: str
    signature: str


@dataclass(frozen=True)
class TrustAnchor:
    issuer: str
    trust_role: TrustRole
    key_id: str
    key_version: int
    algorithm: str
    public_key: str
    public_key_fingerprint: str
    status: str = "active"

    def verify(self, payload: bytes, signature: str) -> bool:
        if self.status != "active":
            return False
        if self.algorithm != "ed25519" or not signature.startswith("vault:v"):
            return False
        try:
            parts = signature.split(":", 2)
            if len(parts) != 3 or int(parts[1][1:]) != self.key_version:
                return False
            encoded = parts[2]
            raw_signature = base64.b64decode(encoded)
            key = _decode_public_key(self.public_key)
            if public_key_fingerprint(self.public_key) != self.public_key_fingerprint:
                return False
            key.verify(raw_signature, payload)
            return True
        except Exception:
            return False


def _decode_public_key(value: str) -> Ed25519PublicKey:
    raw = value.encode("ascii")
    if value.startswith("-----BEGIN"):
        key = load_pem_public_key(raw)
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("Vault trust anchor is not Ed25519")
        return key
    return Ed25519PublicKey.from_public_bytes(base64.b64decode(raw))


def public_key_fingerprint(public_key: str) -> str:
    key = _decode_public_key(public_key)
    raw = key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()


class TrustAnchorRegistry:
    """Explicit trust anchors; caller-supplied keys are never trusted."""

    def __init__(self, anchors: list[TrustAnchor]) -> None:
        self._anchors = {
            (a.issuer, a.trust_role, a.key_id, a.key_version): a for a in anchors
        }

    def resolve(
        self, issuer: str, role: TrustRole, key_id: str, key_version: int
    ) -> TrustAnchor:
        try:
            return self._anchors[(issuer, role, key_id, key_version)]
        except KeyError as exc:
            raise ValueError("unknown Vault trust anchor") from exc

    def verify(
        self,
        issuer: str,
        role: TrustRole,
        key_id: str,
        key_version: int,
        payload: bytes,
        signature: str,
    ) -> bool:
        return self.resolve(issuer, role, key_id, key_version).verify(
            payload, signature
        )


class VaultTransitError(RuntimeError):
    """Fail-closed Vault Transit operation error."""


@dataclass(frozen=True)
class VaultSession:
    """Short-lived Vault session; token is never shown in repr."""

    token: str = field(repr=False)
    lease_duration: int
    renewable: bool
    issued_at: float
    expires_at: float

    def usable(self, now: float | None = None, skew: float = 5.0) -> bool:
        return (
            bool(self.token)
            and (now if now is not None else time.time()) < self.expires_at - skew
        )


class VaultSessionProvider(Protocol):
    def session(self, role: TrustRole) -> VaultSession: ...


_ROLE_ENV = {
    TrustRole.IDENTITY: "IDENTITY",
    TrustRole.ACCEPTANCE: "ACCEPTANCE",
    TrustRole.APPROVAL: "APPROVAL",
}
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_CORR_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_NS_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")


def _validate_address(address: str, *, operational: bool) -> str:
    parsed = urlsplit(address)
    allowed = ("https",) if operational else ("http", "https")
    if (
        parsed.scheme not in allowed
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(
            "Vault address must be a host-only HTTPS URL in operational mode"
        )
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in address):
        raise ValueError("Vault address contains control characters")
    return address.rstrip("/")


def _validate_identifier(value: str, label: str) -> str:
    if not _ID_RE.fullmatch(value) or ".." in value:
        raise ValueError(f"invalid Vault {label}")
    return value


def _validate_namespace(value: str) -> str:
    if not _NS_RE.fullmatch(value) or any(c in value for c in "\r\n"):
        raise ValueError("invalid Vault namespace")
    return value


def _timeout(value: float) -> httpx.Timeout:
    if value <= 0 or value > 120:
        raise ValueError("Vault timeout must be between 0 and 120 seconds")
    return httpx.Timeout(value)


def _client(http_client: httpx.Client | None, timeout: float) -> httpx.Client:
    if http_client is not None:
        if getattr(http_client, "follow_redirects", None) is not False:
            raise ValueError("Vault HTTP clients must disable redirects")
        return http_client
    return httpx.Client(timeout=_timeout(timeout), follow_redirects=False)


class AppRoleAuthenticator:
    """Role-specific short-lived Vault AppRole sessions."""

    def __init__(
        self,
        address: str,
        role_ids: Mapping[TrustRole, str],
        secret_ids: Mapping[TrustRole, str | Callable[[], str]],
        *,
        mount: str = "approle",
        namespace: str | None = None,
        http_client: httpx.Client | None = None,
        timeout: float = 10.0,
    ) -> None:
        if set(role_ids) != set(TrustRole) or set(secret_ids) != set(TrustRole):
            raise ValueError("AppRole mappings must cover every trust role")
        if len(set(role_ids.values())) != len(role_ids):
            raise ValueError("AppRole role IDs must be distinct")
        self.address = _validate_address(address, operational=True)
        self.role_ids = {
            r: _validate_identifier(v, "role ID") for r, v in role_ids.items()
        }
        self._secret_ids = dict(secret_ids)
        self.mount = _validate_identifier(mount, "auth mount")
        self.namespace = _validate_namespace(namespace) if namespace else None
        self.client = _client(http_client, timeout)
        self._sessions: dict[TrustRole, VaultSession] = {}
        self._locks = {r: threading.Lock() for r in TrustRole}

    def _headers(self, token: str | None = None) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self.namespace:
            headers["X-Vault-Namespace"] = self.namespace
        if token:
            headers["X-Vault-Token"] = token
        return headers

    def _secret(self, role: TrustRole) -> str:
        value = self._secret_ids[role]
        secret = value() if callable(value) else value
        if not secret:
            raise VaultTransitError("Vault AppRole SecretID unavailable")
        return secret

    def _parse_session(self, body: Any) -> VaultSession:
        auth = body.get("auth") if isinstance(body, dict) else None
        if not isinstance(auth, dict):
            raise VaultTransitError("Vault authentication returned malformed data")
        token, lease, renewable = (
            auth.get("client_token"),
            auth.get("lease_duration"),
            auth.get("renewable"),
        )
        if (
            not isinstance(token, str)
            or not token
            or not isinstance(lease, int)
            or lease <= 0
            or not isinstance(renewable, bool)
        ):
            raise VaultTransitError("Vault authentication returned invalid session")
        now = time.time()
        return VaultSession(token, lease, renewable, now, now + lease)

    def _request(
        self,
        path: str,
        payload: dict[str, str],
        role: TrustRole,
        token: str | None = None,
    ) -> VaultSession:
        try:
            response = self.client.post(
                f"{self.address}/v1/{path}", headers=self._headers(token), json=payload
            )
        except Exception as exc:
            raise VaultTransitError("Vault authentication transport failure") from exc
        if 300 <= response.status_code < 400:
            raise VaultTransitError("Vault authentication redirect rejected")
        if response.status_code >= 400:
            raise VaultTransitError(
                f"Vault authentication denied ({response.status_code}) for {role.value}"
            )
        try:
            return self._parse_session(response.json())
        except ValueError as exc:
            raise VaultTransitError(
                "Vault authentication returned invalid JSON"
            ) from exc

    def session(self, role: TrustRole) -> VaultSession:
        with self._locks[role]:
            current = self._sessions.get(role)
            if current and current.usable():
                return current
            if current and current.renewable and current.expires_at > time.time():
                try:
                    renewed = self._request(
                        "auth/token/renew-self", {}, role, current.token
                    )
                    self._sessions[role] = renewed
                    return renewed
                except VaultTransitError:
                    pass
            fresh = self._request(
                f"auth/{self.mount}/login",
                {"role_id": self.role_ids[role], "secret_id": self._secret(role)},
                role,
            )
            self._sessions[role] = fresh
            return fresh


class VaultTransitClient:
    """Vault Transit client with explicit operational transport policy."""

    def __init__(
        self,
        address: str,
        token: str | None = None,
        *,
        session_provider: VaultSessionProvider | None = None,
        http_client: httpx.Client | None = None,
        namespace: str | None = None,
        operational: bool = False,
        timeout: float = 10.0,
    ) -> None:
        if operational and token:
            raise ValueError("static Vault tokens are not permitted operationally")
        if not token and not session_provider:
            raise ValueError("Vault session provider is required")
        self._address = _validate_address(address, operational=operational)
        self._token, self._session_provider = token, session_provider
        self._namespace, self._operational = (
            (_validate_namespace(namespace) if namespace else None),
            operational,
        )
        self._client = _client(http_client, timeout)

    @classmethod
    def from_environment(
        cls, *, http_client: httpx.Client | None = None
    ) -> "VaultTransitClient":
        mode = os.getenv("FG_CUSTOMER_ZERO_VAULT_AUTH_MODE", "")
        environment = os.getenv("FG_CUSTOMER_ZERO_ENVIRONMENT", "").lower()
        if mode != "static_token" or environment not in {
            "test",
            "development",
            "local",
        }:
            raise ValueError(
                "static-token mode is test/development only; configure AppRole operationally"
            )
        return cls(
            os.getenv("FG_CUSTOMER_ZERO_VAULT_ADDR", ""),
            os.getenv("FG_CUSTOMER_ZERO_VAULT_TOKEN", ""),
            http_client=http_client,
        )

    @classmethod
    def from_approle_environment(
        cls, *, http_client: httpx.Client | None = None
    ) -> "VaultTransitClient":
        address, namespace = (
            os.getenv("FG_CUSTOMER_ZERO_VAULT_ADDR", ""),
            os.getenv("FG_CUSTOMER_ZERO_VAULT_NAMESPACE"),
        )
        role_ids = {
            r: os.getenv(f"FG_CUSTOMER_ZERO_{suffix}_VAULT_ROLE_ID", "")
            for r, suffix in _ROLE_ENV.items()
        }
        secret_ids = {
            r: os.getenv(f"FG_CUSTOMER_ZERO_{suffix}_VAULT_SECRET_ID", "")
            for r, suffix in _ROLE_ENV.items()
        }
        auth = AppRoleAuthenticator(
            address, role_ids, secret_ids, namespace=namespace, http_client=http_client
        )
        return cls(
            address,
            session_provider=auth,
            namespace=namespace,
            operational=True,
            http_client=http_client,
        )

    def _headers(self, role: TrustRole, correlation_id: str | None) -> dict[str, str]:
        token = self._token or (
            self._session_provider.session(role).token if self._session_provider else ""
        )
        headers = {"X-Vault-Token": token}
        if self._namespace:
            headers["X-Vault-Namespace"] = self._namespace
        if correlation_id:
            if not _CORR_RE.fullmatch(correlation_id):
                raise ValueError("invalid correlation ID")
            headers["X-FrostGate-Correlation-Id"] = correlation_id
        return headers

    def _response_data(
        self, response: httpx.Response, role: TrustRole
    ) -> dict[str, Any]:
        if 300 <= response.status_code < 400:
            raise VaultTransitError("Vault Transit redirect rejected")
        if response.status_code >= 400:
            raise VaultTransitError(
                f"Vault Transit request failed ({response.status_code}) for {role.value}"
            )
        try:
            body = response.json()
        except ValueError as exc:
            raise VaultTransitError("Vault Transit returned invalid JSON") from exc
        if not isinstance(body, dict) or not isinstance(body.get("data"), dict):
            raise VaultTransitError("Vault Transit returned malformed data")
        return body["data"]

    def _post(
        self,
        path: str,
        payload: dict[str, Any],
        role: TrustRole,
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        try:
            return self._response_data(
                self._client.post(
                    f"{self._address}/v1/{path}",
                    headers=self._headers(role, correlation_id),
                    json=payload,
                ),
                role,
            )
        except VaultTransitError:
            raise
        except Exception as exc:
            raise VaultTransitError("Vault Transit transport failure") from exc

    def _get(
        self, path: str, role: TrustRole, correlation_id: str | None = None
    ) -> dict[str, Any]:
        try:
            return self._response_data(
                self._client.get(
                    f"{self._address}/v1/{path}",
                    headers=self._headers(role, correlation_id),
                ),
                role,
            )
        except VaultTransitError:
            raise
        except Exception as exc:
            raise VaultTransitError("Vault Transit transport failure") from exc

    def sign(
        self,
        key_id: str,
        payload: bytes,
        role: TrustRole = TrustRole.APPROVAL,
        correlation_id: str | None = None,
    ) -> tuple[str, int]:
        key_id = _validate_identifier(key_id, "key ID")
        data = self._post(
            f"transit/sign/{key_id}",
            {"input": base64.b64encode(payload).decode("ascii")},
            role,
            correlation_id,
        )
        signature = data.get("signature")
        if not isinstance(signature, str) or not signature.startswith("vault:v"):
            raise VaultTransitError("Vault Transit returned malformed signature")
        try:
            version = int(signature.split(":", 2)[1][1:])
        except (IndexError, ValueError) as exc:
            raise VaultTransitError(
                "Vault Transit signature has no valid key version"
            ) from exc
        return signature, version

    def public_key(
        self,
        key_id: str,
        key_version: int,
        role: TrustRole = TrustRole.APPROVAL,
        correlation_id: str | None = None,
    ) -> str:
        data = self._get(
            f"transit/keys/{_validate_identifier(key_id, 'key ID')}",
            role,
            correlation_id,
        )
        keys = data.get("keys")
        if not isinstance(keys, dict) or not isinstance(
            keys.get(str(key_version)), dict
        ):
            raise VaultTransitError("Vault Transit public key version unavailable")
        public_key = keys[str(key_version)].get("public_key")
        if not isinstance(public_key, str) or not public_key:
            raise VaultTransitError("Vault Transit public key missing")
        return public_key


class VaultCustomerZeroSigner:
    """Role-separated Customer-Zero signer backed by Vault Transit."""

    def __init__(
        self,
        client: VaultTransitClient,
        key_ids: dict[TrustRole, str],
        issuer: str = "vault-transit",
    ) -> None:
        if set(key_ids) != set(TrustRole) or len(set(key_ids.values())) != len(key_ids):
            raise ValueError("Customer-Zero trust roles require three distinct key IDs")
        self._client = client
        self._key_ids = dict(key_ids)
        self._issuer = issuer

    def sign(self, role: TrustRole, payload: bytes) -> ManagedSignature:
        key_id = self._key_ids[role]
        signature, version = self._client.sign(key_id, payload, role)
        public_key = self._client.public_key(key_id, version, role)
        return ManagedSignature(
            issuer=self._issuer,
            trust_role=role,
            key_id=key_id,
            key_version=version,
            algorithm="ed25519",
            public_key_fingerprint=public_key_fingerprint(public_key),
            signature=signature,
        )


@dataclass(frozen=True)
class VaultCustomerZeroConfig:
    """Non-secret operational configuration for the three trust roles."""

    address: str
    key_ids: dict[TrustRole, str]
    issuer: str = "vault-transit"

    @classmethod
    def from_environment(cls) -> "VaultCustomerZeroConfig":
        address = os.getenv("FG_CUSTOMER_ZERO_VAULT_ADDR", "")
        values = {
            TrustRole.IDENTITY: os.getenv("FG_CUSTOMER_ZERO_IDENTITY_KEY_ID", ""),
            TrustRole.ACCEPTANCE: os.getenv("FG_CUSTOMER_ZERO_ACCEPTANCE_KEY_ID", ""),
            TrustRole.APPROVAL: os.getenv("FG_CUSTOMER_ZERO_APPROVAL_KEY_ID", ""),
        }
        if not address or any(not value for value in values.values()):
            raise ValueError("Vault address and all Customer-Zero key IDs are required")
        values = {
            role: _validate_identifier(value, "key ID")
            for role, value in values.items()
        }
        if len(set(values.values())) != len(values):
            raise ValueError("Customer-Zero trust roles require distinct Vault key IDs")
        return cls(
            address=_validate_address(address, operational=False), key_ids=values
        )


def signer_from_environment(
    *, http_client: httpx.Client | None = None
) -> VaultCustomerZeroSigner:
    """Build an operational signer without exposing or persisting the Vault token."""
    config = VaultCustomerZeroConfig.from_environment()
    mode = os.getenv("FG_CUSTOMER_ZERO_VAULT_AUTH_MODE", "")
    client = (
        VaultTransitClient.from_approle_environment(http_client=http_client)
        if mode == "approle"
        else VaultTransitClient.from_environment(http_client=http_client)
    )
    return VaultCustomerZeroSigner(client, config.key_ids, issuer=config.issuer)
