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
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

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
        self._anchors = {(a.trust_role, a.key_id, a.key_version): a for a in anchors}

    def resolve(self, role: TrustRole, key_id: str, key_version: int) -> TrustAnchor:
        try:
            return self._anchors[(role, key_id, key_version)]
        except KeyError as exc:
            raise ValueError("unknown Vault trust anchor") from exc

    def verify(
        self,
        role: TrustRole,
        key_id: str,
        key_version: int,
        payload: bytes,
        signature: str,
    ) -> bool:
        return self.resolve(role, key_id, key_version).verify(payload, signature)


class VaultTransitError(RuntimeError):
    """Fail-closed Vault Transit operation error."""


class VaultTransitClient:
    """Minimal authenticated Vault Transit HTTP client.

    ``token`` is accepted only from an approved runtime secret mechanism; it
    is never represented in metadata, exceptions, or persisted objects.
    """

    def __init__(
        self, address: str, token: str, *, http_client: httpx.Client | None = None
    ) -> None:
        if not address.startswith(("https://", "http://")) or not token:
            raise ValueError("Vault address and runtime token are required")
        self._address = address.rstrip("/")
        self._token = token
        self._client = http_client or httpx.Client(timeout=10.0)

    @classmethod
    def from_environment(
        cls, *, http_client: httpx.Client | None = None
    ) -> "VaultTransitClient":
        address = os.getenv("FG_CUSTOMER_ZERO_VAULT_ADDR", "")
        token = os.getenv("FG_CUSTOMER_ZERO_VAULT_TOKEN", "")
        return cls(address, token, http_client=http_client)

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        response = self._client.post(
            f"{self._address}/v1/{path}",
            headers={"X-Vault-Token": self._token},
            json=payload,
        )
        if response.status_code >= 400:
            raise VaultTransitError(
                f"Vault Transit request failed ({response.status_code})"
            )
        body = response.json()
        if not isinstance(body, dict) or not isinstance(body.get("data"), dict):
            raise VaultTransitError("Vault Transit returned malformed data")
        return body["data"]

    def _get(self, path: str) -> dict[str, Any]:
        response = self._client.get(
            f"{self._address}/v1/{path}",
            headers={"X-Vault-Token": self._token},
        )
        if response.status_code >= 400:
            raise VaultTransitError(
                f"Vault Transit request failed ({response.status_code})"
            )
        body = response.json()
        if not isinstance(body, dict) or not isinstance(body.get("data"), dict):
            raise VaultTransitError("Vault Transit returned malformed data")
        return body["data"]

    def sign(self, key_id: str, payload: bytes) -> tuple[str, int]:
        data = self._post(
            f"transit/sign/{key_id}",
            {"input": base64.b64encode(payload).decode("ascii")},
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

    def public_key(self, key_id: str, key_version: int) -> str:
        data = self._get(f"transit/keys/{key_id}")
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
        signature, version = self._client.sign(key_id, payload)
        public_key = self._client.public_key(key_id, version)
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
        if len(set(values.values())) != len(values):
            raise ValueError("Customer-Zero trust roles require distinct Vault key IDs")
        return cls(address=address, key_ids=values)


def signer_from_environment(
    *, http_client: httpx.Client | None = None
) -> VaultCustomerZeroSigner:
    """Build an operational signer without exposing or persisting the Vault token."""
    config = VaultCustomerZeroConfig.from_environment()
    client = VaultTransitClient.from_environment(http_client=http_client)
    return VaultCustomerZeroSigner(client, config.key_ids, issuer=config.issuer)
