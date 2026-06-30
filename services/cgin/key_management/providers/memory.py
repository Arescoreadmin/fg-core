"""MemoryKeyProvider — default in-process Ed25519 provider. Preserves 17.7B behavior exactly."""

from __future__ import annotations

import base64
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from services.cgin.key_management.provider import (
    AuditEvent,
    ProviderCapabilityManifest,
    ProviderHealth,
    ProviderMetadata,
    SigningAlgorithm,
)

PROVIDER_NAME = "memory"
PROVIDER_VERSION = "1.0"
CONTRACT_VERSION = "1.0"


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + pad)


class MemoryKeyProvider:
    """In-memory Ed25519 provider. Signs with private key, verifies with public key."""

    provider_name: str = PROVIDER_NAME
    provider_version: str = PROVIDER_VERSION
    contract_version: str = CONTRACT_VERSION
    supported_algorithms: list[SigningAlgorithm] = [SigningAlgorithm.ED25519_V1]

    def __init__(
        self,
        key: Any,
    ) -> None:
        if isinstance(key, Ed25519PrivateKey):
            self._private_key: Ed25519PrivateKey | None = key
            self._public_key: Ed25519PublicKey = key.public_key()
            self._key_identifier = "memory-private"
        elif isinstance(key, Ed25519PublicKey):
            self._private_key = None
            self._public_key = key
            self._key_identifier = "memory-public"
        else:
            raise TypeError(
                f"MemoryKeyProvider accepts Ed25519PrivateKey or Ed25519PublicKey,"
                f" got {type(key).__name__}"
            )

    @classmethod
    def from_private_key(cls, private_key: Ed25519PrivateKey) -> "MemoryKeyProvider":
        return cls(private_key)

    @classmethod
    def from_public_key(cls, public_key: Ed25519PublicKey) -> "MemoryKeyProvider":
        return cls(public_key)

    def sign(self, canonical_bytes: bytes, algorithm: SigningAlgorithm) -> str:
        if algorithm != SigningAlgorithm.ED25519_V1:
            raise NotImplementedError(f"MemoryKeyProvider does not support {algorithm}")
        if self._private_key is None:
            raise RuntimeError(
                "MemoryKeyProvider initialized with public key only; cannot sign"
            )
        sig_bytes = self._private_key.sign(canonical_bytes)
        return _b64url_encode(sig_bytes)

    def verify(
        self, canonical_bytes: bytes, signature_b64: str, algorithm: SigningAlgorithm
    ) -> bool:
        try:
            if algorithm != SigningAlgorithm.ED25519_V1:
                return False
            sig_bytes = _b64url_decode(signature_b64)
            self._public_key.verify(sig_bytes, canonical_bytes)
            return True
        except Exception:
            return False

    def metadata(self) -> ProviderMetadata:
        return ProviderMetadata(
            provider_name=self.provider_name,
            provider_version=self.provider_version,
            key_identifier=self._key_identifier,
            signing_algorithm=SigningAlgorithm.ED25519_V1.value,
            generated_at=datetime.now(tz=timezone.utc).isoformat(),
            contract_version=self.contract_version,
        )

    def health(self) -> ProviderHealth:
        return ProviderHealth.READY

    def capabilities(self) -> ProviderCapabilityManifest:
        return ProviderCapabilityManifest(
            provider_name=self.provider_name,
            supported_algorithms=[SigningAlgorithm.ED25519_V1.value],
            key_types=["Ed25519"],
            rotation_supported=True,
            fips_compliant=False,
            offline_capable=True,
            hsm_capable=False,
            pqc_ready=False,
            contract_version=self.contract_version,
        )

    def emit_audit(
        self, operation: str, algorithm: SigningAlgorithm, outcome: str
    ) -> AuditEvent:
        return AuditEvent(
            provider_name=self.provider_name,
            operation=operation,
            algorithm=algorithm.value,
            key_identifier=self._key_identifier,
            outcome=outcome,
            timestamp=datetime.now(tz=timezone.utc).isoformat(),
        )
