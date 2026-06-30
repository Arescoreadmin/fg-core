"""CGIN Key Management provider protocol and data types."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol, runtime_checkable


# ---------------------------------------------------------------------------
# Algorithm registry (moved here from trust.py for clean import topology)
# ---------------------------------------------------------------------------


class SigningAlgorithm(str, Enum):
    """Supported CGIN snapshot signing algorithms.

    Add new values here when rotating algorithms; callers never reference
    raw strings.
    """

    ED25519_V1 = "ed25519-v1"
    # Future slots (not yet active):
    # ED448_V1 = "ed448-v1"
    # DILITHIUM_V1 = "dilithium-v1"
    # SPHINCS_V1 = "sphincs-v1"


# The active algorithm used by sign_payload(). Changing this value here
# is the only action needed to rotate the algorithm platform-wide.
ACTIVE_SIGNING_ALGORITHM = SigningAlgorithm.ED25519_V1


# ---------------------------------------------------------------------------
# Provider health
# ---------------------------------------------------------------------------


class ProviderHealth(str, Enum):
    READY = "ready"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    NOT_IMPLEMENTED = "not_implemented"


# ---------------------------------------------------------------------------
# Capability manifest
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProviderCapabilityManifest:
    provider_name: str
    supported_algorithms: list[str]
    key_types: list[str]
    rotation_supported: bool
    fips_compliant: bool
    offline_capable: bool
    hsm_capable: bool
    pqc_ready: bool
    contract_version: str


# ---------------------------------------------------------------------------
# Provider metadata (emitted with each signature)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProviderMetadata:
    provider_name: str
    provider_version: str
    key_identifier: str
    signing_algorithm: str
    generated_at: str
    contract_version: str


# ---------------------------------------------------------------------------
# Audit event (emitted by every sign/verify operation)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuditEvent:
    provider_name: str
    operation: str  # "sign" or "verify"
    algorithm: str
    key_identifier: str
    outcome: str  # "success" or "failure"
    timestamp: str


# ---------------------------------------------------------------------------
# Crypto policy
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CryptoPolicy:
    minimum_algorithm: SigningAlgorithm = SigningAlgorithm.ED25519_V1
    require_provider: str | None = None


# ---------------------------------------------------------------------------
# KeyProvider protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class KeyProvider(Protocol):
    provider_name: str
    provider_version: str
    contract_version: str
    supported_algorithms: list[SigningAlgorithm]

    def sign(self, canonical_bytes: bytes, algorithm: SigningAlgorithm) -> str: ...
    def verify(
        self, canonical_bytes: bytes, signature_b64: str, algorithm: SigningAlgorithm
    ) -> bool: ...
    def metadata(self) -> ProviderMetadata: ...
    def health(self) -> ProviderHealth: ...
    def capabilities(self) -> ProviderCapabilityManifest: ...
    def emit_audit(
        self, operation: str, algorithm: SigningAlgorithm, outcome: str
    ) -> AuditEvent: ...
