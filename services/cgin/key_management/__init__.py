"""CGIN Key Management Authority — provider-based key management architecture."""

from __future__ import annotations

from typing import Any

from services.cgin.key_management.provider import (
    AuditEvent,
    CryptoPolicy,
    KeyProvider,
    ProviderCapabilityManifest,
    ProviderHealth,
    ProviderMetadata,
    SigningAlgorithm,
)
from services.cgin.key_management.providers.memory import MemoryKeyProvider
from services.cgin.key_management.registry import (
    ACTIVE_PROVIDER_REGISTRY,
    ProviderRegistry,
)
from services.cgin.key_management.trust_evidence import (
    CeremonyStateMachine,
    EvidenceState,
    ValidationResult,
    aggregate_states,
    canonical_manifest_bytes,
    fingerprint_manifest,
    validate_manifest,
)
from services.cgin.key_management.vault_transit import (
    AppRoleAuthenticator,
    ManagedSignature,
    TrustAnchor,
    TrustAnchorRegistry,
    TrustRole,
    VaultCustomerZeroConfig,
    VaultCustomerZeroSigner,
    VaultKeyVersionUnavailableError,
    VaultSession,
    VaultSessionProvider,
    VaultTransitClient,
    VaultTransitError,
    VaultVerifierUnavailableError,
    public_key_fingerprint,
    signer_from_environment,
)


def as_provider(key: Any) -> KeyProvider:
    """Wrap a raw key in MemoryKeyProvider, or return it directly if already a KeyProvider."""
    if isinstance(key, KeyProvider):
        return key
    return MemoryKeyProvider(key)


__all__ = [
    "ACTIVE_PROVIDER_REGISTRY",
    "AppRoleAuthenticator",
    "AuditEvent",
    "CeremonyStateMachine",
    "CryptoPolicy",
    "EvidenceState",
    "KeyProvider",
    "ManagedSignature",
    "MemoryKeyProvider",
    "ProviderCapabilityManifest",
    "ProviderHealth",
    "ProviderMetadata",
    "ProviderRegistry",
    "SigningAlgorithm",
    "TrustAnchor",
    "TrustAnchorRegistry",
    "TrustRole",
    "ValidationResult",
    "VaultCustomerZeroConfig",
    "VaultCustomerZeroSigner",
    "VaultKeyVersionUnavailableError",
    "VaultSession",
    "VaultSessionProvider",
    "VaultTransitClient",
    "VaultTransitError",
    "VaultVerifierUnavailableError",
    "aggregate_states",
    "as_provider",
    "canonical_manifest_bytes",
    "fingerprint_manifest",
    "public_key_fingerprint",
    "signer_from_environment",
    "validate_manifest",
]
