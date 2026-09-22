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
from services.cgin.key_management.vault_transit import (
    ManagedSignature,
    TrustAnchor,
    TrustAnchorRegistry,
    TrustRole,
    VaultCustomerZeroConfig,
    VaultCustomerZeroSigner,
    VaultTransitClient,
    VaultSession,
    VaultSessionProvider,
    AppRoleAuthenticator,
    VaultTransitError,
    public_key_fingerprint,
    signer_from_environment,
)
from services.cgin.key_management.registry import (
    ACTIVE_PROVIDER_REGISTRY,
    ProviderRegistry,
)


def as_provider(key: Any) -> KeyProvider:
    """Wrap a raw key in MemoryKeyProvider, or return it directly if already a KeyProvider."""
    if isinstance(key, KeyProvider):
        return key
    return MemoryKeyProvider(key)


__all__ = [
    "KeyProvider",
    "ProviderHealth",
    "ProviderCapabilityManifest",
    "ProviderMetadata",
    "AuditEvent",
    "CryptoPolicy",
    "SigningAlgorithm",
    "ProviderRegistry",
    "ACTIVE_PROVIDER_REGISTRY",
    "MemoryKeyProvider",
    "ManagedSignature",
    "TrustAnchor",
    "TrustAnchorRegistry",
    "TrustRole",
    "VaultCustomerZeroConfig",
    "VaultCustomerZeroSigner",
    "VaultTransitClient",
    "VaultSession",
    "VaultSessionProvider",
    "AppRoleAuthenticator",
    "VaultTransitError",
    "public_key_fingerprint",
    "signer_from_environment",
    "as_provider",
]
