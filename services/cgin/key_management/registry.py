"""Provider registry — single source of truth for active provider."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from services.cgin.key_management.provider import KeyProvider, SigningAlgorithm
from services.cgin.key_management.providers.memory import MemoryKeyProvider


class ProviderRegistry:
    """Immutable registry of KeyProviders. Validates on construction."""

    def __init__(self, providers: list[KeyProvider], active_name: str):
        # Validate: no duplicate names, active_name must exist
        names = [p.provider_name for p in providers]
        if len(names) != len(set(names)):
            raise ValueError(f"Duplicate provider names: {names}")
        if active_name not in names:
            raise ValueError(
                f"Active provider {active_name!r} not registered. Available: {names}"
            )
        self._providers = {p.provider_name: p for p in providers}
        self._active_name = active_name

    def active(self) -> KeyProvider:
        return self._providers[self._active_name]

    def get(self, name: str) -> KeyProvider:
        try:
            return self._providers[name]
        except KeyError:
            raise KeyError(
                f"Provider {name!r} not registered. Available: {sorted(self._providers)}"
            )

    def all(self) -> list[KeyProvider]:
        return list(self._providers.values())

    def names(self) -> list[str]:
        return sorted(self._providers.keys())

    def algorithms(self) -> list[SigningAlgorithm]:
        seen: set[SigningAlgorithm] = set()
        result: list[SigningAlgorithm] = []
        for p in self._providers.values():
            for alg in p.supported_algorithms:
                if alg not in seen:
                    seen.add(alg)
                    result.append(alg)
        return result


# Default registry with a generated ephemeral key (appropriate for dev/test)
_DEFAULT_KEY = Ed25519PrivateKey.generate()
_DEFAULT_MEMORY_PROVIDER = MemoryKeyProvider.from_private_key(_DEFAULT_KEY)

ACTIVE_PROVIDER_REGISTRY = ProviderRegistry(
    providers=[_DEFAULT_MEMORY_PROVIDER],
    active_name=_DEFAULT_MEMORY_PROVIDER.provider_name,
)
