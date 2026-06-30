"""AzureKeyVaultProvider — enterprise stub for Azure Key Vault."""

from __future__ import annotations

from datetime import datetime, timezone

from services.cgin.key_management.provider import (
    AuditEvent,
    ProviderCapabilityManifest,
    ProviderHealth,
    ProviderMetadata,
    SigningAlgorithm,
)

PROVIDER_NAME = "azure-key-vault"
PROVIDER_VERSION = "1.0"
CONTRACT_VERSION = "1.0"


class AzureKeyVaultProvider:
    """Architecture stub for Azure Key Vault. Runtime operations not implemented."""

    provider_name: str = PROVIDER_NAME
    provider_version: str = PROVIDER_VERSION
    contract_version: str = CONTRACT_VERSION
    supported_algorithms: list[SigningAlgorithm] = [SigningAlgorithm.ED25519_V1]

    def sign(self, canonical_bytes: bytes, algorithm: SigningAlgorithm) -> str:
        raise NotImplementedError(
            "AzureKeyVaultProvider: runtime operations not implemented (architecture stub)"
        )

    def verify(
        self, canonical_bytes: bytes, signature_b64: str, algorithm: SigningAlgorithm
    ) -> bool:
        raise NotImplementedError(
            "AzureKeyVaultProvider: runtime operations not implemented (architecture stub)"
        )

    def metadata(self) -> ProviderMetadata:
        return ProviderMetadata(
            provider_name=self.provider_name,
            provider_version=self.provider_version,
            key_identifier="azure-key-vault-stub",
            signing_algorithm=SigningAlgorithm.ED25519_V1.value,
            generated_at=datetime.now(tz=timezone.utc).isoformat(),
            contract_version=self.contract_version,
        )

    def health(self) -> ProviderHealth:
        return ProviderHealth.NOT_IMPLEMENTED

    def capabilities(self) -> ProviderCapabilityManifest:
        return ProviderCapabilityManifest(
            provider_name=self.provider_name,
            supported_algorithms=[SigningAlgorithm.ED25519_V1.value],
            key_types=["RSA-2048", "EC-P256", "Ed25519"],
            rotation_supported=True,
            fips_compliant=True,
            offline_capable=False,
            hsm_capable=True,
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
            key_identifier="azure-key-vault-stub",
            outcome=outcome,
            timestamp=datetime.now(tz=timezone.utc).isoformat(),
        )
