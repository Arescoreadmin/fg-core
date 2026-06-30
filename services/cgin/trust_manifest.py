"""CGIN TrustManifest — signed, self-describing authority declaration."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from services.cgin.privacy import (
    ACTIVE_FINGERPRINT_ALGORITHM,
    CGIN_BENCHMARK_VERSION,
    CGIN_PRIVACY_VERSION,
    CGIN_SCHEMA_VERSION,
)
from services.cgin.trust import (
    ACTIVE_SIGNING_ALGORITHM,
    CGIN_CANONICALIZATION_VERSION,
    CGIN_TRUST_VERSION,
    SigningAlgorithm,
    VerificationResult,
    canonicalize_snapshot,
    generate_digest,
    sign_payload,
    verify_payload,
)


@dataclass
class TrustManifest:
    authority_name: str
    authority_version: str
    signing_algorithm: str
    fingerprint_algorithm: str
    schema_version: str
    benchmark_version: str
    privacy_version: str
    digest: str
    signature: str
    generated_at: str
    trust_version: str
    canonicalization_version: str


def generate_trust_manifest(
    authority_name: str,
    signing_key: Any,
    *,
    authority_version: str = "1.0",
    algorithm: SigningAlgorithm = ACTIVE_SIGNING_ALGORITHM,
) -> TrustManifest:
    """Build and sign a TrustManifest for the given authority."""
    generated_at = datetime.now(tz=timezone.utc).isoformat()

    body: dict[str, Any] = {
        "authority_name": authority_name,
        "authority_version": authority_version,
        "signing_algorithm": algorithm.value,
        "fingerprint_algorithm": ACTIVE_FINGERPRINT_ALGORITHM.value,
        "schema_version": CGIN_SCHEMA_VERSION,
        "benchmark_version": CGIN_BENCHMARK_VERSION,
        "privacy_version": CGIN_PRIVACY_VERSION,
        "generated_at": generated_at,
        "trust_version": CGIN_TRUST_VERSION,
        "canonicalization_version": CGIN_CANONICALIZATION_VERSION,
    }

    canonical_bytes = canonicalize_snapshot(body)
    digest = generate_digest(canonical_bytes)
    signature = sign_payload(canonical_bytes, signing_key)

    return TrustManifest(
        authority_name=authority_name,
        authority_version=authority_version,
        signing_algorithm=algorithm.value,
        fingerprint_algorithm=ACTIVE_FINGERPRINT_ALGORITHM.value,
        schema_version=CGIN_SCHEMA_VERSION,
        benchmark_version=CGIN_BENCHMARK_VERSION,
        privacy_version=CGIN_PRIVACY_VERSION,
        digest=digest,
        signature=signature,
        generated_at=generated_at,
        trust_version=CGIN_TRUST_VERSION,
        canonicalization_version=CGIN_CANONICALIZATION_VERSION,
    )


def verify_trust_manifest(
    manifest: TrustManifest, verification_key: Any
) -> VerificationResult:
    """Verify a TrustManifest. Reconstructs the body, re-canonicalizes, verifies. Never raises."""
    errors: list[str] = []

    try:
        algorithm = SigningAlgorithm(manifest.signing_algorithm)
    except ValueError:
        return VerificationResult(
            valid=False,
            digest_match=False,
            signature_valid=False,
            algorithm_supported=False,
            canonicalization_valid=False,
            errors=[f"unsupported signing algorithm: {manifest.signing_algorithm!r}"],
        )

    try:
        body: dict[str, Any] = {
            "authority_name": manifest.authority_name,
            "authority_version": manifest.authority_version,
            "signing_algorithm": manifest.signing_algorithm,
            "fingerprint_algorithm": manifest.fingerprint_algorithm,
            "schema_version": manifest.schema_version,
            "benchmark_version": manifest.benchmark_version,
            "privacy_version": manifest.privacy_version,
            "generated_at": manifest.generated_at,
            "trust_version": manifest.trust_version,
            "canonicalization_version": manifest.canonicalization_version,
        }
        canonical_bytes = canonicalize_snapshot(body)
    except Exception as exc:
        return VerificationResult(
            valid=False,
            digest_match=False,
            signature_valid=False,
            algorithm_supported=True,
            canonicalization_valid=False,
            errors=[f"canonicalization failed: {exc}"],
        )

    computed_digest = generate_digest(canonical_bytes)
    digest_match = computed_digest == manifest.digest
    if not digest_match:
        errors.append("digest mismatch")

    signature_valid = verify_payload(
        canonical_bytes, manifest.signature, verification_key, algorithm
    )
    if not signature_valid:
        errors.append("signature verification failed")

    valid = digest_match and signature_valid

    return VerificationResult(
        valid=valid,
        digest_match=digest_match,
        signature_valid=signature_valid,
        algorithm_supported=True,
        canonicalization_valid=True,
        errors=errors,
    )
