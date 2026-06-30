# api/cgin_trust.py
"""CGIN Trust & Integrity Authority API — PR 17.7B / 17.7C.

All routes are tenant-scoped. All routes require governance:read.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from api.auth_scopes import require_bound_tenant, require_scopes
from services.cgin.key_management import ACTIVE_PROVIDER_REGISTRY
from services.cgin.trust import (
    ACTIVE_SIGNING_ALGORITHM,
    SigningAlgorithm,
    VerificationResult,
    verify_snapshot,
    _b64url_decode,
)
from services.cgin.trust_manifest import generate_trust_manifest

router = APIRouter(tags=["cgin-trust"])


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class AlgorithmInfo(BaseModel):
    algorithm: str
    active: bool


class AlgorithmsResponse(BaseModel):
    algorithms: list[AlgorithmInfo]


class VerificationResponse(BaseModel):
    valid: bool
    digest_match: bool
    signature_valid: bool
    algorithm_supported: bool
    canonicalization_valid: bool
    errors: list[str]


class TrustManifestResponse(BaseModel):
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


class VerifyRequest(BaseModel):
    snapshot: dict[str, Any]
    public_key_b64: str
    expected_digest: str | None = None


class ProviderCapabilityResponse(BaseModel):
    provider_name: str
    supported_algorithms: list[str]
    key_types: list[str]
    rotation_supported: bool
    fips_compliant: bool
    offline_capable: bool
    hsm_capable: bool
    pqc_ready: bool
    contract_version: str


class ProviderInfoResponse(BaseModel):
    provider_name: str
    provider_version: str
    contract_version: str
    supported_algorithms: list[str]
    health: str
    capabilities: ProviderCapabilityResponse


class ProvidersResponse(BaseModel):
    providers: list[ProviderInfoResponse]
    active: str


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get(
    "/cgin/trust/algorithms",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=AlgorithmsResponse,
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
    },
)
def get_algorithms(request: Request) -> AlgorithmsResponse:
    require_bound_tenant(request)
    algorithms = [
        AlgorithmInfo(
            algorithm=alg.value,
            active=(alg == ACTIVE_SIGNING_ALGORITHM),
        )
        for alg in SigningAlgorithm
    ]
    return AlgorithmsResponse(algorithms=algorithms)


@router.post(
    "/cgin/trust/verify",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=VerificationResponse,
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        422: {"description": "Validation error"},
    },
)
def verify_snapshot_post(
    body: VerifyRequest,
    request: Request,
) -> VerificationResponse:
    require_bound_tenant(request)
    try:
        raw_key_bytes = _b64url_decode(body.public_key_b64)
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        # Load raw 32-byte Ed25519 public key
        public_key = Ed25519PublicKey.from_public_bytes(raw_key_bytes)
    except Exception as exc:
        return VerificationResponse(
            valid=False,
            digest_match=False,
            signature_valid=False,
            algorithm_supported=False,
            canonicalization_valid=False,
            errors=[f"invalid public_key_b64: {exc}"],
        )

    result: VerificationResult = verify_snapshot(
        body.snapshot, public_key, expected_digest=body.expected_digest
    )
    return VerificationResponse(
        valid=result.valid,
        digest_match=result.digest_match,
        signature_valid=result.signature_valid,
        algorithm_supported=result.algorithm_supported,
        canonicalization_valid=result.canonicalization_valid,
        errors=result.errors,
    )


@router.get(
    "/cgin/trust/verify",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=VerificationResponse,
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
    },
)
def verify_snapshot_get(request: Request) -> VerificationResponse:
    """Query-param driven verify endpoint for tooling compatibility.

    Returns a stub response — full verification requires POST with snapshot body.
    """
    require_bound_tenant(request)
    return VerificationResponse(
        valid=False,
        digest_match=False,
        signature_valid=False,
        algorithm_supported=True,
        canonicalization_valid=False,
        errors=["use POST /cgin/trust/verify with snapshot body for full verification"],
    )


@router.get(
    "/cgin/trust/manifest/{snapshot_id}",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=TrustManifestResponse,
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
    },
)
def get_manifest(snapshot_id: str, request: Request) -> TrustManifestResponse:
    """Return a freshly generated trust manifest demonstrating the structure."""
    require_bound_tenant(request)
    provider = ACTIVE_PROVIDER_REGISTRY.active()
    manifest = generate_trust_manifest(
        authority_name=f"cgin-trust-authority:{snapshot_id}",
        signing_key=provider,
    )
    return TrustManifestResponse(
        authority_name=manifest.authority_name,
        authority_version=manifest.authority_version,
        signing_algorithm=manifest.signing_algorithm,
        fingerprint_algorithm=manifest.fingerprint_algorithm,
        schema_version=manifest.schema_version,
        benchmark_version=manifest.benchmark_version,
        privacy_version=manifest.privacy_version,
        digest=manifest.digest,
        signature=manifest.signature,
        generated_at=manifest.generated_at,
        trust_version=manifest.trust_version,
        canonicalization_version=manifest.canonicalization_version,
    )


# ---------------------------------------------------------------------------
# Provider management helpers
# ---------------------------------------------------------------------------


def _provider_info(p: Any) -> ProviderInfoResponse:
    caps = p.capabilities()
    return ProviderInfoResponse(
        provider_name=p.provider_name,
        provider_version=p.provider_version,
        contract_version=p.contract_version,
        supported_algorithms=[a.value for a in p.supported_algorithms],
        health=p.health().value,
        capabilities=ProviderCapabilityResponse(
            provider_name=caps.provider_name,
            supported_algorithms=caps.supported_algorithms,
            key_types=caps.key_types,
            rotation_supported=caps.rotation_supported,
            fips_compliant=caps.fips_compliant,
            offline_capable=caps.offline_capable,
            hsm_capable=caps.hsm_capable,
            pqc_ready=caps.pqc_ready,
            contract_version=caps.contract_version,
        ),
    )


# ---------------------------------------------------------------------------
# Provider routes
# ---------------------------------------------------------------------------


@router.get(
    "/cgin/trust/providers",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=ProvidersResponse,
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
    },
)
def list_providers(request: Request) -> ProvidersResponse:
    """List all registered key providers and the active provider name."""
    require_bound_tenant(request)
    providers = [_provider_info(p) for p in ACTIVE_PROVIDER_REGISTRY.all()]
    return ProvidersResponse(
        providers=providers,
        active=ACTIVE_PROVIDER_REGISTRY.active().provider_name,
    )


@router.get(
    "/cgin/trust/providers/active",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=ProviderInfoResponse,
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
    },
)
def get_active_provider(request: Request) -> ProviderInfoResponse:
    """Return info about the currently active key provider."""
    require_bound_tenant(request)
    return _provider_info(ACTIVE_PROVIDER_REGISTRY.active())


@router.get(
    "/cgin/trust/providers/{provider_name}",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=ProviderInfoResponse,
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Provider not found"},
    },
)
def get_provider(provider_name: str, request: Request) -> ProviderInfoResponse:
    """Return info about a specific key provider by name."""
    require_bound_tenant(request)
    try:
        provider = ACTIVE_PROVIDER_REGISTRY.get(provider_name)
    except KeyError:
        raise HTTPException(
            status_code=404,
            detail=f"Provider {provider_name!r} not registered",
        )
    return _provider_info(provider)
