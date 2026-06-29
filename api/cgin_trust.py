# api/cgin_trust.py
"""CGIN Trust & Integrity Authority API — PR 17.7B.

All routes are tenant-scoped. All routes require governance:read.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from api.auth_scopes import require_bound_tenant, require_scopes
from services.cgin.trust import (
    ACTIVE_SIGNING_ALGORITHM,
    SigningAlgorithm,
    VerificationResult,
    verify_snapshot,
    _b64url_decode,
)
from services.cgin.trust_manifest import generate_trust_manifest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

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
    """Return a freshly generated trust manifest demonstrating the structure.

    Real storage integration is out of scope for PR 17.7B.
    """
    require_bound_tenant(request)
    private_key = Ed25519PrivateKey.generate()
    manifest = generate_trust_manifest(
        authority_name=f"cgin-trust-authority:{snapshot_id}",
        private_key=private_key,
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
